/**
 * @file rate_limit_filter.c
 * @brief SSH Proxy Core - Rate Limiting Filter Implementation
 */

#include "rate_limit_filter.h"
#include "logger.h"
#include "router.h"
#include "session.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Maximum tracked entries */
#define MAX_ENTRIES 1024

/* Rate limit entry (tracks connections per key) */
typedef struct rate_entry {
    char key[256];           /* Key (IP or user) */
    int current_connections; /* Current connection count */
    int connection_count;    /* Connections in current interval */
    time_t interval_start;   /* Start of current interval */
    bool active;
} rate_entry_t;

/* Rate limit filter state */
typedef struct rate_limit_state {
    rate_entry_t entries[MAX_ENTRIES];
    int total_connections;
    int total_in_interval;
    time_t global_interval_start;
    pthread_mutex_t lock;
} rate_limit_state_t;

/* Forward declarations */
static filter_status_t rate_limit_on_connect(filter_t *filter, filter_context_t *ctx);
static filter_status_t rate_limit_on_authenticated(filter_t *filter, filter_context_t *ctx);
static void rate_limit_on_close(filter_t *filter, filter_context_t *ctx);
static void rate_limit_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t rate_limit_callbacks = {.on_connect = rate_limit_on_connect,
                                                        .on_auth = NULL,
                                                        .on_authenticated = rate_limit_on_authenticated,
                                                        .on_route = NULL,
                                                        .on_data_upstream = NULL,
                                                        .on_data_downstream = NULL,
                                                        .on_close = rate_limit_on_close,
                                                        .destroy = rate_limit_destroy};

/* Find or create entry for key */
static rate_entry_t *find_or_create_entry(rate_limit_state_t *state, const char *key) {
    if (key == NULL || *key == '\0') {
        return NULL;
    }

    /* Look for existing entry */
    rate_entry_t *free_slot = NULL;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (state->entries[i].active) {
            if (strcmp(state->entries[i].key, key) == 0) {
                return &state->entries[i];
            }
        } else if (free_slot == NULL) {
            free_slot = &state->entries[i];
        }
    }

    /* Create new entry */
    if (free_slot != NULL) {
        memset(free_slot, 0, sizeof(*free_slot));
        strncpy(free_slot->key, key, sizeof(free_slot->key) - 1);
        free_slot->active = true;
        free_slot->interval_start = time(NULL);
        return free_slot;
    }

    return NULL;
}

/* Check rate limit for an entry */
static rate_limit_result_t check_entry_limit(rate_entry_t *entry, const rate_limit_rule_t *rule) {
    if (entry == NULL || rule == NULL) {
        return RATE_LIMIT_ALLOW;
    }

    time_t now = time(NULL);

    /* Reset interval if needed */
    if ((now - entry->interval_start) >= rule->interval_sec) {
        entry->connection_count = 0;
        entry->interval_start = now;
    }

    /* Check concurrent connections */
    if (rule->max_connections > 0 && entry->current_connections >= rule->max_connections) {
        return RATE_LIMIT_DENY;
    }

    /* Check rate */
    if (rule->max_rate > 0 && entry->connection_count >= rule->max_rate) {
        return RATE_LIMIT_THROTTLE;
    }

    return RATE_LIMIT_ALLOW;
}

/* Filter callbacks implementation */
static filter_status_t rate_limit_on_connect(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }

    rate_limit_filter_config_t *config = (rate_limit_filter_config_t *)filter->config;
    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (config == NULL || state == NULL) {
        return FILTER_CONTINUE;
    }

    session_metadata_t *meta = NULL;
    if (ctx->session != NULL) {
        meta = session_get_metadata(ctx->session);
    }

    const char *client_addr = meta ? meta->client_addr : NULL;

    rate_limit_result_t result = rate_limit_check(filter, client_addr, ctx->username);

    if (result == RATE_LIMIT_DENY) {
        if (config->log_rejections) {
            LOG_WARN("Rate limit: Connection denied for %s (concurrent limit)",
                     client_addr ? client_addr : "(unknown)");
        }
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, result,
                             config->event_user_data);
        }
        return FILTER_REJECT;
    }

    if (result == RATE_LIMIT_THROTTLE) {
        if (config->log_rejections) {
            LOG_WARN("Rate limit: Connection throttled for %s (rate limit)",
                     client_addr ? client_addr : "(unknown)");
        }
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, result,
                             config->event_user_data);
        }
        return FILTER_REJECT;
    }

    return FILTER_CONTINUE;
}

static filter_status_t rate_limit_on_authenticated(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL || ctx->username == NULL) {
        return FILTER_CONTINUE;
    }

    session_metadata_t *meta = NULL;
    if (ctx->session != NULL) {
        meta = session_get_metadata(ctx->session);
    }

    rate_limit_result_t result = rate_limit_check_user_sessions(filter, ctx->username);
    if (result == RATE_LIMIT_DENY) {
        rate_limit_filter_config_t *config = (rate_limit_filter_config_t *)filter->config;
        if (config != NULL && config->log_rejections) {
            LOG_WARN("Rate limit: User '%s' exceeded per-user session limit", ctx->username);
        }
        if (config != NULL && config->event_cb != NULL) {
            config->event_cb(ctx->username,
                             meta ? meta->client_addr : NULL,
                             result,
                             config->event_user_data);
        }
        return FILTER_REJECT;
    }

    return FILTER_CONTINUE;
}

static void rate_limit_on_close(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL) {
        return;
    }

    session_metadata_t *meta = NULL;
    if (ctx->session != NULL) {
        meta = session_get_metadata(ctx->session);
    }

    const char *client_addr = meta ? meta->client_addr : NULL;

    /* Release IP-based tracking */
    rate_limit_release(filter, client_addr, ctx->username);

    /* Release username-based tracking (for per-user session limits) */
    if (ctx->username != NULL) {
        rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
        if (state != NULL) {
            pthread_mutex_lock(&state->lock);
            for (int i = 0; i < MAX_ENTRIES; i++) {
                if (state->entries[i].active && strcmp(state->entries[i].key, ctx->username) == 0) {
                    if (state->entries[i].current_connections > 0) {
                        state->entries[i].current_connections--;
                    }
                    if (state->entries[i].current_connections == 0) {
                        state->entries[i].active = false;
                    }
                    break;
                }
            }
            pthread_mutex_unlock(&state->lock);
        }
    }
}

static void rate_limit_destroy(filter_t *filter) {
    if (filter == NULL) {
        return;
    }

    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (state != NULL) {
        pthread_mutex_destroy(&state->lock);
        free(state);
    }

    rate_limit_filter_config_t *config = (rate_limit_filter_config_t *)filter->config;
    if (config != NULL) {
        rate_limit_rule_t *rule = config->rules;
        while (rule != NULL) {
            rate_limit_rule_t *next = rule->next;
            free(rule);
            rule = next;
        }
        rate_limit_rule_t *urule = config->user_session_rules;
        while (urule != NULL) {
            rate_limit_rule_t *next = urule->next;
            free(urule);
            urule = next;
        }
    }

    LOG_DEBUG("Rate limit filter destroyed");
}

filter_t *rate_limit_filter_create(const rate_limit_filter_config_t *config) {
    if (config == NULL) {
        return NULL;
    }

    /* Copy configuration */
    rate_limit_filter_config_t *cfg_copy = calloc(1, sizeof(rate_limit_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }
    *cfg_copy = *config;
    cfg_copy->rules = NULL;
    cfg_copy->user_session_rules = NULL;

    /* Copy rules */
    rate_limit_rule_t *src = config->rules;
    rate_limit_rule_t **dst = &cfg_copy->rules;
    while (src != NULL) {
        *dst = calloc(1, sizeof(rate_limit_rule_t));
        if (*dst == NULL) {
            /* Cleanup on error */
            rate_limit_rule_t *r = cfg_copy->rules;
            while (r != NULL) {
                rate_limit_rule_t *next = r->next;
                free(r);
                r = next;
            }
            free(cfg_copy);
            return NULL;
        }
        **dst = *src;
        (*dst)->next = NULL;
        dst = &(*dst)->next;
        src = src->next;
    }

    /* Copy user session rules */
    src = config->user_session_rules;
    dst = &cfg_copy->user_session_rules;
    while (src != NULL) {
        *dst = calloc(1, sizeof(rate_limit_rule_t));
        if (*dst == NULL) {
            /* Cleanup on error */
            rate_limit_rule_t *r = cfg_copy->user_session_rules;
            while (r != NULL) {
                rate_limit_rule_t *next = r->next;
                free(r);
                r = next;
            }
            r = cfg_copy->rules;
            while (r != NULL) {
                rate_limit_rule_t *next = r->next;
                free(r);
                r = next;
            }
            free(cfg_copy);
            return NULL;
        }
        **dst = *src;
        (*dst)->next = NULL;
        dst = &(*dst)->next;
        src = src->next;
    }

    filter_t *filter =
        filter_create("rate_limit", FILTER_TYPE_RATE_LIMIT, &rate_limit_callbacks, cfg_copy);
    if (filter == NULL) {
        rate_limit_rule_t *r = cfg_copy->rules;
        while (r != NULL) {
            rate_limit_rule_t *next = r->next;
            free(r);
            r = next;
        }
        r = cfg_copy->user_session_rules;
        while (r != NULL) {
            rate_limit_rule_t *next = r->next;
            free(r);
            r = next;
        }
        free(cfg_copy);
        return NULL;
    }

    /* Create state */
    rate_limit_state_t *state = calloc(1, sizeof(rate_limit_state_t));
    if (state == NULL) {
        free(filter);
        rate_limit_rule_t *r = cfg_copy->rules;
        while (r != NULL) {
            rate_limit_rule_t *next = r->next;
            free(r);
            r = next;
        }
        r = cfg_copy->user_session_rules;
        while (r != NULL) {
            rate_limit_rule_t *next = r->next;
            free(r);
            r = next;
        }
        free(cfg_copy);
        return NULL;
    }

    pthread_mutex_init(&state->lock, NULL);
    state->global_interval_start = time(NULL);
    filter->state = state;

    LOG_DEBUG("Rate limit filter created, global_max=%d, rate=%d/%ds",
              config->global_max_connections, config->global_max_rate, config->global_interval_sec);

    return filter;
}

int rate_limit_add_rule(rate_limit_filter_config_t *config, const rate_limit_rule_t *rule) {
    if (config == NULL || rule == NULL) {
        return -1;
    }

    rate_limit_rule_t *new_rule = calloc(1, sizeof(rate_limit_rule_t));
    if (new_rule == NULL) {
        return -1;
    }

    *new_rule = *rule;
    new_rule->next = config->rules;
    config->rules = new_rule;

    LOG_DEBUG("Rate limit rule '%s' added: pattern=%s, max_conn=%d, rate=%d/%ds", rule->name,
              rule->match_pattern, rule->max_connections, rule->max_rate, rule->interval_sec);

    return 0;
}

int rate_limit_remove_rule(rate_limit_filter_config_t *config, const char *name) {
    if (config == NULL || name == NULL) {
        return -1;
    }

    rate_limit_rule_t *prev = NULL;
    rate_limit_rule_t *rule = config->rules;

    while (rule != NULL) {
        if (strcmp(rule->name, name) == 0) {
            if (prev == NULL) {
                config->rules = rule->next;
            } else {
                prev->next = rule->next;
            }
            free(rule);
            LOG_DEBUG("Rate limit rule '%s' removed", name);
            return 0;
        }
        prev = rule;
        rule = rule->next;
    }

    return -1;
}

rate_limit_result_t rate_limit_check(filter_t *filter, const char *client_addr,
                                     const char *username) {
    if (filter == NULL) {
        return RATE_LIMIT_ALLOW;
    }

    rate_limit_filter_config_t *config = (rate_limit_filter_config_t *)filter->config;
    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (config == NULL || state == NULL) {
        return RATE_LIMIT_ALLOW;
    }

    pthread_mutex_lock(&state->lock);

    time_t now = time(NULL);

    /* Check global limits */
    if (config->global_interval_sec > 0) {
        if ((now - state->global_interval_start) >= config->global_interval_sec) {
            state->total_in_interval = 0;
            state->global_interval_start = now;
        }
    }

    if (config->global_max_connections > 0 &&
        state->total_connections >= config->global_max_connections) {
        pthread_mutex_unlock(&state->lock);
        return RATE_LIMIT_DENY;
    }

    if (config->global_max_rate > 0 && state->total_in_interval >= config->global_max_rate) {
        pthread_mutex_unlock(&state->lock);
        return RATE_LIMIT_THROTTLE;
    }

    /* Check per-pattern rules */
    rate_limit_rule_t *rule = config->rules;
    while (rule != NULL) {
        bool matches = false;

        if (client_addr != NULL && router_glob_match(rule->match_pattern, client_addr)) {
            matches = true;
        } else if (username != NULL && router_glob_match(rule->match_pattern, username)) {
            matches = true;
        }

        if (matches) {
            const char *key = client_addr ? client_addr : username;
            rate_entry_t *entry = find_or_create_entry(state, key);
            if (entry != NULL) {
                rate_limit_result_t result = check_entry_limit(entry, rule);
                if (result != RATE_LIMIT_ALLOW) {
                    pthread_mutex_unlock(&state->lock);
                    return result;
                }
            }
        }

        rule = rule->next;
    }

    /* Track connection */
    if (client_addr != NULL) {
        rate_entry_t *entry = find_or_create_entry(state, client_addr);
        if (entry != NULL) {
            entry->current_connections++;
            entry->connection_count++;
        }
    }

    state->total_connections++;
    state->total_in_interval++;

    pthread_mutex_unlock(&state->lock);
    return RATE_LIMIT_ALLOW;
}

void rate_limit_release(filter_t *filter, const char *client_addr, const char *username) {
    if (filter == NULL) {
        return;
    }

    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (state == NULL) {
        return;
    }

    pthread_mutex_lock(&state->lock);

    const char *key = client_addr ? client_addr : username;
    if (key != NULL) {
        for (int i = 0; i < MAX_ENTRIES; i++) {
            if (state->entries[i].active && strcmp(state->entries[i].key, key) == 0) {
                if (state->entries[i].current_connections > 0) {
                    state->entries[i].current_connections--;
                }
                /* Deactivate if no more connections */
                if (state->entries[i].current_connections == 0) {
                    state->entries[i].active = false;
                }
                break;
            }
        }
    }

    if (state->total_connections > 0) {
        state->total_connections--;
    }

    pthread_mutex_unlock(&state->lock);
}

rate_limit_result_t rate_limit_check_user_sessions(filter_t *filter, const char *username)
{
    if (filter == NULL || username == NULL) {
        return RATE_LIMIT_ALLOW;
    }

    rate_limit_filter_config_t *config = (rate_limit_filter_config_t *)filter->config;
    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (config == NULL || state == NULL) {
        return RATE_LIMIT_ALLOW;
    }

    pthread_mutex_lock(&state->lock);

    /* Count current sessions for this user */
    int user_sessions = 0;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (state->entries[i].active && strcmp(state->entries[i].key, username) == 0) {
            user_sessions = state->entries[i].current_connections;
            break;
        }
    }
    if (config->count_user_cb != NULL) {
        int shared_sessions = config->count_user_cb(username, config->count_user_user_data);
        if (shared_sessions >= 0) {
            user_sessions = shared_sessions;
        }
    }

    /* Check per-user rules first (more specific) */
    rate_limit_rule_t *rule = config->user_session_rules;
    while (rule != NULL) {
        if (router_glob_match(rule->match_pattern, username)) {
            if (rule->max_connections > 0 && user_sessions >= rule->max_connections) {
                pthread_mutex_unlock(&state->lock);
                return RATE_LIMIT_DENY;
            }
            pthread_mutex_unlock(&state->lock);
            return RATE_LIMIT_ALLOW;  /* Matched specific rule, use it */
        }
        rule = rule->next;
    }

    /* Check default per-user limit */
    if (config->per_user_max_sessions > 0 && user_sessions >= config->per_user_max_sessions) {
        pthread_mutex_unlock(&state->lock);
        return RATE_LIMIT_DENY;
    }

    /* Track user connection */
    rate_entry_t *entry = find_or_create_entry(state, username);
    if (entry != NULL) {
        entry->current_connections++;
    }

    pthread_mutex_unlock(&state->lock);
    return RATE_LIMIT_ALLOW;
}

int rate_limit_get_count(filter_t *filter, const char *pattern) {
    if (filter == NULL || pattern == NULL) {
        return 0;
    }

    rate_limit_state_t *state = (rate_limit_state_t *)filter->state;
    if (state == NULL) {
        return 0;
    }

    pthread_mutex_lock(&state->lock);

    int count = 0;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (state->entries[i].active && router_glob_match(pattern, state->entries[i].key)) {
            count += state->entries[i].current_connections;
        }
    }

    pthread_mutex_unlock(&state->lock);
    return count;
}
