/**
 * @file webhook_runtime.c
 * @brief Thread-safe runtime integration for webhook delivery
 */

#include "webhook_runtime.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>

static bool string_equal(const char *a, const char *b) {
    if (a == NULL) {
        return b == NULL;
    }
    if (b == NULL) {
        return false;
    }
    return strcmp(a, b) == 0;
}

static webhook_manager_t *create_manager(const webhook_config_t *config) {
    if (config == NULL || !config->enabled) {
        return NULL;
    }

    webhook_manager_t *manager = webhook_manager_create(config);
    if (manager == NULL) {
        LOG_ERROR("webhook: failed to create runtime manager");
    }
    return manager;
}

int webhook_runtime_init(webhook_runtime_t *runtime, const webhook_config_t *config) {
    if (runtime == NULL) {
        return -1;
    }

    memset(runtime, 0, sizeof(*runtime));
    if (pthread_mutex_init(&runtime->lock, NULL) != 0) {
        return -1;
    }

    runtime->manager = create_manager(config);
    if (config != NULL && config->enabled && runtime->manager == NULL) {
        pthread_mutex_destroy(&runtime->lock);
        return -1;
    }

    runtime->initialized = true;
    return 0;
}

int webhook_runtime_reload(webhook_runtime_t *runtime, const webhook_config_t *config) {
    if (runtime == NULL || !runtime->initialized) {
        return -1;
    }

    webhook_manager_t *replacement = create_manager(config);
    if (config != NULL && config->enabled && replacement == NULL) {
        return -1;
    }

    pthread_mutex_lock(&runtime->lock);
    webhook_manager_t *previous = runtime->manager;
    runtime->manager = replacement;
    pthread_mutex_unlock(&runtime->lock);

    webhook_manager_destroy(previous);
    return 0;
}

void webhook_runtime_destroy(webhook_runtime_t *runtime) {
    if (runtime == NULL || !runtime->initialized) {
        return;
    }

    pthread_mutex_lock(&runtime->lock);
    webhook_manager_t *manager = runtime->manager;
    runtime->manager = NULL;
    runtime->initialized = false;
    pthread_mutex_unlock(&runtime->lock);

    webhook_manager_destroy(manager);
    pthread_mutex_destroy(&runtime->lock);
}

int webhook_runtime_emit(webhook_runtime_t *runtime, webhook_event_type_t event_type,
                         const char *username, const char *client_addr, const char *detail) {
    if (runtime == NULL || !runtime->initialized) {
        return -1;
    }

    char payload[1024];
    if (webhook_build_payload(payload, sizeof(payload), webhook_event_name(event_type), username,
                              client_addr, detail) < 0) {
        LOG_WARN("webhook: failed to build payload for event %s", webhook_event_name(event_type));
        return -1;
    }

    pthread_mutex_lock(&runtime->lock);
    webhook_manager_t *manager = runtime->manager;
    int rc = (manager != NULL) ? webhook_notify(manager, event_type, payload) : 0;
    pthread_mutex_unlock(&runtime->lock);

    return rc;
}

static const config_user_t *find_user_entry(const config_user_t *users, const char *username) {
    for (const config_user_t *user = users; user != NULL; user = user->next) {
        if (strcmp(user->username, username) == 0) {
            return user;
        }
    }
    return NULL;
}

static bool users_equal(const config_user_t *a, const config_user_t *b) {
    return a != NULL && b != NULL && strcmp(a->username, b->username) == 0 &&
           strcmp(a->password_hash, b->password_hash) == 0 &&
           string_equal(a->pubkeys, b->pubkeys) &&
           a->password_changed_at == b->password_changed_at &&
           a->password_changed_at_set == b->password_changed_at_set &&
           a->password_change_required == b->password_change_required && a->enabled == b->enabled;
}

static bool policies_equal(const config_policy_t *a, const config_policy_t *b) {
    return a != NULL && b != NULL && strcmp(a->username_pattern, b->username_pattern) == 0 &&
           strcmp(a->upstream_pattern, b->upstream_pattern) == 0 &&
           a->allowed_features == b->allowed_features && a->denied_features == b->denied_features;
}

static bool policy_lists_equal(const config_policy_t *left, const config_policy_t *right) {
    size_t left_count = 0;
    size_t right_count = 0;

    for (const config_policy_t *policy = left; policy != NULL; policy = policy->next) {
        left_count++;
        bool found = false;
        for (const config_policy_t *candidate = right; candidate != NULL;
             candidate = candidate->next) {
            if (policies_equal(policy, candidate)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }

    for (const config_policy_t *policy = right; policy != NULL; policy = policy->next) {
        (void)policy;
        right_count++;
    }

    return left_count == right_count;
}

void webhook_runtime_emit_config_diff(webhook_runtime_t *runtime, const proxy_config_t *old_config,
                                      const proxy_config_t *new_config, const char *detail) {
    if (runtime == NULL || old_config == NULL || new_config == NULL) {
        return;
    }

    for (const config_user_t *user = new_config->users; user != NULL; user = user->next) {
        const config_user_t *previous = find_user_entry(old_config->users, user->username);
        if (previous == NULL) {
            webhook_runtime_emit(runtime, WEBHOOK_EVENT_USER_CREATED, user->username, NULL, detail);
        } else if (!users_equal(previous, user)) {
            webhook_runtime_emit(runtime, WEBHOOK_EVENT_USER_UPDATED, user->username, NULL, detail);
        }
    }

    for (const config_user_t *user = old_config->users; user != NULL; user = user->next) {
        if (find_user_entry(new_config->users, user->username) == NULL) {
            webhook_runtime_emit(runtime, WEBHOOK_EVENT_USER_DELETED, user->username, NULL, detail);
        }
    }

    if (!policy_lists_equal(old_config->policies, new_config->policies)) {
        webhook_runtime_emit(runtime, WEBHOOK_EVENT_POLICY_UPDATED, NULL, NULL, detail);
    }

    webhook_runtime_emit(runtime, WEBHOOK_EVENT_CONFIG_RELOADED, NULL, NULL, detail);
}
