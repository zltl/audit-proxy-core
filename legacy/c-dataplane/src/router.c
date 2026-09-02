/**
 * @file router.c
 * @brief SSH Proxy Core - Router and Upstream Implementation
 */

#include "router.h"
#include "metrics.h"
#include "logger.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ROUTER_HASH_VIRTUAL_NODES 32

/* Router structure */
struct router {
    router_config_t config;
    upstream_t upstreams[ROUTER_MAX_UPSTREAMS];
    size_t upstream_count;
    route_rule_t *rules;
    int default_upstream;
    size_t round_robin_index;   /* For round-robin LB */
    connection_pool_t pool;     /* Upstream connection pool */
};

typedef struct hash_ring_entry {
    uint64_t point;
    int upstream_index;
} hash_ring_entry_t;

static uint64_t router_hash64(const char *value)
{
    uint64_t hash = 1469598103934665603ULL;
    if (value == NULL) {
        return hash;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        hash ^= (uint64_t)(*p);
        hash *= 1099511628211ULL;
    }
    /* Finalize with an avalanche step so nearby labels/usernames still spread evenly. */
    hash ^= (hash >> 33);
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= (hash >> 33);
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= (hash >> 33);
    return hash;
}

static int compare_hash_ring_entries(const void *a, const void *b)
{
    const hash_ring_entry_t *left = (const hash_ring_entry_t *)a;
    const hash_ring_entry_t *right = (const hash_ring_entry_t *)b;
    if (left->point < right->point) {
        return -1;
    }
    if (left->point > right->point) {
        return 1;
    }
    return left->upstream_index - right->upstream_index;
}

static size_t build_hash_ring(router_t *router, const int *healthy_indices,
                              size_t healthy_count, hash_ring_entry_t *ring,
                              size_t ring_capacity)
{
    if (router == NULL || healthy_indices == NULL || ring == NULL || ring_capacity == 0) {
        return 0;
    }

    size_t ring_count = 0;
    char label[ROUTER_MAX_HOST + 32];
    for (size_t i = 0; i < healthy_count; i++) {
        int upstream_index = healthy_indices[i];
        upstream_t *upstream = &router->upstreams[upstream_index];
        for (size_t vnode = 0; vnode < ROUTER_HASH_VIRTUAL_NODES &&
                                ring_count < ring_capacity; vnode++) {
            snprintf(label, sizeof(label), "%s:%u#%zu", upstream->config.host,
                     (unsigned int)upstream->config.port, vnode);
            ring[ring_count].point = router_hash64(label);
            ring[ring_count].upstream_index = upstream_index;
            ring_count++;
        }
    }

    qsort(ring, ring_count, sizeof(ring[0]), compare_hash_ring_entries);
    return ring_count;
}

static int upstream_weight(const upstream_t *upstream)
{
    if (upstream == NULL || upstream->config.weight <= 0) {
        return 1;
    }
    return upstream->config.weight;
}

static int select_upstream_consistent_hash(router_t *router, const char *key,
                                           const int *healthy_indices, size_t healthy_count)
{
    if (router == NULL || healthy_indices == NULL || healthy_count == 0) {
        return -1;
    }
    if (key == NULL || *key == '\0') {
        return healthy_indices[0];
    }

    hash_ring_entry_t ring[ROUTER_MAX_UPSTREAMS * ROUTER_HASH_VIRTUAL_NODES];
    size_t ring_count = build_hash_ring(router, healthy_indices, healthy_count,
                                        ring, sizeof(ring) / sizeof(ring[0]));
    if (ring_count == 0) {
        return healthy_indices[0];
    }

    uint64_t point = router_hash64(key);
    size_t left = 0;
    size_t right = ring_count;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (ring[mid].point < point) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    if (left >= ring_count) {
        return ring[0].upstream_index;
    }
    return ring[left].upstream_index;
}

static int select_upstream_weighted(router_t *router, const int *healthy_indices,
                                    size_t healthy_count)
{
    if (router == NULL || healthy_indices == NULL || healthy_count == 0) {
        return -1;
    }

    int selected = healthy_indices[0];
    int best_weight = 0;
    int total_weight = 0;
    bool have_best = false;

    for (size_t i = 0; i < healthy_count; i++) {
        upstream_t *upstream = &router->upstreams[healthy_indices[i]];
        int weight = upstream_weight(upstream);
        upstream->current_weight += weight;
        total_weight += weight;
        if (!have_best || upstream->current_weight > best_weight) {
            best_weight = upstream->current_weight;
            selected = healthy_indices[i];
            have_best = true;
        }
    }

    router->upstreams[selected].current_weight -= total_weight;
    return selected;
}

/* Simple glob pattern matching */
bool router_glob_match(const char *pattern, const char *str)
{
    if (pattern == NULL || str == NULL) {
        return false;
    }

    while (*pattern && *str) {
        if (*pattern == '*') {
            /* Skip consecutive stars */
            while (*pattern == '*') {
                pattern++;
            }
            if (*pattern == '\0') {
                return true;
            }
            /* Try to match rest of pattern */
            while (*str) {
                if (router_glob_match(pattern, str)) {
                    return true;
                }
                str++;
            }
            return false;
        } else if (*pattern == '?' || *pattern == *str) {
            pattern++;
            str++;
        } else {
            return false;
        }
    }

    /* Handle trailing stars */
    while (*pattern == '*') {
        pattern++;
    }

    return (*pattern == '\0' && *str == '\0');
}

router_t *router_create(const router_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    router_t *router = calloc(1, sizeof(router_t));
    if (router == NULL) {
        return NULL;
    }

    router->config = *config;
    router->upstream_count = 0;
    router->rules = NULL;
    router->default_upstream = -1;
    router->round_robin_index = 0;

    if (config->pool_enabled) {
        connection_pool_init(&router->pool,
                             config->pool_max_idle > 0 ? config->pool_max_idle : 10,
                             config->pool_max_idle_time_sec > 0 ? config->pool_max_idle_time_sec : 300);
    }

    LOG_DEBUG("Router created, lb_policy=%d", config->lb_policy);
    return router;
}

void router_destroy(router_t *router)
{
    if (router == NULL) {
        return;
    }

    /* Destroy connection pool */
    connection_pool_destroy(&router->pool);

    /* Free rules */
    route_rule_t *rule = router->rules;
    while (rule != NULL) {
        route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }

    free(router);
    LOG_DEBUG("Router destroyed");
}

int router_add_upstream(router_t *router, const upstream_config_t *config)
{
    if (router == NULL || config == NULL) {
        return -1;
    }

    if (router->upstream_count >= ROUTER_MAX_UPSTREAMS) {
        LOG_ERROR("Maximum upstreams reached (%d)", ROUTER_MAX_UPSTREAMS);
        return -1;
    }

    int index = (int)router->upstream_count;
    upstream_t *upstream = &router->upstreams[index];

    upstream->config = *config;
    upstream->health = UPSTREAM_HEALTH_UNKNOWN;
    upstream->active_connections = 0;
    upstream->total_connections = 0;
    upstream->last_check = 0;
    upstream->last_failure = 0;
    upstream->consecutive_failures = 0;
    upstream->current_weight = 0;

    router->upstream_count++;

    /* Set as default if first upstream */
    if (router->default_upstream < 0) {
        router->default_upstream = index;
    }

    LOG_INFO("Upstream %d added: %s:%d (weight=%d)",
             index, config->host, config->port, config->weight);

    return index;
}

int router_remove_upstream(router_t *router, int index)
{
    if (router == NULL || index < 0 || (size_t)index >= router->upstream_count) {
        return -1;
    }

    /* Mark as disabled instead of removing to preserve indices */
    router->upstreams[index].config.enabled = false;
    router->upstreams[index].current_weight = 0;

    LOG_INFO("Upstream %d disabled: %s:%d",
             index,
             router->upstreams[index].config.host,
             router->upstreams[index].config.port);

    return 0;
}

upstream_t *router_get_upstream(router_t *router, int index)
{
    if (router == NULL || index < 0 || (size_t)index >= router->upstream_count) {
        return NULL;
    }
    return &router->upstreams[index];
}

size_t router_get_upstream_count(const router_t *router)
{
    if (router == NULL) {
        return 0;
    }
    return router->upstream_count;
}

int router_add_rule(router_t *router, const route_rule_t *rule)
{
    if (router == NULL || rule == NULL) {
        return -1;
    }

    route_rule_t *new_rule = calloc(1, sizeof(route_rule_t));
    if (new_rule == NULL) {
        return -1;
    }

    *new_rule = *rule;
    new_rule->next = NULL;

    /* Add to end of list */
    if (router->rules == NULL) {
        router->rules = new_rule;
    } else {
        route_rule_t *last = router->rules;
        while (last->next != NULL) {
            last = last->next;
        }
        last->next = new_rule;
    }

    LOG_DEBUG("Route rule '%s' added: user=%s, target=%s -> upstream=%d",
              rule->name, rule->match_username, rule->match_target,
              rule->upstream_index);

    return 0;
}

int router_remove_rule(router_t *router, const char *name)
{
    if (router == NULL || name == NULL) {
        return -1;
    }

    route_rule_t *prev = NULL;
    route_rule_t *rule = router->rules;

    while (rule != NULL) {
        if (strcmp(rule->name, name) == 0) {
            if (prev == NULL) {
                router->rules = rule->next;
            } else {
                prev->next = rule->next;
            }
            free(rule);
            LOG_DEBUG("Route rule '%s' removed", name);
            return 0;
        }
        prev = rule;
        rule = rule->next;
    }

    return -1;
}

/* Select upstream using load balancing policy */
static int select_upstream_lb(router_t *router, const char *username)
{
    if (router->upstream_count == 0) {
        return -1;
    }

    size_t healthy_count = 0;
    int healthy_indices[ROUTER_MAX_UPSTREAMS];

    /* Find all healthy/enabled upstreams */
    for (size_t i = 0; i < router->upstream_count; i++) {
        upstream_t *u = &router->upstreams[i];
        if (u->config.enabled &&
            u->health != UPSTREAM_HEALTH_UNHEALTHY) {
            healthy_indices[healthy_count++] = (int)i;
        } else {
            u->current_weight = 0;
        }
    }

    if (healthy_count == 0) {
        /* Fall back to default if all unhealthy */
        if (router->default_upstream >= 0 &&
            router->upstreams[router->default_upstream].config.enabled) {
            return router->default_upstream;
        }
        return -1;
    }

    int selected = -1;

    switch (router->config.lb_policy) {
    case LB_POLICY_ROUND_ROBIN:
        selected = healthy_indices[router->round_robin_index % healthy_count];
        router->round_robin_index++;
        break;

    case LB_POLICY_RANDOM:
        selected = healthy_indices[rand() % healthy_count];
        break;

    case LB_POLICY_LEAST_CONN: {
        size_t min_conn = SIZE_MAX;
        for (size_t i = 0; i < healthy_count; i++) {
            upstream_t *u = &router->upstreams[healthy_indices[i]];
            if (u->active_connections < min_conn) {
                min_conn = u->active_connections;
                selected = healthy_indices[i];
            }
        }
        break;
    }

    case LB_POLICY_HASH:
        selected = select_upstream_consistent_hash(router, username, healthy_indices,
                                                   healthy_count);
        break;

    case LB_POLICY_WEIGHTED:
        selected = select_upstream_weighted(router, healthy_indices, healthy_count);
        break;

    default:
        selected = healthy_indices[0];
        break;
    }

    return selected;
}

int router_resolve(router_t *router, const char *username,
                   const char *target, route_result_t *result)
{
    if (router == NULL || result == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    /* Try to match rules first */
    route_rule_t *rule = router->rules;
    while (rule != NULL) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }

        bool username_match = (rule->match_username[0] == '\0' ||
                               router_glob_match(rule->match_username, username ? username : ""));
        bool target_match = (rule->match_target[0] == '\0' ||
                             router_glob_match(rule->match_target, target ? target : ""));

        if (username_match && target_match) {
            int idx = rule->upstream_index;
            if (idx < 0) {
                idx = router->default_upstream;
            }
            if (idx >= 0 && (size_t)idx < router->upstream_count) {
                result->upstream = &router->upstreams[idx];
                result->upstream_index = idx;
                result->matched_rule = rule->name;
                LOG_DEBUG("Route matched rule '%s' -> upstream %d", rule->name, idx);
                return 0;
            }
        }
        rule = rule->next;
    }

    /* No rule matched, use load balancing */
    int selected = select_upstream_lb(router, username);
    if (selected >= 0) {
        result->upstream = &router->upstreams[selected];
        result->upstream_index = selected;
        result->matched_rule = NULL;
        LOG_DEBUG("Route using LB -> upstream %d", selected);
        return 0;
    }

    LOG_WARN("No route found for user='%s', target='%s'",
             username ? username : "(null)", target ? target : "(null)");
    return -1;
}

ssh_session router_connect(router_t *router, route_result_t *result,
                           uint32_t timeout_ms)
{
    if (router == NULL || result == NULL || result->upstream == NULL) {
        return NULL;
    }

    upstream_t *upstream = result->upstream;

    /* Create SSH session */
    ssh_session session = ssh_new();
    if (session == NULL) {
        LOG_ERROR("Failed to create SSH session");
        return NULL;
    }

    /* Set connection options */
    ssh_options_set(session, SSH_OPTIONS_HOST, upstream->config.host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &upstream->config.port);

    long timeout_sec = timeout_ms / 1000;
    if (timeout_sec == 0) {
        timeout_sec = 10;
    }
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_sec);

    /* Set strict host key checking to "no" for now */
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &(int){0});

    LOG_DEBUG("Connecting to upstream %s:%d",
              upstream->config.host, upstream->config.port);

    /* Connect */
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        LOG_ERROR("Failed to connect to upstream %s:%d: %s",
                  upstream->config.host, upstream->config.port,
                  ssh_get_error(session));
        ssh_free(session);
        router_notify_connect(router, result->upstream_index, false);
        return NULL;
    }

    router_notify_connect(router, result->upstream_index, true);
    LOG_INFO("Connected to upstream %s:%d",
             upstream->config.host, upstream->config.port);

    return session;
}

void router_notify_connect(router_t *router, int upstream_index, bool success)
{
    if (router == NULL || upstream_index < 0 ||
        (size_t)upstream_index >= router->upstream_count) {
        return;
    }

    upstream_t *upstream = &router->upstreams[upstream_index];

    if (success) {
        upstream->active_connections++;
        upstream->total_connections++;
        upstream->consecutive_failures = 0;
        upstream->health = UPSTREAM_HEALTH_HEALTHY;
    } else {
        upstream->consecutive_failures++;
        upstream->last_failure = time(NULL);

        /* Mark unhealthy after 3 consecutive failures */
        if (upstream->consecutive_failures >= 3) {
            upstream->health = UPSTREAM_HEALTH_UNHEALTHY;
            LOG_WARN("Upstream %d marked unhealthy after %d failures",
                     upstream_index, upstream->consecutive_failures);
        }
    }
}

void router_notify_close(router_t *router, int upstream_index)
{
    if (router == NULL || upstream_index < 0 ||
        (size_t)upstream_index >= router->upstream_count) {
        return;
    }

    upstream_t *upstream = &router->upstreams[upstream_index];
    if (upstream->active_connections > 0) {
        upstream->active_connections--;
    }
}

void router_health_check(router_t *router)
{
    if (router == NULL || !router->config.health_check_enabled) {
        return;
    }

    time_t now = time(NULL);

    for (size_t i = 0; i < router->upstream_count; i++) {
        upstream_t *upstream = &router->upstreams[i];

        if (!upstream->config.enabled) {
            continue;
        }

        /* Check if health check is due */
        if ((now - upstream->last_check) < (time_t)router->config.health_check_interval) {
            continue;
        }

        upstream->last_check = now;

        /* Simple TCP connect check */
        ssh_session session = ssh_new();
        if (session == NULL) {
            continue;
        }

        ssh_options_set(session, SSH_OPTIONS_HOST, upstream->config.host);
        ssh_options_set(session, SSH_OPTIONS_PORT, &upstream->config.port);
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &(long){5});

        int rc = ssh_connect(session);
        if (rc == SSH_OK) {
            if (upstream->health == UPSTREAM_HEALTH_UNHEALTHY) {
                LOG_INFO("Upstream %zu is now healthy", i);
            }
            upstream->health = UPSTREAM_HEALTH_HEALTHY;
            upstream->consecutive_failures = 0;
            ssh_disconnect(session);
        } else {
            if (upstream->health != UPSTREAM_HEALTH_UNHEALTHY) {
                LOG_WARN("Upstream %zu health check failed", i);
            }
            upstream->health = UPSTREAM_HEALTH_UNHEALTHY;
        }

        ssh_free(session);
    }
}

ssh_session router_connect_with_retry(router_t *router, const char *username,
                                       const char *target, route_result_t *result,
                                       uint32_t timeout_ms)
{
    if (router == NULL || result == NULL) {
        return NULL;
    }

    router_config_t *config = &router->config;
    int max_retries = config->max_retries > 0 ? config->max_retries : 3;
    uint32_t initial_delay = config->retry_initial_delay_ms > 0
                             ? config->retry_initial_delay_ms : 100;
    uint32_t max_delay = config->retry_max_delay_ms > 0
                         ? config->retry_max_delay_ms : 5000;
    float backoff = config->retry_backoff_factor > 0
                    ? config->retry_backoff_factor : 2.0f;

    ssh_session upstream = NULL;
    uint32_t delay_ms = initial_delay;

    for (int attempt = 0; attempt <= max_retries; attempt++) {
        if (attempt > 0) {
            METRICS_INC(upstream_retries_total);

            LOG_INFO("Retry %d/%d connecting to upstream %s:%d (delay %ums)",
                     attempt, max_retries,
                     result->upstream ? result->upstream->config.host : "unknown",
                     result->upstream ? result->upstream->config.port : 0,
                     delay_ms);

            struct timespec ts = {
                .tv_sec = delay_ms / 1000,
                .tv_nsec = (delay_ms % 1000) * 1000000L
            };
            nanosleep(&ts, NULL);

            /* Re-resolve route on retry (LB may pick different upstream) */
            if (username != NULL) {
                route_result_t new_result;
                if (router_resolve(router, username, target, &new_result) == 0) {
                    *result = new_result;
                }
            }

            delay_ms = (uint32_t)(delay_ms * backoff);
            if (delay_ms > max_delay) {
                delay_ms = max_delay;
            }
        }

        upstream = router_connect(router, result, timeout_ms);
        if (upstream != NULL) {
            if (attempt > 0) {
                METRICS_INC(upstream_retries_success);
                LOG_INFO("Successfully connected to upstream on attempt %d",
                         attempt + 1);
            }
            return upstream;
        }

        LOG_WARN("Failed to connect to upstream %s:%d (attempt %d/%d)",
                 result->upstream ? result->upstream->config.host : "unknown",
                 result->upstream ? result->upstream->config.port : 0,
                 attempt + 1, max_retries + 1);
    }

    METRICS_INC(upstream_retries_exhausted);
    LOG_ERROR("All %d connection attempts to upstream exhausted",
              max_retries + 1);
    return NULL;
}

int router_set_default_upstream(router_t *router, int index)
{
    if (router == NULL) {
        return -1;
    }

    if (index < 0 || (size_t)index >= router->upstream_count) {
        return -1;
    }

    router->default_upstream = index;
    LOG_DEBUG("Default upstream set to %d", index);
    return 0;
}

/* --- Connection Pool Implementation --- */

int connection_pool_init(connection_pool_t *pool, size_t max_idle, uint32_t max_idle_time)
{
    if (!pool) return -1;
    memset(pool, 0, sizeof(*pool));
    pool->max_idle = max_idle;
    pool->max_idle_time_sec = max_idle_time;
    pool->enabled = true;
    pthread_mutex_init(&pool->lock, NULL);
    LOG_INFO("Connection pool initialized (max_idle=%zu, max_idle_time=%us)",
             max_idle, max_idle_time);
    return 0;
}

ssh_session connection_pool_get(connection_pool_t *pool, const char *host, uint16_t port)
{
    if (!pool || !pool->enabled || !host) return NULL;

    pthread_mutex_lock(&pool->lock);

    pooled_conn_t *prev = NULL;
    pooled_conn_t *conn = pool->connections;
    time_t now = time(NULL);

    while (conn) {
        /* Skip in-use or expired connections */
        if (conn->in_use ||
            (pool->max_idle_time_sec > 0 &&
             (now - conn->idle_since) > (time_t)pool->max_idle_time_sec)) {
            prev = conn;
            conn = conn->next;
            continue;
        }

        /* Match by host and port */
        if (strcmp(conn->host, host) == 0 && conn->port == port) {
            /* Check if SSH session is still alive */
            if (ssh_is_connected(conn->session)) {
                /* Remove from idle list */
                if (prev) {
                    prev->next = conn->next;
                } else {
                    pool->connections = conn->next;
                }
                pool->idle_count--;
                pool->active_count++;

                ssh_session session = conn->session;
                free(conn);

                pthread_mutex_unlock(&pool->lock);
                LOG_DEBUG("Connection pool: Reusing connection to %s:%u", host, port);
                return session;
            } else {
                /* Dead connection, remove it */
                if (prev) {
                    prev->next = conn->next;
                } else {
                    pool->connections = conn->next;
                }
                pooled_conn_t *dead = conn;
                conn = conn->next;
                ssh_disconnect(dead->session);
                ssh_free(dead->session);
                free(dead);
                pool->idle_count--;
                continue;
            }
        }

        prev = conn;
        conn = conn->next;
    }

    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

int connection_pool_put(connection_pool_t *pool, ssh_session session,
                        const char *host, uint16_t port, const char *username)
{
    if (!pool || !pool->enabled || !session || !host) return -1;

    /* Check if session is still connected */
    if (!ssh_is_connected(session)) {
        return -1;
    }

    pthread_mutex_lock(&pool->lock);

    /* Check if pool is full */
    if (pool->idle_count >= pool->max_idle) {
        pthread_mutex_unlock(&pool->lock);
        LOG_DEBUG("Connection pool full, not pooling connection to %s:%u", host, port);
        return -1;
    }

    pooled_conn_t *conn = calloc(1, sizeof(pooled_conn_t));
    if (!conn) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    conn->session = session;
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->port = port;
    if (username) {
        strncpy(conn->username, username, sizeof(conn->username) - 1);
    }
    conn->idle_since = time(NULL);
    conn->in_use = false;

    /* Add to front of list */
    conn->next = pool->connections;
    pool->connections = conn;
    pool->idle_count++;

    if (pool->active_count > 0) {
        pool->active_count--;
    }

    pthread_mutex_unlock(&pool->lock);
    LOG_DEBUG("Connection pool: Cached connection to %s:%u (idle=%zu)",
             host, port, pool->idle_count);
    return 0;
}

int connection_pool_cleanup(connection_pool_t *pool)
{
    if (!pool || !pool->enabled) return 0;

    pthread_mutex_lock(&pool->lock);

    int cleaned = 0;
    time_t now = time(NULL);
    pooled_conn_t *prev = NULL;
    pooled_conn_t *conn = pool->connections;

    while (conn) {
        bool expired = (pool->max_idle_time_sec > 0 &&
                       (now - conn->idle_since) > (time_t)pool->max_idle_time_sec);
        bool dead = !ssh_is_connected(conn->session);

        if (!conn->in_use && (expired || dead)) {
            pooled_conn_t *to_remove = conn;
            if (prev) {
                prev->next = conn->next;
            } else {
                pool->connections = conn->next;
            }
            conn = conn->next;

            ssh_disconnect(to_remove->session);
            ssh_free(to_remove->session);
            free(to_remove);
            pool->idle_count--;
            cleaned++;
        } else {
            prev = conn;
            conn = conn->next;
        }
    }

    pthread_mutex_unlock(&pool->lock);

    if (cleaned > 0) {
        LOG_DEBUG("Connection pool: Cleaned %d expired connections", cleaned);
    }
    return cleaned;
}

void connection_pool_destroy(connection_pool_t *pool)
{
    if (!pool) return;

    pthread_mutex_lock(&pool->lock);

    pooled_conn_t *conn = pool->connections;
    while (conn) {
        pooled_conn_t *next = conn->next;
        if (conn->session) {
            ssh_disconnect(conn->session);
            ssh_free(conn->session);
        }
        free(conn);
        conn = next;
    }
    pool->connections = NULL;
    pool->idle_count = 0;
    pool->enabled = false;

    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);

    LOG_INFO("Connection pool destroyed");
}
