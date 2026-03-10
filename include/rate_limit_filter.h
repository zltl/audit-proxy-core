/**
 * @file rate_limit_filter.h
 * @brief SSH Proxy Core - Rate Limiting Filter
 *
 * Implements connection rate limiting and concurrency control.
 */

#ifndef SSH_PROXY_RATE_LIMIT_FILTER_H
#define SSH_PROXY_RATE_LIMIT_FILTER_H

#include "filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Rate limit result */
typedef enum {
    RATE_LIMIT_ALLOW = 0,
    RATE_LIMIT_DENY,
    RATE_LIMIT_THROTTLE
} rate_limit_result_t;

/* Forward declaration */
typedef struct rate_limit_filter_config rate_limit_filter_config_t;

/* Rate limit rule */
typedef struct rate_limit_rule {
    char name[64];              /* Rule name */
    char match_pattern[256];    /* Pattern to match (IP, user, etc.) */
    int max_connections;        /* Max concurrent connections */
    int max_rate;               /* Max connections per interval */
    int interval_sec;           /* Rate limit interval */
    struct rate_limit_rule *next;
} rate_limit_rule_t;

/* Rate limit filter configuration */
struct rate_limit_filter_config {
    int global_max_connections;     /* Global max concurrent connections */
    int global_max_rate;            /* Global max connections per interval */
    int global_interval_sec;        /* Global rate limit interval */
    bool log_rejections;            /* Log rate limit rejections */
    rate_limit_rule_t *rules;       /* Per-pattern rules */
    int per_user_max_sessions;              /* Default per-user max concurrent sessions (0 = unlimited) */
    rate_limit_rule_t *user_session_rules;  /* Per-user session limit rules */
};

/**
 * @brief Create rate limit filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *rate_limit_filter_create(const rate_limit_filter_config_t *config);

/**
 * @brief Add a rate limit rule
 * @param config Rate limit configuration
 * @param rule Rule to add (copied)
 * @return 0 on success, -1 on error
 */
int rate_limit_add_rule(rate_limit_filter_config_t *config,
                        const rate_limit_rule_t *rule);

/**
 * @brief Remove a rate limit rule by name
 * @param config Rate limit configuration
 * @param name Rule name
 * @return 0 on success, -1 if not found
 */
int rate_limit_remove_rule(rate_limit_filter_config_t *config,
                           const char *name);

/**
 * @brief Check rate limit for a connection
 * @param filter Rate limit filter
 * @param client_addr Client IP address
 * @param username Username (may be NULL before auth)
 * @return RATE_LIMIT_ALLOW, RATE_LIMIT_DENY, or RATE_LIMIT_THROTTLE
 */
rate_limit_result_t rate_limit_check(filter_t *filter,
                                     const char *client_addr,
                                     const char *username);

/**
 * @brief Notify rate limiter of connection close
 * @param filter Rate limit filter
 * @param client_addr Client IP address
 * @param username Username
 */
void rate_limit_release(filter_t *filter,
                        const char *client_addr,
                        const char *username);

/**
 * @brief Check per-user session limit
 * @param filter Rate limit filter instance
 * @param username Username to check
 * @return RATE_LIMIT_ALLOW if under limit, RATE_LIMIT_DENY if at limit
 */
rate_limit_result_t rate_limit_check_user_sessions(filter_t *filter, const char *username);

/**
 * @brief Get current connection count for a pattern
 * @param filter Rate limit filter
 * @param pattern Pattern to check
 * @return Current connection count
 */
int rate_limit_get_count(filter_t *filter, const char *pattern);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_RATE_LIMIT_FILTER_H */
