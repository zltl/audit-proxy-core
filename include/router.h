/**
 * @file router.h
 * @brief SSH Proxy Core - Router and Upstream Management
 *
 * Implements routing decisions and upstream connection management.
 * Routes SSH connections based on username, target address, or metadata.
 */

#ifndef SSH_PROXY_ROUTER_H
#define SSH_PROXY_ROUTER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of upstream servers */
#define ROUTER_MAX_UPSTREAMS 64

/* Maximum hostname length */
#define ROUTER_MAX_HOST 256

/* Upstream health status */
typedef enum {
    UPSTREAM_HEALTH_UNKNOWN = 0,
    UPSTREAM_HEALTH_HEALTHY,
    UPSTREAM_HEALTH_UNHEALTHY
} upstream_health_t;

/* Load balancing policy */
typedef enum {
    LB_POLICY_ROUND_ROBIN = 0,  /* Rotate through upstreams */
    LB_POLICY_RANDOM,           /* Random selection */
    LB_POLICY_LEAST_CONN,       /* Least connections */
    LB_POLICY_HASH,             /* Consistent hash-based routing (by username) */
    LB_POLICY_WEIGHTED          /* Smooth weighted round-robin */
} lb_policy_t;

/* Forward declarations */
typedef struct router router_t;
typedef struct upstream upstream_t;
typedef struct route_rule route_rule_t;

/* Upstream server configuration */
typedef struct upstream_config {
    char host[ROUTER_MAX_HOST];     /* Host address */
    uint16_t port;                  /* Port number */
    int weight;                     /* Load balancing weight */
    bool enabled;                   /* Whether upstream is enabled */
} upstream_config_t;

/* Upstream server state */
struct upstream {
    upstream_config_t config;       /* Configuration */
    upstream_health_t health;       /* Health status */
    size_t active_connections;      /* Current connection count */
    size_t total_connections;       /* Total historical connections */
    time_t last_check;              /* Last health check time */
    time_t last_failure;            /* Last failure time */
    int consecutive_failures;       /* Consecutive failure count */
    int current_weight;             /* Smooth weighted round-robin state */
};

/* Route rule - matches connections to upstreams */
typedef struct route_rule {
    char name[64];                  /* Rule name */
    char match_username[128];       /* Username pattern (glob) */
    char match_target[256];         /* Target pattern (glob) */
    int upstream_index;             /* Index of upstream to use (-1 for default) */
    bool enabled;                   /* Whether rule is enabled */
    route_rule_t *next;             /* Next rule in list */
} route_rule_t;

/* Connection pool entry */
typedef struct pooled_conn {
    ssh_session session;            /* SSH session handle */
    char host[256];                 /* Upstream host */
    uint16_t port;                  /* Upstream port */
    char username[128];             /* Authenticated user */
    time_t idle_since;              /* When connection became idle */
    bool in_use;                    /* Currently checked out */
    struct pooled_conn *next;       /* Linked list */
} pooled_conn_t;

/* Connection pool */
typedef struct {
    pooled_conn_t *connections;     /* Linked list of pooled connections */
    size_t idle_count;              /* Number of idle connections */
    size_t active_count;            /* Number of active (checked out) connections */
    size_t max_idle;                /* Max idle connections per upstream */
    uint32_t max_idle_time_sec;     /* Max time a connection can be idle */
    bool enabled;                   /* Pool enabled flag */
    pthread_mutex_t lock;           /* Thread safety */
} connection_pool_t;

/* Router configuration */
typedef struct router_config {
    lb_policy_t lb_policy;          /* Load balancing policy */
    uint32_t connect_timeout_ms;    /* Upstream connect timeout */
    uint32_t health_check_interval; /* Health check interval (seconds) */
    int max_retries;                /* Maximum connection retries */
    bool health_check_enabled;      /* Enable health checks */
    uint32_t retry_initial_delay_ms;/* Initial retry delay (default: 100) */
    uint32_t retry_max_delay_ms;    /* Maximum retry delay (default: 5000) */
    float retry_backoff_factor;     /* Backoff multiplier (default: 2.0) */
    bool pool_enabled;              /* Enable connection pooling */
    size_t pool_max_idle;           /* Max idle connections (default: 10) */
    uint32_t pool_max_idle_time_sec; /* Max idle time in seconds (default: 300) */
} router_config_t;

/* Route result */
typedef struct route_result {
    upstream_t *upstream;           /* Selected upstream */
    int upstream_index;             /* Upstream index */
    const char *matched_rule;       /* Name of matched rule (or NULL) */
} route_result_t;

/**
 * @brief Create a new router
 * @param config Router configuration
 * @return Router instance or NULL on error
 */
router_t *router_create(const router_config_t *config);

/**
 * @brief Destroy router
 * @param router Router instance
 */
void router_destroy(router_t *router);

/**
 * @brief Add an upstream server
 * @param router Router instance
 * @param config Upstream configuration
 * @return Upstream index (>= 0) on success, -1 on error
 */
int router_add_upstream(router_t *router, const upstream_config_t *config);

/**
 * @brief Remove an upstream server
 * @param router Router instance
 * @param index Upstream index
 * @return 0 on success, -1 on error
 */
int router_remove_upstream(router_t *router, int index);

/**
 * @brief Get upstream by index
 * @param router Router instance
 * @param index Upstream index
 * @return Upstream or NULL if not found
 */
upstream_t *router_get_upstream(router_t *router, int index);

/**
 * @brief Get number of upstreams
 * @param router Router instance
 * @return Number of upstreams
 */
size_t router_get_upstream_count(const router_t *router);

/**
 * @brief Add a routing rule
 * @param router Router instance
 * @param rule Route rule (copied)
 * @return 0 on success, -1 on error
 */
int router_add_rule(router_t *router, const route_rule_t *rule);

/**
 * @brief Remove a routing rule by name
 * @param router Router instance
 * @param name Rule name
 * @return 0 on success, -1 if not found
 */
int router_remove_rule(router_t *router, const char *name);

/**
 * @brief Resolve route for a session
 * @param router Router instance
 * @param username Username
 * @param target Target address
 * @param result Route result (output)
 * @return 0 on success, -1 if no route found
 */
int router_resolve(router_t *router, const char *username,
                   const char *target, route_result_t *result);

/**
 * @brief Connect to upstream server
 * @param router Router instance
 * @param result Route result from router_resolve
 * @param timeout_ms Connection timeout in milliseconds
 * @return SSH session connected to upstream, or NULL on error
 */
ssh_session router_connect(router_t *router, route_result_t *result,
                           uint32_t timeout_ms);

/**
 * @brief Notify router of connection result
 * @param router Router instance
 * @param upstream_index Upstream index
 * @param success Whether connection succeeded
 */
void router_notify_connect(router_t *router, int upstream_index, bool success);

/**
 * @brief Notify router of connection close
 * @param router Router instance
 * @param upstream_index Upstream index
 */
void router_notify_close(router_t *router, int upstream_index);

/**
 * @brief Run health checks on all upstreams
 * @param router Router instance
 */
void router_health_check(router_t *router);

/**
 * @brief Set default upstream index
 * @param router Router instance
 * @param index Upstream index to use as default
 * @return 0 on success, -1 if index invalid
 */
int router_set_default_upstream(router_t *router, int index);

/**
 * @brief Connect to upstream with retry and exponential backoff
 * @param router Router instance
 * @param username Username for re-resolving routes on retry
 * @param target Target address for re-resolving
 * @param result Route result (updated on each retry)
 * @param timeout_ms Connection timeout per attempt
 * @return SSH session connected to upstream, or NULL if all retries exhausted
 */
ssh_session router_connect_with_retry(router_t *router, const char *username,
                                       const char *target, route_result_t *result,
                                       uint32_t timeout_ms);

/**
 * @brief Match a string against a glob pattern
 * @param pattern Glob pattern (supports * and ?)
 * @param str String to match
 * @return true if matches
 */
bool router_glob_match(const char *pattern, const char *str);

/**
 * @brief Initialize the connection pool
 * @param pool Pool to initialize
 * @param max_idle Max idle connections
 * @param max_idle_time Max idle time in seconds
 * @return 0 on success
 */
int connection_pool_init(connection_pool_t *pool, size_t max_idle, uint32_t max_idle_time);

/**
 * @brief Get a connection from the pool
 * @param pool Connection pool
 * @param host Target host
 * @param port Target port
 * @return SSH session if available, NULL if no cached connection
 */
ssh_session connection_pool_get(connection_pool_t *pool, const char *host, uint16_t port);

/**
 * @brief Return a connection to the pool
 * @param pool Connection pool
 * @param session SSH session to return
 * @param host Upstream host
 * @param port Upstream port
 * @param username User who was connected
 * @return 0 if pooled, -1 if pool full (caller should close session)
 */
int connection_pool_put(connection_pool_t *pool, ssh_session session,
                        const char *host, uint16_t port, const char *username);

/**
 * @brief Clean up expired idle connections
 * @param pool Connection pool
 * @return Number of connections cleaned up
 */
int connection_pool_cleanup(connection_pool_t *pool);

/**
 * @brief Destroy the connection pool (closes all connections)
 * @param pool Connection pool
 */
void connection_pool_destroy(connection_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_ROUTER_H */
