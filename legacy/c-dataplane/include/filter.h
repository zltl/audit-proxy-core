/**
 * @file filter.h
 * @brief SSH Proxy Core - Filter Chain Architecture
 *
 * Implements an Envoy-style filter chain for processing SSH connections.
 * Filters can intercept authentication, routing, and data flow.
 */

#ifndef SSH_PROXY_FILTER_H
#define SSH_PROXY_FILTER_H

#include <stdint.h>
#include <stdbool.h>
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Filter chain processing result */
typedef enum {
    FILTER_CONTINUE = 0,    /* Continue to next filter */
    FILTER_STOP,            /* Stop processing, wait for async completion */
    FILTER_REJECT           /* Reject connection */
} filter_status_t;

/* Filter types */
typedef enum {
    FILTER_TYPE_AUTH = 0,       /* Authentication filter */
    FILTER_TYPE_RBAC,           /* Role-based access control filter */
    FILTER_TYPE_AUDIT,          /* Audit/logging filter */
    FILTER_TYPE_RATE_LIMIT,     /* Rate limiting filter */
    FILTER_TYPE_CUSTOM          /* Custom user filter */
} filter_type_t;

/* Forward declarations */
typedef struct filter filter_t;
typedef struct filter_chain filter_chain_t;
typedef struct filter_context filter_context_t;

/**
 * @brief Filter context - passed to all filter callbacks
 */
struct filter_context {
    session_t *session;         /* Current session */
    void *user_data;            /* Filter-specific data */
    const char *username;       /* Username (for auth/rbac) */
    const char *password;       /* Password (for password auth) */
    const void *pubkey;         /* Public key (for pubkey auth) */
    size_t pubkey_len;          /* Public key length */
    const char *target_host;    /* Target host (for routing) */
    uint16_t target_port;       /* Target port (for routing) */
};

/**
 * @brief Filter callback signatures
 */

/* Called when a new connection is established */
typedef filter_status_t (*filter_on_connect_fn)(filter_t *filter,
                                                filter_context_t *ctx);

/* Called during authentication */
typedef filter_status_t (*filter_on_auth_fn)(filter_t *filter,
                                             filter_context_t *ctx);

/* Called after successful authentication */
typedef filter_status_t (*filter_on_authenticated_fn)(filter_t *filter,
                                                      filter_context_t *ctx);

/* Called before connecting to upstream */
typedef filter_status_t (*filter_on_route_fn)(filter_t *filter,
                                              filter_context_t *ctx);

/* Called when data flows from client to upstream */
typedef filter_status_t (*filter_on_data_upstream_fn)(filter_t *filter,
                                                      filter_context_t *ctx,
                                                      const uint8_t *data,
                                                      size_t len);

/* Called when data flows from upstream to client */
typedef filter_status_t (*filter_on_data_downstream_fn)(filter_t *filter,
                                                        filter_context_t *ctx,
                                                        const uint8_t *data,
                                                        size_t len);

/* Called when connection is closing */
typedef void (*filter_on_close_fn)(filter_t *filter, filter_context_t *ctx);

/* Called to destroy filter instance */
typedef void (*filter_destroy_fn)(filter_t *filter);

/**
 * @brief Filter callbacks structure
 */
typedef struct filter_callbacks {
    filter_on_connect_fn on_connect;
    filter_on_auth_fn on_auth;
    filter_on_authenticated_fn on_authenticated;
    filter_on_route_fn on_route;
    filter_on_data_upstream_fn on_data_upstream;
    filter_on_data_downstream_fn on_data_downstream;
    filter_on_close_fn on_close;
    filter_destroy_fn destroy;
} filter_callbacks_t;

/**
 * @brief Filter structure
 */
struct filter {
    const char *name;           /* Filter name */
    filter_type_t type;         /* Filter type */
    filter_callbacks_t callbacks; /* Filter callbacks */
    void *config;               /* Filter configuration */
    void *state;                /* Filter runtime state */
    filter_t *next;             /* Next filter in chain */
};

/**
 * @brief Create a new filter chain
 * @return Filter chain instance or NULL on error
 */
filter_chain_t *filter_chain_create(void);

/**
 * @brief Destroy filter chain and all filters
 * @param chain Filter chain instance
 */
void filter_chain_destroy(filter_chain_t *chain);

/**
 * @brief Add a filter to the chain
 * @param chain Filter chain
 * @param filter Filter to add (takes ownership)
 * @return 0 on success, -1 on error
 */
int filter_chain_add(filter_chain_t *chain, filter_t *filter);

/**
 * @brief Remove a filter from the chain by name
 * @param chain Filter chain
 * @param name Filter name
 * @return 0 on success, -1 if not found
 */
int filter_chain_remove(filter_chain_t *chain, const char *name);

/**
 * @brief Get filter by name
 * @param chain Filter chain
 * @param name Filter name
 * @return Filter or NULL if not found
 */
filter_t *filter_chain_get(filter_chain_t *chain, const char *name);

/**
 * @brief Get number of filters in chain
 * @param chain Filter chain
 * @return Number of filters
 */
size_t filter_chain_count(const filter_chain_t *chain);

/* Filter chain processing functions */

/**
 * @brief Process on_connect through filter chain
 */
filter_status_t filter_chain_on_connect(filter_chain_t *chain,
                                        filter_context_t *ctx);

/**
 * @brief Process on_auth through filter chain
 */
filter_status_t filter_chain_on_auth(filter_chain_t *chain,
                                     filter_context_t *ctx);

/**
 * @brief Process on_authenticated through filter chain
 */
filter_status_t filter_chain_on_authenticated(filter_chain_t *chain,
                                              filter_context_t *ctx);

/**
 * @brief Process on_route through filter chain
 */
filter_status_t filter_chain_on_route(filter_chain_t *chain,
                                      filter_context_t *ctx);

/**
 * @brief Process on_data_upstream through filter chain
 */
filter_status_t filter_chain_on_data_upstream(filter_chain_t *chain,
                                              filter_context_t *ctx,
                                              const uint8_t *data,
                                              size_t len);

/**
 * @brief Process on_data_downstream through filter chain
 */
filter_status_t filter_chain_on_data_downstream(filter_chain_t *chain,
                                                filter_context_t *ctx,
                                                const uint8_t *data,
                                                size_t len);

/**
 * @brief Process on_close through filter chain
 */
void filter_chain_on_close(filter_chain_t *chain, filter_context_t *ctx);

/**
 * @brief Create a basic filter with the given callbacks
 * @param name Filter name
 * @param type Filter type
 * @param callbacks Filter callbacks
 * @param config Filter configuration (filter takes ownership)
 * @return New filter or NULL on error
 */
filter_t *filter_create(const char *name, filter_type_t type,
                        const filter_callbacks_t *callbacks, void *config);

/**
 * @brief Get filter type name as string
 * @param type Filter type
 * @return Type name string
 */
const char *filter_type_name(filter_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_FILTER_H */
