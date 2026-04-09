/**
 * @file proxy_handler.h
 * @brief SSH Proxy Core - Connection Handler
 *
 * Handles the lifecycle of a single SSH proxy connection:
 * Handshake -> Auth -> Upstream Connect -> Forwarding -> Cleanup
 */

#ifndef SSH_PROXY_HANDLER_H
#define SSH_PROXY_HANDLER_H

#include "session.h"
#include "filter.h"
#include "router.h"
#include "config.h"
#include "webhook_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Context for the proxy handler thread
 */
typedef struct proxy_handler_context {
    session_manager_t *session_mgr;
    filter_chain_t *filters;
    router_t *router;
    session_t *session;
    proxy_config_t *config;  /* Configuration for route lookup */
    webhook_runtime_t *webhooks;
} proxy_handler_context_t;

/**
 * @brief Main entry point for handling a proxy connection
 * @param arg Pointer to proxy_handler_context_t (will be freed by the handler)
 * @return NULL
 */
void *proxy_handler_run(void *arg);

/**
 * @brief Expand variables in a banner/MOTD string
 * @param tmpl Template string with {variable} placeholders
 * @param output Output buffer
 * @param output_size Output buffer size
 * @param username Username (for {username} variable)
 * @param client_ip Client IP address (for {client_ip} variable)
 *
 * Supported variables: {username}, {client_ip}, {datetime}, {hostname}, {version}
 */
void banner_expand_vars(const char *tmpl, char *output, size_t output_size,
                        const char *username, const char *client_ip);

/**
 * @brief Upstream connection error classification
 */
typedef enum {
    UPSTREAM_ERR_NONE = 0,
    UPSTREAM_ERR_ROUTE_NOT_FOUND,
    UPSTREAM_ERR_SESSION_ALLOC,
    UPSTREAM_ERR_CONNECT_FAILED,
    UPSTREAM_ERR_HOST_KEY,
    UPSTREAM_ERR_AUTH_PRIVKEY_LOAD,
    UPSTREAM_ERR_AUTH_PRIVKEY,
    UPSTREAM_ERR_AUTH_AUTO,
    UPSTREAM_ERR_AUTH_NONE,
    UPSTREAM_ERR_AUTH_ALL_FAILED,
    UPSTREAM_ERR_POLICY_DENIED,
    UPSTREAM_ERR_CIRCUIT_OPEN,
    UPSTREAM_ERR_CHANNEL_OPEN,
    UPSTREAM_ERR_CHANNEL_REQUEST
} upstream_error_t;

/**
 * @brief Detailed result from upstream connection attempt
 */
typedef struct connect_result {
    upstream_error_t error;
    char stage[64];        /* Human-readable stage name */
    char detail[256];      /* Error detail (e.g., ssh_get_error()) */
    char host[256];        /* Upstream host attempted */
    uint16_t port;         /* Upstream port attempted */
    char user[128];        /* Upstream user attempted */
    int attempts;          /* Number of connection attempts made */
} connect_result_t;

/**
 * @brief Context for banner variable expansion
 */
typedef struct banner_context {
    const char *username;
    const char *client_ip;
    const char *upstream_host;
    uint16_t upstream_port;
    const char *upstream_user;
    uint64_t session_id;
} banner_context_t;

void banner_expand_vars_ctx(const char *tmpl, char *output, size_t output_size,
                            const banner_context_t *bctx);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_HANDLER_H */
