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

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_HANDLER_H */
