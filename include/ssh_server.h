/**
 * @file ssh_server.h
 * @brief SSH Server - libssh based SSH server implementation
 */

#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct ssh_server ssh_server_t;

/**
 * @brief SSH server configuration
 */
typedef struct ssh_server_config {
    const char *bind_addr;      /* Address to bind to */
    uint16_t port;              /* Port to listen on */
    const char *host_key_rsa;   /* Path to RSA host key (or NULL to generate) */
    const char *host_key_ecdsa; /* Path to ECDSA host key (optional) */
    const char *host_key_ed25519; /* Path to Ed25519 host key (optional) */
    int log_verbosity;          /* libssh log level (0-4) */
} ssh_server_config_t;

/**
 * @brief Create a new SSH server instance
 * @param config Server configuration
 * @return Server instance or NULL on error
 */
ssh_server_t *ssh_server_create(const ssh_server_config_t *config);

/**
 * @brief Destroy SSH server instance
 * @param server Server instance
 */
void ssh_server_destroy(ssh_server_t *server);

/**
 * @brief Start the SSH server (binds and listens)
 * @param server Server instance
 * @return 0 on success, -1 on error
 */
int ssh_server_start(ssh_server_t *server);

/**
 * @brief Stop the SSH server
 * @param server Server instance
 */
void ssh_server_stop(ssh_server_t *server);

/**
 * @brief Accept a new client connection
 * @param server Server instance
 * @return New SSH session or NULL on error/timeout
 */
ssh_session ssh_server_accept(ssh_server_t *server);

/**
 * @brief Check if server is running
 * @param server Server instance
 * @return true if running
 */
bool ssh_server_is_running(const ssh_server_t *server);

/**
 * @brief Get last error message
 * @param server Server instance
 * @return Error message string
 */
const char *ssh_server_get_error(const ssh_server_t *server);

/**
 * @brief Check if a configuration reload was requested (SIGHUP)
 *
 * Returns true exactly once after a SIGHUP is received; subsequent
 * calls return false until the next SIGHUP.
 *
 * @param server Server instance
 * @return true if reload was requested since last check
 */
bool ssh_server_reload_requested(ssh_server_t *server);

/**
 * @brief Generate a new RSA host key
 * @param path Path to save the key
 * @param bits Key size in bits (default 4096)
 * @return 0 on success, -1 on error
 */
int ssh_server_generate_key(const char *path, int bits);

#ifdef __cplusplus
}
#endif

#endif /* SSH_SERVER_H */
