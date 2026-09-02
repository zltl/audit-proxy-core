/**
 * @file config_auth.h
 * @brief Configuration-backed authentication helpers
 */

#ifndef SSH_PROXY_CONFIG_AUTH_H
#define SSH_PROXY_CONFIG_AUTH_H

#include "auth_filter.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Authenticate a user against the loaded proxy configuration
 * @param config Loaded proxy configuration
 * @param username Username supplied by the client
 * @param password Password supplied by the client
 * @return AUTH_RESULT_SUCCESS on success, AUTH_RESULT_DENIED when rotation or
 *         expiry blocks a valid password, AUTH_RESULT_FAILURE otherwise
 */
auth_result_t config_authenticate_password(const proxy_config_t *config, const char *username,
                                           const char *password);

/**
 * @brief Authenticate a user public key or SSH certificate against the loaded proxy configuration
 * @param config Loaded proxy configuration
 * @param username Username supplied by the client
 * @param client_addr Client IP address if known
 * @param authorized_key_line OpenSSH public-key/certificate line
 * @return AUTH_RESULT_SUCCESS on success, AUTH_RESULT_DENIED for valid-but-disallowed certificates,
 *         AUTH_RESULT_FAILURE otherwise
 */
auth_result_t config_authenticate_pubkey(const proxy_config_t *config, const char *username,
                                         const char *client_addr, const char *authorized_key_line);

/**
 * @brief Authorize a successfully authenticated login against contextual policy
 * @param config Loaded proxy configuration
 * @param username Username supplied by the client
 * @param client_addr Client IP address if known
 * @return AUTH_RESULT_SUCCESS when the login is allowed, AUTH_RESULT_DENIED when blocked by policy
 */
auth_result_t config_authorize_login(const proxy_config_t *config, const char *username,
                                     const char *client_addr);

/**
 * @brief Time-injectable variant of config_authorize_login
 * @param config Loaded proxy configuration
 * @param username Username supplied by the client
 * @param client_addr Client IP address if known
 * @param now Timestamp used for policy evaluation
 * @return AUTH_RESULT_SUCCESS when the login is allowed, AUTH_RESULT_DENIED when blocked by policy
 */
auth_result_t config_authorize_login_at(const proxy_config_t *config, const char *username,
                                        const char *client_addr, time_t now);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_CONFIG_AUTH_H */
