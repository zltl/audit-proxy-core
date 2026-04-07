/**
 * @file account_lock.h
 * @brief SSH Proxy Core - Account Lockout Module
 *
 * Tracks failed login attempts per username and locks accounts after
 * exceeding a configurable threshold. Thread-safe via pthread_mutex.
 */

#ifndef SSH_PROXY_ACCOUNT_LOCK_H
#define SSH_PROXY_ACCOUNT_LOCK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Account lockout configuration */
typedef struct account_lock_config {
    bool lockout_enabled;           /* Enable/disable lockout (default: false) */
    uint32_t lockout_threshold;     /* Failures before lockout (default: 5) */
    uint32_t lockout_duration_sec;  /* Lockout duration in seconds (default: 300) */
} account_lock_config_t;

/**
 * @brief Initialize the account lockout system
 * @param config Lockout configuration (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int account_lock_init(const account_lock_config_t *config);

/**
 * @brief Shut down the account lockout system and free resources
 */
void account_lock_cleanup(void);

/**
 * @brief Check if an account is currently locked
 * @param username Username to check
 * @return true if locked, false otherwise
 */
bool account_is_locked(const char *username);

/**
 * @brief Record a failed login attempt for a username
 * @param username Username that failed authentication
 */
void account_record_failure(const char *username);

/**
 * @brief Record a successful login, resetting failure count
 * @param username Username that authenticated successfully
 */
void account_record_success(const char *username);

/**
 * @brief Get the current failure count for a username
 * @param username Username to query
 * @return Number of failed attempts, or 0 if not tracked
 */
int account_get_failures(const char *username);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_ACCOUNT_LOCK_H */
