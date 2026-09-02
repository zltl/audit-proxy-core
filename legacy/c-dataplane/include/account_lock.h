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
    bool ip_ban_enabled;            /* Enable/disable client IP bans (default: false) */
    uint32_t ip_ban_threshold;      /* Failures before IP ban (default: 10) */
    uint32_t ip_ban_duration_sec;   /* IP ban duration in seconds (default: 900) */
} account_lock_config_t;

/**
 * @brief Initialize the account lockout system
 * @param config Lockout configuration (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int account_lock_init(const account_lock_config_t *config);

/**
 * @brief Update runtime lockout/ban settings without dropping the module
 * @param config New settings (NULL resets to defaults)
 * @return 0 on success, -1 if module is not initialized
 */
int account_lock_update_config(const account_lock_config_t *config);

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

/**
 * @brief Check if a client IP is temporarily banned
 * @param client_addr Client IP address
 * @return true if banned, false otherwise
 */
bool account_ip_is_blocked(const char *client_addr);

/**
 * @brief Record a failed login attempt for a client IP
 * @param client_addr Client IP address that failed authentication
 */
void account_ip_record_failure(const char *client_addr);

/**
 * @brief Record a successful login for a client IP, resetting failures
 * @param client_addr Client IP address that authenticated successfully
 */
void account_ip_record_success(const char *client_addr);

/**
 * @brief Get the current failure count for a client IP
 * @param client_addr Client IP address to query
 * @return Number of failed attempts, or 0 if not tracked
 */
int account_ip_get_failures(const char *client_addr);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_ACCOUNT_LOCK_H */
