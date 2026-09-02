/**
 * @file password_policy.h
 * @brief SSH Proxy Core - Password Policy Module
 *
 * Validates passwords against configurable complexity requirements and
 * enforces password age during login.
 */

#ifndef SSH_PROXY_PASSWORD_POLICY_H
#define SSH_PROXY_PASSWORD_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum length of policy error message */
#define PASSWORD_POLICY_ERROR_MAX 256

/* Password policy configuration */
typedef struct password_policy {
    uint32_t min_length;    /* Minimum password length (default: 8) */
    bool require_uppercase; /* Require at least one uppercase letter */
    bool require_lowercase; /* Require at least one lowercase letter */
    bool require_digit;     /* Require at least one digit */
    bool require_special;   /* Require at least one special character */
    uint32_t max_age_days;  /* Max password age in days (0 = no expiry) */
} password_policy_t;

/**
 * @brief Create a password policy with default values
 * @return Policy with sensible defaults
 */
password_policy_t password_policy_defaults(void);

/**
 * @brief Check a password against the policy
 * @param policy Password policy to check against
 * @param password Password to validate
 * @return 0 if password meets policy, -1 if it does not
 *
 * Use password_policy_error() to get the descriptive error after failure.
 */
int password_policy_check(const password_policy_t *policy, const char *password);

/**
 * @brief Get the last error message from password_policy_check()
 * @return Descriptive error string (thread-local, valid until next check)
 */
const char *password_policy_error(void);

/**
 * @brief Check whether a password is expired under the current policy
 * @param policy Password policy to check against
 * @param has_last_changed Whether a last-changed timestamp is available
 * @param last_changed_at Password last-changed timestamp (Unix epoch seconds)
 * @param now Current time to evaluate against
 * @return 0 if password is still valid, -1 if it is expired
 *
 * If password expiry is disabled or no timestamp is available, this returns 0.
 * Use password_policy_error() to get the descriptive error after failure.
 */
int password_policy_check_expiry(const password_policy_t *policy, bool has_last_changed,
                                 time_t last_changed_at, time_t now);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_PASSWORD_POLICY_H */
