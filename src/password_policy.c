/**
 * @file password_policy.c
 * @brief SSH Proxy Core - Password Policy Implementation
 *
 * Validates passwords against configurable complexity requirements.
 */

#include "password_policy.h"
#include "logger.h"

#include <string.h>
#include <ctype.h>

/* Thread-local error buffer */
static _Thread_local char g_policy_error[PASSWORD_POLICY_ERROR_MAX];

password_policy_t password_policy_defaults(void)
{
    password_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    policy.min_length = 8;
    policy.require_uppercase = true;
    policy.require_lowercase = true;
    policy.require_digit = true;
    policy.require_special = false;
    policy.max_age_days = 0;
    return policy;
}

int password_policy_check(const password_policy_t *policy,
                          const char *password)
{
    g_policy_error[0] = '\0';

    if (policy == NULL) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "policy is NULL");
        return -1;
    }

    if (password == NULL) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password is NULL");
        return -1;
    }

    size_t len = strlen(password);

    /* Minimum length */
    if (len < policy->min_length) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password too short: %zu < %u minimum",
                 len, policy->min_length);
        return -1;
    }

    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)password[i];
        if (isupper(ch)) has_upper = true;
        else if (islower(ch)) has_lower = true;
        else if (isdigit(ch)) has_digit = true;
        else if (ispunct(ch) || ch == ' ') has_special = true;
    }

    if (policy->require_uppercase && !has_upper) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password must contain at least one uppercase letter");
        return -1;
    }

    if (policy->require_lowercase && !has_lower) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password must contain at least one lowercase letter");
        return -1;
    }

    if (policy->require_digit && !has_digit) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password must contain at least one digit");
        return -1;
    }

    if (policy->require_special && !has_special) {
        snprintf(g_policy_error, sizeof(g_policy_error),
                 "password must contain at least one special character");
        return -1;
    }

    return 0;
}

const char *password_policy_error(void)
{
    return g_policy_error;
}
