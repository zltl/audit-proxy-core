/**
 * @file mfa_filter.h
 * @brief TOTP/MFA two-factor authentication filter
 *
 * Implements RFC 6238 TOTP with HMAC-SHA1.
 * Used as a filter in the post-authentication stage.
 */
#ifndef MFA_FILTER_H
#define MFA_FILTER_H

#include "filter.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MFA filter configuration */
typedef struct {
    bool enabled;               /* Global MFA enable flag */
    char issuer[64];            /* TOTP issuer name */
    int time_step;              /* Time step in seconds (default: 30) */
    int digits;                 /* TOTP digit count (default: 6) */
    int window;                 /* Time window tolerance (default: 1) */
} mfa_filter_config_t;

/* Per-user MFA settings */
typedef struct {
    bool mfa_enabled;           /* User has MFA enabled */
    char totp_secret[64];       /* Base32-encoded TOTP secret */
} mfa_user_config_t;

/**
 * @brief Create an MFA filter instance
 * @param config MFA configuration
 * @return Filter instance, or NULL on failure
 */
filter_t *mfa_filter_create(const mfa_filter_config_t *config);

/* TOTP Algorithm Functions (exposed for testing) */

/**
 * @brief Decode a Base32-encoded string
 * @param encoded Base32 string (uppercase, no padding required)
 * @param decoded Output buffer
 * @param decoded_size Size of output buffer
 * @return Number of bytes decoded, or -1 on error
 */
int base32_decode(const char *encoded, uint8_t *decoded, size_t decoded_size);

/**
 * @brief Compute HMAC-SHA1
 * @param key Key bytes
 * @param key_len Key length
 * @param data Data to authenticate
 * @param data_len Data length
 * @param output 20-byte output buffer
 */
void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *output);

/**
 * @brief Generate a TOTP code
 * @param secret_base32 Base32-encoded secret
 * @param time_step Time step in seconds
 * @param digits Number of digits (6 or 8)
 * @param time_offset Time offset from current time (for window validation)
 * @return TOTP code, or -1 on error
 */
int totp_generate(const char *secret_base32, int time_step, int digits,
                  int time_offset);

/**
 * @brief Validate a TOTP code
 * @param secret_base32 Base32-encoded secret
 * @param code The code to validate
 * @param time_step Time step
 * @param digits Number of digits
 * @param window Window size (checks +/-window time steps)
 * @return true if valid, false if invalid
 */
bool totp_validate(const char *secret_base32, int code, int time_step,
                   int digits, int window);

#ifdef __cplusplus
}
#endif

#endif /* MFA_FILTER_H */
