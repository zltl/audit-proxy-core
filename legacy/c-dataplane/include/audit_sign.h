/**
 * @file audit_sign.h
 * @brief SSH Proxy Core - Audit Log Signing & Integrity Verification
 *
 * Provides HMAC-SHA256 signing and chain-hash integrity for audit log lines,
 * plus a verification function to validate an entire log file.
 */

#ifndef SSH_PROXY_AUDIT_SIGN_H
#define SSH_PROXY_AUDIT_SIGN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 digest size in bytes */
#define SHA256_DIGEST_SIZE 32

/* SHA-256 block size in bytes */
#define SHA256_BLOCK_SIZE 64

/* Hex-encoded SHA-256 digest length (without NUL) */
#define SHA256_HEX_SIZE (SHA256_DIGEST_SIZE * 2)

/* ===== SHA-256 (FIPS 180-4) ===== */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/**
 * @brief One-shot SHA-256 hash
 */
void sha256(const uint8_t *data, size_t len,
            uint8_t digest[SHA256_DIGEST_SIZE]);

/* ===== HMAC-SHA256 (RFC 2104) ===== */

/**
 * @brief Compute HMAC-SHA256
 * @param key   HMAC key bytes
 * @param key_len  Key length in bytes
 * @param data  Message to authenticate
 * @param data_len  Message length
 * @param output  32-byte output buffer
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[SHA256_DIGEST_SIZE]);

/* ===== Hex utilities ===== */

/**
 * @brief Encode binary data to lowercase hex string
 * @param bin   Input bytes
 * @param bin_len  Number of bytes
 * @param hex   Output buffer (must be >= bin_len*2 + 1)
 */
void hex_encode(const uint8_t *bin, size_t bin_len, char *hex);

/**
 * @brief Decode hex string to binary
 * @param hex   Hex string (must be even length)
 * @param bin   Output buffer
 * @param bin_size  Output buffer size
 * @return Number of bytes decoded, or -1 on error
 */
int hex_decode(const char *hex, uint8_t *bin, size_t bin_size);

/* ===== Audit log signing ===== */

/**
 * @brief Sign a JSON audit log line with HMAC-SHA256 and chain hash
 *
 * Takes a JSON string (without trailing newline) and appends:
 *   ,"_prev":"<chain_hex>","_hmac":"<hmac_hex>"}
 * replacing the trailing '}' of the original JSON.
 *
 * The HMAC is computed over the JSON content including _prev but before _hmac.
 * After signing, prev_hash is updated to SHA-256(signed_line) for chaining.
 *
 * @param json_line   Original JSON line (must end with '}')
 * @param hex_key     Hex-encoded HMAC key
 * @param prev_hash   Previous line's SHA-256 hash (32 bytes), updated on return
 * @param enable_chain  Whether to include _prev chain hash
 * @param out_buf     Output buffer for signed line
 * @param out_size    Size of output buffer
 * @return Length of signed line, or -1 on error
 */
int audit_sign_line(const char *json_line, const char *hex_key,
                    uint8_t prev_hash[SHA256_DIGEST_SIZE],
                    int enable_chain,
                    char *out_buf, size_t out_size);

/**
 * @brief Verify all HMAC signatures and chain hashes in an audit log file
 *
 * @param path      Path to audit log file
 * @param hex_key   Hex-encoded HMAC key
 * @return Number of verified lines on success (>= 0), or -1 on error
 *
 * On error, the global audit_verify_error_line is set to the 1-based line
 * number where verification failed, and audit_verify_error_msg describes
 * the failure.
 */
int audit_verify_log(const char *path, const char *hex_key);

/* Error detail for audit_verify_log */
extern int audit_verify_error_line;
extern const char *audit_verify_error_msg;

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_AUDIT_SIGN_H */
