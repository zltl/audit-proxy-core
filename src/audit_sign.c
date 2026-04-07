/**
 * @file audit_sign.c
 * @brief Audit Log Signing & Integrity — SHA-256, HMAC-SHA256, chain hashing
 *
 * Self-contained implementation with no external crypto dependencies.
 * SHA-256 per FIPS 180-4, HMAC-SHA256 per RFC 2104.
 */

#include "audit_sign.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===== SHA-256 Implementation (FIPS 180-4) ===== */

/* SHA-256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SHA256_SIG1(w[i - 2]) + w[i - 7] +
               SHA256_SIG0(w[i - 15]) + w[i - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + K256[i] + w[i];
        uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t index = (size_t)(ctx->count % SHA256_BLOCK_SIZE);
    ctx->count += len;

    size_t i = 0;
    if (index) {
        size_t part_len = SHA256_BLOCK_SIZE - index;
        if (len >= part_len) {
            memcpy(ctx->buffer + index, data, part_len);
            sha256_transform(ctx->state, ctx->buffer);
            i = part_len;
        } else {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
    }

    for (; i + SHA256_BLOCK_SIZE <= len; i += SHA256_BLOCK_SIZE) {
        sha256_transform(ctx->state, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    uint64_t bit_count = ctx->count * 8;
    size_t index = (size_t)(ctx->count % SHA256_BLOCK_SIZE);

    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        memset(ctx->buffer + index, 0, SHA256_BLOCK_SIZE - index);
        sha256_transform(ctx->state, ctx->buffer);
        index = 0;
    }
    memset(ctx->buffer + index, 0, 56 - index);

    /* Append big-endian bit count */
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }
    sha256_transform(ctx->state, ctx->buffer);

    /* Output digest in big-endian */
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256(const uint8_t *data, size_t len,
            uint8_t digest[SHA256_DIGEST_SIZE])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ===== HMAC-SHA256 (RFC 2104) ===== */

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[SHA256_DIGEST_SIZE])
{
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_SIZE];
    sha256_ctx_t ctx;
    uint8_t inner[SHA256_DIGEST_SIZE];

    /* If key is longer than block size, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }

    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: H(K XOR ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    /* Outer hash: H(K XOR opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, output);
}

/* ===== Hex utilities ===== */

void hex_encode(const uint8_t *bin, size_t bin_len, char *hex)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i * 2]     = hex_chars[(bin[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = hex_chars[bin[i] & 0x0f];
    }
    hex[bin_len * 2] = '\0';
}

static int hex_char_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, uint8_t *bin, size_t bin_size)
{
    if (hex == NULL || bin == NULL) return -1;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;

    size_t out_len = hex_len / 2;
    if (out_len > bin_size) return -1;

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char_val(hex[i * 2]);
        int lo = hex_char_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)out_len;
}

/* ===== Audit log signing ===== */

int audit_sign_line(const char *json_line, const char *hex_key,
                    uint8_t prev_hash[SHA256_DIGEST_SIZE],
                    int enable_chain,
                    char *out_buf, size_t out_size)
{
    if (json_line == NULL || hex_key == NULL || out_buf == NULL) {
        return -1;
    }

    size_t json_len = strlen(json_line);
    if (json_len < 2 || json_line[json_len - 1] != '}') {
        return -1;
    }

    /* Decode the HMAC key */
    uint8_t key_bin[128];
    int key_len = hex_decode(hex_key, key_bin, sizeof(key_bin));
    if (key_len <= 0) {
        return -1;
    }

    /* Build the content to sign: json without trailing '}' + chain + '}' */
    /* First, build the intermediate JSON (with _prev but without _hmac) */

    /* We need: <json_without_closing_brace>,<maybe _prev>} */
    char prev_hex[SHA256_HEX_SIZE + 1];
    int written = 0;

    if (enable_chain && prev_hash != NULL) {
        hex_encode(prev_hash, SHA256_DIGEST_SIZE, prev_hex);

        written = snprintf(out_buf, out_size, "%.*s,\"_prev\":\"%s\"}",
                           (int)(json_len - 1), json_line, prev_hex);
    } else {
        written = snprintf(out_buf, out_size, "%s", json_line);
    }

    if (written < 0 || (size_t)written >= out_size) {
        return -1;
    }

    /* Compute HMAC over the content so far (which does NOT have _hmac yet) */
    uint8_t hmac_out[SHA256_DIGEST_SIZE];
    hmac_sha256(key_bin, (size_t)key_len,
                (const uint8_t *)out_buf, (size_t)written,
                hmac_out);

    char hmac_hex[SHA256_HEX_SIZE + 1];
    hex_encode(hmac_out, SHA256_DIGEST_SIZE, hmac_hex);

    /* Now build final line: replace trailing '}' with ,"_hmac":"<hex>"} */
    int final_len = snprintf(out_buf, out_size, "%.*s%s,\"_hmac\":\"%s\"}",
                             (int)(json_len - 1), json_line,
                             (enable_chain && prev_hash != NULL) ?
                                 "" : "",
                             hmac_hex);

    /* Actually we need to rebuild properly with both _prev and _hmac */
    if (enable_chain && prev_hash != NULL) {
        final_len = snprintf(out_buf, out_size,
                             "%.*s,\"_prev\":\"%s\",\"_hmac\":\"%s\"}",
                             (int)(json_len - 1), json_line,
                             prev_hex, hmac_hex);
    } else {
        final_len = snprintf(out_buf, out_size,
                             "%.*s,\"_hmac\":\"%s\"}",
                             (int)(json_len - 1), json_line,
                             hmac_hex);
    }

    if (final_len < 0 || (size_t)final_len >= out_size) {
        return -1;
    }

    /* Update prev_hash to SHA-256 of the signed line for chaining */
    if (prev_hash != NULL) {
        sha256((const uint8_t *)out_buf, (size_t)final_len, prev_hash);
    }

    return final_len;
}

/* ===== Audit log verification ===== */

int audit_verify_error_line = 0;
const char *audit_verify_error_msg = NULL;

/**
 * Find the value of a JSON string field in a flat JSON object.
 * Returns pointer to the value (within quotes), or NULL.
 * Sets *value_len to the length of the hex string.
 */
static const char *find_json_field(const char *json, const char *field,
                                   size_t *value_len)
{
    /* Search for "field":"value" pattern */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", field);

    const char *pos = strstr(json, pattern);
    if (pos == NULL) {
        *value_len = 0;
        return NULL;
    }

    const char *val_start = pos + strlen(pattern);
    const char *val_end = strchr(val_start, '"');
    if (val_end == NULL) {
        *value_len = 0;
        return NULL;
    }

    *value_len = (size_t)(val_end - val_start);
    return val_start;
}

/**
 * Reconstruct the content that was HMAC'd: the JSON with _prev but without
 * the ,"_hmac":"..." part (but including the closing brace).
 */
static int reconstruct_hmac_content(const char *line, char *buf, size_t buf_size)
{
    /* Find the ,"_hmac":" portion and remove it along with value and "} */
    const char *hmac_field = strstr(line, ",\"_hmac\":\"");
    if (hmac_field == NULL) {
        return -1;
    }

    /* Content is everything before ,"_hmac":"..." plus closing '}' */
    size_t prefix_len = (size_t)(hmac_field - line);
    if (prefix_len + 2 > buf_size) {
        return -1;
    }

    memcpy(buf, line, prefix_len);
    buf[prefix_len] = '}';
    buf[prefix_len + 1] = '\0';
    return (int)(prefix_len + 1);
}

int audit_verify_log(const char *path, const char *hex_key)
{
    if (path == NULL || hex_key == NULL) {
        audit_verify_error_line = 0;
        audit_verify_error_msg = "NULL argument";
        return -1;
    }

    /* Decode the key */
    uint8_t key_bin[128];
    int key_len = hex_decode(hex_key, key_bin, sizeof(key_bin));
    if (key_len <= 0) {
        audit_verify_error_line = 0;
        audit_verify_error_msg = "invalid hex key";
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        audit_verify_error_line = 0;
        audit_verify_error_msg = "cannot open file";
        return -1;
    }

    uint8_t prev_hash[SHA256_DIGEST_SIZE];
    memset(prev_hash, 0, SHA256_DIGEST_SIZE);

    char line_buf[8192];
    char content_buf[8192];
    int line_num = 0;

    while (fgets(line_buf, (int)sizeof(line_buf), f) != NULL) {
        line_num++;

        /* Strip trailing newline */
        size_t line_len = strlen(line_buf);
        while (line_len > 0 &&
               (line_buf[line_len - 1] == '\n' || line_buf[line_len - 1] == '\r')) {
            line_buf[--line_len] = '\0';
        }

        if (line_len == 0) continue;

        /* Extract _hmac value */
        size_t hmac_val_len = 0;
        const char *hmac_val = find_json_field(line_buf, "_hmac", &hmac_val_len);
        if (hmac_val == NULL || hmac_val_len != SHA256_HEX_SIZE) {
            audit_verify_error_line = line_num;
            audit_verify_error_msg = "missing or invalid _hmac field";
            fclose(f);
            return -1;
        }

        /* Decode claimed HMAC */
        uint8_t claimed_hmac[SHA256_DIGEST_SIZE];
        if (hex_decode(hmac_val, claimed_hmac, SHA256_DIGEST_SIZE) !=
            SHA256_DIGEST_SIZE) {
            /* hex_decode reads from a non-NUL terminated segment,
               so we need to copy to a temp buffer */
            char hmac_hex_tmp[SHA256_HEX_SIZE + 1];
            memcpy(hmac_hex_tmp, hmac_val, SHA256_HEX_SIZE);
            hmac_hex_tmp[SHA256_HEX_SIZE] = '\0';
            if (hex_decode(hmac_hex_tmp, claimed_hmac, SHA256_DIGEST_SIZE) !=
                SHA256_DIGEST_SIZE) {
                audit_verify_error_line = line_num;
                audit_verify_error_msg = "invalid _hmac hex value";
                fclose(f);
                return -1;
            }
        }

        /* Reconstruct the HMAC content (everything except ,"_hmac":"..."}
           plus a closing brace) */
        int content_len = reconstruct_hmac_content(line_buf, content_buf,
                                                   sizeof(content_buf));
        if (content_len < 0) {
            audit_verify_error_line = line_num;
            audit_verify_error_msg = "failed to reconstruct HMAC content";
            fclose(f);
            return -1;
        }

        /* Compute expected HMAC */
        uint8_t expected_hmac[SHA256_DIGEST_SIZE];
        hmac_sha256(key_bin, (size_t)key_len,
                    (const uint8_t *)content_buf, (size_t)content_len,
                    expected_hmac);

        /* Compare */
        if (memcmp(claimed_hmac, expected_hmac, SHA256_DIGEST_SIZE) != 0) {
            audit_verify_error_line = line_num;
            audit_verify_error_msg = "HMAC verification failed";
            fclose(f);
            return -1;
        }

        /* Verify chain hash if _prev field is present */
        size_t prev_val_len = 0;
        const char *prev_val = find_json_field(line_buf, "_prev", &prev_val_len);
        if (prev_val != NULL && prev_val_len == SHA256_HEX_SIZE) {
            uint8_t claimed_prev[SHA256_DIGEST_SIZE];
            char prev_hex_tmp[SHA256_HEX_SIZE + 1];
            memcpy(prev_hex_tmp, prev_val, SHA256_HEX_SIZE);
            prev_hex_tmp[SHA256_HEX_SIZE] = '\0';
            if (hex_decode(prev_hex_tmp, claimed_prev, SHA256_DIGEST_SIZE) !=
                SHA256_DIGEST_SIZE) {
                audit_verify_error_line = line_num;
                audit_verify_error_msg = "invalid _prev hex value";
                fclose(f);
                return -1;
            }

            if (memcmp(claimed_prev, prev_hash, SHA256_DIGEST_SIZE) != 0) {
                audit_verify_error_line = line_num;
                audit_verify_error_msg = "chain hash mismatch";
                fclose(f);
                return -1;
            }
        }

        /* Update prev_hash to SHA-256 of this full signed line */
        sha256((const uint8_t *)line_buf, line_len, prev_hash);
    }

    fclose(f);
    audit_verify_error_line = 0;
    audit_verify_error_msg = NULL;
    return line_num;
}
