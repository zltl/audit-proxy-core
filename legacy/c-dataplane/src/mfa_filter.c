/**
 * @file mfa_filter.c
 * @brief TOTP/MFA implementation with self-contained SHA-1 and HMAC-SHA1
 */
#include "mfa_filter.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ===== SHA-1 Implementation (RFC 3174) ===== */

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} sha1_ctx_t;

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t index = (size_t)(ctx->count % 64);
    ctx->count += len;

    size_t i = 0;
    if (index) {
        size_t part_len = 64 - index;
        if (len >= part_len) {
            memcpy(ctx->buffer + index, data, part_len);
            sha1_transform(ctx->state, ctx->buffer);
            i = part_len;
        } else {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
    }

    for (; i + 64 <= len; i += 64) {
        sha1_transform(ctx->state, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20])
{
    uint64_t bit_count = ctx->count * 8;
    size_t index = (size_t)(ctx->count % 64);

    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        memset(ctx->buffer + index, 0, 64 - index);
        sha1_transform(ctx->state, ctx->buffer);
        index = 0;
    }
    memset(ctx->buffer + index, 0, 56 - index);

    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }
    sha1_transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ===== HMAC-SHA1 ===== */

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *output)
{
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[20];
    sha1_ctx_t ctx;
    uint8_t inner[20];

    if (key_len > 64) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, tk);
        key = tk;
        key_len = 20;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: H(K XOR ipad || data) */
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner);

    /* Outer hash: H(K XOR opad || inner) */
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, output);
}

/* ===== Base32 Decode ===== */

static int base32_char_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int base32_decode(const char *encoded, uint8_t *decoded, size_t decoded_size)
{
    if (!encoded || !decoded) return -1;

    size_t encoded_len = strlen(encoded);
    while (encoded_len > 0 && encoded[encoded_len - 1] == '=') {
        encoded_len--;
    }

    size_t out_len = 0;
    uint64_t buffer = 0;
    int bits_left = 0;

    for (size_t i = 0; i < encoded_len; i++) {
        int val = base32_char_val(encoded[i]);
        if (val < 0) continue;

        buffer = (buffer << 5) | (uint64_t)val;
        bits_left += 5;

        if (bits_left >= 8) {
            bits_left -= 8;
            if (out_len >= decoded_size) return -1;
            decoded[out_len++] = (uint8_t)(buffer >> bits_left);
        }
    }

    return (int)out_len;
}

/* ===== TOTP ===== */

int totp_generate(const char *secret_base32, int time_step, int digits,
                  int time_offset)
{
    if (!secret_base32) return -1;
    if (time_step <= 0) time_step = 30;
    if (digits <= 0 || digits > 8) digits = 6;

    uint8_t secret[64];
    int secret_len = base32_decode(secret_base32, secret, sizeof(secret));
    if (secret_len < 0) return -1;

    time_t now = time(NULL) + time_offset;
    uint64_t counter = (uint64_t)now / (uint64_t)time_step;

    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    uint8_t hash[20];
    hmac_sha1(secret, (size_t)secret_len, counter_bytes, 8, hash);

    /* Dynamic truncation (RFC 4226 Section 5.4) */
    int offset = hash[19] & 0x0F;
    uint32_t code = ((uint32_t)(hash[offset] & 0x7F) << 24) |
                    ((uint32_t)hash[offset + 1] << 16) |
                    ((uint32_t)hash[offset + 2] << 8) |
                    ((uint32_t)hash[offset + 3]);

    int mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;

    return (int)(code % (uint32_t)mod);
}

bool totp_validate(const char *secret_base32, int code, int time_step,
                   int digits, int window)
{
    if (!secret_base32) return false;
    if (time_step <= 0) time_step = 30;
    if (digits <= 0) digits = 6;
    if (window < 0) window = 1;

    for (int i = -window; i <= window; i++) {
        int generated = totp_generate(secret_base32, time_step, digits,
                                      i * time_step);
        if (generated >= 0 && generated == code) {
            return true;
        }
    }
    return false;
}

/* ===== MFA Filter ===== */

typedef struct {
    int placeholder;
} mfa_filter_state_t;

static filter_status_t mfa_on_authenticated(filter_t *filter,
                                            filter_context_t *ctx)
{
    if (!filter || !ctx) return FILTER_CONTINUE;

    mfa_filter_config_t *config = (mfa_filter_config_t *)filter->config;
    if (!config || !config->enabled) return FILTER_CONTINUE;

    LOG_DEBUG("MFA filter: on_authenticated for user '%s'",
              ctx->username ? ctx->username : "unknown");

    return FILTER_CONTINUE;
}

static void mfa_destroy(filter_t *filter)
{
    if (!filter) return;
    free(filter->config);
    free(filter->state);
}

static filter_callbacks_t mfa_callbacks = {
    .on_authenticated = mfa_on_authenticated,
    .destroy = mfa_destroy,
};

filter_t *mfa_filter_create(const mfa_filter_config_t *config)
{
    if (!config) return NULL;

    mfa_filter_config_t *cfg = calloc(1, sizeof(mfa_filter_config_t));
    if (!cfg) return NULL;
    *cfg = *config;

    if (cfg->time_step <= 0) cfg->time_step = 30;
    if (cfg->digits <= 0) cfg->digits = 6;
    if (cfg->window < 0) cfg->window = 1;

    mfa_filter_state_t *state = calloc(1, sizeof(mfa_filter_state_t));
    if (!state) {
        free(cfg);
        return NULL;
    }

    filter_t *filter = filter_create("mfa", FILTER_TYPE_AUTH,
                                     &mfa_callbacks, cfg);
    if (!filter) {
        free(cfg);
        free(state);
        return NULL;
    }
    filter->state = state;

    LOG_INFO("MFA filter created (issuer=%s, time_step=%d, digits=%d, "
             "window=%d)",
             cfg->issuer, cfg->time_step, cfg->digits, cfg->window);

    return filter;
}
