/**
 * @file health_check.c
 * @brief Lightweight HTTP server for /health, /metrics, and admin API endpoints
 *
 * Features:
 *   - Optional TLS via OpenSSL (compile with TLS_ENABLED=1)
 *   - HMAC-SHA256 token authentication with scopes and expiry
 *   - Self-contained SHA-256 implementation for builds without OpenSSL
 *   - API audit logging
 */

#include "health_check.h"
#include "metrics.h"
#include "version.h"
#include "logger.h"
#include "session.h"
#include "router.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#ifdef TLS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define HC_BACKLOG      8
#define HC_BUF_SIZE     4096
#define HC_RESP_SIZE    8192

/* ------------------------------------------------------------------ */
/* TLS connection wrapper                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
#ifdef TLS_ENABLED
    SSL *ssl;
#endif
    char peer_addr[64];
} hc_conn_t;

static ssize_t hc_write(hc_conn_t *conn, const void *buf, size_t len)
{
#ifdef TLS_ENABLED
    if (conn->ssl) {
        return (ssize_t)SSL_write(conn->ssl, buf, (int)len);
    }
#endif
    return write(conn->fd, buf, len);
}

static ssize_t hc_read(hc_conn_t *conn, void *buf, size_t len)
{
#ifdef TLS_ENABLED
    if (conn->ssl) {
        return (ssize_t)SSL_read(conn->ssl, buf, (int)len);
    }
#endif
    return read(conn->fd, buf, len);
}

/* ------------------------------------------------------------------ */
/* SHA-256 Implementation (FIPS 180-4)                                 */
/* Self-contained — used for HMAC-SHA256 token auth regardless of      */
/* whether OpenSSL is linked (avoids OpenSSL 3.x deprecation issues).  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} hc_sha256_ctx_t;

static const uint32_t hc_sha256_k[64] = {
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

#define HC_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define HC_CH(x, y, z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define HC_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define HC_EP0(x)  (HC_ROTR(x, 2)  ^ HC_ROTR(x, 13) ^ HC_ROTR(x, 22))
#define HC_EP1(x)  (HC_ROTR(x, 6)  ^ HC_ROTR(x, 11) ^ HC_ROTR(x, 25))
#define HC_SIG0(x) (HC_ROTR(x, 7)  ^ HC_ROTR(x, 18) ^ ((x) >> 3))
#define HC_SIG1(x) (HC_ROTR(x, 17) ^ HC_ROTR(x, 19) ^ ((x) >> 10))

static void hc_sha256_init(hc_sha256_ctx_t *ctx)
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

static void hc_sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = HC_SIG1(w[i - 2]) + w[i - 7] +
               HC_SIG0(w[i - 15]) + w[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + HC_EP1(e) + HC_CH(e, f, g) +
                       hc_sha256_k[i] + w[i];
        uint32_t t2 = HC_EP0(a) + HC_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void hc_sha256_update(hc_sha256_ctx_t *ctx,
                             const uint8_t *data, size_t len)
{
    size_t index = (size_t)(ctx->count % 64);
    ctx->count += len;

    size_t i = 0;
    if (index) {
        size_t part_len = 64 - index;
        if (len >= part_len) {
            memcpy(ctx->buffer + index, data, part_len);
            hc_sha256_transform(ctx->state, ctx->buffer);
            i = part_len;
        } else {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
    }

    for (; i + 64 <= len; i += 64) {
        hc_sha256_transform(ctx->state, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

static void hc_sha256_final(hc_sha256_ctx_t *ctx, uint8_t digest[32])
{
    uint64_t bit_count = ctx->count * 8;
    size_t index = (size_t)(ctx->count % 64);

    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        memset(ctx->buffer + index, 0, 64 - index);
        hc_sha256_transform(ctx->state, ctx->buffer);
        index = 0;
    }
    memset(ctx->buffer + index, 0, 56 - index);

    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }
    hc_sha256_transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA256                                                         */
/* ------------------------------------------------------------------ */

static void hc_hmac_sha256_raw(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               uint8_t output[32])
{
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[32];
    hc_sha256_ctx_t ctx;
    uint8_t inner[32];

    if (key_len > 64) {
        hc_sha256_init(&ctx);
        hc_sha256_update(&ctx, key, key_len);
        hc_sha256_final(&ctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: H(K XOR ipad || data) */
    hc_sha256_init(&ctx);
    hc_sha256_update(&ctx, k_ipad, 64);
    hc_sha256_update(&ctx, data, data_len);
    hc_sha256_final(&ctx, inner);

    /* Outer hash: H(K XOR opad || inner) */
    hc_sha256_init(&ctx);
    hc_sha256_update(&ctx, k_opad, 64);
    hc_sha256_update(&ctx, inner, 32);
    hc_sha256_final(&ctx, output);

    /* Clear sensitive key material from stack */
    explicit_bzero(k_ipad, sizeof(k_ipad));
    explicit_bzero(k_opad, sizeof(k_opad));
    explicit_bzero(tk, sizeof(tk));
    explicit_bzero(inner, sizeof(inner));
}

int health_check_hmac_sha256(const void *key, size_t key_len,
                             const void *data, size_t data_len,
                             char *hex_out, size_t hex_out_size)
{
    if (!key || !data || !hex_out || hex_out_size < 65) return -1;

    uint8_t digest[32];
    hc_hmac_sha256_raw((const uint8_t *)key, key_len,
                       (const uint8_t *)data, data_len, digest);

    for (int i = 0; i < 32; i++) {
        snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
    }
    hex_out[64] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* HTTP request parsing                                                */
/* ------------------------------------------------------------------ */

int health_check_parse_request(const char *raw, size_t raw_len,
                               hc_http_request_t *req)
{
    if (!raw || raw_len == 0 || !req) return -1;
    memset(req, 0, sizeof(*req));

    /* Parse request line: "METHOD /path HTTP/1.x\r\n" */
    const char *space1 = strchr(raw, ' ');
    if (!space1) return -1;

    size_t method_len = (size_t)(space1 - raw);
    if (method_len >= sizeof(req->method)) return -1;
    memcpy(req->method, raw, method_len);
    req->method[method_len] = '\0';

    const char *path_start = space1 + 1;
    const char *space2 = strchr(path_start, ' ');
    if (!space2) return -1;

    size_t path_len = (size_t)(space2 - path_start);
    if (path_len >= sizeof(req->path)) return -1;
    memcpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    /* Parse Authorization header */
    const char *auth = strstr(raw, "Authorization: Bearer ");
    if (auth) {
        auth += 22; /* skip "Authorization: Bearer " */
        const char *eol = strstr(auth, "\r\n");
        if (eol) {
            size_t len = (size_t)(eol - auth);
            if (len < sizeof(req->auth_header)) {
                memcpy(req->auth_header, auth, len);
                req->auth_header[len] = '\0';
            }
        }
    }

    /* Parse Content-Length header */
    const char *cl = strstr(raw, "Content-Length: ");
    if (!cl) {
        cl = strstr(raw, "content-length: ");
    }
    if (cl) {
        cl += 16;
        req->content_length = atoi(cl);
    }

    /* Locate body (after \r\n\r\n) */
    const char *body_sep = strstr(raw, "\r\n\r\n");
    if (body_sep) {
        body_sep += 4;
        size_t header_size = (size_t)(body_sep - raw);
        if (header_size < raw_len) {
            req->body = body_sep;
            req->body_len = raw_len - header_size;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Token generation and validation                                     */
/* ------------------------------------------------------------------ */

int health_check_generate_token(const char *secret, hc_token_scope_t scope,
                                char *out, size_t out_size)
{
    if (!secret || !out || out_size < 128) return -1;

    const char *scope_str = (scope == HC_TOKEN_SCOPE_ADMIN)
                            ? "admin" : "readonly";

    time_t now = time(NULL);
    char message[128];
    int msg_len = snprintf(message, sizeof(message),
                           "%ld.%s", (long)now, scope_str);
    if (msg_len < 0 || (size_t)msg_len >= sizeof(message)) return -1;

    char hmac_hex[65];
    if (health_check_hmac_sha256(secret, strlen(secret),
                                 message, (size_t)msg_len,
                                 hmac_hex, sizeof(hmac_hex)) != 0) {
        return -1;
    }

    int written = snprintf(out, out_size, "%ld.%s.%s",
                           (long)now, scope_str, hmac_hex);
    if (written < 0 || (size_t)written >= out_size) return -1;

    return 0;
}

hc_auth_result_t health_check_validate_token(const char *token,
                                             const char *secret,
                                             uint32_t expiry_sec)
{
    if (!token || !secret || token[0] == '\0') return HC_AUTH_DENIED;

    /* Copy token for safe tokenization */
    char buf[512];
    size_t token_len = strlen(token);
    if (token_len >= sizeof(buf)) return HC_AUTH_DENIED;
    memcpy(buf, token, token_len + 1);

    /* Split: <timestamp>.<scope>.<hmac_hex> */
    char *dot1 = strchr(buf, '.');
    if (!dot1) return HC_AUTH_DENIED;
    *dot1 = '\0';

    char *scope_str = dot1 + 1;
    char *dot2 = strchr(scope_str, '.');
    if (!dot2) return HC_AUTH_DENIED;
    *dot2 = '\0';

    char *hmac_hex = dot2 + 1;

    /* Parse timestamp */
    char *endptr;
    long timestamp = strtol(buf, &endptr, 10);
    if (*endptr != '\0' || timestamp <= 0) return HC_AUTH_DENIED;

    /* Check expiry */
    if (expiry_sec > 0) {
        time_t now = time(NULL);
        long age = (long)now - timestamp;
        if (age > (long)expiry_sec || timestamp > (long)now + 60) {
            return HC_AUTH_EXPIRED;
        }
    }

    /* Validate scope string */
    hc_auth_result_t result;
    if (strcmp(scope_str, "admin") == 0) {
        result = HC_AUTH_OK_ADMIN;
    } else if (strcmp(scope_str, "readonly") == 0) {
        result = HC_AUTH_OK_READONLY;
    } else {
        return HC_AUTH_DENIED;
    }

    /* Recompute HMAC over "timestamp.scope" */
    char message[128];
    int msg_len = snprintf(message, sizeof(message),
                           "%ld.%s", timestamp, scope_str);
    if (msg_len < 0 || (size_t)msg_len >= sizeof(message)) {
        return HC_AUTH_DENIED;
    }

    char expected[65];
    if (health_check_hmac_sha256(secret, strlen(secret),
                                 message, (size_t)msg_len,
                                 expected, sizeof(expected)) != 0) {
        return HC_AUTH_DENIED;
    }

    /* Constant-time comparison */
    size_t hmac_len = strlen(hmac_hex);
    if (hmac_len != 64) return HC_AUTH_DENIED;

    unsigned char diff = 0;
    for (size_t i = 0; i < 64; i++) {
        diff |= (unsigned char)hmac_hex[i] ^ (unsigned char)expected[i];
    }
    if (diff != 0) return HC_AUTH_DENIED;

    return result;
}

/* ------------------------------------------------------------------ */
/* Admin auth checking                                                 */
/* ------------------------------------------------------------------ */

static hc_auth_result_t check_admin_auth(const health_check_config_t *cfg,
                                         const hc_http_request_t *req)
{
    /* No auth configured — allow everything */
    if (cfg->admin_auth_token[0] == '\0') return HC_AUTH_OK_ADMIN;

    /* HMAC mode: token starts with "hmac:" */
    if (strncmp(cfg->admin_auth_token, "hmac:", 5) == 0) {
        const char *secret = cfg->admin_auth_token + 5;
        uint32_t expiry = cfg->token_expiry_sec > 0
                          ? cfg->token_expiry_sec : 3600;
        return health_check_validate_token(req->auth_header, secret, expiry);
    }

    /* Constant-time string comparison (backward compatible) */
    {
        const char *a = cfg->admin_auth_token;
        const char *b = req->auth_header;
        size_t alen = strlen(a);
        size_t blen = strlen(b);
        volatile uint8_t diff = (alen != blen) ? 1 : 0;
        size_t cmp_len = alen < blen ? alen : blen;
        for (size_t i = 0; i < cmp_len; i++) {
            diff |= (uint8_t)(a[i] ^ b[i]);
        }
        if (diff == 0) return HC_AUTH_OK_ADMIN;
    }
    return HC_AUTH_DENIED;
}

/* ------------------------------------------------------------------ */
/* Audit logging                                                       */
/* ------------------------------------------------------------------ */

static void audit_log(const char *peer, const char *method,
                      const char *path, hc_auth_result_t auth, int status)
{
    const char *auth_str;
    switch (auth) {
    case HC_AUTH_OK_ADMIN:    auth_str = "admin";    break;
    case HC_AUTH_OK_READONLY: auth_str = "readonly"; break;
    case HC_AUTH_DENIED:      auth_str = "denied";   break;
    case HC_AUTH_EXPIRED:     auth_str = "expired";  break;
    default:                  auth_str = "unknown";  break;
    }
    LOG_INFO("AUDIT: %s %s from %s auth=%s status=%d",
             method, path, peer ? peer : "unknown", auth_str, status);
}

/* ------------------------------------------------------------------ */
/* Response helpers                                                    */
/* ------------------------------------------------------------------ */

static void send_response(hc_conn_t *conn, const char *status,
                          const char *content_type,
                          const char *body, size_t body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.1 %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        status, content_type, body_len);
    (void)hc_write(conn, header, (size_t)hlen);
    if (body_len > 0) {
        (void)hc_write(conn, body, body_len);
    }
}

static void send_json_response(hc_conn_t *conn, int status_code,
                               const char *status_text,
                               const char *json_body)
{
    char header[512];
    int body_len = json_body ? (int)strlen(json_body) : 0;
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        status_code, status_text, body_len);
    (void)hc_write(conn, header, (size_t)header_len);
    if (json_body && body_len > 0) {
        (void)hc_write(conn, json_body, (size_t)body_len);
    }
}

/* ------------------------------------------------------------------ */
/* Endpoint handlers                                                   */
/* ------------------------------------------------------------------ */

/* GET /health */
static void handle_health(hc_conn_t *conn)
{
    metrics_t *m = metrics_get();
    time_t uptime = time(NULL) - m->start_time;

    char body[HC_RESP_SIZE];
    int len = snprintf(body, sizeof(body),
        "{\n"
        "  \"status\": \"healthy\",\n"
        "  \"version\": \"%s\",\n"
        "  \"uptime_seconds\": %ld,\n"
        "  \"connections_active\": %" PRIuFAST64 ",\n"
        "  \"connections_total\": %" PRIuFAST64 "\n"
        "}\n",
        SSH_PROXY_VERSION_STRING,
        (long)uptime,
        METRICS_GET(connections_active),
        METRICS_GET(connections_total));

    send_response(conn, "200 OK", "application/json", body, (size_t)len);
}

/* GET /metrics */
static void handle_metrics(hc_conn_t *conn)
{
    metrics_t *m = metrics_get();
    time_t uptime = time(NULL) - m->start_time;

    char body[HC_RESP_SIZE];
    int len = snprintf(body, sizeof(body),
        "# HELP ssh_proxy_up Whether the SSH proxy is up (1 = up).\n"
        "# TYPE ssh_proxy_up gauge\n"
        "ssh_proxy_up 1\n"
        "# HELP ssh_proxy_uptime_seconds Time since process start.\n"
        "# TYPE ssh_proxy_uptime_seconds gauge\n"
        "ssh_proxy_uptime_seconds %ld\n"
        "# HELP ssh_proxy_connections_total Total accepted connections.\n"
        "# TYPE ssh_proxy_connections_total counter\n"
        "ssh_proxy_connections_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_connections_active Current active connections.\n"
        "# TYPE ssh_proxy_connections_active gauge\n"
        "ssh_proxy_connections_active %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_auth_success_total Successful authentications.\n"
        "# TYPE ssh_proxy_auth_success_total counter\n"
        "ssh_proxy_auth_success_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_auth_failure_total Failed authentications.\n"
        "# TYPE ssh_proxy_auth_failure_total counter\n"
        "ssh_proxy_auth_failure_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_bytes_upstream_total Bytes sent to upstream.\n"
        "# TYPE ssh_proxy_bytes_upstream_total counter\n"
        "ssh_proxy_bytes_upstream_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_bytes_downstream_total Bytes sent to client.\n"
        "# TYPE ssh_proxy_bytes_downstream_total counter\n"
        "ssh_proxy_bytes_downstream_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_sessions_rejected_total Sessions rejected by filters.\n"
        "# TYPE ssh_proxy_sessions_rejected_total counter\n"
        "ssh_proxy_sessions_rejected_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_config_reloads_total Successful config reloads.\n"
        "# TYPE ssh_proxy_config_reloads_total counter\n"
        "ssh_proxy_config_reloads_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_config_reload_errors_total Failed config reloads.\n"
        "# TYPE ssh_proxy_config_reload_errors_total counter\n"
        "ssh_proxy_config_reload_errors_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_total Total upstream connection retry attempts.\n"
        "# TYPE ssh_proxy_upstream_retries_total counter\n"
        "ssh_proxy_upstream_retries_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_success Successful connections after retry.\n"
        "# TYPE ssh_proxy_upstream_retries_success counter\n"
        "ssh_proxy_upstream_retries_success %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_exhausted Connections where all retries were exhausted.\n"
        "# TYPE ssh_proxy_upstream_retries_exhausted counter\n"
        "ssh_proxy_upstream_retries_exhausted %" PRIuFAST64 "\n",
        (long)uptime,
        METRICS_GET(connections_total),
        METRICS_GET(connections_active),
        METRICS_GET(auth_success_total),
        METRICS_GET(auth_failure_total),
        METRICS_GET(bytes_upstream),
        METRICS_GET(bytes_downstream),
        METRICS_GET(sessions_rejected),
        METRICS_GET(config_reloads),
        METRICS_GET(config_reload_errors),
        METRICS_GET(upstream_retries_total),
        METRICS_GET(upstream_retries_success),
        METRICS_GET(upstream_retries_exhausted));

    send_response(conn, "200 OK",
                  "text/plain; version=0.0.4; charset=utf-8",
                  body, (size_t)len);
}

static void handle_not_found(hc_conn_t *conn)
{
    const char *body = "404 Not Found\n";
    send_response(conn, "404 Not Found", "text/plain", body, strlen(body));
}

/* ------------------------------------------------------------------ */
/* Admin API endpoint handlers                                         */
/* ------------------------------------------------------------------ */

static void handle_api_sessions_list(hc_conn_t *conn,
                                     health_check_config_t *cfg)
{
    session_manager_t *mgr = (session_manager_t *)cfg->session_manager;
    if (!mgr) {
        send_json_response(conn, 503, "Service Unavailable",
                          "{\"error\":\"session manager not available\"}");
        return;
    }

    size_t count = session_manager_get_count(mgr);

    char body[HC_RESP_SIZE];
    snprintf(body, sizeof(body),
        "{\"sessions\":[],\"total\":%zu}", count);

    send_json_response(conn, 200, "OK", body);
}

static void handle_api_upstreams_list(hc_conn_t *conn,
                                      health_check_config_t *cfg)
{
    router_t *router = (router_t *)cfg->router;
    if (!router) {
        send_json_response(conn, 503, "Service Unavailable",
                          "{\"error\":\"router not available\"}");
        return;
    }

    size_t n = router_get_upstream_count(router);

    char body[HC_RESP_SIZE];
    int pos = 0;
    pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
                    "{\"upstreams\":[");

    for (size_t i = 0; i < n; i++) {
        upstream_t *u = router_get_upstream(router, (int)i);
        if (!u) continue;
        if (i > 0) {
            pos += snprintf(body + pos, sizeof(body) - (size_t)pos, ",");
        }
        const char *health_str = "unknown";
        if (u->health == UPSTREAM_HEALTH_HEALTHY)
            health_str = "healthy";
        else if (u->health == UPSTREAM_HEALTH_UNHEALTHY)
            health_str = "unhealthy";

        pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
            "{\"host\":\"%s\",\"port\":%u,\"health\":\"%s\","
            "\"active_connections\":%zu,\"total_connections\":%zu,"
            "\"enabled\":%s}",
            u->config.host, u->config.port, health_str,
            u->active_connections, u->total_connections,
            u->config.enabled ? "true" : "false");
    }

    pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
        "],\"total\":%zu}", n);

    send_json_response(conn, 200, "OK", body);
}

static void handle_api_reload(hc_conn_t *conn)
{
    kill(getpid(), SIGHUP);
    send_json_response(conn, 200, "OK",
                      "{\"status\":\"reload triggered\"}");
}

static void handle_api_config(hc_conn_t *conn, health_check_config_t *cfg)
{
    proxy_config_t *pcfg = (proxy_config_t *)cfg->config;
    if (!pcfg) {
        send_json_response(conn, 503, "Service Unavailable",
                          "{\"error\":\"config not available\"}");
        return;
    }

    int num_users = 0;
    for (config_user_t *u = pcfg->users; u; u = u->next) num_users++;

    int num_routes = 0;
    for (config_route_t *r = pcfg->routes; r; r = r->next) num_routes++;

    char body[4096];
    snprintf(body, sizeof(body),
        "{\"bind_addr\":\"%s\",\"port\":%u,"
        "\"num_users\":%d,\"num_routes\":%d}",
        pcfg->bind_addr, pcfg->port, num_users, num_routes);

    send_json_response(conn, 200, "OK", body);
}

/* ------------------------------------------------------------------ */
/* JSON body helper                                                    */
/* ------------------------------------------------------------------ */

/**
 * Extract a string value from a simple flat JSON object.
 * Handles: "key" : "value" — no nesting, no escapes.
 */
static int json_extract_string(const char *json, size_t json_len,
                               const char *key,
                               char *value, size_t value_size)
{
    if (!json || !key || !value || value_size == 0) return -1;

    char search[256];
    int slen = snprintf(search, sizeof(search), "\"%s\"", key);
    if (slen < 0 || (size_t)slen >= sizeof(search)) return -1;

    const char *found = strstr(json, search);
    if (!found || (size_t)(found - json) >= json_len) return -1;

    /* Skip past key, then past ':' and whitespace */
    found += slen;
    while (*found && (*found == ' ' || *found == '\t' || *found == ':'))
        found++;

    if (*found != '"') return -1;
    found++; /* skip opening quote */

    const char *end = strchr(found, '"');
    if (!end) return -1;

    size_t len = (size_t)(end - found);
    if (len >= value_size) return -1;

    memcpy(value, found, len);
    value[len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* POST /api/v1/token — generate a new HMAC token                      */
/* ------------------------------------------------------------------ */

static void handle_api_token(hc_conn_t *conn, health_check_config_t *cfg,
                             const hc_http_request_t *req)
{
    /* Only available in HMAC mode */
    if (strncmp(cfg->admin_auth_token, "hmac:", 5) != 0) {
        send_json_response(conn, 400, "Bad Request",
                          "{\"error\":\"HMAC auth not configured\"}");
        return;
    }

    const char *configured_secret = cfg->admin_auth_token + 5;

    if (!req->body || req->body_len == 0) {
        send_json_response(conn, 400, "Bad Request",
                          "{\"error\":\"request body required\"}");
        return;
    }

    char secret[256];
    char scope_str[32];

    if (json_extract_string(req->body, req->body_len,
                            "secret", secret, sizeof(secret)) != 0) {
        send_json_response(conn, 400, "Bad Request",
                          "{\"error\":\"missing 'secret' field\"}");
        return;
    }

    if (json_extract_string(req->body, req->body_len,
                            "scope", scope_str, sizeof(scope_str)) != 0) {
        snprintf(scope_str, sizeof(scope_str), "readonly");
    }

    /* Constant-time comparison of secrets */
    size_t cfg_len = strlen(configured_secret);
    size_t req_len = strlen(secret);
    if (cfg_len != req_len) {
        send_json_response(conn, 401, "Unauthorized",
                          "{\"error\":\"invalid secret\"}");
        return;
    }

    unsigned char diff = 0;
    for (size_t i = 0; i < cfg_len; i++) {
        diff |= (unsigned char)configured_secret[i]
              ^ (unsigned char)secret[i];
    }
    if (diff != 0) {
        send_json_response(conn, 401, "Unauthorized",
                          "{\"error\":\"invalid secret\"}");
        return;
    }

    hc_token_scope_t scope = HC_TOKEN_SCOPE_READONLY;
    if (strcmp(scope_str, "admin") == 0) {
        scope = HC_TOKEN_SCOPE_ADMIN;
    }

    char token[256];
    if (health_check_generate_token(configured_secret, scope,
                                    token, sizeof(token)) != 0) {
        send_json_response(conn, 500, "Internal Server Error",
                          "{\"error\":\"token generation failed\"}");
        return;
    }

    uint32_t expiry = cfg->token_expiry_sec > 0
                      ? cfg->token_expiry_sec : 3600;

    char body[512];
    snprintf(body, sizeof(body),
        "{\"token\":\"%s\",\"expires_in\":%u,\"scope\":\"%s\"}",
        token, expiry, scope_str);

    send_json_response(conn, 200, "OK", body);
}

/* ------------------------------------------------------------------ */
/* Request dispatch                                                    */
/* ------------------------------------------------------------------ */

struct health_check {
    int listen_fd;
    pthread_t thread;
    volatile bool running;
    uint16_t port;
    health_check_config_t config;
#ifdef TLS_ENABLED
    SSL_CTX *ssl_ctx;
#endif
};

static void handle_request(hc_conn_t *conn, health_check_config_t *cfg)
{
    char buf[HC_BUF_SIZE];
    ssize_t n = hc_read(conn, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    hc_http_request_t req;
    if (health_check_parse_request(buf, (size_t)n, &req) != 0) {
        send_json_response(conn, 400, "Bad Request",
                          "{\"error\":\"invalid request\"}");
        return;
    }

    /* Public endpoints (no auth required) */
    if (strcmp(req.path, "/health") == 0 &&
        strcmp(req.method, "GET") == 0) {
        handle_health(conn);
        return;
    }
    if (strcmp(req.path, "/metrics") == 0 &&
        strcmp(req.method, "GET") == 0) {
        handle_metrics(conn);
        return;
    }

    /* Admin API endpoints */
    if (strncmp(req.path, "/api/v1/", 8) == 0) {
        if (!cfg->admin_api_enabled) {
            send_json_response(conn, 404, "Not Found",
                              "{\"error\":\"not found\"}");
            return;
        }

        /* Token generation endpoint — authenticates via secret in body */
        if (strcmp(req.path, "/api/v1/token") == 0 &&
            strcmp(req.method, "POST") == 0) {
            handle_api_token(conn, cfg, &req);
            audit_log(conn->peer_addr, req.method, req.path,
                      HC_AUTH_OK_ADMIN, 200);
            return;
        }

        /* All other admin endpoints require token auth */
        hc_auth_result_t auth = check_admin_auth(cfg, &req);

        if (auth == HC_AUTH_DENIED) {
            audit_log(conn->peer_addr, req.method, req.path, auth, 401);
            send_json_response(conn, 401, "Unauthorized",
                "{\"error\":\"invalid or missing auth token\"}");
            return;
        }

        if (auth == HC_AUTH_EXPIRED) {
            audit_log(conn->peer_addr, req.method, req.path, auth, 401);
            send_json_response(conn, 401, "Unauthorized",
                "{\"error\":\"token expired\"}");
            return;
        }

        /* Scope enforcement: readonly tokens can only GET */
        if (auth == HC_AUTH_OK_READONLY &&
            strcmp(req.method, "GET") != 0) {
            audit_log(conn->peer_addr, req.method, req.path, auth, 403);
            send_json_response(conn, 403, "Forbidden",
                "{\"error\":\"readonly token cannot perform this action\"}");
            return;
        }

        /* Dispatch to endpoint handlers */
        int status = 200;
        if (strcmp(req.path, "/api/v1/sessions") == 0 &&
            strcmp(req.method, "GET") == 0) {
            handle_api_sessions_list(conn, cfg);
        } else if (strcmp(req.path, "/api/v1/upstreams") == 0 &&
                   strcmp(req.method, "GET") == 0) {
            handle_api_upstreams_list(conn, cfg);
        } else if (strcmp(req.path, "/api/v1/reload") == 0 &&
                   strcmp(req.method, "POST") == 0) {
            handle_api_reload(conn);
        } else if (strcmp(req.path, "/api/v1/config") == 0 &&
                   strcmp(req.method, "GET") == 0) {
            handle_api_config(conn, cfg);
        } else {
            status = 404;
            send_json_response(conn, 404, "Not Found",
                              "{\"error\":\"endpoint not found\"}");
        }

        audit_log(conn->peer_addr, req.method, req.path, auth, status);
        return;
    }

    handle_not_found(conn);
}

/* ------------------------------------------------------------------ */
/* Server thread                                                       */
/* ------------------------------------------------------------------ */

static void *health_check_thread(void *arg)
{
    health_check_t *hc = (health_check_t *)arg;

    while (hc->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(hc->listen_fd,
                               (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            if (hc->running && errno != EINTR) {
                LOG_DEBUG("health_check accept error: %s", strerror(errno));
            }
            continue;
        }

        /* Set a short read timeout to avoid hanging on slow clients */
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        hc_conn_t conn;
        memset(&conn, 0, sizeof(conn));
        conn.fd = client_fd;
        inet_ntop(AF_INET, &client_addr.sin_addr,
                  conn.peer_addr, sizeof(conn.peer_addr));

#ifdef TLS_ENABLED
        if (hc->ssl_ctx) {
            conn.ssl = SSL_new(hc->ssl_ctx);
            if (conn.ssl) {
                SSL_set_fd(conn.ssl, client_fd);
                if (SSL_accept(conn.ssl) <= 0) {
                    LOG_WARN("TLS handshake failed from %s", conn.peer_addr);
                    SSL_free(conn.ssl);
                    close(client_fd);
                    continue;
                }
            }
        }
#endif

        handle_request(&conn, &hc->config);

#ifdef TLS_ENABLED
        if (conn.ssl) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
#endif
        close(client_fd);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

health_check_t *health_check_start(const health_check_config_t *config)
{
    uint16_t port = (config && config->port) ? config->port : 9090;
    const char *bind_addr = (config && config->bind_addr) ? config->bind_addr
                                                          : "127.0.0.1";

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("health_check socket(): %s", strerror(errno));
        return NULL;
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        LOG_ERROR("health_check: invalid bind address '%s'", bind_addr);
        close(fd);
        return NULL;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("health_check bind(%s:%u): %s", bind_addr, port,
                  strerror(errno));
        close(fd);
        return NULL;
    }

    if (listen(fd, HC_BACKLOG) < 0) {
        LOG_ERROR("health_check listen(): %s", strerror(errno));
        close(fd);
        return NULL;
    }

    health_check_t *hc = calloc(1, sizeof(health_check_t));
    if (hc == NULL) {
        close(fd);
        return NULL;
    }

    hc->listen_fd = fd;
    hc->port = port;
    hc->running = true;

    if (config) {
        hc->config = *config;
    } else {
        memset(&hc->config, 0, sizeof(hc->config));
    }
    /* Preserve resolved values */
    hc->config.port = port;
    hc->config.bind_addr = bind_addr;

    /* Default token expiry */
    if (hc->config.token_expiry_sec == 0) {
        hc->config.token_expiry_sec = 3600;
    }

#ifdef TLS_ENABLED
    /* Initialize TLS if configured */
    if (config && config->tls_enabled) {
        if (!config->tls_cert_path || !config->tls_key_path) {
            LOG_ERROR("TLS enabled but cert/key paths not set");
            close(fd);
            free(hc);
            return NULL;
        }

        const SSL_METHOD *method = TLS_server_method();
        hc->ssl_ctx = SSL_CTX_new(method);
        if (!hc->ssl_ctx) {
            LOG_ERROR("Failed to create SSL context");
            close(fd);
            free(hc);
            return NULL;
        }

        SSL_CTX_set_min_proto_version(hc->ssl_ctx, TLS1_2_VERSION);

        if (SSL_CTX_use_certificate_file(hc->ssl_ctx,
                config->tls_cert_path, SSL_FILETYPE_PEM) <= 0) {
            LOG_ERROR("Failed to load TLS certificate: %s",
                      config->tls_cert_path);
            SSL_CTX_free(hc->ssl_ctx);
            close(fd);
            free(hc);
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(hc->ssl_ctx,
                config->tls_key_path, SSL_FILETYPE_PEM) <= 0) {
            LOG_ERROR("Failed to load TLS private key: %s",
                      config->tls_key_path);
            SSL_CTX_free(hc->ssl_ctx);
            close(fd);
            free(hc);
            return NULL;
        }

        if (!SSL_CTX_check_private_key(hc->ssl_ctx)) {
            LOG_ERROR("TLS certificate and private key do not match");
            SSL_CTX_free(hc->ssl_ctx);
            close(fd);
            free(hc);
            return NULL;
        }

        LOG_INFO("TLS enabled for health check endpoint");
    }
#else
    if (config && config->tls_enabled) {
        LOG_WARN("TLS requested but not compiled in (build with "
                 "TLS_ENABLED=1). Falling back to plain HTTP.");
    }
#endif

    if (pthread_create(&hc->thread, NULL, health_check_thread, hc) != 0) {
        LOG_ERROR("health_check pthread_create: %s", strerror(errno));
#ifdef TLS_ENABLED
        if (hc->ssl_ctx) SSL_CTX_free(hc->ssl_ctx);
#endif
        close(fd);
        free(hc);
        return NULL;
    }

    const char *proto = "HTTP";
#ifdef TLS_ENABLED
    if (hc->ssl_ctx) proto = "HTTPS";
#endif
    LOG_INFO("Health check endpoint listening on %s://%s:%u",
             proto, bind_addr, port);
    return hc;
}

void health_check_stop(health_check_t *hc)
{
    if (hc == NULL) return;

    hc->running = false;

    /* Close the listening socket to unblock accept() */
    if (hc->listen_fd >= 0) {
        close(hc->listen_fd);
        hc->listen_fd = -1;
    }

    pthread_join(hc->thread, NULL);

#ifdef TLS_ENABLED
    if (hc->ssl_ctx) {
        SSL_CTX_free(hc->ssl_ctx);
        hc->ssl_ctx = NULL;
    }
#endif

    free(hc);
    LOG_DEBUG("Health check server stopped");
}
