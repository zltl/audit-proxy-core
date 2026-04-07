/**
 * @file health_check.h
 * @brief Lightweight HTTP health check and metrics endpoint with TLS support
 *
 * Provides:
 *   GET /health  - JSON health status (200 OK / 503 unhealthy)
 *   GET /metrics - Prometheus text exposition format
 *   Admin API endpoints with HMAC-SHA256 token authentication
 */

#ifndef HEALTH_CHECK_H
#define HEALTH_CHECK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct health_check health_check_t;

/* ------------------------------------------------------------------ */
/* Auth and token types                                                */
/* ------------------------------------------------------------------ */

/** Authentication result from token validation */
typedef enum {
    HC_AUTH_OK_ADMIN = 0,   /**< Full access (all methods) */
    HC_AUTH_OK_READONLY,    /**< Read-only access (GET only) */
    HC_AUTH_DENIED,         /**< Invalid or missing token */
    HC_AUTH_EXPIRED         /**< Token expired */
} hc_auth_result_t;

/** Token scope */
typedef enum {
    HC_TOKEN_SCOPE_ADMIN = 0,   /**< admin scope: all methods */
    HC_TOKEN_SCOPE_READONLY     /**< readonly scope: GET only */
} hc_token_scope_t;

/* ------------------------------------------------------------------ */
/* HTTP request parsing (exported for testing)                         */
/* ------------------------------------------------------------------ */

/** Parsed HTTP request */
typedef struct {
    char method[16];
    char path[512];
    char auth_header[512];
    int content_length;
    const char *body;       /**< Points into raw buffer (not separately allocated) */
    size_t body_len;
} hc_http_request_t;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t port;              /**< HTTP listen port (default 9090) */
    const char *bind_addr;      /**< Bind address (default "127.0.0.1") */

    /* Admin API settings */
    bool admin_api_enabled;
    char admin_auth_token[256]; /**< Bearer token or "hmac:<secret>" */

    /* TLS settings */
    bool tls_enabled;           /**< Enable TLS for HTTPS */
    const char *tls_cert_path;  /**< Path to TLS certificate file */
    const char *tls_key_path;   /**< Path to TLS private key file */

    /* Token settings */
    uint32_t token_expiry_sec;  /**< Token expiry in seconds (default 3600) */

    /* Component references for admin API */
    void *session_manager;      /**< session_manager_t* */
    void *router;               /**< router_t* */
    void *config;               /**< proxy_config_t* (for reload) */
} health_check_config_t;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * @brief Create and start the health check HTTP server
 * @param config Configuration (NULL for defaults)
 * @return Server handle or NULL on error
 */
health_check_t *health_check_start(const health_check_config_t *config);

/**
 * @brief Stop and destroy the health check server
 */
void health_check_stop(health_check_t *hc);

/* ------------------------------------------------------------------ */
/* Token utilities (exported for testing and CLI tools)                 */
/* ------------------------------------------------------------------ */

/**
 * @brief Parse an HTTP request from raw bytes
 * @param raw Raw HTTP request data (null-terminated)
 * @param raw_len Length of raw data
 * @param req Output parsed request
 * @return 0 on success, -1 on parse error
 */
int health_check_parse_request(const char *raw, size_t raw_len,
                               hc_http_request_t *req);

/**
 * @brief Generate an HMAC-SHA256 token
 * @param secret HMAC secret key
 * @param scope Token scope (admin or readonly)
 * @param out Output buffer for the token string
 * @param out_size Size of output buffer (must be >= 128)
 * @return 0 on success, -1 on error
 */
int health_check_generate_token(const char *secret, hc_token_scope_t scope,
                                char *out, size_t out_size);

/**
 * @brief Validate an HMAC-SHA256 token
 * @param token Token string to validate
 * @param secret HMAC secret key
 * @param expiry_sec Maximum token age in seconds (0 = no expiry check)
 * @return Authentication result
 */
hc_auth_result_t health_check_validate_token(const char *token,
                                             const char *secret,
                                             uint32_t expiry_sec);

/**
 * @brief Compute HMAC-SHA256 and output as hex string
 * @param key HMAC key
 * @param key_len Key length
 * @param data Input data
 * @param data_len Data length
 * @param hex_out Output buffer for hex string (must be >= 65 bytes)
 * @param hex_out_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int health_check_hmac_sha256(const void *key, size_t key_len,
                             const void *data, size_t data_len,
                             char *hex_out, size_t hex_out_size);

#ifdef __cplusplus
}
#endif

#endif /* HEALTH_CHECK_H */
