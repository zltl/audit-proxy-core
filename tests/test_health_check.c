/**
 * @file test_health_check.c
 * @brief Unit tests for health check module — HMAC-SHA256, tokens, HTTP parsing
 */
#include "health_check.h"
#include "logger.h"
#include "test_utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ===== HMAC-SHA256 Tests ===== */

/* RFC 4231 Test Case 2 */
static int test_hmac_sha256_rfc4231(void) {
    const char *key = "Jefe";
    const char *data = "what do ya want for nothing?";
    const char *expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    char hex_out[65];
    int rc = health_check_hmac_sha256(key, 4, data, 28, hex_out, sizeof(hex_out));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex_out, expected);
    return 0;
}

static int test_hmac_sha256_empty_data(void) {
    const char *key = "key";
    char hex_out[65];
    int rc = health_check_hmac_sha256(key, 3, "", 0, hex_out, sizeof(hex_out));
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(strlen(hex_out), (size_t)64);
    return 0;
}

static int test_hmac_sha256_null_handling(void) {
    char hex_out[65];
    ASSERT_EQ(health_check_hmac_sha256(NULL, 0, "d", 1, hex_out, sizeof(hex_out)), -1);
    ASSERT_EQ(health_check_hmac_sha256("k", 1, NULL, 0, hex_out, sizeof(hex_out)), -1);
    ASSERT_EQ(health_check_hmac_sha256("k", 1, "d", 1, NULL, 0), -1);
    /* Buffer too small */
    ASSERT_EQ(health_check_hmac_sha256("k", 1, "d", 1, hex_out, 32), -1);
    return 0;
}

/* RFC 4231 Test Case 3: 20-byte key, 50 * 0xdd */
static int test_hmac_sha256_rfc4231_case3(void) {
    uint8_t key[20];
    memset(key, 0xaa, 20);
    uint8_t data[50];
    memset(data, 0xdd, 50);

    const char *expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

    char hex_out[65];
    int rc = health_check_hmac_sha256(key, 20, data, 50, hex_out, sizeof(hex_out));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex_out, expected);
    return 0;
}

/* ===== Token Generation and Validation ===== */

static int test_token_generate_validate_admin(void) {
    const char *secret = "test-secret-key-123";
    char token[256];

    int rc = health_check_generate_token(secret, HC_TOKEN_SCOPE_ADMIN, token, sizeof(token));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(strlen(token) > 0);

    hc_auth_result_t result = health_check_validate_token(token, secret, 3600);
    ASSERT_EQ(result, HC_AUTH_OK_ADMIN);
    return 0;
}

static int test_token_generate_validate_readonly(void) {
    const char *secret = "test-secret-key-456";
    char token[256];

    int rc = health_check_generate_token(secret, HC_TOKEN_SCOPE_READONLY, token, sizeof(token));
    ASSERT_EQ(rc, 0);

    hc_auth_result_t result = health_check_validate_token(token, secret, 3600);
    ASSERT_EQ(result, HC_AUTH_OK_READONLY);
    return 0;
}

static int test_token_generate_null_handling(void) {
    char token[256];
    ASSERT_EQ(health_check_generate_token(NULL, HC_TOKEN_SCOPE_ADMIN, token, sizeof(token)), -1);
    ASSERT_EQ(health_check_generate_token("secret", HC_TOKEN_SCOPE_ADMIN, NULL, 0), -1);
    ASSERT_EQ(health_check_generate_token("secret", HC_TOKEN_SCOPE_ADMIN, token, 10),
              -1); /* too small */
    return 0;
}

/* ===== Token Expiry ===== */

static int test_token_expiry_expired(void) {
    const char *secret = "expiry-test-secret";

    /* Manually construct a token with timestamp 2 hours in the past */
    time_t old_time = time(NULL) - 7200;
    char message[128];
    snprintf(message, sizeof(message), "%ld.admin", (long)old_time);

    char hmac_hex[65];
    health_check_hmac_sha256(secret, strlen(secret), message, strlen(message), hmac_hex,
                             sizeof(hmac_hex));

    char token[256];
    snprintf(token, sizeof(token), "%ld.admin.%s", (long)old_time, hmac_hex);

    /* Should be expired with 3600 sec expiry */
    hc_auth_result_t result = health_check_validate_token(token, secret, 3600);
    ASSERT_EQ(result, HC_AUTH_EXPIRED);

    return 0;
}

static int test_token_expiry_no_check(void) {
    const char *secret = "expiry-test-secret";

    time_t old_time = time(NULL) - 7200;
    char message[128];
    snprintf(message, sizeof(message), "%ld.admin", (long)old_time);

    char hmac_hex[65];
    health_check_hmac_sha256(secret, strlen(secret), message, strlen(message), hmac_hex,
                             sizeof(hmac_hex));

    char token[256];
    snprintf(token, sizeof(token), "%ld.admin.%s", (long)old_time, hmac_hex);

    /* Should be valid with 0 expiry (no check) */
    hc_auth_result_t result = health_check_validate_token(token, secret, 0);
    ASSERT_EQ(result, HC_AUTH_OK_ADMIN);

    return 0;
}

static int test_token_expiry_future(void) {
    const char *secret = "future-test";

    /* Token with timestamp far in the future (>60s clock skew) */
    time_t future = time(NULL) + 3600;
    char message[128];
    snprintf(message, sizeof(message), "%ld.admin", (long)future);

    char hmac_hex[65];
    health_check_hmac_sha256(secret, strlen(secret), message, strlen(message), hmac_hex,
                             sizeof(hmac_hex));

    char token[256];
    snprintf(token, sizeof(token), "%ld.admin.%s", (long)future, hmac_hex);

    hc_auth_result_t result = health_check_validate_token(token, secret, 3600);
    ASSERT_EQ(result, HC_AUTH_EXPIRED);

    return 0;
}

/* ===== Token Scope ===== */

static int test_token_scope_admin(void) {
    const char *secret = "scope-secret";
    char token[256];

    health_check_generate_token(secret, HC_TOKEN_SCOPE_ADMIN, token, sizeof(token));
    ASSERT_EQ(health_check_validate_token(token, secret, 3600), HC_AUTH_OK_ADMIN);

    /* Verify token contains "admin" scope */
    ASSERT_TRUE(strstr(token, ".admin.") != NULL);
    return 0;
}

static int test_token_scope_readonly(void) {
    const char *secret = "scope-secret";
    char token[256];

    health_check_generate_token(secret, HC_TOKEN_SCOPE_READONLY, token, sizeof(token));
    ASSERT_EQ(health_check_validate_token(token, secret, 3600), HC_AUTH_OK_READONLY);

    ASSERT_TRUE(strstr(token, ".readonly.") != NULL);
    return 0;
}

/* ===== HMAC Validation (wrong secret, tampered) ===== */

static int test_token_wrong_secret(void) {
    char token[256];
    health_check_generate_token("correct-secret", HC_TOKEN_SCOPE_ADMIN, token, sizeof(token));

    ASSERT_EQ(health_check_validate_token(token, "wrong-secret", 3600), HC_AUTH_DENIED);
    return 0;
}

static int test_token_tampered(void) {
    const char *secret = "tamper-test";
    char token[256];
    health_check_generate_token(secret, HC_TOKEN_SCOPE_ADMIN, token, sizeof(token));

    /* Flip a character in the HMAC portion */
    size_t len = strlen(token);
    if (len > 0) {
        token[len - 1] = (token[len - 1] == 'a') ? 'b' : 'a';
    }

    ASSERT_EQ(health_check_validate_token(token, secret, 3600), HC_AUTH_DENIED);
    return 0;
}

static int test_token_invalid_format(void) {
    ASSERT_EQ(health_check_validate_token(NULL, "s", 0), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_token("", "s", 0), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_token("nodots", "s", 0), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_token("one.dot", "s", 0), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_token("nan.admin.abc", "s", 0), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_token("123.badscope.abc", "s", 0), HC_AUTH_DENIED);
    /* HMAC too short */
    ASSERT_EQ(health_check_validate_token("123.admin.short", "s", 0), HC_AUTH_DENIED);
    return 0;
}

/* ===== JWT Generation and Validation ===== */

static int test_jwt_generate_validate_admin(void) {
    const char *secret = "jwt-secret-admin";
    char token[512];

    ASSERT_EQ(health_check_generate_jwt(secret, HC_TOKEN_SCOPE_ADMIN, 3600, token, sizeof(token)),
              0);
    ASSERT_TRUE(strchr(token, '.') != NULL);
    ASSERT_EQ(health_check_validate_jwt(token, secret), HC_AUTH_OK_ADMIN);
    return 0;
}

static int test_jwt_generate_validate_readonly(void) {
    const char *secret = "jwt-secret-readonly";
    char token[512];

    ASSERT_EQ(
        health_check_generate_jwt(secret, HC_TOKEN_SCOPE_READONLY, 3600, token, sizeof(token)), 0);
    ASSERT_EQ(health_check_validate_jwt(token, secret), HC_AUTH_OK_READONLY);
    return 0;
}

static int test_jwt_expiry(void) {
    const char *secret = "jwt-expiry-secret";
    char token[512];

    ASSERT_EQ(health_check_generate_jwt(secret, HC_TOKEN_SCOPE_ADMIN, 1, token, sizeof(token)), 0);
    sleep(2);
    ASSERT_EQ(health_check_validate_jwt(token, secret), HC_AUTH_EXPIRED);
    return 0;
}

static int test_jwt_wrong_secret(void) {
    char token[512];
    ASSERT_EQ(
        health_check_generate_jwt("jwt-correct", HC_TOKEN_SCOPE_ADMIN, 3600, token, sizeof(token)),
        0);
    ASSERT_EQ(health_check_validate_jwt(token, "jwt-wrong"), HC_AUTH_DENIED);
    return 0;
}

static int test_jwt_tampered(void) {
    const char *secret = "jwt-tamper-secret";
    char token[512];

    ASSERT_EQ(health_check_generate_jwt(secret, HC_TOKEN_SCOPE_ADMIN, 3600, token, sizeof(token)),
              0);
    size_t len = strlen(token);
    if (len > 0) {
        token[len - 1] = (token[len - 1] == 'a') ? 'b' : 'a';
    }
    ASSERT_EQ(health_check_validate_jwt(token, secret), HC_AUTH_DENIED);
    return 0;
}

static int test_jwt_invalid_format(void) {
    ASSERT_EQ(health_check_validate_jwt(NULL, "s"), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_jwt("", "s"), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_jwt("not-a-jwt", "s"), HC_AUTH_DENIED);
    ASSERT_EQ(health_check_validate_jwt("a.b.c.d", "s"), HC_AUTH_DENIED);
    return 0;
}

/* ===== HTTP Request Parsing ===== */

static int test_parse_http_get(void) {
    const char *raw = "GET /health HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "\r\n";
    hc_http_request_t req;

    int rc = health_check_parse_request(raw, strlen(raw), &req);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.method, "GET");
    ASSERT_STR_EQ(req.path, "/health");
    ASSERT_EQ(req.content_length, 0);
    ASSERT_EQ(req.auth_header[0], '\0');
    return 0;
}

static int test_parse_http_with_auth(void) {
    const char *raw = "GET /api/v1/sessions HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "Authorization: Bearer mytoken123\r\n"
                      "\r\n";
    hc_http_request_t req;

    int rc = health_check_parse_request(raw, strlen(raw), &req);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.method, "GET");
    ASSERT_STR_EQ(req.path, "/api/v1/sessions");
    ASSERT_STR_EQ(req.auth_header, "mytoken123");
    return 0;
}

static int test_parse_http_post_with_body(void) {
    const char *raw = "POST /api/v1/token HTTP/1.1\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 38\r\n"
                      "\r\n"
                      "{\"secret\":\"mysecret\",\"scope\":\"admin\"}";
    hc_http_request_t req;

    int rc = health_check_parse_request(raw, strlen(raw), &req);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT_STR_EQ(req.path, "/api/v1/token");
    ASSERT_EQ(req.content_length, 38);
    ASSERT_NOT_NULL(req.body);
    ASSERT_TRUE(req.body_len > 0);
    return 0;
}

static int test_parse_http_invalid(void) {
    hc_http_request_t req;
    ASSERT_EQ(health_check_parse_request(NULL, 0, &req), -1);
    ASSERT_EQ(health_check_parse_request("", 0, &req), -1);
    ASSERT_EQ(health_check_parse_request("GARBAGE", 7, &req), -1);
    ASSERT_EQ(health_check_parse_request("NOSPACE", 7, &req), -1);
    return 0;
}

static int test_parse_http_methods(void) {
    const char *raw = "DELETE /api/v1/sessions/123 HTTP/1.1\r\n"
                      "\r\n";
    hc_http_request_t req;

    int rc = health_check_parse_request(raw, strlen(raw), &req);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.method, "DELETE");
    ASSERT_STR_EQ(req.path, "/api/v1/sessions/123");
    return 0;
}

static void sleep_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static int reserve_loopback_port(uint16_t *port_out) {
    if (port_out == NULL) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    *port_out = ntohs(addr.sin_port);
    close(fd);
    return 0;
}

static int http_request(uint16_t port, const char *request, char *response, size_t response_size) {
    if (request == NULL || response == NULL || response_size == 0) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    size_t request_len = strlen(request);
    if (write(fd, request, request_len) != (ssize_t)request_len) {
        close(fd);
        return -1;
    }

    size_t total = 0;
    while (total + 1 < response_size) {
        ssize_t n = read(fd, response + total, response_size - total - 1);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    response[total] = '\0';
    close(fd);
    return (int)total;
}

static int test_health_endpoint_reports_draining_status(void) {
    TEST_START();

    uint16_t port = 0;
    ASSERT_EQ(reserve_loopback_port(&port), 0);

    atomic_bool drain_mode = true;
    health_check_config_t cfg = {
        .port = port, .bind_addr = "127.0.0.1", .drain_mode = &drain_mode};

    health_check_t *hc = health_check_start(&cfg);
    ASSERT_NOT_NULL(hc);
    sleep_ms(50);

    char response[4096];
    ASSERT_TRUE(http_request(port, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n", response,
                             sizeof(response)) > 0);
    ASSERT_TRUE(strstr(response, "503 Service Unavailable") != NULL);
    ASSERT_TRUE(strstr(response, "\"status\": \"draining\"") != NULL);
    ASSERT_TRUE(strstr(response, "\"draining\": true") != NULL);

    health_check_stop(hc);
    TEST_PASS();
}

static int test_drain_endpoint_round_trip(void) {
    TEST_START();

    uint16_t port = 0;
    ASSERT_EQ(reserve_loopback_port(&port), 0);

    atomic_bool drain_mode = false;
    health_check_config_t cfg = {.port = port,
                                 .bind_addr = "127.0.0.1",
                                 .admin_api_enabled = true,
                                 .drain_mode = &drain_mode};

    health_check_t *hc = health_check_start(&cfg);
    ASSERT_NOT_NULL(hc);
    sleep_ms(50);

    char response[4096];
    ASSERT_TRUE(http_request(port,
                             "PUT /drain HTTP/1.1\r\n"
                             "Host: localhost\r\n"
                             "Content-Type: application/json\r\n"
                             "Content-Length: 17\r\n"
                             "\r\n"
                             "{\"draining\":true}",
                             response, sizeof(response)) > 0);
    ASSERT_TRUE(strstr(response, "200 OK") != NULL);
    ASSERT_TRUE(strstr(response, "\"draining\":true") != NULL);
    ASSERT_TRUE(atomic_load(&drain_mode));

    ASSERT_TRUE(http_request(port, "GET /drain HTTP/1.1\r\nHost: localhost\r\n\r\n", response,
                             sizeof(response)) > 0);
    ASSERT_TRUE(strstr(response, "\"status\":\"draining\"") != NULL);
    ASSERT_TRUE(strstr(response, "\"active_sessions\":0") != NULL);

    health_check_stop(hc);
    TEST_PASS();
}

/* ===== Main ===== */

int main(void) {
    TEST_BEGIN("Health Check Module Tests");

    log_init(LOG_LEVEL_WARN, NULL);

    /* HMAC-SHA256 */
    RUN_TEST(test_hmac_sha256_rfc4231);
    RUN_TEST(test_hmac_sha256_empty_data);
    RUN_TEST(test_hmac_sha256_null_handling);
    RUN_TEST(test_hmac_sha256_rfc4231_case3);

    /* Token generation and validation */
    RUN_TEST(test_token_generate_validate_admin);
    RUN_TEST(test_token_generate_validate_readonly);
    RUN_TEST(test_token_generate_null_handling);

    /* Token expiry */
    RUN_TEST(test_token_expiry_expired);
    RUN_TEST(test_token_expiry_no_check);
    RUN_TEST(test_token_expiry_future);

    /* Token scope */
    RUN_TEST(test_token_scope_admin);
    RUN_TEST(test_token_scope_readonly);

    /* HMAC validation edge cases */
    RUN_TEST(test_token_wrong_secret);
    RUN_TEST(test_token_tampered);
    RUN_TEST(test_token_invalid_format);

    /* JWT generation and validation */
    RUN_TEST(test_jwt_generate_validate_admin);
    RUN_TEST(test_jwt_generate_validate_readonly);
    RUN_TEST(test_jwt_expiry);
    RUN_TEST(test_jwt_wrong_secret);
    RUN_TEST(test_jwt_tampered);
    RUN_TEST(test_jwt_invalid_format);

    /* HTTP request parsing */
    RUN_TEST(test_parse_http_get);
    RUN_TEST(test_parse_http_with_auth);
    RUN_TEST(test_parse_http_post_with_body);
    RUN_TEST(test_parse_http_invalid);
    RUN_TEST(test_parse_http_methods);
    RUN_TEST(test_health_endpoint_reports_draining_status);
    RUN_TEST(test_drain_endpoint_round_trip);

    log_shutdown();

    TEST_END();
}
