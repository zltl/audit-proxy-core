/**
 * @file test_proxy_handler.c
 * @brief Tests for proxy handler banner expansion and connect_result types
 */

#include "test_utils.h"
#include "proxy_handler.h"
#include "version.h"
#include <string.h>
#include <unistd.h>

/* Test backward-compatible banner_expand_vars */
static int test_banner_expand_vars_basic(void) {
    char output[512];
    banner_expand_vars("Hello {username} from {client_ip}!", output, sizeof(output),
                       "alice", "10.0.0.1");
    ASSERT_STR_EQ(output, "Hello alice from 10.0.0.1!");
    return 0;
}

static int test_banner_expand_vars_version(void) {
    char output[512];
    banner_expand_vars("v{version}", output, sizeof(output), "u", "1.2.3.4");
    char expected[64];
    snprintf(expected, sizeof(expected), "v%s", SSH_PROXY_VERSION_STRING);
    ASSERT_STR_EQ(output, expected);
    return 0;
}

static int test_banner_expand_vars_hostname(void) {
    char output[512];
    banner_expand_vars("host={hostname}", output, sizeof(output), "u", "ip");
    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);
    char expected[512];
    snprintf(expected, sizeof(expected), "host=%s", hostname);
    ASSERT_STR_EQ(output, expected);
    return 0;
}

static int test_banner_expand_vars_null_safe(void) {
    char output[512];
    banner_expand_vars("Hello {username}", output, sizeof(output), NULL, NULL);
    ASSERT_STR_EQ(output, "Hello unknown");
    return 0;
}

static int test_banner_expand_vars_null_tmpl(void) {
    char output[512] = "unchanged";
    banner_expand_vars(NULL, output, sizeof(output), "u", "ip");
    ASSERT_STR_EQ(output, "unchanged");
    return 0;
}

/* Test new banner_expand_vars_ctx */
static int test_banner_expand_vars_ctx_upstream(void) {
    char output[512];
    banner_context_t bctx = {
        .username = "bob",
        .client_ip = "192.168.1.1",
        .upstream_host = "web-server.local",
        .upstream_port = 2222,
        .upstream_user = "deploy",
        .session_id = 42
    };
    banner_expand_vars_ctx("{upstream_host}:{upstream_port} user={upstream_user}",
                           output, sizeof(output), &bctx);
    ASSERT_STR_EQ(output, "web-server.local:2222 user=deploy");
    return 0;
}

static int test_banner_expand_vars_ctx_session_id(void) {
    char output[512];
    banner_context_t bctx = {
        .username = "u",
        .client_ip = "ip",
        .upstream_host = "h",
        .upstream_port = 22,
        .upstream_user = "uu",
        .session_id = 12345
    };
    banner_expand_vars_ctx("session={session_id}", output, sizeof(output), &bctx);
    ASSERT_STR_EQ(output, "session=12345");
    return 0;
}

static int test_banner_expand_vars_ctx_all_vars(void) {
    char output[1024];
    banner_context_t bctx = {
        .username = "alice",
        .client_ip = "10.0.0.5",
        .upstream_host = "prod-01",
        .upstream_port = 443,
        .upstream_user = "root",
        .session_id = 99
    };
    banner_expand_vars_ctx(
        "User: {username}, IP: {client_ip}, Upstream: {upstream_host}:{upstream_port}, "
        "UUser: {upstream_user}, SID: {session_id}, Ver: {version}",
        output, sizeof(output), &bctx);

    /* Check substrings are present */
    TEST_ASSERT(strstr(output, "User: alice") != NULL, "username missing");
    TEST_ASSERT(strstr(output, "IP: 10.0.0.5") != NULL, "client_ip missing");
    TEST_ASSERT(strstr(output, "Upstream: prod-01:443") != NULL, "upstream missing");
    TEST_ASSERT(strstr(output, "UUser: root") != NULL, "upstream_user missing");
    TEST_ASSERT(strstr(output, "SID: 99") != NULL, "session_id missing");
    TEST_ASSERT(strstr(output, SSH_PROXY_VERSION_STRING) != NULL, "version missing");
    return 0;
}

static int test_banner_expand_vars_ctx_null_context(void) {
    char output[512];
    banner_expand_vars_ctx("{username} {upstream_host}", output, sizeof(output), NULL);
    ASSERT_STR_EQ(output, "unknown unknown");
    return 0;
}

static int test_banner_expand_vars_ctx_backwards_compat(void) {
    /* Ensure old variables still work through ctx version */
    char output_old[512];
    char output_ctx[512];
    banner_expand_vars("Hello {username} from {client_ip} v{version}",
                       output_old, sizeof(output_old), "testuser", "1.2.3.4");
    banner_context_t bctx = {
        .username = "testuser",
        .client_ip = "1.2.3.4",
        .upstream_host = NULL,
        .upstream_port = 0,
        .upstream_user = NULL,
        .session_id = 0
    };
    banner_expand_vars_ctx("Hello {username} from {client_ip} v{version}",
                           output_ctx, sizeof(output_ctx), &bctx);
    ASSERT_STR_EQ(output_old, output_ctx);
    return 0;
}

/* Test connect_result_t struct layout */
static int test_connect_result_init(void) {
    connect_result_t cr;
    memset(&cr, 0, sizeof(cr));
    ASSERT_EQ((int)cr.error, (int)UPSTREAM_ERR_NONE);
    ASSERT_EQ(cr.port, 0);
    ASSERT_EQ(cr.attempts, 0);
    ASSERT_STR_EQ(cr.stage, "");
    ASSERT_STR_EQ(cr.detail, "");
    return 0;
}

static int test_upstream_error_enum_values(void) {
    ASSERT_EQ((int)UPSTREAM_ERR_NONE, 0);
    ASSERT_NE((int)UPSTREAM_ERR_ROUTE_NOT_FOUND, 0);
    ASSERT_NE((int)UPSTREAM_ERR_CONNECT_FAILED, 0);
    ASSERT_NE((int)UPSTREAM_ERR_AUTH_ALL_FAILED, 0);
    ASSERT_NE((int)UPSTREAM_ERR_CHANNEL_OPEN, 0);
    /* All error codes should be distinct */
    ASSERT_NE((int)UPSTREAM_ERR_ROUTE_NOT_FOUND, (int)UPSTREAM_ERR_SESSION_ALLOC);
    ASSERT_NE((int)UPSTREAM_ERR_CONNECT_FAILED, (int)UPSTREAM_ERR_HOST_KEY);
    return 0;
}

/* Test banner_context_t */
static int test_banner_context_init(void) {
    banner_context_t bctx = {
        .username = "test",
        .client_ip = "127.0.0.1",
        .upstream_host = "host",
        .upstream_port = 22,
        .upstream_user = "user",
        .session_id = 1
    };
    ASSERT_STR_EQ(bctx.username, "test");
    ASSERT_EQ(bctx.upstream_port, 22);
    ASSERT_EQ(bctx.session_id, 1UL);
    return 0;
}

int main(void)
{
    TEST_BEGIN("Proxy Handler Tests");

    RUN_TEST(test_banner_expand_vars_basic);
    RUN_TEST(test_banner_expand_vars_version);
    RUN_TEST(test_banner_expand_vars_hostname);
    RUN_TEST(test_banner_expand_vars_null_safe);
    RUN_TEST(test_banner_expand_vars_null_tmpl);
    RUN_TEST(test_banner_expand_vars_ctx_upstream);
    RUN_TEST(test_banner_expand_vars_ctx_session_id);
    RUN_TEST(test_banner_expand_vars_ctx_all_vars);
    RUN_TEST(test_banner_expand_vars_ctx_null_context);
    RUN_TEST(test_banner_expand_vars_ctx_backwards_compat);
    RUN_TEST(test_connect_result_init);
    RUN_TEST(test_upstream_error_enum_values);
    RUN_TEST(test_banner_context_init);

    TEST_END();
}
