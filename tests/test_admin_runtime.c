/**
 * @file test_admin_runtime.c
 * @brief Unit tests for admin runtime wiring
 */

#include <string.h>

#include "admin_runtime.h"
#include "logger.h"
#include "test_utils.h"

static int test_admin_runtime_requires_tls(void) {
    TEST_START();

    proxy_config_t *config = config_create();
    ASSERT_NOT_NULL(config);

    config->admin_api_enabled = true;
    strncpy(config->admin_auth_token, "hmac:secret", sizeof(config->admin_auth_token) - 1);
    config->admin_token_expiry_sec = 7200;

    health_check_config_t hc_cfg = {.port = 9090, .bind_addr = "127.0.0.1"};
    admin_runtime_apply_health_config(&hc_cfg, config);

    ASSERT_FALSE(hc_cfg.admin_api_enabled);
    ASSERT_FALSE(hc_cfg.tls_enabled);
    ASSERT_STR_EQ(hc_cfg.admin_auth_token, "hmac:secret");
    ASSERT_EQ(hc_cfg.token_expiry_sec, (uint32_t)7200);

    config_destroy(config);
    TEST_PASS();
}

static int test_admin_runtime_tls_wiring(void) {
    TEST_START();

    proxy_config_t *config = config_create();
    ASSERT_NOT_NULL(config);

    config->admin_api_enabled = true;
    config->admin_tls_enabled = true;
    strncpy(config->admin_auth_token, "hmac:secret", sizeof(config->admin_auth_token) - 1);
    strncpy(config->admin_tls_cert_path, "/tmp/admin-cert.pem",
            sizeof(config->admin_tls_cert_path) - 1);
    strncpy(config->admin_tls_key_path, "/tmp/admin-key.pem",
            sizeof(config->admin_tls_key_path) - 1);

    health_check_config_t hc_cfg = {.port = 9090, .bind_addr = "127.0.0.1"};
    admin_runtime_apply_health_config(&hc_cfg, config);

#ifdef TLS_ENABLED
    ASSERT_TRUE(hc_cfg.admin_api_enabled);
    ASSERT_TRUE(hc_cfg.tls_enabled);
    ASSERT_TRUE(hc_cfg.tls_cert_path != NULL);
    ASSERT_TRUE(hc_cfg.tls_key_path != NULL);
    ASSERT_STR_EQ(hc_cfg.tls_cert_path, "/tmp/admin-cert.pem");
    ASSERT_STR_EQ(hc_cfg.tls_key_path, "/tmp/admin-key.pem");
#else
    ASSERT_FALSE(hc_cfg.admin_api_enabled);
    ASSERT_FALSE(hc_cfg.tls_enabled);
    ASSERT_NULL(hc_cfg.tls_cert_path);
    ASSERT_NULL(hc_cfg.tls_key_path);
#endif

    config_destroy(config);
    TEST_PASS();
}

static int test_admin_runtime_requires_cert_and_key(void) {
    TEST_START();

    proxy_config_t *config = config_create();
    ASSERT_NOT_NULL(config);

    config->admin_api_enabled = true;
    config->admin_tls_enabled = true;
    strncpy(config->admin_auth_token, "hmac:secret", sizeof(config->admin_auth_token) - 1);

    health_check_config_t hc_cfg = {.port = 9090, .bind_addr = "127.0.0.1"};
    admin_runtime_apply_health_config(&hc_cfg, config);

    ASSERT_FALSE(hc_cfg.admin_api_enabled);
    ASSERT_FALSE(hc_cfg.tls_enabled);

    config_destroy(config);
    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Admin Runtime Module Tests");

    RUN_TEST(test_admin_runtime_requires_tls);
    RUN_TEST(test_admin_runtime_tls_wiring);
    RUN_TEST(test_admin_runtime_requires_cert_and_key);

    log_shutdown();

    TEST_END();
}
