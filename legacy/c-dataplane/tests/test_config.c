/**
 * @file test_config.c
 * @brief Unit tests for configuration module
 */

#include "config.h"
#include "audit_sign.h"
#include "logger.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_CONFIG_PATH "/tmp/test_ssh_proxy.conf"
#define TEST_CA_KEYS_PATH "/tmp/test_trusted_user_ca_keys.pub"
#define TEST_MASTER_KEY_PATH "/tmp/test_master_key.hex"
#define TEST_GEOIP_PATH "/tmp/test_geoip.json"
#define TEST_MASTER_KEY_HEX "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#define TEST_AUDIT_KEY_HEX "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

static const char *kFixtureTrustedUserCA =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDbtnhwX0ejxhvKPjjivt+EnAILdLWeQYDXoXd7O0rzQ";
static const char *kFixtureOtherUserCA =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPyC5TEOvesubC86/XAjgNmINIihvvYG+AFI++WkcMBy";

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test)                                                                             \
    do {                                                                                           \
        printf("Running %s...\n", #test);                                                          \
        tests_run++;                                                                               \
        if (test()) {                                                                              \
            printf("  PASS\n");                                                                    \
            tests_passed++;                                                                        \
        } else {                                                                                   \
            printf("  FAIL\n");                                                                    \
        }                                                                                          \
    } while (0)

/* Helper: create test config file */
static int create_test_config(const char *content) {
    FILE *fp = fopen(TEST_CONFIG_PATH, "w");
    if (fp == NULL)
        return -1;
    fprintf(fp, "%s", content);
    fclose(fp);
    return 0;
}

static int create_test_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    fprintf(fp, "%s", content);
    fclose(fp);
    return 0;
}

static time_t make_utc_time(int year, int month, int day, int hour, int minute, int second) {
    struct tm tm_value;

    memset(&tm_value, 0, sizeof(tm_value));
    tm_value.tm_year = year - 1900;
    tm_value.tm_mon = month - 1;
    tm_value.tm_mday = day;
    tm_value.tm_hour = hour;
    tm_value.tm_min = minute;
    tm_value.tm_sec = second;
    return timegm(&tm_value);
}

static char *encrypt_secret_for_test(const char *hex_key, const char *plaintext, uint8_t nonce_seed) {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char nonce_hex[sizeof(nonce) * 2 + 1];
    char tag_hex[sizeof(tag) * 2 + 1];
    char *ciphertext_hex = NULL;
    char *out = NULL;
    size_t plaintext_len = 0;
    int key_len = 0;
    int out_len = 0;
    int final_len = 0;
    int written = 0;

    memset(nonce, 0, sizeof(nonce));
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(nonce_seed + (uint8_t)i);
    }

    key_len = hex_decode(hex_key, key, sizeof(key));
    if (key_len != 32) {
        return NULL;
    }

    plaintext_len = strlen(plaintext);
    ciphertext = calloc(plaintext_len > 0 ? plaintext_len : 1, 1);
    if (ciphertext == NULL) {
        explicit_bzero(key, sizeof(key));
        return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        (plaintext_len > 0 &&
         EVP_EncryptUpdate(ctx, ciphertext, &out_len, (const unsigned char *)plaintext,
                           (int)plaintext_len) != 1) ||
        EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(key, sizeof(key));
        explicit_bzero(ciphertext, plaintext_len > 0 ? plaintext_len : 1);
        free(ciphertext);
        return NULL;
    }

    hex_encode(nonce, sizeof(nonce), nonce_hex);
    hex_encode(tag, sizeof(tag), tag_hex);
    ciphertext_hex = calloc((size_t)(out_len + final_len) * 2 + 1, 1);
    if (ciphertext_hex == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(key, sizeof(key));
        explicit_bzero(ciphertext, plaintext_len > 0 ? plaintext_len : 1);
        free(ciphertext);
        return NULL;
    }
    hex_encode(ciphertext, (size_t)(out_len + final_len), ciphertext_hex);

    written = snprintf(NULL, 0, "enc:v1:%s:%s:%s", nonce_hex, ciphertext_hex, tag_hex);
    out = calloc((size_t)written + 1, 1);
    if (out != NULL) {
        snprintf(out, (size_t)written + 1, "enc:v1:%s:%s:%s", nonce_hex, ciphertext_hex, tag_hex);
    }

    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(key, sizeof(key));
    explicit_bzero(ciphertext, plaintext_len > 0 ? plaintext_len : 1);
    free(ciphertext);
    explicit_bzero(ciphertext_hex, (size_t)(out_len + final_len) * 2 + 1);
    free(ciphertext_hex);
    return out;
}

static int result_list_contains_message(const config_valid_result_t *results, const char *needle) {
    while (results != NULL) {
        if (strstr(results->message, needle) != NULL) {
            return 1;
        }
        results = results->next;
    }
    return 0;
}

/* Test: config_create */
static int test_config_create(void) {
    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;

    /* Check defaults */
    if (strcmp(config->bind_addr, "0.0.0.0") != 0) {
        config_destroy(config);
        return 0;
    }
    if (config->port != 2222) {
        config_destroy(config);
        return 0;
    }
    if (config->max_sessions != 1000) {
        config_destroy(config);
        return 0;
    }
    if (config->audit_max_file_size != 0) {
        config_destroy(config);
        return 0;
    }
    if (config->audit_max_archived_files != 0 || config->audit_retention_days != 0) {
        config_destroy(config);
        return 0;
    }
    if (strcmp(config->webhook.dead_letter_path,
               "/tmp/ssh_proxy_audit/webhook-dlq.jsonl") != 0) {
        config_destroy(config);
        return 0;
    }
    if (config->router_retry_max != 3 || config->router_retry_initial_delay_ms != 100 ||
        config->router_retry_max_delay_ms != 5000 ||
        config->router_retry_backoff_factor != 2.0f || config->router_pool_enabled ||
        config->router_pool_max_idle != 10 || config->router_pool_max_idle_time_sec != 300 ||
        !config->router_circuit_breaker_enabled ||
        config->router_circuit_breaker_failure_threshold != 3 ||
        config->router_circuit_breaker_open_seconds != 30) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

/* Test: config loads audit rotation settings */
static int test_config_load_logging(void) {
    const char *content = "[logging]\n"
                          "level = warn\n"
                          "audit_dir = /tmp/custom_audit\n"
                          "audit_max_file_size = 4096\n"
                          "audit_max_archived_files = 7\n"
                          "audit_retention_days = 30\n"
                          "audit_encryption_key = "
                          "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (config->log_level != 2 || strcmp(config->audit_log_dir, "/tmp/custom_audit") != 0 ||
        config->audit_max_file_size != 4096 || config->audit_max_archived_files != 7 ||
        config->audit_retention_days != 30 || config->audit_encryption_key == NULL ||
        strcmp(config->webhook.dead_letter_path, "/tmp/custom_audit/webhook-dlq.jsonl") != 0 ||
        strcmp(config->audit_encryption_key,
               "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_validate_invalid_audit_encryption_key(void) {
    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;

    config->audit_encryption_key = strdup("deadbeef");
    if (config->audit_encryption_key == NULL) {
        config_destroy(config);
        return 0;
    }

    config_valid_result_t *results = config_validate(config, NULL);
    int ok = result_list_contains_message(
        results, "logging.audit_encryption_key must be a 64-character hex AES-256 key");
    config_valid_free(results);
    config_destroy(config);
    return ok ? 1 : 0;
}

/* Test: config loads admin API settings */
static int test_config_load_admin(void) {
    const char *content = "[admin]\n"
                          "enabled = true\n"
                          "auth_token = hmac:supersecret\n"
                          "token_expiry = 7200\n"
                          "tls_enabled = true\n"
                          "tls_cert = /etc/ssh-proxy/cert.pem\n"
                          "tls_key = /etc/ssh-proxy/key.pem\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (!config->admin_api_enabled || strcmp(config->admin_auth_token, "hmac:supersecret") != 0 ||
        config->admin_token_expiry_sec != 7200 || !config->admin_tls_enabled ||
        strcmp(config->admin_tls_cert_path, "/etc/ssh-proxy/cert.pem") != 0 ||
        strcmp(config->admin_tls_key_path, "/etc/ssh-proxy/key.pem") != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_add_user */
static int test_config_add_user(void) {
    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;

    /* Add user */
    int rc = config_add_user(config, "testuser", "$6$salt$hash", "ssh-rsa AAAA...");
    if (rc != 0) {
        config_destroy(config);
        return 0;
    }

    /* Find user */
    config_user_t *user = config_find_user(config, "testuser");
    if (user == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(user->username, "testuser") != 0) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(user->password_hash, "$6$salt$hash") != 0) {
        config_destroy(config);
        return 0;
    }

    if (user->pubkeys == NULL || strcmp(user->pubkeys, "ssh-rsa AAAA...") != 0) {
        config_destroy(config);
        return 0;
    }

    if (user->password_changed_at_set || user->password_change_required) {
        config_destroy(config);
        return 0;
    }

    /* User not found */
    if (config_find_user(config, "nonexistent") != NULL) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

/* Test: config_load with server section */
static int test_config_load_server(void) {
    const char *content = "[server]\n"
                          "bind_addr = 127.0.0.1\n"
                          "port = 3333\n"
                          "host_key = /custom/host/key\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (strcmp(config->bind_addr, "127.0.0.1") != 0) {
        config_destroy(config);
        return 0;
    }

    if (config->port != 3333) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(config->host_key_path, "/custom/host/key") != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_load with users */
static int test_config_load_users(void) {
    const char *content = "[user:alice]\n"
                          "password_hash = $6$salt$alicehash\n"
                          "password_changed_at = 1710000000\n"
                          "pubkey = ssh-rsa AAAA... alice@example.com\n"
                          "enabled = true\n"
                          "\n"
                          "[user:bob]\n"
                          "password_hash = $6$salt$bobhash\n"
                          "password_change_required = true\n"
                          "enabled = false\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    /* Find alice */
    config_user_t *alice = config_find_user(config, "alice");
    if (alice == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(alice->password_hash, "$6$salt$alicehash") != 0) {
        config_destroy(config);
        return 0;
    }

    if (alice->pubkeys == NULL || strstr(alice->pubkeys, "ssh-rsa") == NULL) {
        config_destroy(config);
        return 0;
    }

    if (!alice->password_changed_at_set || alice->password_changed_at != (time_t)1710000000) {
        config_destroy(config);
        return 0;
    }

    /* Bob is disabled, should not be found */
    if (config_find_user(config, "bob") != NULL) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config loads password expiry and forced rotation settings */
static int test_config_load_password_rotation(void) {
    const char *content = "[security]\n"
                          "password_max_age_days = 30\n"
                          "\n"
                          "[user:alice]\n"
                          "password_hash = $6$salt$alicehash\n"
                          "password_changed_at = 1710000000\n"
                          "password_change_required = true\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (config->password_policy.max_age_days != 30) {
        config_destroy(config);
        return 0;
    }

    config_user_t *alice = config_find_user(config, "alice");
    if (alice == NULL) {
        config_destroy(config);
        return 0;
    }

    if (!alice->password_changed_at_set || alice->password_changed_at != (time_t)1710000000 ||
        !alice->password_change_required) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_load with comments and empty lines */
static int test_config_load_comments(void) {
    const char *content = "# This is a comment\n"
                          "\n"
                          "[server]\n"
                          "# Another comment\n"
                          "port = 4444\n"
                          "; Semicolon comment\n"
                          "bind_addr = 0.0.0.0\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (config->port != 4444) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_load with quoted values */
static int test_config_load_quoted(void) {
    const char *content = "[server]\n"
                          "bind_addr = \"127.0.0.1\"\n"
                          "host_key = '/path/with spaces/key'\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (strcmp(config->bind_addr, "127.0.0.1") != 0) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(config->host_key_path, "/path/with spaces/key") != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_reload */
static int test_config_reload(void) {
    const char *content1 = "[server]\n"
                           "port = 1111\n";

    const char *content2 = "[server]\n"
                           "port = 2222\n";

    if (create_test_config(content1) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (config->port != 1111) {
        config_destroy(config);
        return 0;
    }

    /* Update config file */
    if (create_test_config(content2) != 0) {
        config_destroy(config);
        return 0;
    }

    /* Reload */
    if (config_reload(config, TEST_CONFIG_PATH) != 0) {
        config_destroy(config);
        return 0;
    }

    if (config->port != 2222) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_load_encrypted_sensitive_values(void) {
    char *enc_password = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "$6$salt$alicehash", 1);
    char *enc_token = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "hmac:supersecret", 2);
    char *enc_hmac = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "signing-secret", 3);
    char *enc_audit_key = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, TEST_AUDIT_KEY_HEX, 4);
    char content[8192];

    if (enc_password == NULL || enc_token == NULL || enc_hmac == NULL || enc_audit_key == NULL) {
        free(enc_password);
        free(enc_token);
        free(enc_hmac);
        free(enc_audit_key);
        return 0;
    }

    snprintf(content, sizeof(content),
             "[user:alice]\n"
             "password_hash = %s\n"
             "enabled = true\n"
             "\n"
             "[admin]\n"
             "enabled = true\n"
             "auth_token = %s\n"
             "\n"
             "[webhook]\n"
             "enabled = true\n"
             "url = https://hooks.example.com/ssh-events\n"
             "hmac_secret = %s\n"
             "\n"
             "[logging]\n"
             "audit_encryption_key = %s\n"
             "\n"
             "[security]\n"
             "master_key = %s\n",
             enc_password, enc_token, enc_hmac, enc_audit_key, TEST_MASTER_KEY_HEX);

    if (create_test_config(content) != 0) {
        free(enc_password);
        free(enc_token);
        free(enc_hmac);
        free(enc_audit_key);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CONFIG_PATH);
        free(enc_password);
        free(enc_token);
        free(enc_hmac);
        free(enc_audit_key);
        return 0;
    }

    config_user_t *user = config_find_user(config, "alice");
    if (user == NULL || strcmp(user->password_hash, "$6$salt$alicehash") != 0 ||
        !user->password_hash_is_indirect ||
        strcmp(config->admin_auth_token, "hmac:supersecret") != 0 ||
        !config->admin_auth_token_is_indirect ||
        strcmp(config->webhook.hmac_secret, "signing-secret") != 0 ||
        !config->webhook_hmac_secret_is_indirect ||
        config->audit_encryption_key == NULL ||
        strcmp(config->audit_encryption_key, TEST_AUDIT_KEY_HEX) != 0 ||
        !config->audit_encryption_key_is_indirect) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        free(enc_password);
        free(enc_token);
        free(enc_hmac);
        free(enc_audit_key);
        return 0;
    }

    config_valid_result_t *results = config_validate(config, NULL);
    if (result_list_contains_message(results, "password_hash appears to be plaintext") ||
        result_list_contains_message(results, "admin.auth_token appears to be plaintext") ||
        result_list_contains_message(results, "webhook.hmac_secret appears to be plaintext") ||
        result_list_contains_message(results, "logging.audit_encryption_key appears to be plaintext")) {
        config_valid_free(results);
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        free(enc_password);
        free(enc_token);
        free(enc_hmac);
        free(enc_audit_key);
        return 0;
    }

    config_valid_free(results);
    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    free(enc_password);
    free(enc_token);
    free(enc_hmac);
    free(enc_audit_key);
    return 1;
}

static int test_config_load_encrypted_values_with_master_key_file(void) {
    char *enc_password = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "$6$salt$alicehash", 5);
    char content[4096];

    if (enc_password == NULL) {
        return 0;
    }
    if (create_test_file(TEST_MASTER_KEY_PATH, TEST_MASTER_KEY_HEX) != 0) {
        free(enc_password);
        return 0;
    }

    snprintf(content, sizeof(content),
             "[security]\n"
             "master_key_file = %s\n"
             "\n"
             "[user:alice]\n"
             "password_hash = %s\n"
             "enabled = true\n",
             TEST_MASTER_KEY_PATH, enc_password);

    if (create_test_config(content) != 0) {
        unlink(TEST_MASTER_KEY_PATH);
        free(enc_password);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CONFIG_PATH);
        unlink(TEST_MASTER_KEY_PATH);
        free(enc_password);
        return 0;
    }

    config_user_t *user = config_find_user(config, "alice");
    int ok = user != NULL && strcmp(user->password_hash, "$6$salt$alicehash") == 0 &&
             user->password_hash_is_indirect;

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    unlink(TEST_MASTER_KEY_PATH);
    free(enc_password);
    return ok ? 1 : 0;
}

static int test_config_rejects_encrypted_value_without_master_key(void) {
    char *enc_password = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "$6$salt$alicehash", 6);
    char content[2048];

    if (enc_password == NULL) {
        return 0;
    }
    snprintf(content, sizeof(content),
             "[user:alice]\n"
             "password_hash = %s\n"
             "enabled = true\n",
             enc_password);

    if (create_test_config(content) != 0) {
        free(enc_password);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    free(enc_password);
    unlink(TEST_CONFIG_PATH);
    if (config != NULL) {
        config_destroy(config);
        return 0;
    }
    return 1;
}

static int test_config_reload_updates_encrypted_sensitive_values(void) {
    char *enc_new_token = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, "hmac:new-secret", 7);
    char *enc_new_audit = encrypt_secret_for_test(TEST_MASTER_KEY_HEX, TEST_AUDIT_KEY_HEX, 8);
    char content1[4096];
    char content2[4096];

    if (enc_new_token == NULL || enc_new_audit == NULL) {
        free(enc_new_token);
        free(enc_new_audit);
        return 0;
    }

    snprintf(content1, sizeof(content1),
             "[server]\n"
             "port = 1111\n"
             "\n"
             "[admin]\n"
             "auth_token = hmac:old-secret\n"
             "\n"
             "[logging]\n"
             "audit_max_file_size = 128\n");

    snprintf(content2, sizeof(content2),
             "[server]\n"
             "port = 2222\n"
             "\n"
             "[admin]\n"
             "auth_token = %s\n"
             "\n"
             "[logging]\n"
             "audit_max_file_size = 256\n"
             "audit_encryption_key = %s\n"
             "\n"
             "[security]\n"
             "master_key = %s\n",
             enc_new_token, enc_new_audit, TEST_MASTER_KEY_HEX);

    if (create_test_config(content1) != 0) {
        free(enc_new_token);
        free(enc_new_audit);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CONFIG_PATH);
        free(enc_new_token);
        free(enc_new_audit);
        return 0;
    }

    if (create_test_config(content2) != 0 || config_reload(config, TEST_CONFIG_PATH) != 0) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        free(enc_new_token);
        free(enc_new_audit);
        return 0;
    }

    if (config->port != 2222 || strcmp(config->admin_auth_token, "hmac:new-secret") != 0 ||
        !config->admin_auth_token_is_indirect || config->audit_max_file_size != 256 ||
        config->audit_encryption_key == NULL ||
        strcmp(config->audit_encryption_key, TEST_AUDIT_KEY_HEX) != 0 ||
        !config->audit_encryption_key_is_indirect) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        free(enc_new_token);
        free(enc_new_audit);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    free(enc_new_token);
    free(enc_new_audit);
    return 1;
}

/* Test: null handling */
static int test_config_null_handling(void) {
    /* config_load with NULL */
    if (config_load(NULL) != NULL)
        return 0;

    /* config_load with non-existent file */
    if (config_load("/nonexistent/path/config.ini") != NULL)
        return 0;

    /* config_add_user with NULL */
    if (config_add_user(NULL, "user", "hash", NULL) != -1)
        return 0;

    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;

    if (config_add_user(config, NULL, "hash", NULL) != -1) {
        config_destroy(config);
        return 0;
    }

    /* config_find_user with NULL */
    if (config_find_user(NULL, "user") != NULL) {
        config_destroy(config);
        return 0;
    }

    if (config_find_user(config, NULL) != NULL) {
        config_destroy(config);
        return 0;
    }

    /* config_add_route with NULL */
    if (config_add_route(NULL, "user", "host", 22, "user", "/key") != -1) {
        config_destroy(config);
        return 0;
    }

    if (config_add_route(config, NULL, "host", 22, "user", "/key") != -1) {
        config_destroy(config);
        return 0;
    }

    if (config_add_route(config, "user", NULL, 22, "user", "/key") != -1) {
        config_destroy(config);
        return 0;
    }

    /* config_find_route with NULL */
    if (config_find_route(NULL, "user") != NULL) {
        config_destroy(config);
        return 0;
    }

    if (config_find_route(config, NULL) != NULL) {
        config_destroy(config);
        return 0;
    }

    /* config_destroy with NULL */
    config_destroy(NULL); /* Should not crash */

    config_destroy(config);
    return 1;
}

/* Test: config_add_route and config_find_route */
static int test_config_routes(void) {
    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;

    /* Add route */
    int rc = config_add_route(config, "admin", "prod.example.com", 22, "root", "/keys/admin.key");
    if (rc != 0) {
        config_destroy(config);
        return 0;
    }

    /* Add wildcard route */
    rc = config_add_route(config, "dev-*", "dev.example.com", 22, "developer", NULL);
    if (rc != 0) {
        config_destroy(config);
        return 0;
    }

    /* Find exact match */
    config_route_t *route = config_find_route(config, "admin");
    if (route == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_host, "prod.example.com") != 0) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_user, "root") != 0) {
        config_destroy(config);
        return 0;
    }

    /* Find wildcard match */
    route = config_find_route(config, "dev-alice");
    if (route == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_host, "dev.example.com") != 0) {
        config_destroy(config);
        return 0;
    }

    /* No match */
    route = config_find_route(config, "unknown-user");
    if (route != NULL) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

/* Test: config_load with routes */
static int test_config_load_routes(void) {
    const char *content = "[route:admin]\n"
                          "upstream = prod.example.com\n"
                          "port = 22\n"
                          "user = root\n"
                          "privkey = /keys/admin.key\n"
                          "enabled = true\n"
                          "\n"
                          "[route:dev-*]\n"
                          "host = dev.example.com\n"
                          "upstream_user = developer\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    /* Find admin route */
    config_route_t *route = config_find_route(config, "admin");
    if (route == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_host, "prod.example.com") != 0) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_user, "root") != 0) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->privkey_path, "/keys/admin.key") != 0) {
        config_destroy(config);
        return 0;
    }

    /* Find dev-alice (wildcard) */
    route = config_find_route(config, "dev-alice");
    if (route == NULL) {
        config_destroy(config);
        return 0;
    }

    if (strcmp(route->upstream_host, "dev.example.com") != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_find_route_for_client_geo_routing(void) {
    const char *geoip_content =
        "[\n"
        "  {\"cidr\":\"203.0.113.0/24\",\"country_code\":\"US\",\"country\":\"United States\",\"region\":\"California\",\"city\":\"San Francisco\",\"latitude\":37.7749,\"longitude\":-122.4194},\n"
        "  {\"cidr\":\"198.51.100.0/24\",\"country_code\":\"DE\",\"country\":\"Germany\",\"region\":\"Hesse\",\"city\":\"Frankfurt\",\"latitude\":50.1109,\"longitude\":8.6821}\n"
        "]\n";
    const char *content =
        "[network_sources]\n"
        "geoip_data_file = " TEST_GEOIP_PATH "\n"
        "\n"
        "[route:alice]\n"
        "upstream = sfo.example.com\n"
        "user = ubuntu\n"
        "country_code = US\n"
        "region = California\n"
        "city = San Francisco\n"
        "latitude = 37.7749\n"
        "longitude = -122.4194\n"
        "\n"
        "[route:alice]\n"
        "upstream = fra.example.com\n"
        "user = ubuntu\n"
        "country_code = DE\n"
        "region = Hesse\n"
        "city = Frankfurt\n"
        "latitude = 50.1109\n"
        "longitude = 8.6821\n";

    if (create_test_file(TEST_GEOIP_PATH, geoip_content) != 0 || create_test_config(content) != 0) {
        unlink(TEST_GEOIP_PATH);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_GEOIP_PATH);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    config_route_t *route = config_find_route_for_client(config, "alice", "203.0.113.55");
    if (route == NULL || strcmp(route->upstream_host, "sfo.example.com") != 0 ||
        strcmp(route->geo_city, "San Francisco") != 0 || !route->geo_has_coordinates) {
        config_destroy(config);
        unlink(TEST_GEOIP_PATH);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    route = config_find_route_for_client(config, "alice", "198.51.100.42");
    if (route == NULL || strcmp(route->upstream_host, "fra.example.com") != 0 ||
        strcmp(route->geo_region, "Hesse") != 0) {
        config_destroy(config);
        unlink(TEST_GEOIP_PATH);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    route = config_find_route(config, "alice");
    config_route_t *sticky_route = config_find_route(config, "alice");
    if (route == NULL || sticky_route == NULL ||
        strcmp(route->upstream_host, sticky_route->upstream_host) != 0) {
        config_destroy(config);
        unlink(TEST_GEOIP_PATH);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_GEOIP_PATH);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_find_route_connection_affinity(void) {
    proxy_config_t *config = config_create();
    const char *users[] = {"alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi"};
    const char *distinct_hosts[8];
    size_t distinct_count = 0;

    if (config == NULL) {
        return 0;
    }
    if (config_add_route(config, "*", "node-a.example.com", 22, "ubuntu", NULL) != 0 ||
        config_add_route(config, "*", "node-b.example.com", 22, "ubuntu", NULL) != 0 ||
        config_add_route(config, "*", "node-c.example.com", 22, "ubuntu", NULL) != 0) {
        config_destroy(config);
        return 0;
    }

    config_route_t *alice_route = config_find_route(config, "alice");
    if (alice_route == NULL) {
        config_destroy(config);
        return 0;
    }
    for (int i = 0; i < 8; i++) {
        config_route_t *route = config_find_route(config, "alice");
        if (route == NULL || strcmp(route->upstream_host, alice_route->upstream_host) != 0) {
            config_destroy(config);
            return 0;
        }
    }

    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        config_route_t *route = config_find_route(config, users[i]);
        bool seen = false;
        if (route == NULL) {
            config_destroy(config);
            return 0;
        }
        for (size_t j = 0; j < distinct_count; j++) {
            if (strcmp(distinct_hosts[j], route->upstream_host) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            distinct_hosts[distinct_count++] = route->upstream_host;
        }
    }

    config_destroy(config);
    return distinct_count >= 2;
}

static int test_config_load_router_circuit_breaker_settings(void) {
    const char *content =
        "[router]\n"
        "retry_max = 5\n"
        "retry_initial_delay_ms = 250\n"
        "retry_max_delay_ms = 4000\n"
        "retry_backoff_factor = 1.5\n"
        "pool_enabled = true\n"
        "pool_max_idle = 12\n"
        "pool_max_idle_time = 45\n"
        "circuit_breaker_enabled = false\n"
        "circuit_breaker_failure_threshold = 7\n"
        "circuit_breaker_open_seconds = 90\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    if (config->router_retry_max != 5 || config->router_retry_initial_delay_ms != 250 ||
        config->router_retry_max_delay_ms != 4000 ||
        config->router_retry_backoff_factor != 1.5f || !config->router_pool_enabled ||
        config->router_pool_max_idle != 12 || config->router_pool_max_idle_time_sec != 45 ||
        config->router_circuit_breaker_enabled ||
        config->router_circuit_breaker_failure_threshold != 7 ||
        config->router_circuit_breaker_open_seconds != 90) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_route_circuit_breaker_state_machine(void) {
    proxy_config_t *config = config_create();
    config_route_t *route = NULL;
    bool half_open_probe = false;
    time_t now = make_utc_time(2024, 6, 1, 8, 0, 0);

    if (config == NULL) {
        return 0;
    }
    config->router_circuit_breaker_enabled = true;
    config->router_circuit_breaker_failure_threshold = 2;
    config->router_circuit_breaker_open_seconds = 30;
    if (config_add_route(config, "alice", "node-a.example.com", 22, "ubuntu", NULL) != 0) {
        config_destroy(config);
        return 0;
    }

    route = config->routes;
    if (route == NULL || !config_route_circuit_try_acquire(config, route, now, &half_open_probe) ||
        half_open_probe) {
        config_destroy(config);
        return 0;
    }
    if (config_route_circuit_record_failure(config, route, now) ||
        config_route_circuit_state(config, route, now) != CONFIG_ROUTE_CIRCUIT_CLOSED) {
        config_destroy(config);
        return 0;
    }
    if (!config_route_circuit_try_acquire(config, route, now, &half_open_probe) ||
        half_open_probe || !config_route_circuit_record_failure(config, route, now) ||
        config_route_circuit_state(config, route, now) != CONFIG_ROUTE_CIRCUIT_OPEN) {
        config_destroy(config);
        return 0;
    }
    if (config_route_circuit_try_acquire(config, route, now + 10, &half_open_probe)) {
        config_destroy(config);
        return 0;
    }
    if (!config_route_circuit_try_acquire(config, route, now + 31, &half_open_probe) ||
        !half_open_probe ||
        config_route_circuit_state(config, route, now + 31) != CONFIG_ROUTE_CIRCUIT_HALF_OPEN) {
        config_destroy(config);
        return 0;
    }

    config_route_circuit_release_probe(route);
    if (!config_route_circuit_try_acquire(config, route, now + 31, &half_open_probe) ||
        !half_open_probe) {
        config_destroy(config);
        return 0;
    }
    config_route_circuit_record_success(route);
    if (config_route_circuit_state(config, route, now + 31) != CONFIG_ROUTE_CIRCUIT_CLOSED) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

static int test_config_find_route_skips_open_circuit_candidate(void) {
    proxy_config_t *config = config_create();
    config_route_t *primary = NULL;
    config_route_t *fallback = NULL;
    time_t now = time(NULL);

    if (config == NULL) {
        return 0;
    }
    config->router_circuit_breaker_enabled = true;
    config->router_circuit_breaker_failure_threshold = 1;
    config->router_circuit_breaker_open_seconds = 60;
    if (config_add_route(config, "*", "node-a.example.com", 22, "ubuntu", NULL) != 0 ||
        config_add_route(config, "*", "node-b.example.com", 22, "ubuntu", NULL) != 0) {
        config_destroy(config);
        return 0;
    }

    primary = config_find_route(config, "alice");
    if (primary == NULL || !config_route_circuit_record_failure(config, primary, now)) {
        config_destroy(config);
        return 0;
    }

    fallback = config_find_route(config, "alice");
    if (fallback == NULL || strcmp(fallback->upstream_host, primary->upstream_host) == 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

static int test_config_load_rejects_partial_route_geo_coordinates(void) {
    const char *content =
        "[route:alice]\n"
        "upstream = prod.example.com\n"
        "latitude = 37.7749\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config != NULL) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_load_policy_login_window(void) {
    const char *content = "[policy:alice@prod.example.com]\n"
                          "allow = shell, exec\n"
                          "login_window = 09:00-18:00\n"
                          "login_days = mon-fri\n"
                          "login_timezone = +08:00\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        return 0;
    }

    config_policy_t *policy = config_find_policy(config, "alice", "prod.example.com");
    if (policy == NULL || !policy->login_window_enabled ||
        policy->login_days_mask != (CONFIG_POLICY_DAY_MON | CONFIG_POLICY_DAY_TUE |
                                    CONFIG_POLICY_DAY_WED | CONFIG_POLICY_DAY_THU |
                                    CONFIG_POLICY_DAY_FRI) ||
        policy->login_window_start_minute != (9 * 60) ||
        policy->login_window_end_minute != (18 * 60) ||
        policy->login_timezone_offset_minutes != (8 * 60)) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_policy_allows_connection_by_time_window(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return 0;
    }
    if (config_add_policy(config, "alice", "prod.example.com", 0xFFFFFFFF, 0) != 0) {
        config_destroy(config);
        return 0;
    }

    config_policy_t *policy = config_find_policy(config, "alice", "prod.example.com");
    if (policy == NULL) {
        config_destroy(config);
        return 0;
    }

    policy->login_window_enabled = true;
    policy->login_days_mask = CONFIG_POLICY_DAY_MON | CONFIG_POLICY_DAY_TUE |
                              CONFIG_POLICY_DAY_WED | CONFIG_POLICY_DAY_THU |
                              CONFIG_POLICY_DAY_FRI;
    policy->login_window_start_minute = 9 * 60;
    policy->login_window_end_minute = 18 * 60;
    policy->login_timezone_offset_minutes = 8 * 60;

    char reason[256];
    if (!config_policy_allows_connection(config, "alice", "prod.example.com", "203.0.113.10",
                                         make_utc_time(2024, 1, 8, 2, 30, 0), reason,
                                         sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (config_policy_allows_connection(config, "alice", "prod.example.com", "203.0.113.10",
                                        make_utc_time(2024, 1, 8, 11, 30, 0), reason,
                                        sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (strstr(reason, "outside login window") == NULL) {
        config_destroy(config);
        return 0;
    }
    if (config_policy_allows_connection(config, "alice", "prod.example.com", "203.0.113.10",
                                        make_utc_time(2024, 1, 13, 2, 30, 0), reason,
                                        sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (!config_policy_allows_connection(config, "alice", "other.example.com", "203.0.113.10",
                                         make_utc_time(2024, 1, 13, 2, 30, 0), reason,
                                         sizeof(reason))) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

static int test_config_policy_allows_connection_overnight_window(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return 0;
    }
    if (config_add_policy(config, "alice", "prod.example.com", 0xFFFFFFFF, 0) != 0) {
        config_destroy(config);
        return 0;
    }

    config_policy_t *policy = config_find_policy(config, "alice", "prod.example.com");
    if (policy == NULL) {
        config_destroy(config);
        return 0;
    }

    policy->login_window_enabled = true;
    policy->login_days_mask = CONFIG_POLICY_DAY_FRI;
    policy->login_window_start_minute = 22 * 60;
    policy->login_window_end_minute = 2 * 60;
    policy->login_timezone_offset_minutes = 0;

    char reason[256];
    if (!config_policy_allows_connection(config, "alice", "prod.example.com", "203.0.113.10",
                                         make_utc_time(2024, 1, 13, 1, 0, 0), reason,
                                         sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (config_policy_allows_connection(config, "alice", "prod.example.com", "203.0.113.10",
                                        make_utc_time(2024, 1, 13, 3, 0, 0), reason,
                                        sizeof(reason))) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

static int test_config_load_network_source_policy(void) {
    const char *content = "[network_sources]\n"
                          "office_cidrs = 10.0.0.0/8\n"
                          "vpn_cidrs = 100.64.0.0/10\n"
                          "\n"
                          "[policy:alice]\n"
                          "allowed_source_types = office, vpn\n"
                          "denied_source_types = public\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        return 0;
    }

    config_policy_t *policy = config_find_policy(config, "alice", NULL);
    if (policy == NULL || config->office_source_cidrs == NULL ||
        strcmp(config->office_source_cidrs, "10.0.0.0/8") != 0 ||
        config->vpn_source_cidrs == NULL ||
        strcmp(config->vpn_source_cidrs, "100.64.0.0/10") != 0 ||
        policy->allowed_source_types != (CONFIG_POLICY_SOURCE_OFFICE | CONFIG_POLICY_SOURCE_VPN) ||
        policy->denied_source_types != CONFIG_POLICY_SOURCE_PUBLIC) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_policy_allows_connection_by_source_type(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return 0;
    }
    config->office_source_cidrs = strdup("10.0.0.0/8,2001:db8::/32");
    config->vpn_source_cidrs = strdup("100.64.0.0/10");
    if (config->office_source_cidrs == NULL || config->vpn_source_cidrs == NULL ||
        config_add_policy(config, "alice", NULL, 0xFFFFFFFF, 0) != 0) {
        config_destroy(config);
        return 0;
    }

    config_policy_t *policy = config_find_policy(config, "alice", NULL);
    if (policy == NULL) {
        config_destroy(config);
        return 0;
    }
    policy->allowed_source_types = CONFIG_POLICY_SOURCE_OFFICE | CONFIG_POLICY_SOURCE_VPN;
    policy->denied_source_types = CONFIG_POLICY_SOURCE_PUBLIC;

    char reason[256];
    if (!config_policy_allows_connection(config, "alice", NULL, "10.1.2.3", (time_t)0, reason,
                                         sizeof(reason)) ||
        !config_policy_allows_connection(config, "alice", NULL, "100.64.1.2", (time_t)0, reason,
                                         sizeof(reason)) ||
        !config_policy_allows_connection(config, "alice", NULL, "2001:db8::1", (time_t)0, reason,
                                         sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (config_policy_allows_connection(config, "alice", NULL, "203.0.113.10", (time_t)0, reason,
                                        sizeof(reason))) {
        config_destroy(config);
        return 0;
    }
    if (strstr(reason, "public") == NULL) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    return 1;
}

static int test_config_rejects_invalid_network_source_policy(void) {
    const char *content = "[network_sources]\n"
                          "office_cidrs = not-a-cidr\n"
                          "\n"
                          "[policy:alice]\n"
                          "allowed_source_types = office\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    unlink(TEST_CONFIG_PATH);
    if (config != NULL) {
        config_destroy(config);
        return 0;
    }
    return 1;
}

static int test_config_rejects_invalid_policy_login_window(void) {
    const char *content = "[policy:alice]\n"
                          "login_window = 09:00-09:00\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    unlink(TEST_CONFIG_PATH);
    if (config != NULL) {
        config_destroy(config);
        return 0;
    }
    return 1;
}

/* Test: ${env:VAR} expansion */
static int test_config_env_expansion(void) {
    /* Set a test environment variable */
    setenv("SSH_PROXY_TEST_VAR", "expanded_value", 1);

    char out[256];
    if (config_expand_env("prefix_${env:SSH_PROXY_TEST_VAR}_suffix", out, sizeof(out)) != 0) {
        return 0;
    }

    if (strcmp(out, "prefix_expanded_value_suffix") != 0) {
        printf("  Got: '%s'\n", out);
        return 0;
    }

    unsetenv("SSH_PROXY_TEST_VAR");
    return 1;
}

/* Test: ${file:path} expansion */
static int test_config_file_expansion(void) {
    /* Create a temp file with a known value */
    const char *filepath = "test_expand_file.txt";
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL)
        return 0;
    fprintf(fp, "file_secret_value\n");
    fclose(fp);

    char pattern[512];
    snprintf(pattern, sizeof(pattern), "${file:%s}", filepath);

    char out[256];
    if (config_expand_env(pattern, out, sizeof(out)) != 0) {
        unlink(filepath);
        return 0;
    }

    if (strcmp(out, "file_secret_value") != 0) {
        printf("  Got: '%s'\n", out);
        unlink(filepath);
        return 0;
    }

    unlink(filepath);
    return 1;
}

/* Test: missing env var expands to empty */
static int test_config_missing_env(void) {
    unsetenv("SSH_PROXY_NONEXISTENT_VAR_12345");

    char out[256];
    if (config_expand_env("${env:SSH_PROXY_NONEXISTENT_VAR_12345}", out, sizeof(out)) != 0) {
        return 0;
    }

    if (strcmp(out, "") != 0) {
        printf("  Got: '%s'\n", out);
        return 0;
    }

    return 1;
}

/* Test: no expansion pattern passes through */
static int test_config_no_expansion(void) {
    char out[256];
    if (config_expand_env("plain_value", out, sizeof(out)) != 0) {
        return 0;
    }

    if (strcmp(out, "plain_value") != 0) {
        return 0;
    }

    return 1;
}

/* Test: config loads security section */
static int test_config_load_security(void) {
    const char *content = "[security]\n"
                          "lockout_enabled = true\n"
                          "lockout_threshold = 10\n"
                          "lockout_duration = 600\n"
                          "ip_ban_enabled = true\n"
                          "ip_ban_threshold = 12\n"
                          "ip_ban_duration = 900\n"
                          "password_min_length = 12\n"
                          "password_require_uppercase = true\n"
                          "password_require_digit = false\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (!config->lockout.lockout_enabled) {
        config_destroy(config);
        return 0;
    }

    if (config->lockout.lockout_threshold != 10) {
        config_destroy(config);
        return 0;
    }

    if (config->lockout.lockout_duration_sec != 600) {
        config_destroy(config);
        return 0;
    }

    if (!config->lockout.ip_ban_enabled || config->lockout.ip_ban_threshold != 12 ||
        config->lockout.ip_ban_duration_sec != 900) {
        config_destroy(config);
        return 0;
    }

    if (config->password_policy.min_length != 12) {
        config_destroy(config);
        return 0;
    }

    if (!config->password_policy.require_uppercase) {
        config_destroy(config);
        return 0;
    }

    if (config->password_policy.require_digit) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

static int test_config_load_trusted_user_ca_keys(void) {
    const char *content = "[security]\n"
                          "trusted_user_ca_key = ssh-ed25519 "
                          "AAAAC3NzaC1lZDI1NTE5AAAAIDbtnhwX0ejxhvKPjjivt+EnAILdLWeQYDXoXd7O0rzQ\n"
                          "trusted_user_ca_keys_file = /tmp/test_trusted_user_ca_keys.pub\n"
                          "\n"
                          "[user:alice]\n"
                          "enabled = true\n";

    if (create_test_file(TEST_CA_KEYS_PATH, kFixtureOtherUserCA) != 0)
        return 0;
    if (create_test_config(content) != 0) {
        unlink(TEST_CA_KEYS_PATH);
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CA_KEYS_PATH);
        return 0;
    }

    if (config->trusted_user_ca_keys == NULL ||
        strstr(config->trusted_user_ca_keys, kFixtureTrustedUserCA) == NULL ||
        strstr(config->trusted_user_ca_keys, kFixtureOtherUserCA) == NULL) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        unlink(TEST_CA_KEYS_PATH);
        return 0;
    }

    config->host_key_path[0] = '\0';
    config_valid_result_t *results = config_validate(config, TEST_CONFIG_PATH);
    if (result_list_contains_message(results, "has no password hash, public keys, or trusted SSH CA")) {
        config_valid_free(results);
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        unlink(TEST_CA_KEYS_PATH);
        return 0;
    }

    config_valid_free(results);
    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    unlink(TEST_CA_KEYS_PATH);
    return 1;
}

static int test_config_load_revoked_user_cert_serials(void) {
    const char *content = "[security]\n"
                          "revoked_user_cert_serial = 7\n"
                          "revoked_user_cert_serials_file = /tmp/test_revoked_user_cert_serials.txt\n";

    if (create_test_file("/tmp/test_revoked_user_cert_serials.txt", "42\n99\n") != 0)
        return 0;
    if (create_test_config(content) != 0) {
        unlink("/tmp/test_revoked_user_cert_serials.txt");
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        unlink(TEST_CONFIG_PATH);
        unlink("/tmp/test_revoked_user_cert_serials.txt");
        return 0;
    }

    if (config->revoked_user_cert_serials == NULL ||
        strstr(config->revoked_user_cert_serials, "7") == NULL ||
        strstr(config->revoked_user_cert_serials, "42") == NULL ||
        strstr(config->revoked_user_cert_serials, "99") == NULL) {
        config_destroy(config);
        unlink(TEST_CONFIG_PATH);
        unlink("/tmp/test_revoked_user_cert_serials.txt");
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    unlink("/tmp/test_revoked_user_cert_serials.txt");
    return 1;
}

static int test_config_validate_cert_only_user_with_trusted_ca(void) {
    proxy_config_t *config = config_create();
    if (config == NULL)
        return 0;
    config->host_key_path[0] = '\0';
    if (config_add_user(config, "alice", NULL, NULL) != 0) {
        config_destroy(config);
        return 0;
    }

    config_valid_result_t *results = config_validate(config, NULL);
    if (results == NULL ||
        !result_list_contains_message(results, "has no password hash, public keys, or trusted SSH CA")) {
        config_valid_free(results);
        config_destroy(config);
        return 0;
    }
    config_valid_free(results);

    config->trusted_user_ca_keys = strdup(kFixtureTrustedUserCA);
    if (config->trusted_user_ca_keys == NULL) {
        config_destroy(config);
        return 0;
    }

    results = config_validate(config, NULL);
    if (result_list_contains_message(results, "has no password hash, public keys, or trusted SSH CA")) {
        config_valid_free(results);
        config_destroy(config);
        return 0;
    }

    config_valid_free(results);
    config_destroy(config);
    return 1;
}

static int test_config_load_session_store(void) {
    const char *content = "[session_store]\n"
                          "type = file\n"
                          "path = /tmp/cluster-sessions.ndjson\n"
                          "sync_interval = 7\n"
                          "instance_id = proxy-a\n";

    if (create_test_config(content) != 0) {
        return 0;
    }

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) {
        return 0;
    }

    int ok = strcmp(config->session_store_type, "file") == 0 &&
             strcmp(config->session_store_path, "/tmp/cluster-sessions.ndjson") == 0 &&
             config->session_store_sync_interval == 7 &&
             strcmp(config->session_store_instance_id, "proxy-a") == 0;

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return ok ? 1 : 0;
}

static int test_config_validate_session_store_requires_path(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return 0;
    }

    strncpy(config->session_store_type, "file", sizeof(config->session_store_type) - 1);
    config_valid_result_t *results = config_validate(config, NULL);
    int ok = result_list_contains_message(
        results, "session_store.path is required when session_store.type=file");

    config_valid_free(results);
    config_destroy(config);
    return ok ? 1 : 0;
}

/* Test: config loads webhook section */
static int test_config_load_webhook(void) {
    const char *content = "[webhook]\n"
                          "enabled = true\n"
                          "url = https://hooks.example.com/ssh-events\n"
                          "auth_header = Authorization: Bearer secret\n"
                          "hmac_secret = signing-secret\n"
                          "dead_letter_path = /tmp/webhook-dlq.jsonl\n"
                          "events = auth.failure, user.updated, policy.updated\n"
                          "retry_max = 5\n"
                          "retry_delay_ms = 250\n"
                          "timeout_ms = 3000\n"
                          "queue_size = 32\n";

    if (create_test_config(content) != 0)
        return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL)
        return 0;

    if (!config->webhook.enabled) {
        config_destroy(config);
        return 0;
    }
    if (strcmp(config->webhook.url, "https://hooks.example.com/ssh-events") != 0) {
        config_destroy(config);
        return 0;
    }
    if (strcmp(config->webhook.auth_header, "Authorization: Bearer secret") != 0) {
        config_destroy(config);
        return 0;
    }
    if (strcmp(config->webhook.hmac_secret, "signing-secret") != 0) {
        config_destroy(config);
        return 0;
    }
    if (strcmp(config->webhook.dead_letter_path, "/tmp/webhook-dlq.jsonl") != 0) {
        config_destroy(config);
        return 0;
    }
    if (config->webhook.retry_max != 5 || config->webhook.retry_delay_ms != 250 ||
        config->webhook.timeout_ms != 3000 || config->webhook.queue_size != 32) {
        config_destroy(config);
        return 0;
    }
    if ((config->webhook.event_mask & (uint32_t)WEBHOOK_EVENT_AUTH_FAILURE) == 0 ||
        (config->webhook.event_mask & (uint32_t)WEBHOOK_EVENT_USER_UPDATED) == 0 ||
        (config->webhook.event_mask & (uint32_t)WEBHOOK_EVENT_POLICY_UPDATED) == 0 ||
        (config->webhook.event_mask & (uint32_t)WEBHOOK_EVENT_AUTH_SUCCESS) != 0) {
        config_destroy(config);
        return 0;
    }

    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

int main(void) {
    printf("=== Configuration Module Tests ===\n\n");

    log_init(LOG_LEVEL_WARN, NULL); /* Suppress info/debug logs during tests */

    RUN_TEST(test_config_create);
    RUN_TEST(test_config_add_user);
    RUN_TEST(test_config_load_server);
    RUN_TEST(test_config_load_logging);
    RUN_TEST(test_config_validate_invalid_audit_encryption_key);
    RUN_TEST(test_config_load_admin);
    RUN_TEST(test_config_load_users);
    RUN_TEST(test_config_load_password_rotation);
    RUN_TEST(test_config_load_comments);
    RUN_TEST(test_config_load_quoted);
    RUN_TEST(test_config_reload);
    RUN_TEST(test_config_load_encrypted_sensitive_values);
    RUN_TEST(test_config_load_encrypted_values_with_master_key_file);
    RUN_TEST(test_config_rejects_encrypted_value_without_master_key);
    RUN_TEST(test_config_reload_updates_encrypted_sensitive_values);
    RUN_TEST(test_config_null_handling);
    RUN_TEST(test_config_routes);
    RUN_TEST(test_config_load_routes);
    RUN_TEST(test_config_find_route_for_client_geo_routing);
    RUN_TEST(test_config_find_route_connection_affinity);
    RUN_TEST(test_config_load_router_circuit_breaker_settings);
    RUN_TEST(test_config_route_circuit_breaker_state_machine);
    RUN_TEST(test_config_find_route_skips_open_circuit_candidate);
    RUN_TEST(test_config_load_rejects_partial_route_geo_coordinates);
    RUN_TEST(test_config_load_policy_login_window);
    RUN_TEST(test_config_policy_allows_connection_by_time_window);
    RUN_TEST(test_config_policy_allows_connection_overnight_window);
    RUN_TEST(test_config_load_network_source_policy);
    RUN_TEST(test_config_policy_allows_connection_by_source_type);
    RUN_TEST(test_config_rejects_invalid_network_source_policy);
    RUN_TEST(test_config_rejects_invalid_policy_login_window);
    RUN_TEST(test_config_env_expansion);
    RUN_TEST(test_config_file_expansion);
    RUN_TEST(test_config_missing_env);
    RUN_TEST(test_config_no_expansion);
    RUN_TEST(test_config_load_security);
    RUN_TEST(test_config_load_trusted_user_ca_keys);
    RUN_TEST(test_config_load_revoked_user_cert_serials);
    RUN_TEST(test_config_validate_cert_only_user_with_trusted_ca);
    RUN_TEST(test_config_load_session_store);
    RUN_TEST(test_config_validate_session_store_requires_path);
    RUN_TEST(test_config_load_webhook);

    log_shutdown();

    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_run - tests_passed);

    return (tests_passed == tests_run) ? 0 : 1;
}
