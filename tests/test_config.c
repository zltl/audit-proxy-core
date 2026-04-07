/**
 * @file test_config.c
 * @brief Unit tests for configuration module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "logger.h"

#define TEST_CONFIG_PATH "/tmp/test_ssh_proxy.conf"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test) do { \
    printf("Running %s...\n", #test); \
    tests_run++; \
    if (test()) { \
        printf("  PASS\n"); \
        tests_passed++; \
    } else { \
        printf("  FAIL\n"); \
    } \
} while(0)

/* Helper: create test config file */
static int create_test_config(const char *content) {
    FILE *fp = fopen(TEST_CONFIG_PATH, "w");
    if (fp == NULL) return -1;
    fprintf(fp, "%s", content);
    fclose(fp);
    return 0;
}

/* Test: config_create */
static int test_config_create(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) return 0;
    
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
    
    config_destroy(config);
    return 1;
}

/* Test: config_add_user */
static int test_config_add_user(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) return 0;
    
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
    const char *content = 
        "[server]\n"
        "bind_addr = 127.0.0.1\n"
        "port = 3333\n"
        "host_key = /custom/host/key\n";
    
    if (create_test_config(content) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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
    const char *content = 
        "[user:alice]\n"
        "password_hash = $6$salt$alicehash\n"
        "pubkey = ssh-rsa AAAA... alice@example.com\n"
        "enabled = true\n"
        "\n"
        "[user:bob]\n"
        "password_hash = $6$salt$bobhash\n"
        "enabled = false\n";
    
    if (create_test_config(content) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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
    
    /* Bob is disabled, should not be found */
    if (config_find_user(config, "bob") != NULL) {
        config_destroy(config);
        return 0;
    }
    
    config_destroy(config);
    unlink(TEST_CONFIG_PATH);
    return 1;
}

/* Test: config_load with comments and empty lines */
static int test_config_load_comments(void) {
    const char *content = 
        "# This is a comment\n"
        "\n"
        "[server]\n"
        "# Another comment\n"
        "port = 4444\n"
        "; Semicolon comment\n"
        "bind_addr = 0.0.0.0\n";
    
    if (create_test_config(content) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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
    const char *content = 
        "[server]\n"
        "bind_addr = \"127.0.0.1\"\n"
        "host_key = '/path/with spaces/key'\n";
    
    if (create_test_config(content) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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
    const char *content1 = 
        "[server]\n"
        "port = 1111\n";
    
    const char *content2 = 
        "[server]\n"
        "port = 2222\n";
    
    if (create_test_config(content1) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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

/* Test: null handling */
static int test_config_null_handling(void) {
    /* config_load with NULL */
    if (config_load(NULL) != NULL) return 0;
    
    /* config_load with non-existent file */
    if (config_load("/nonexistent/path/config.ini") != NULL) return 0;
    
    /* config_add_user with NULL */
    if (config_add_user(NULL, "user", "hash", NULL) != -1) return 0;
    
    proxy_config_t *config = config_create();
    if (config == NULL) return 0;
    
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
    config_destroy(NULL);  /* Should not crash */
    
    config_destroy(config);
    return 1;
}

/* Test: config_add_route and config_find_route */
static int test_config_routes(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) return 0;
    
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
    const char *content = 
        "[route:admin]\n"
        "upstream = prod.example.com\n"
        "port = 22\n"
        "user = root\n"
        "privkey = /keys/admin.key\n"
        "enabled = true\n"
        "\n"
        "[route:dev-*]\n"
        "host = dev.example.com\n"
        "upstream_user = developer\n";
    
    if (create_test_config(content) != 0) return 0;
    
    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;
    
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
    if (fp == NULL) return 0;
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
    const char *content =
        "[security]\n"
        "lockout_enabled = true\n"
        "lockout_threshold = 10\n"
        "lockout_duration = 600\n"
        "password_min_length = 12\n"
        "password_require_uppercase = true\n"
        "password_require_digit = false\n";

    if (create_test_config(content) != 0) return 0;

    proxy_config_t *config = config_load(TEST_CONFIG_PATH);
    if (config == NULL) return 0;

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

int main(void) {
    printf("=== Configuration Module Tests ===\n\n");
    
    log_init(LOG_LEVEL_WARN, NULL);  /* Suppress info/debug logs during tests */
    
    RUN_TEST(test_config_create);
    RUN_TEST(test_config_add_user);
    RUN_TEST(test_config_load_server);
    RUN_TEST(test_config_load_users);
    RUN_TEST(test_config_load_comments);
    RUN_TEST(test_config_load_quoted);
    RUN_TEST(test_config_reload);
    RUN_TEST(test_config_null_handling);
    RUN_TEST(test_config_routes);
    RUN_TEST(test_config_load_routes);
    RUN_TEST(test_config_env_expansion);
    RUN_TEST(test_config_file_expansion);
    RUN_TEST(test_config_missing_env);
    RUN_TEST(test_config_no_expansion);
    RUN_TEST(test_config_load_security);
    
    log_shutdown();
    
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_run - tests_passed);
    
    return (tests_passed == tests_run) ? 0 : 1;
}
