/**
 * @file test_ssh_server.c
 * @brief SSH Server Unit Tests
 */

#include "test_utils.h"
#include "ssh_server.h"
#include <unistd.h>

/* Test: Create and destroy server */
static int test_create_destroy(void)
{
    ssh_server_config_t config = {
        .bind_addr = "127.0.0.1",
        .port = 2222,
        .host_key_rsa = NULL,
        .log_verbosity = 0
    };

    ssh_server_t *server = ssh_server_create(&config);
    TEST_ASSERT_NOT_NULL(server, "Server should be created");

    ssh_server_destroy(server);
    return 0;
}

/* Test: Create with NULL config */
static int test_create_null_config(void)
{
    ssh_server_t *server = ssh_server_create(NULL);
    TEST_ASSERT_NULL(server, "Server should be NULL with NULL config");
    return 0;
}

/* Test: Server state */
static int test_server_state(void)
{
    ssh_server_config_t config = {
        .bind_addr = "127.0.0.1",
        .port = 2223,
        .host_key_rsa = NULL,
        .log_verbosity = 0
    };

    ssh_server_t *server = ssh_server_create(&config);
    TEST_ASSERT_NOT_NULL(server, "Server should be created");

    TEST_ASSERT(!ssh_server_is_running(server), "Server should not be running initially");

    ssh_server_destroy(server);
    return 0;
}

/* Test: NULL operations */
static int test_null_operations(void)
{
    TEST_ASSERT(!ssh_server_is_running(NULL), "is_running with NULL should return false");
    TEST_ASSERT_NOT_NULL(ssh_server_get_error(NULL), "get_error with NULL should return message");
    
    /* These should not crash */
    ssh_server_stop(NULL);
    ssh_server_destroy(NULL);
    
    return 0;
}

/* Test: Generate key */
static int test_generate_key(void)
{
    const char *key_path = "/tmp/test_ssh_key";
    
    /* Remove if exists */
    unlink(key_path);
    
    int ret = ssh_server_generate_key(key_path, 2048);
    TEST_ASSERT_EQ(ret, 0, "Key generation should succeed");
    
    /* Check file exists */
    TEST_ASSERT_EQ(access(key_path, F_OK), 0, "Key file should exist");
    
    /* Cleanup */
    unlink(key_path);
    
    return 0;
}

int main(void)
{
    TEST_BEGIN("SSH Server Tests");

    RUN_TEST(test_create_destroy);
    RUN_TEST(test_create_null_config);
    RUN_TEST(test_server_state);
    RUN_TEST(test_null_operations);
    RUN_TEST(test_generate_key);

    TEST_END();
}
