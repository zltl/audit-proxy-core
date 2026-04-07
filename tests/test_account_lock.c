/**
 * @file test_account_lock.c
 * @brief Unit tests for account lockout module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "account_lock.h"
#include "logger.h"
#include "test_utils.h"

/* Test: init and cleanup */
static int test_init_cleanup(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 3,
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);
    account_lock_cleanup();

    /* Double cleanup should not crash */
    account_lock_cleanup();

    TEST_PASS();
}

/* Test: init with NULL uses defaults */
static int test_init_defaults(void)
{
    TEST_START();

    ASSERT_EQ(account_lock_init(NULL), 0);

    /* Should not be locked (lockout disabled by default) */
    ASSERT_FALSE(account_is_locked("testuser"));

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: lock after N failures */
static int test_lockout_after_threshold(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 3,
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    /* Record failures below threshold */
    account_record_failure("alice");
    ASSERT_FALSE(account_is_locked("alice"));
    ASSERT_EQ(account_get_failures("alice"), 1);

    account_record_failure("alice");
    ASSERT_FALSE(account_is_locked("alice"));
    ASSERT_EQ(account_get_failures("alice"), 2);

    /* Third failure should trigger lockout */
    account_record_failure("alice");
    ASSERT_TRUE(account_is_locked("alice"));
    ASSERT_EQ(account_get_failures("alice"), 3);

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: unlock after duration expires */
static int test_unlock_after_duration(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 2,
        .lockout_duration_sec = 1  /* 1 second for quick test */
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    account_record_failure("bob");
    account_record_failure("bob");
    ASSERT_TRUE(account_is_locked("bob"));

    /* Wait for lockout to expire */
    sleep(2);

    ASSERT_FALSE(account_is_locked("bob"));

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: reset on success */
static int test_reset_on_success(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 3,
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    account_record_failure("carol");
    account_record_failure("carol");
    ASSERT_EQ(account_get_failures("carol"), 2);

    /* Success resets counter */
    account_record_success("carol");
    ASSERT_EQ(account_get_failures("carol"), 0);
    ASSERT_FALSE(account_is_locked("carol"));

    /* Should need 3 more failures to lock */
    account_record_failure("carol");
    account_record_failure("carol");
    ASSERT_FALSE(account_is_locked("carol"));

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: different users are independent */
static int test_independent_users(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 2,
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    account_record_failure("user_a");
    account_record_failure("user_a");
    ASSERT_TRUE(account_is_locked("user_a"));
    ASSERT_FALSE(account_is_locked("user_b"));

    account_record_failure("user_b");
    ASSERT_EQ(account_get_failures("user_b"), 1);

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: NULL/edge cases */
static int test_null_handling(void)
{
    TEST_START();

    /* Operations before init should not crash */
    ASSERT_FALSE(account_is_locked("user"));
    account_record_failure(NULL);
    account_record_success(NULL);
    ASSERT_EQ(account_get_failures(NULL), 0);

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 3,
        .lockout_duration_sec = 60
    };
    ASSERT_EQ(account_lock_init(&cfg), 0);

    /* NULL username */
    ASSERT_FALSE(account_is_locked(NULL));
    account_record_failure(NULL);
    account_record_success(NULL);
    ASSERT_EQ(account_get_failures(NULL), 0);

    account_lock_cleanup();
    TEST_PASS();
}

/* Test: disabled lockout does not lock */
static int test_disabled_lockout(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = false,
        .lockout_threshold = 1,
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    account_record_failure("dave");
    account_record_failure("dave");
    account_record_failure("dave");
    ASSERT_FALSE(account_is_locked("dave"));

    account_lock_cleanup();
    TEST_PASS();
}

/* Concurrent access test */
#define THREAD_COUNT 4
#define ITER_COUNT 50

static void *thread_func(void *arg)
{
    const char *username = (const char *)arg;
    for (int i = 0; i < ITER_COUNT; i++) {
        account_record_failure(username);
        (void)account_is_locked(username);
        (void)account_get_failures(username);
    }
    return NULL;
}

static int test_concurrent_access(void)
{
    TEST_START();

    account_lock_config_t cfg = {
        .lockout_enabled = true,
        .lockout_threshold = 1000, /* High threshold so we don't lock during test */
        .lockout_duration_sec = 60
    };

    ASSERT_EQ(account_lock_init(&cfg), 0);

    pthread_t threads[THREAD_COUNT];
    const char *usernames[THREAD_COUNT] = {
        "thread_user_0", "thread_user_1", "thread_user_2", "thread_user_3"
    };

    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, thread_func,
                           (void *)usernames[i]) != 0) {
            TEST_FAIL("pthread_create failed");
        }
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Each thread recorded ITER_COUNT failures for its own user */
    for (int i = 0; i < THREAD_COUNT; i++) {
        ASSERT_EQ(account_get_failures(usernames[i]), ITER_COUNT);
    }

    account_lock_cleanup();
    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Account Lockout Module Tests");

    RUN_TEST(test_init_cleanup);
    RUN_TEST(test_init_defaults);
    RUN_TEST(test_lockout_after_threshold);
    RUN_TEST(test_unlock_after_duration);
    RUN_TEST(test_reset_on_success);
    RUN_TEST(test_independent_users);
    RUN_TEST(test_null_handling);
    RUN_TEST(test_disabled_lockout);
    RUN_TEST(test_concurrent_access);

    log_shutdown();

    TEST_END();
}
