/**
 * @file test_password_policy.c
 * @brief Unit tests for password policy module
 */

#include "logger.h"
#include "password_policy.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Test: defaults */
static int test_defaults(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(p.min_length, (uint32_t)8);
    ASSERT_TRUE(p.require_uppercase);
    ASSERT_TRUE(p.require_lowercase);
    ASSERT_TRUE(p.require_digit);
    ASSERT_FALSE(p.require_special);
    ASSERT_EQ(p.max_age_days, (uint32_t)0);

    TEST_PASS();
}

/* Test: valid password passes */
static int test_valid_password(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, "Hello123world"), 0);

    TEST_PASS();
}

/* Test: too short fails */
static int test_too_short(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, "Hi1"), -1);

    const char *err = password_policy_error();
    ASSERT_NOT_NULL(err);
    ASSERT_TRUE(strstr(err, "short") != NULL);

    TEST_PASS();
}

/* Test: missing uppercase fails */
static int test_missing_uppercase(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, "hello123world"), -1);

    const char *err = password_policy_error();
    ASSERT_TRUE(strstr(err, "uppercase") != NULL);

    TEST_PASS();
}

/* Test: missing lowercase fails */
static int test_missing_lowercase(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, "HELLO123WORLD"), -1);

    const char *err = password_policy_error();
    ASSERT_TRUE(strstr(err, "lowercase") != NULL);

    TEST_PASS();
}

/* Test: missing digit fails */
static int test_missing_digit(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, "HelloWorld"), -1);

    const char *err = password_policy_error();
    ASSERT_TRUE(strstr(err, "digit") != NULL);

    TEST_PASS();
}

/* Test: missing special char fails when required */
static int test_missing_special(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    p.require_special = true;
    ASSERT_EQ(password_policy_check(&p, "Hello123world"), -1);

    const char *err = password_policy_error();
    ASSERT_TRUE(strstr(err, "special") != NULL);

    /* With special character */
    ASSERT_EQ(password_policy_check(&p, "Hello123!world"), 0);

    TEST_PASS();
}

/* Test: NULL inputs */
static int test_null_inputs(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();

    ASSERT_EQ(password_policy_check(NULL, "hello"), -1);
    ASSERT_EQ(password_policy_check(&p, NULL), -1);
    ASSERT_EQ(password_policy_check(NULL, NULL), -1);

    TEST_PASS();
}

/* Test: empty password */
static int test_empty_password(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    ASSERT_EQ(password_policy_check(&p, ""), -1);

    TEST_PASS();
}

/* Test: relaxed policy */
static int test_relaxed_policy(void) {
    TEST_START();

    password_policy_t p;
    memset(&p, 0, sizeof(p));
    p.min_length = 1;
    p.require_uppercase = false;
    p.require_lowercase = false;
    p.require_digit = false;
    p.require_special = false;

    ASSERT_EQ(password_policy_check(&p, "a"), 0);
    ASSERT_EQ(password_policy_check(&p, "1"), 0);
    ASSERT_EQ(password_policy_check(&p, "!"), 0);

    TEST_PASS();
}

/* Test: exact min length boundary */
static int test_exact_min_length(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();

    /* Exactly 8 characters, all requirements met */
    ASSERT_EQ(password_policy_check(&p, "Abcdef1x"), 0);

    /* 7 characters */
    ASSERT_EQ(password_policy_check(&p, "Abcde1x"), -1);

    TEST_PASS();
}

/* Test: password expiry check */
static int test_password_expiry(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    p.max_age_days = 30;

    time_t now = (time_t)1710000000;
    ASSERT_EQ(password_policy_check_expiry(&p, true, now - (29 * 86400), now), 0);
    ASSERT_EQ(password_policy_check_expiry(&p, true, now - (31 * 86400), now), -1);
    ASSERT_TRUE(strstr(password_policy_error(), "expired") != NULL);

    TEST_PASS();
}

/* Test: expiry disabled without metadata */
static int test_password_expiry_without_timestamp(void) {
    TEST_START();

    password_policy_t p = password_policy_defaults();
    p.max_age_days = 30;

    ASSERT_EQ(password_policy_check_expiry(&p, false, (time_t)0, (time_t)1710000000), 0);

    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Password Policy Module Tests");

    RUN_TEST(test_defaults);
    RUN_TEST(test_valid_password);
    RUN_TEST(test_too_short);
    RUN_TEST(test_missing_uppercase);
    RUN_TEST(test_missing_lowercase);
    RUN_TEST(test_missing_digit);
    RUN_TEST(test_missing_special);
    RUN_TEST(test_null_inputs);
    RUN_TEST(test_empty_password);
    RUN_TEST(test_relaxed_policy);
    RUN_TEST(test_exact_min_length);
    RUN_TEST(test_password_expiry);
    RUN_TEST(test_password_expiry_without_timestamp);

    log_shutdown();

    TEST_END();
}
