/**
 * @file test_utils.h
 * @brief Simple Unit Test Framework for C
 *
 * Usage:
 *   1. Include this header in your test file
 *   2. Define test functions returning int (0=pass, non-zero=fail)
 *   3. Use TEST_BEGIN(name) at start of main
 *   4. Use RUN_TEST(func) for each test
 *   5. Use TEST_END() at end of main
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test state - must be defined in each test file */
static int g_tests_run __attribute__((unused)) = 0;
static int g_tests_passed __attribute__((unused)) = 0;
static int g_tests_failed __attribute__((unused)) = 0;

/**
 * @brief Start a test function
 */
#define TEST_START() printf("Running %s...\n", __func__)

/**
 * @brief Pass a test
 */
#define TEST_PASS() do { printf("  PASS\n"); return 0; } while(0)

/**
 * @brief Fail a test with message
 */
#define TEST_FAIL(msg) do { printf("  FAIL: %s\n", msg); return 1; } while(0)

/**
 * @brief Assert condition, return from test on failure
 */
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return 1; \
    } \
} while(0)

/**
 * @brief Assert two values are equal
 */
#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)

/**
 * @brief Assert two values are not equal
 */
#define TEST_ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)

/**
 * @brief Assert pointer is NULL
 */
#define TEST_ASSERT_NULL(ptr, msg) TEST_ASSERT((ptr) == NULL, msg)

/**
 * @brief Assert pointer is not NULL
 */
#define TEST_ASSERT_NOT_NULL(ptr, msg) TEST_ASSERT((ptr) != NULL, msg)

/**
 * @brief Assert two strings are equal
 */
#define TEST_ASSERT_STR_EQ(a, b, msg) TEST_ASSERT(strcmp((a), (b)) == 0, msg)

/* Convenience macros with auto-generated messages */
#define ASSERT_TRUE(cond) TEST_ASSERT((cond), #cond " is false")
#define ASSERT_FALSE(cond) TEST_ASSERT(!(cond), #cond " is true")
#define ASSERT_EQ(a, b) TEST_ASSERT((a) == (b), #a " != " #b)
#define ASSERT_NE(a, b) TEST_ASSERT((a) != (b), #a " == " #b)
#define ASSERT_NULL(ptr) TEST_ASSERT((ptr) == NULL, #ptr " is not NULL")
#define ASSERT_NOT_NULL(ptr) TEST_ASSERT((ptr) != NULL, #ptr " is NULL")
#define ASSERT_STR_EQ(a, b) TEST_ASSERT(strcmp((a), (b)) == 0, #a " != " #b)

/**
 * @brief Run a test function and track results
 */
#define RUN_TEST(test_func) do { \
    g_tests_run++; \
    printf("Running %s...\n", #test_func); \
    if (test_func() == 0) { \
        printf("  PASS\n"); \
        g_tests_passed++; \
    } else { \
        g_tests_failed++; \
    } \
} while(0)

/**
 * @brief Print test suite header
 */
#define TEST_BEGIN(suite_name) \
    printf("=== %s ===\n\n", suite_name)

/**
 * @brief Print test summary and return exit code
 */
#define TEST_END() do { \
    printf("\n=== Test Summary ===\n"); \
    printf("Total:  %d\n", g_tests_run); \
    printf("Passed: %d\n", g_tests_passed); \
    printf("Failed: %d\n", g_tests_failed); \
    return g_tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS; \
} while(0)

#endif /* TEST_UTILS_H */
