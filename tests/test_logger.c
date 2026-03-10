/**
 * @file test_logger.c
 * @brief Logger Unit Tests
 */

#include "test_utils.h"
#include "logger.h"

/* Test: Initialize and shutdown */
static int test_init_shutdown(void)
{
    int ret = log_init(LOG_LEVEL_INFO, NULL);
    TEST_ASSERT_EQ(ret, 0, "log_init should succeed");

    log_shutdown();
    return 0;
}

/* Test: Set and get level */
static int test_set_get_level(void)
{
    log_init(LOG_LEVEL_INFO, NULL);

    TEST_ASSERT_EQ(log_get_level(), LOG_LEVEL_INFO, "Initial level should be INFO");

    log_set_level(LOG_LEVEL_DEBUG);
    TEST_ASSERT_EQ(log_get_level(), LOG_LEVEL_DEBUG, "Level should be DEBUG");

    log_set_level(LOG_LEVEL_ERROR);
    TEST_ASSERT_EQ(log_get_level(), LOG_LEVEL_ERROR, "Level should be ERROR");

    log_shutdown();
    return 0;
}

/* Test: Log output (visual test) */
static int test_log_output(void)
{
    log_init(LOG_LEVEL_TRACE, NULL);
    log_set_color(0);

    printf("  (Visual test - checking log output)\n");
    LOG_TRACE("This is a trace message");
    LOG_DEBUG("This is a debug message");
    LOG_INFO("This is an info message");
    LOG_WARN("This is a warning message");
    LOG_ERROR("This is an error message");

    log_shutdown();
    return 0;
}

/* Test: Log filtering */
static int test_log_filtering(void)
{
    log_init(LOG_LEVEL_WARN, NULL);
    log_set_color(0);

    printf("  (Only WARN and above should appear)\n");
    LOG_DEBUG("This should NOT appear");
    LOG_INFO("This should NOT appear");
    LOG_WARN("This SHOULD appear");
    LOG_ERROR("This SHOULD appear");

    log_shutdown();
    return 0;
}

/* Test: Format arguments */
static int test_format_args(void)
{
    log_init(LOG_LEVEL_INFO, NULL);
    log_set_color(0);

    LOG_INFO("String: %s, Int: %d, Float: %.2f", "test", 42, 3.14);

    log_shutdown();
    return 0;
}

/* Test: JSON format set/get */
static int test_json_format_set_get(void)
{
    log_init(LOG_LEVEL_INFO, NULL);

    TEST_ASSERT_EQ(log_get_format(), LOG_FORMAT_TEXT, "Default format should be TEXT");

    log_set_format(LOG_FORMAT_JSON);
    TEST_ASSERT_EQ(log_get_format(), LOG_FORMAT_JSON, "Format should be JSON");

    log_set_format(LOG_FORMAT_TEXT);
    TEST_ASSERT_EQ(log_get_format(), LOG_FORMAT_TEXT, "Format should be TEXT again");

    log_shutdown();
    return 0;
}

/* Test: JSON format output */
static int test_json_format_output(void)
{
    log_init(LOG_LEVEL_TRACE, NULL);
    log_set_format(LOG_FORMAT_JSON);

    printf("  (Visual test - checking JSON log output)\n");
    LOG_TRACE("Trace message in JSON");
    LOG_DEBUG("Debug message in JSON");
    LOG_INFO("Info message in JSON");
    LOG_WARN("Warning message in JSON");
    LOG_ERROR("Error message in JSON");

    log_set_format(LOG_FORMAT_TEXT);
    log_shutdown();
    return 0;
}

/* Test: JSON escaping of special characters */
static int test_json_escape_special_chars(void)
{
    log_init(LOG_LEVEL_INFO, NULL);
    log_set_format(LOG_FORMAT_JSON);

    printf("  (Visual test - JSON escaping special chars)\n");
    LOG_INFO("Message with \"quotes\"");
    LOG_INFO("Message with back\\slash");
    LOG_INFO("Message with\nnewline");
    LOG_INFO("Message with\ttab");
    LOG_INFO("String: %s, Int: %d", "hello \"world\"", 42);

    log_set_format(LOG_FORMAT_TEXT);
    log_shutdown();
    return 0;
}

int main(void)
{
    TEST_BEGIN("Logger Tests");

    RUN_TEST(test_init_shutdown);
    RUN_TEST(test_set_get_level);
    RUN_TEST(test_log_output);
    RUN_TEST(test_log_filtering);
    RUN_TEST(test_format_args);
    RUN_TEST(test_json_format_set_get);
    RUN_TEST(test_json_format_output);
    RUN_TEST(test_json_escape_special_chars);

    TEST_END();
}
