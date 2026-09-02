/**
 * @file test_filter.c
 * @brief Unit tests for Filter Chain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "filter.h"
#include "logger.h"
#include "test_utils.h"

/* Test filter callbacks */
static int connect_count = 0;
static int auth_count = 0;
static int close_count = 0;

static filter_status_t test_on_connect(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    connect_count++;
    return FILTER_CONTINUE;
}

static filter_status_t test_on_auth(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    auth_count++;
    return FILTER_CONTINUE;
}

static void test_on_close(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    close_count++;
}

static int test_filter_chain_create(void)
{
    TEST_START();

    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);
    ASSERT_EQ(filter_chain_count(chain), 0);

    filter_chain_destroy(chain);
    TEST_PASS();
}

static int test_filter_chain_add(void)
{
    TEST_START();

    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);

    filter_callbacks_t callbacks = {
        .on_connect = test_on_connect,
        .on_auth = test_on_auth,
        .on_close = test_on_close,
        .destroy = NULL
    };

    filter_t *f1 = filter_create("test1", FILTER_TYPE_CUSTOM, &callbacks, NULL);
    filter_t *f2 = filter_create("test2", FILTER_TYPE_CUSTOM, &callbacks, NULL);

    ASSERT_NOT_NULL(f1);
    ASSERT_NOT_NULL(f2);

    ASSERT_EQ(filter_chain_add(chain, f1), 0);
    ASSERT_EQ(filter_chain_count(chain), 1);

    ASSERT_EQ(filter_chain_add(chain, f2), 0);
    ASSERT_EQ(filter_chain_count(chain), 2);

    filter_chain_destroy(chain);
    TEST_PASS();
}

static int test_filter_chain_process(void)
{
    TEST_START();

    connect_count = 0;
    auth_count = 0;
    close_count = 0;

    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);

    filter_callbacks_t callbacks = {
        .on_connect = test_on_connect,
        .on_auth = test_on_auth,
        .on_close = test_on_close,
        .destroy = NULL
    };

    filter_t *f1 = filter_create("test1", FILTER_TYPE_CUSTOM, &callbacks, NULL);
    filter_t *f2 = filter_create("test2", FILTER_TYPE_CUSTOM, &callbacks, NULL);

    filter_chain_add(chain, f1);
    filter_chain_add(chain, f2);

    filter_context_t ctx = {0};

    /* Test on_connect - should call both filters */
    filter_status_t status = filter_chain_on_connect(chain, &ctx);
    ASSERT_EQ(status, FILTER_CONTINUE);
    ASSERT_EQ(connect_count, 2);

    /* Test on_auth - should call both filters */
    status = filter_chain_on_auth(chain, &ctx);
    ASSERT_EQ(status, FILTER_CONTINUE);
    ASSERT_EQ(auth_count, 2);

    /* Test on_close - should call both filters */
    filter_chain_on_close(chain, &ctx);
    ASSERT_EQ(close_count, 2);

    filter_chain_destroy(chain);
    TEST_PASS();
}

static int test_filter_chain_get(void)
{
    TEST_START();

    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);

    filter_callbacks_t callbacks = {0};

    filter_t *f1 = filter_create("auth", FILTER_TYPE_AUTH, &callbacks, NULL);
    filter_t *f2 = filter_create("audit", FILTER_TYPE_AUDIT, &callbacks, NULL);

    filter_chain_add(chain, f1);
    filter_chain_add(chain, f2);

    ASSERT_NOT_NULL(filter_chain_get(chain, "auth"));
    ASSERT_NOT_NULL(filter_chain_get(chain, "audit"));
    ASSERT_NULL(filter_chain_get(chain, "nonexistent"));

    filter_chain_destroy(chain);
    TEST_PASS();
}

static int test_filter_type_names(void)
{
    TEST_START();

    ASSERT_STR_EQ(filter_type_name(FILTER_TYPE_AUTH), "AUTH");
    ASSERT_STR_EQ(filter_type_name(FILTER_TYPE_RBAC), "RBAC");
    ASSERT_STR_EQ(filter_type_name(FILTER_TYPE_AUDIT), "AUDIT");
    ASSERT_STR_EQ(filter_type_name(FILTER_TYPE_RATE_LIMIT), "RATE_LIMIT");
    ASSERT_STR_EQ(filter_type_name(FILTER_TYPE_CUSTOM), "CUSTOM");

    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);
    printf("=== Filter Chain Tests ===\n\n");

    int failed = 0;
    failed += test_filter_chain_create();
    failed += test_filter_chain_add();
    failed += test_filter_chain_process();
    failed += test_filter_chain_get();
    failed += test_filter_type_names();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failed);
    }

    log_shutdown();
    return failed;
}
