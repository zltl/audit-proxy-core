/**
 * @file test_router.c
 * @brief Unit tests for Router
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "router.h"
#include "logger.h"
#include "test_utils.h"

static int test_router_create(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);
    ASSERT_EQ(router_get_upstream_count(router), 0);

    router_destroy(router);
    TEST_PASS();
}

static int test_router_add_upstream(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);

    upstream_config_t upstream = {
        .port = 22,
        .weight = 1,
        .enabled = true
    };
    strncpy(upstream.host, "192.168.1.1", ROUTER_MAX_HOST - 1);

    int idx = router_add_upstream(router, &upstream);
    ASSERT_EQ(idx, 0);
    ASSERT_EQ(router_get_upstream_count(router), 1);

    strncpy(upstream.host, "192.168.1.2", ROUTER_MAX_HOST - 1);
    idx = router_add_upstream(router, &upstream);
    ASSERT_EQ(idx, 1);
    ASSERT_EQ(router_get_upstream_count(router), 2);

    upstream_t *u = router_get_upstream(router, 0);
    ASSERT_NOT_NULL(u);
    ASSERT_STR_EQ(u->config.host, "192.168.1.1");

    router_destroy(router);
    TEST_PASS();
}

static int test_router_glob_match(void)
{
    TEST_START();

    /* Exact match */
    ASSERT_TRUE(router_glob_match("hello", "hello"));
    ASSERT_FALSE(router_glob_match("hello", "world"));

    /* Star wildcard */
    ASSERT_TRUE(router_glob_match("*", "anything"));
    ASSERT_TRUE(router_glob_match("*", ""));
    ASSERT_TRUE(router_glob_match("hello*", "helloworld"));
    ASSERT_TRUE(router_glob_match("*world", "helloworld"));
    ASSERT_TRUE(router_glob_match("*lo*", "helloworld"));
    ASSERT_FALSE(router_glob_match("hello*", "world"));

    /* Question mark wildcard */
    ASSERT_TRUE(router_glob_match("h?llo", "hello"));
    ASSERT_TRUE(router_glob_match("h?llo", "hallo"));
    ASSERT_FALSE(router_glob_match("h?llo", "hllo"));

    /* Combined */
    ASSERT_TRUE(router_glob_match("*.example.com", "www.example.com"));
    ASSERT_TRUE(router_glob_match("user-*", "user-admin"));
    ASSERT_TRUE(router_glob_match("192.168.*.*", "192.168.1.1"));

    TEST_PASS();
}

static int test_router_resolve(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);

    /* Add upstreams */
    upstream_config_t upstream = {
        .port = 22,
        .weight = 1,
        .enabled = true
    };
    strncpy(upstream.host, "server1.example.com", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    strncpy(upstream.host, "server2.example.com", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    /* Test round-robin */
    route_result_t result;
    ASSERT_EQ(router_resolve(router, "user1", "target", &result), 0);
    ASSERT_NOT_NULL(result.upstream);
    ASSERT_STR_EQ(result.upstream->config.host, "server1.example.com");

    ASSERT_EQ(router_resolve(router, "user2", "target", &result), 0);
    ASSERT_STR_EQ(result.upstream->config.host, "server2.example.com");

    ASSERT_EQ(router_resolve(router, "user3", "target", &result), 0);
    ASSERT_STR_EQ(result.upstream->config.host, "server1.example.com");

    router_destroy(router);
    TEST_PASS();
}

static int test_router_rules(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);

    /* Add upstreams */
    upstream_config_t upstream = {
        .port = 22,
        .weight = 1,
        .enabled = true
    };
    strncpy(upstream.host, "prod-server", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    strncpy(upstream.host, "dev-server", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    /* Add rule: admin users go to dev-server (index 1) */
    route_rule_t rule = {
        .name = "admin-rule",
        .match_username = "admin*",
        .match_target = "",
        .upstream_index = 1,
        .enabled = true
    };
    ASSERT_EQ(router_add_rule(router, &rule), 0);

    /* Test rule matching */
    route_result_t result;
    ASSERT_EQ(router_resolve(router, "admin-john", "any-target", &result), 0);
    ASSERT_STR_EQ(result.upstream->config.host, "dev-server");
    ASSERT_STR_EQ(result.matched_rule, "admin-rule");

    /* Non-admin should go through LB */
    ASSERT_EQ(router_resolve(router, "regular-user", "any-target", &result), 0);
    ASSERT_NULL(result.matched_rule);

    router_destroy(router);
    TEST_PASS();
}

static int test_router_null_handling(void)
{
    TEST_START();

    ASSERT_NULL(router_create(NULL));
    ASSERT_EQ(router_get_upstream_count(NULL), 0);
    ASSERT_NULL(router_get_upstream(NULL, 0));
    ASSERT_EQ(router_add_upstream(NULL, NULL), -1);

    router_destroy(NULL);  /* Should not crash */

    TEST_PASS();
}

static int test_router_consistent_hash_minimizes_reassignment(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_HASH,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);

    upstream_config_t upstream = {
        .port = 22,
        .weight = 1,
        .enabled = true
    };
    strncpy(upstream.host, "server1.example.com", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);
    strncpy(upstream.host, "server2.example.com", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);
    strncpy(upstream.host, "server3.example.com", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    int before[128];
    memset(before, -1, sizeof(before));
    for (int i = 0; i < 128; i++) {
        char username[32];
        route_result_t result;
        snprintf(username, sizeof(username), "user-%03d", i);
        ASSERT_EQ(router_resolve(router, username, "target", &result), 0);
        before[i] = result.upstream_index;
    }

    ASSERT_EQ(router_remove_upstream(router, 1), 0);

    int moved_from_survivor = 0;
    int moved_from_removed = 0;
    for (int i = 0; i < 128; i++) {
        char username[32];
        route_result_t result;
        snprintf(username, sizeof(username), "user-%03d", i);
        ASSERT_EQ(router_resolve(router, username, "target", &result), 0);
        if (before[i] == 1) {
            if (result.upstream_index != 1) {
                moved_from_removed++;
            }
        } else if (result.upstream_index != before[i]) {
            moved_from_survivor++;
        }
    }

    ASSERT_TRUE(moved_from_removed > 0);
    ASSERT_EQ(moved_from_survivor, 0);

    router_destroy(router);
    TEST_PASS();
}

static int test_router_weighted_routing(void)
{
    TEST_START();

    router_config_t config = {
        .lb_policy = LB_POLICY_WEIGHTED,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&config);
    ASSERT_NOT_NULL(router);

    upstream_config_t upstream = {
        .port = 22,
        .enabled = true
    };
    upstream.weight = 1;
    strncpy(upstream.host, "small-capacity", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    upstream.weight = 3;
    strncpy(upstream.host, "large-capacity", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    int small_hits = 0;
    int large_hits = 0;
    route_result_t result;
    for (int i = 0; i < 40; i++) {
        ASSERT_EQ(router_resolve(router, "user", "target", &result), 0);
        if (strcmp(result.upstream->config.host, "small-capacity") == 0) {
            small_hits++;
        } else if (strcmp(result.upstream->config.host, "large-capacity") == 0) {
            large_hits++;
        }
    }

    ASSERT_EQ(small_hits, 10);
    ASSERT_EQ(large_hits, 30);

    router_destroy(router);
    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);
    printf("=== Router Tests ===\n\n");

    int failed = 0;
    failed += test_router_create();
    failed += test_router_add_upstream();
    failed += test_router_glob_match();
    failed += test_router_resolve();
    failed += test_router_rules();
    failed += test_router_null_handling();
    failed += test_router_consistent_hash_minimizes_reassignment();
    failed += test_router_weighted_routing();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failed);
    }

    log_shutdown();
    return failed;
}
