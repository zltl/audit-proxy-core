/**
 * @file test_integration.c
 * @brief Integration tests for SSH Proxy Core
 *
 * Tests the complete data flow through all components:
 * Session Manager -> Filter Chain -> Router
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "session.h"
#include "filter.h"
#include "router.h"
#include "account_lock.h"
#include "auth_filter.h"
#include "rbac_filter.h"
#include "audit_filter.h"
#include "rate_limit_filter.h"
#include "logger.h"
#include "test_utils.h"

/* ========== Test: Complete Workflow ========== */

static int test_complete_workflow(void)
{
    TEST_START();

    /* 1. Create Session Manager */
    session_manager_config_t sm_cfg = {
        .max_sessions = 100,
        .session_timeout = 3600,
        .auth_timeout = 60
    };
    session_manager_t *session_mgr = session_manager_create(&sm_cfg);
    ASSERT_NOT_NULL(session_mgr);
    printf("    [1] Session Manager created\n");

    /* 2. Create Filter Chain */
    filter_chain_t *filters = filter_chain_create();
    ASSERT_NOT_NULL(filters);
    printf("    [2] Filter Chain created\n");

    /* 3. Create Router with upstreams */
    router_config_t router_cfg = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };
    router_t *router = router_create(&router_cfg);
    ASSERT_NOT_NULL(router);

    upstream_config_t upstream = {
        .port = 22,
        .weight = 1,
        .enabled = true
    };
    strncpy(upstream.host, "server1.example.com", ROUTER_MAX_HOST - 1);
    ASSERT_EQ(router_add_upstream(router, &upstream), 0);

    strncpy(upstream.host, "server2.example.com", ROUTER_MAX_HOST - 1);
    ASSERT_EQ(router_add_upstream(router, &upstream), 1);
    printf("    [3] Router created with 2 upstreams\n");

    /* 4. Test route resolution */
    route_result_t result;
    ASSERT_EQ(router_resolve(router, "testuser", "target.example.com", &result), 0);
    ASSERT_NOT_NULL(result.upstream);
    printf("    [4] Route resolved to: %s\n", result.upstream->config.host);

    /* Cleanup */
    router_destroy(router);
    filter_chain_destroy(filters);
    session_manager_destroy(session_mgr);

    TEST_PASS();
}

/* ========== Test: Filter Chain Processing ========== */

static int g_connect_called = 0;
static int g_auth_called = 0;
static int g_close_called = 0;

static filter_status_t mock_on_connect(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    g_connect_called++;
    return FILTER_CONTINUE;
}

static filter_status_t mock_on_auth(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    g_auth_called++;
    return FILTER_CONTINUE;
}

static void mock_on_close(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    g_close_called++;
}

static int test_filter_chain_workflow(void)
{
    TEST_START();

    g_connect_called = 0;
    g_auth_called = 0;
    g_close_called = 0;

    /* Create filter chain */
    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);

    /* Add multiple filters */
    filter_callbacks_t cb1 = {
        .on_connect = mock_on_connect,
        .on_auth = mock_on_auth,
        .on_close = mock_on_close
    };
    filter_t *f1 = filter_create("filter1", FILTER_TYPE_CUSTOM, &cb1, NULL);
    filter_t *f2 = filter_create("filter2", FILTER_TYPE_CUSTOM, &cb1, NULL);
    filter_t *f3 = filter_create("filter3", FILTER_TYPE_CUSTOM, &cb1, NULL);

    filter_chain_add(chain, f1);
    filter_chain_add(chain, f2);
    filter_chain_add(chain, f3);

    ASSERT_EQ(filter_chain_count(chain), 3);
    printf("    Added 3 filters to chain\n");

    /* Simulate connection lifecycle */
    filter_context_t ctx = {0};

    /* on_connect - all 3 filters */
    filter_status_t status = filter_chain_on_connect(chain, &ctx);
    ASSERT_EQ(status, FILTER_CONTINUE);
    ASSERT_EQ(g_connect_called, 3);
    printf("    on_connect: called 3 times\n");

    /* on_auth - all 3 filters */
    status = filter_chain_on_auth(chain, &ctx);
    ASSERT_EQ(status, FILTER_CONTINUE);
    ASSERT_EQ(g_auth_called, 3);
    printf("    on_auth: called 3 times\n");

    /* on_close - all 3 filters */
    filter_chain_on_close(chain, &ctx);
    ASSERT_EQ(g_close_called, 3);
    printf("    on_close: called 3 times\n");

    filter_chain_destroy(chain);
    TEST_PASS();
}

/* ========== Test: Filter Rejection ========== */

static filter_status_t reject_on_connect(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    return FILTER_REJECT;
}

static int test_filter_rejection(void)
{
    TEST_START();

    filter_chain_t *chain = filter_chain_create();
    ASSERT_NOT_NULL(chain);

    /* Add rejecting filter */
    filter_callbacks_t cb = {
        .on_connect = reject_on_connect
    };
    filter_t *f = filter_create("rejector", FILTER_TYPE_CUSTOM, &cb, NULL);
    filter_chain_add(chain, f);

    /* Should reject */
    filter_context_t ctx = {0};
    filter_status_t status = filter_chain_on_connect(chain, &ctx);
    ASSERT_EQ(status, FILTER_REJECT);
    printf("    Filter correctly rejected connection\n");

    filter_chain_destroy(chain);
    TEST_PASS();
}

/* ========== Test: RBAC Access Control ========== */

static int test_rbac_workflow(void)
{
    TEST_START();

    /* Create RBAC config */
    rbac_filter_config_t cfg = {
        .default_action = RBAC_ACTION_DENY,
        .log_denials = true,
        .roles = NULL,
        .user_roles = NULL
    };

    /* Add roles */
    ASSERT_EQ(rbac_add_role(&cfg, "admin"), 0);
    ASSERT_EQ(rbac_add_role(&cfg, "developer"), 0);
    printf("    Added roles: admin, developer\n");

    /* Add permissions */
    ASSERT_EQ(rbac_add_permission(&cfg, "admin", "*", RBAC_ACTION_ALLOW), 0);
    ASSERT_EQ(rbac_add_permission(&cfg, "developer", "dev-*", RBAC_ACTION_ALLOW), 0);
    ASSERT_EQ(rbac_add_permission(&cfg, "developer", "prod-*", RBAC_ACTION_DENY), 0);
    printf("    Added permissions\n");

    /* Assign roles */
    ASSERT_EQ(rbac_assign_role(&cfg, "admin-*", "admin"), 0);
    ASSERT_EQ(rbac_assign_role(&cfg, "dev-*", "developer"), 0);
    printf("    Assigned roles to users\n");

    /* Test access checks */
    rbac_action_t action;

    /* Admin can access anything */
    action = rbac_check_access(&cfg, "admin-john", "prod-server1");
    ASSERT_EQ(action, RBAC_ACTION_ALLOW);
    printf("    admin-john -> prod-server1: ALLOW (correct)\n");

    /* Developer can access dev servers */
    action = rbac_check_access(&cfg, "dev-alice", "dev-server1");
    ASSERT_EQ(action, RBAC_ACTION_ALLOW);
    printf("    dev-alice -> dev-server1: ALLOW (correct)\n");

    /* Developer cannot access prod servers */
    action = rbac_check_access(&cfg, "dev-alice", "prod-server1");
    ASSERT_EQ(action, RBAC_ACTION_DENY);
    printf("    dev-alice -> prod-server1: DENY (correct)\n");

    /* Unknown user - default deny */
    action = rbac_check_access(&cfg, "unknown-user", "any-server");
    ASSERT_EQ(action, RBAC_ACTION_DENY);
    printf("    unknown-user -> any-server: DENY (correct)\n");

    /* Cleanup */
    rbac_role_t *role = cfg.roles;
    while (role) {
        rbac_role_t *next = role->next;
        rbac_permission_t *perm = role->permissions;
        while (perm) {
            rbac_permission_t *pnext = perm->next;
            free(perm);
            perm = pnext;
        }
        free(role);
        role = next;
    }
    rbac_user_role_t *ur = cfg.user_roles;
    while (ur) {
        rbac_user_role_t *next = ur->next;
        free(ur);
        ur = next;
    }

    TEST_PASS();
}

/* ========== Test: Rate Limiting ========== */

static int test_rate_limit_workflow(void)
{
    TEST_START();

    /* Create rate limit config */
    rate_limit_filter_config_t cfg = {
        .global_max_connections = 5,
        .global_max_rate = 3,
        .global_interval_sec = 1,
        .log_rejections = false,
        .rules = NULL
    };

    filter_t *filter = rate_limit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);
    printf("    Rate limit filter created (max_conn=5, rate=3/s)\n");

    /* Simulate connections */
    rate_limit_result_t result;

    /* First 3 should succeed (within rate) */
    result = rate_limit_check(filter, "192.168.1.1", NULL);
    ASSERT_EQ(result, RATE_LIMIT_ALLOW);

    result = rate_limit_check(filter, "192.168.1.2", NULL);
    ASSERT_EQ(result, RATE_LIMIT_ALLOW);

    result = rate_limit_check(filter, "192.168.1.3", NULL);
    ASSERT_EQ(result, RATE_LIMIT_ALLOW);
    printf("    First 3 connections: ALLOW\n");

    /* 4th should be throttled (rate limit) */
    result = rate_limit_check(filter, "192.168.1.4", NULL);
    ASSERT_EQ(result, RATE_LIMIT_THROTTLE);
    printf("    4th connection: THROTTLE (rate limit)\n");

    /* Release some connections */
    rate_limit_release(filter, "192.168.1.1", NULL);
    rate_limit_release(filter, "192.168.1.2", NULL);
    rate_limit_release(filter, "192.168.1.3", NULL);
    printf("    Released 3 connections\n");

    /* Wait for rate window to reset */
    sleep(2);

    /* Should allow again after window reset */
    result = rate_limit_check(filter, "192.168.1.5", NULL);
    ASSERT_EQ(result, RATE_LIMIT_ALLOW);
    printf("    After 2s wait: ALLOW (rate reset)\n");

    filter_chain_destroy(NULL);  /* Proper cleanup would need chain */
    free(filter->state);
    free(filter->config);
    free(filter);

    TEST_PASS();
}

/* ========== Test: Router Load Balancing ========== */

static int test_router_load_balancing(void)
{
    TEST_START();

    /* Test Round Robin */
    router_config_t cfg = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };

    router_t *router = router_create(&cfg);
    ASSERT_NOT_NULL(router);

    upstream_config_t upstream = { .port = 22, .weight = 1, .enabled = true };

    strncpy(upstream.host, "server-a", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    strncpy(upstream.host, "server-b", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    strncpy(upstream.host, "server-c", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);

    printf("    Added 3 upstreams: server-a, server-b, server-c\n");

    /* Round robin should cycle through servers */
    route_result_t result;
    const char *expected[] = {"server-a", "server-b", "server-c", "server-a", "server-b"};

    for (int i = 0; i < 5; i++) {
        router_resolve(router, "user", "target", &result);
        ASSERT_STR_EQ(result.upstream->config.host, expected[i]);
    }
    printf("    Round robin correctly cycles through servers\n");

    router_destroy(router);
    TEST_PASS();
}

/* ========== Test: Router with Rules ========== */

static int test_router_with_rules(void)
{
    TEST_START();

    router_config_t cfg = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 5000,
        .health_check_enabled = false
    };

    router_t *router = router_create(&cfg);
    ASSERT_NOT_NULL(router);

    /* Add upstreams */
    upstream_config_t upstream = { .port = 22, .weight = 1, .enabled = true };

    strncpy(upstream.host, "prod-cluster", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);  /* index 0 */

    strncpy(upstream.host, "staging-cluster", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);  /* index 1 */

    strncpy(upstream.host, "dev-cluster", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream);  /* index 2 */

    printf("    Added upstreams: prod(0), staging(1), dev(2)\n");

    /* Add routing rules */
    route_rule_t rule1 = {
        .name = "admin-to-prod",
        .match_username = "admin*",
        .match_target = "",
        .upstream_index = 0,
        .enabled = true
    };
    router_add_rule(router, &rule1);

    route_rule_t rule2 = {
        .name = "qa-to-staging",
        .match_username = "qa*",
        .match_target = "",
        .upstream_index = 1,
        .enabled = true
    };
    router_add_rule(router, &rule2);

    route_rule_t rule3 = {
        .name = "dev-to-dev",
        .match_username = "dev*",
        .match_target = "",
        .upstream_index = 2,
        .enabled = true
    };
    router_add_rule(router, &rule3);

    printf("    Added 3 routing rules\n");

    /* Test routing */
    route_result_t result;

    router_resolve(router, "admin-john", "any", &result);
    ASSERT_STR_EQ(result.upstream->config.host, "prod-cluster");
    ASSERT_STR_EQ(result.matched_rule, "admin-to-prod");
    printf("    admin-john -> prod-cluster (rule: admin-to-prod)\n");

    router_resolve(router, "qa-alice", "any", &result);
    ASSERT_STR_EQ(result.upstream->config.host, "staging-cluster");
    ASSERT_STR_EQ(result.matched_rule, "qa-to-staging");
    printf("    qa-alice -> staging-cluster (rule: qa-to-staging)\n");

    router_resolve(router, "dev-bob", "any", &result);
    ASSERT_STR_EQ(result.upstream->config.host, "dev-cluster");
    ASSERT_STR_EQ(result.matched_rule, "dev-to-dev");
    printf("    dev-bob -> dev-cluster (rule: dev-to-dev)\n");

    /* No matching rule - falls back to LB */
    router_resolve(router, "guest", "any", &result);
    ASSERT_NULL(result.matched_rule);
    printf("    guest -> %s (LB fallback)\n", result.upstream->config.host);

    router_destroy(router);
    TEST_PASS();
}

/* ========== Test: Session Lifecycle ========== */

static int test_session_lifecycle(void)
{
    TEST_START();

    session_manager_config_t cfg = {
        .max_sessions = 10,
        .session_timeout = 3600,
        .auth_timeout = 60
    };

    session_manager_t *mgr = session_manager_create(&cfg);
    ASSERT_NOT_NULL(mgr);
    ASSERT_EQ(session_manager_get_count(mgr), 0);
    printf("    Session manager created (max=10)\n");

    /* Note: We can't create real sessions without SSH connections,
       but we can verify the manager works correctly */

    session_manager_destroy(mgr);
    printf("    Session manager destroyed\n");

    TEST_PASS();
}

/* ========== Test: Glob Pattern Matching ========== */

static int test_glob_patterns(void)
{
    TEST_START();

    /* IP patterns */
    ASSERT_TRUE(router_glob_match("192.168.*.*", "192.168.1.100"));
    ASSERT_TRUE(router_glob_match("10.0.0.*", "10.0.0.1"));
    ASSERT_FALSE(router_glob_match("192.168.1.*", "192.168.2.100"));
    printf("    IP patterns: OK\n");

    /* Username patterns */
    ASSERT_TRUE(router_glob_match("admin*", "admin-john"));
    ASSERT_TRUE(router_glob_match("*@example.com", "user@example.com"));
    ASSERT_TRUE(router_glob_match("dev-?", "dev-a"));
    ASSERT_FALSE(router_glob_match("dev-?", "dev-ab"));
    printf("    Username patterns: OK\n");

    /* Host patterns */
    ASSERT_TRUE(router_glob_match("*.example.com", "www.example.com"));
    ASSERT_TRUE(router_glob_match("*-prod-*", "web-prod-01"));
    ASSERT_TRUE(router_glob_match("db-*", "db-master"));
    printf("    Host patterns: OK\n");

    /* Edge cases */
    ASSERT_TRUE(router_glob_match("*", "anything"));
    ASSERT_TRUE(router_glob_match("*", ""));
    ASSERT_TRUE(router_glob_match("", ""));
    ASSERT_FALSE(router_glob_match("", "something"));
    printf("    Edge cases: OK\n");

    TEST_PASS();
}

/* ========== Test: Auth Filter ========== */

static auth_result_t test_auth_callback(const char *username,
                                        const char *password,
                                        void *user_data)
{
    (void)user_data;

    /* Simple test auth - accept "testuser" with "testpass" */
    if (strcmp(username, "testuser") == 0 &&
        strcmp(password, "testpass") == 0) {
        return AUTH_RESULT_SUCCESS;
    }
    return AUTH_RESULT_FAILURE;
}

static int test_auth_filter_workflow(void)
{
    TEST_START();

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_CALLBACK,
        .allow_password = true,
        .allow_pubkey = false,
        .max_attempts = 3,
        .timeout_sec = 60,
        .local_users = NULL,
        .password_cb = test_auth_callback,
        .pubkey_cb = NULL,
        .cb_user_data = NULL
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);
    printf("    Auth filter created with callback\n");

    /* Test successful auth */
    filter_context_t ctx = {
        .session = NULL,
        .username = "testuser",
        .password = "testpass"
    };

    filter_status_t status = filter->callbacks.on_auth(filter, &ctx);
    ASSERT_EQ(status, FILTER_CONTINUE);
    printf("    testuser/testpass: AUTH SUCCESS\n");

    /* Test failed auth */
    ctx.password = "wrongpass";
    status = filter->callbacks.on_auth(filter, &ctx);
    ASSERT_EQ(status, FILTER_REJECT);
    printf("    testuser/wrongpass: AUTH FAILED\n");

    /* Cleanup */
    if (filter->callbacks.destroy) {
        filter->callbacks.destroy(filter);
    }
    free(filter->config);
    free(filter);

    TEST_PASS();
}

static int test_auth_filter_ip_ban(void)
{
    TEST_START();

    account_lock_config_t lock_cfg = {
        .lockout_enabled = false,
        .lockout_threshold = 3,
        .lockout_duration_sec = 60,
        .ip_ban_enabled = true,
        .ip_ban_threshold = 2,
        .ip_ban_duration_sec = 60
    };
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_CALLBACK,
        .allow_password = true,
        .allow_pubkey = false,
        .max_attempts = 3,
        .timeout_sec = 60,
        .local_users = NULL,
        .password_cb = test_auth_callback,
        .pubkey_cb = NULL,
        .cb_user_data = NULL
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    session_manager_config_t sm_cfg = {
        .max_sessions = 4,
        .session_timeout = 60,
        .auth_timeout = 60
    };
    session_manager_t *session_mgr = session_manager_create(&sm_cfg);
    ASSERT_NOT_NULL(session_mgr);

    ssh_session client = ssh_new();
    ASSERT_NOT_NULL(client);

    session_t *session = session_manager_create_session(session_mgr, client);
    ASSERT_NOT_NULL(session);

    session_metadata_t *meta = session_get_metadata(session);
    ASSERT_NOT_NULL(meta);
    strncpy(meta->client_addr, "10.10.10.5", sizeof(meta->client_addr) - 1);

    filter_context_t ctx = {
        .session = session,
        .username = "testuser",
        .password = "wrongpass"
    };

    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_FALSE(account_ip_is_blocked("10.10.10.5"));
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_TRUE(account_ip_is_blocked("10.10.10.5"));

    ctx.password = "testpass";
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);

    if (filter->callbacks.destroy) {
        filter->callbacks.destroy(filter);
    }
    free(filter->config);
    free(filter);
    session_manager_destroy(session_mgr);
    account_lock_cleanup();

    TEST_PASS();
}

/* ========== Main ========== */

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║           SSH Proxy Core - Integration Tests                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    int failed = 0;

    printf("▶ Core Workflow Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_complete_workflow();
    failed += test_session_lifecycle();
    printf("\n");

    printf("▶ Filter Chain Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_filter_chain_workflow();
    failed += test_filter_rejection();
    printf("\n");

    printf("▶ Authentication Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_auth_filter_workflow();
    failed += test_auth_filter_ip_ban();
    printf("\n");

    printf("▶ RBAC Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_rbac_workflow();
    printf("\n");

    printf("▶ Rate Limiting Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_rate_limit_workflow();
    printf("\n");

    printf("▶ Router Tests\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    failed += test_router_load_balancing();
    failed += test_router_with_rules();
    failed += test_glob_patterns();
    printf("\n");

    printf("═════════════════════════════════════════════════════════════════\n");
    if (failed == 0) {
        printf("✓ All integration tests passed!\n");
    } else {
        printf("✗ %d test(s) failed.\n", failed);
    }
    printf("═════════════════════════════════════════════════════════════════\n");

    log_shutdown();
    return failed;
}
