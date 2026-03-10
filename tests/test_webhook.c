/**
 * @file test_webhook.c
 * @brief Unit tests for the webhook event notification module
 */

#include "test_utils.h"
#include "webhook.h"
#include <string.h>

/* ---- event name mapping ---- */

static int test_event_names(void)
{
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_AUTH_SUCCESS),       "auth.success");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_AUTH_FAILURE),       "auth.failure");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_SESSION_START),      "session.start");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_SESSION_END),        "session.end");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_RATE_LIMIT),         "rate_limit.triggered");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_IP_ACL_DENIED),      "ip_acl.denied");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_UPSTREAM_UNHEALTHY), "upstream.unhealthy");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_UPSTREAM_HEALTHY),   "upstream.healthy");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_CONFIG_RELOADED),    "config.reloaded");
    ASSERT_STR_EQ(webhook_event_name((webhook_event_type_t)0),          "unknown");
    return 0;
}

/* ---- payload builder ---- */

static int test_build_payload(void)
{
    char buf[1024];
    int len = webhook_build_payload(buf, sizeof(buf),
                                    "auth.failure", "admin",
                                    "192.168.1.1", "bad password");
    ASSERT_TRUE(len > 0);
    ASSERT_TRUE(strstr(buf, "\"event\":\"auth.failure\"")     != NULL);
    ASSERT_TRUE(strstr(buf, "\"username\":\"admin\"")         != NULL);
    ASSERT_TRUE(strstr(buf, "\"client_addr\":\"192.168.1.1\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"detail\":\"bad password\"")    != NULL);
    ASSERT_TRUE(strstr(buf, "\"timestamp\":")                 != NULL);
    return 0;
}

static int test_build_payload_nulls(void)
{
    char buf[1024];
    int len = webhook_build_payload(buf, sizeof(buf), NULL, NULL, NULL, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_TRUE(strstr(buf, "\"event\":\"unknown\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"username\":\"\"")     != NULL);
    ASSERT_TRUE(strstr(buf, "\"client_addr\":\"\"")  != NULL);
    ASSERT_TRUE(strstr(buf, "\"detail\":\"\"")       != NULL);
    return 0;
}

static int test_build_payload_invalid(void)
{
    ASSERT_EQ(webhook_build_payload(NULL, 0, "e", NULL, NULL, NULL), -1);
    return 0;
}

/* ---- manager lifecycle ---- */

static int test_create_disabled(void)
{
    webhook_config_t config;
    memset(&config, 0, sizeof(config));
    config.enabled = false;
    webhook_manager_t *mgr = webhook_manager_create(&config);
    ASSERT_NULL(mgr);
    return 0;
}

static int test_create_null(void)
{
    webhook_manager_t *mgr = webhook_manager_create(NULL);
    ASSERT_NULL(mgr);
    return 0;
}

static int test_notify_null(void)
{
    ASSERT_EQ(webhook_notify(NULL, WEBHOOK_EVENT_AUTH_FAILURE, "{}"), -1);
    return 0;
}

static int test_destroy_null(void)
{
    webhook_manager_destroy(NULL);  /* must not crash */
    return 0;
}

/* ---- event mask bitmask logic ---- */

static int test_event_mask(void)
{
    uint32_t mask = (uint32_t)WEBHOOK_EVENT_AUTH_FAILURE
                  | (uint32_t)WEBHOOK_EVENT_RATE_LIMIT;

    ASSERT_TRUE(mask & (uint32_t)WEBHOOK_EVENT_AUTH_FAILURE);
    ASSERT_TRUE(mask & (uint32_t)WEBHOOK_EVENT_RATE_LIMIT);
    ASSERT_FALSE(mask & (uint32_t)WEBHOOK_EVENT_SESSION_START);
    return 0;
}

static int test_event_all_mask(void)
{
    uint32_t all = (uint32_t)WEBHOOK_EVENT_ALL;

    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_AUTH_SUCCESS);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_AUTH_FAILURE);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_SESSION_START);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_SESSION_END);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_RATE_LIMIT);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_IP_ACL_DENIED);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_UPSTREAM_UNHEALTHY);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_UPSTREAM_HEALTHY);
    ASSERT_TRUE(all & (uint32_t)WEBHOOK_EVENT_CONFIG_RELOADED);
    return 0;
}

/* ---- manager create/destroy round-trip ---- */

static int test_create_destroy(void)
{
    webhook_config_t config;
    memset(&config, 0, sizeof(config));
    config.enabled    = true;
    config.event_mask = (uint32_t)WEBHOOK_EVENT_ALL;
    config.queue_size = 16;
    snprintf(config.url, sizeof(config.url), "http://127.0.0.1:19999/hook");

    webhook_manager_t *mgr = webhook_manager_create(&config);
    ASSERT_NOT_NULL(mgr);
    webhook_manager_destroy(mgr);
    return 0;
}

/* ---- entry point ---- */

int main(void)
{
    TEST_BEGIN("Webhook Tests");

    RUN_TEST(test_event_names);
    RUN_TEST(test_build_payload);
    RUN_TEST(test_build_payload_nulls);
    RUN_TEST(test_build_payload_invalid);
    RUN_TEST(test_create_disabled);
    RUN_TEST(test_create_null);
    RUN_TEST(test_notify_null);
    RUN_TEST(test_destroy_null);
    RUN_TEST(test_event_mask);
    RUN_TEST(test_event_all_mask);
    RUN_TEST(test_create_destroy);

    TEST_END();
}
