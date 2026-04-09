/**
 * @file test_webhook_runtime.c
 * @brief Unit tests for webhook runtime integration
 */

#include "config.h"
#include "test_utils.h"
#include "webhook_runtime.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_runtime_config(webhook_config_t *config, const char *dlq_path)
{
    memset(config, 0, sizeof(*config));
    config->enabled = true;
    config->event_mask = (uint32_t)WEBHOOK_EVENT_ALL;
    config->queue_size = 8;
    config->retry_max = 1;
    config->retry_delay_ms = 10;
    config->timeout_ms = 10;
    snprintf(config->url, sizeof(config->url), "http://127.0.0.1:1/hook");
    snprintf(config->dead_letter_path, sizeof(config->dead_letter_path), "%s",
             dlq_path);
}

static int read_file(const char *path, char *buf, size_t buf_size)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    size_t n = fread(buf, 1, buf_size - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static int count_substr(const char *haystack, const char *needle)
{
    int count = 0;
    const char *pos = haystack;
    size_t needle_len = strlen(needle);

    while ((pos = strstr(pos, needle)) != NULL) {
        count++;
        pos += needle_len;
    }

    return count;
}

static int test_runtime_emit_writes_dlq(void)
{
    char dlq_path[256];
    snprintf(dlq_path, sizeof(dlq_path),
             "/tmp/sshproxy-webhook-runtime-%ld.jsonl", (long)getpid());
    unlink(dlq_path);

    webhook_config_t config;
    fill_runtime_config(&config, dlq_path);

    webhook_runtime_t runtime;
    ASSERT_EQ(webhook_runtime_init(&runtime, &config), 0);
    ASSERT_EQ(webhook_runtime_emit(&runtime, WEBHOOK_EVENT_AUTH_FAILURE,
                                   "alice", "127.0.0.1", "bad password"), 0);

    usleep(200000);
    webhook_runtime_destroy(&runtime);

    char buf[2048];
    ASSERT_EQ(read_file(dlq_path, buf, sizeof(buf)), 0);
    unlink(dlq_path);

    ASSERT_TRUE(strstr(buf, "\"event\":\"auth.failure\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"attempts\":2") != NULL);
    ASSERT_TRUE(strstr(buf, "alice") != NULL);
    return 0;
}

static int test_runtime_reload_can_disable_delivery(void)
{
    char dlq_path[256];
    snprintf(dlq_path, sizeof(dlq_path),
             "/tmp/sshproxy-webhook-runtime-reload-%ld.jsonl", (long)getpid());
    unlink(dlq_path);

    webhook_config_t enabled;
    fill_runtime_config(&enabled, dlq_path);

    webhook_runtime_t runtime;
    ASSERT_EQ(webhook_runtime_init(&runtime, &enabled), 0);
    ASSERT_EQ(webhook_runtime_emit(&runtime, WEBHOOK_EVENT_AUTH_FAILURE,
                                   "alice", "127.0.0.1", NULL), 0);

    webhook_config_t disabled;
    memset(&disabled, 0, sizeof(disabled));
    ASSERT_EQ(webhook_runtime_reload(&runtime, &disabled), 0);
    ASSERT_EQ(webhook_runtime_emit(&runtime, WEBHOOK_EVENT_AUTH_FAILURE,
                                   "bob", "127.0.0.1", NULL), 0);

    usleep(200000);
    webhook_runtime_destroy(&runtime);

    char buf[2048];
    ASSERT_EQ(read_file(dlq_path, buf, sizeof(buf)), 0);
    unlink(dlq_path);

    ASSERT_EQ(count_substr(buf, "\"attempts\":2"), 1);
    ASSERT_TRUE(strstr(buf, "alice") != NULL);
    ASSERT_TRUE(strstr(buf, "bob") == NULL);
    return 0;
}

static int test_runtime_emits_config_diff_events(void)
{
    char dlq_path[256];
    snprintf(dlq_path, sizeof(dlq_path),
             "/tmp/sshproxy-webhook-runtime-diff-%ld.jsonl", (long)getpid());
    unlink(dlq_path);

    webhook_config_t config;
    fill_runtime_config(&config, dlq_path);

    webhook_runtime_t runtime;
    ASSERT_EQ(webhook_runtime_init(&runtime, &config), 0);

    proxy_config_t *old_config = config_create();
    proxy_config_t *new_config = config_create();
    ASSERT_NOT_NULL(old_config);
    ASSERT_NOT_NULL(new_config);

    ASSERT_EQ(config_add_user(old_config, "alice", "hash-v1", NULL), 0);
    ASSERT_EQ(config_add_user(old_config, "carol", "hash-v1", NULL), 0);
    ASSERT_EQ(config_add_policy(old_config, "alice", "db-*", 1, 0), 0);

    ASSERT_EQ(config_add_user(new_config, "alice", "hash-v2", NULL), 0);
    ASSERT_EQ(config_add_user(new_config, "bob", "hash-v1", NULL), 0);
    ASSERT_EQ(config_add_policy(new_config, "alice", "db-*", 2, 0), 0);

    webhook_runtime_emit_config_diff(&runtime, old_config, new_config,
                                     "reload:/tmp/test.conf");

    usleep(500000);
    webhook_runtime_destroy(&runtime);
    config_destroy(old_config);
    config_destroy(new_config);

    char buf[4096];
    ASSERT_EQ(read_file(dlq_path, buf, sizeof(buf)), 0);
    unlink(dlq_path);

    ASSERT_TRUE(strstr(buf, "user.updated") != NULL);
    ASSERT_TRUE(strstr(buf, "user.created") != NULL);
    ASSERT_TRUE(strstr(buf, "user.deleted") != NULL);
    ASSERT_TRUE(strstr(buf, "policy.updated") != NULL);
    ASSERT_TRUE(strstr(buf, "config.reloaded") != NULL);
    ASSERT_TRUE(strstr(buf, "alice") != NULL);
    ASSERT_TRUE(strstr(buf, "bob") != NULL);
    ASSERT_TRUE(strstr(buf, "carol") != NULL);
    return 0;
}

int main(void)
{
    TEST_BEGIN("Webhook Runtime Tests");

    RUN_TEST(test_runtime_emit_writes_dlq);
    RUN_TEST(test_runtime_reload_can_disable_delivery);
    RUN_TEST(test_runtime_emits_config_diff_events);

    TEST_END();
}
