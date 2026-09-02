/**
 * @file test_webhook.c
 * @brief Unit tests for the webhook event notification module
 */

#include "test_utils.h"
#include "webhook.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int listen_fd;
} slow_webhook_server_t;

static void *slow_webhook_server_main(void *arg)
{
    slow_webhook_server_t *server = (slow_webhook_server_t *)arg;
    if (server == NULL || server->listen_fd < 0) {
        return NULL;
    }

    int client_fd = accept(server->listen_fd, NULL, NULL);
    if (client_fd >= 0) {
        usleep(500000);
        const char *response =
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        write(client_fd, response, strlen(response));
        close(client_fd);
    }

    close(server->listen_fd);
    server->listen_fd = -1;
    return NULL;
}

static int start_slow_webhook_server(slow_webhook_server_t *server, pthread_t *thread,
                                     uint16_t *port_out)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    server->listen_fd = fd;
    *port_out = ntohs(addr.sin_port);
    if (pthread_create(thread, NULL, slow_webhook_server_main, server) != 0) {
        close(fd);
        server->listen_fd = -1;
        return -1;
    }

    return 0;
}

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
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_USER_CREATED),       "user.created");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_USER_UPDATED),       "user.updated");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_USER_DELETED),       "user.deleted");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_POLICY_UPDATED),     "policy.updated");
    ASSERT_STR_EQ(webhook_event_name(WEBHOOK_EVENT_CERT_ISSUED),        "certificate.issued");
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

static int test_sign_payload(void)
{
    webhook_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.hmac_secret, sizeof(config.hmac_secret), "secret-key");

    char signature[65];
    int len = webhook_sign_payload(&config, "{\"event\":\"auth.failure\"}",
                                   signature, sizeof(signature));
    ASSERT_EQ(len, 64);
    ASSERT_STR_EQ(signature,
                  "b3150c2031c684535bca5b1b893d41c9039e4f73e9e3f8adee4e5b5061858661");
    return 0;
}

static int test_dead_letter_queue(void)
{
    char dlq_path[256];
    snprintf(dlq_path, sizeof(dlq_path),
             "/tmp/sshproxy-webhook-dlq-%ld.jsonl", (long)getpid());
    unlink(dlq_path);

    webhook_config_t config;
    memset(&config, 0, sizeof(config));
    config.enabled        = true;
    config.event_mask     = (uint32_t)WEBHOOK_EVENT_ALL;
    config.queue_size     = 4;
    config.retry_max      = 1;
    config.retry_delay_ms = 10;
    config.timeout_ms     = 10;
    snprintf(config.url, sizeof(config.url), "http://127.0.0.1:1/hook");
    snprintf(config.dead_letter_path, sizeof(config.dead_letter_path), "%s",
             dlq_path);

    webhook_manager_t *mgr = webhook_manager_create(&config);
    ASSERT_NOT_NULL(mgr);
    ASSERT_EQ(webhook_notify(mgr, WEBHOOK_EVENT_AUTH_FAILURE,
                             "{\"event\":\"auth.failure\"}"), 0);

    usleep(200000);
    webhook_manager_destroy(mgr);

    FILE *fp = fopen(dlq_path, "r");
    ASSERT_NOT_NULL(fp);

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    unlink(dlq_path);
    buf[n] = '\0';

    ASSERT_TRUE(strstr(buf, "\"event\":\"auth.failure\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"attempts\":2") != NULL);
    ASSERT_TRUE(strstr(buf, "\\\"event\\\":\\\"auth.failure\\\"") != NULL);
    return 0;
}

static int test_queue_full_spills_to_dead_letter(void)
{
    char dlq_path[256];
    snprintf(dlq_path, sizeof(dlq_path),
             "/tmp/sshproxy-webhook-queue-full-%ld.jsonl", (long)getpid());
    unlink(dlq_path);

    slow_webhook_server_t server = {.listen_fd = -1};
    pthread_t thread;
    uint16_t port = 0;
    ASSERT_EQ(start_slow_webhook_server(&server, &thread, &port), 0);

    webhook_config_t config;
    memset(&config, 0, sizeof(config));
    config.enabled = true;
    config.event_mask = (uint32_t)WEBHOOK_EVENT_ALL;
    config.queue_size = 1;
    config.retry_max = 0;
    config.timeout_ms = 1000;
    snprintf(config.url, sizeof(config.url), "http://127.0.0.1:%u/hook", (unsigned)port);
    snprintf(config.dead_letter_path, sizeof(config.dead_letter_path), "%s", dlq_path);

    webhook_manager_t *mgr = webhook_manager_create(&config);
    ASSERT_NOT_NULL(mgr);
    ASSERT_EQ(webhook_notify(mgr, WEBHOOK_EVENT_AUTH_FAILURE,
                             "{\"event\":\"auth.failure\",\"detail\":\"first\"}"), 0);

    int spilled = 0;
    for (int i = 0; i < 8; i++) {
        char payload[128];
        snprintf(payload, sizeof(payload),
                 "{\"event\":\"auth.failure\",\"detail\":\"overflow-marker-%d\"}", i);
        if (webhook_notify(mgr, WEBHOOK_EVENT_AUTH_FAILURE, payload) != 0) {
            spilled++;
        }
    }
    ASSERT_TRUE(spilled > 0);

    usleep(800000);
    webhook_manager_destroy(mgr);
    pthread_join(thread, NULL);

    FILE *fp = fopen(dlq_path, "r");
    ASSERT_NOT_NULL(fp);

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    unlink(dlq_path);
    buf[n] = '\0';

    ASSERT_TRUE(strstr(buf, "\"attempts\":0") != NULL);
    ASSERT_TRUE(strstr(buf, "overflow-marker-") != NULL);
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
    RUN_TEST(test_sign_payload);
    RUN_TEST(test_dead_letter_queue);
    RUN_TEST(test_queue_full_spills_to_dead_letter);

    TEST_END();
}
