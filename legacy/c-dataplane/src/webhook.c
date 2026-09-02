/**
 * @file webhook.c
 * @brief Webhook event notification system implementation
 *
 * Background worker thread processes a ring-buffer queue of events and
 * delivers them as HTTP POST requests over raw TCP sockets (no libcurl).
 */

#include "webhook.h"
#include "audit_sign.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_PAYLOAD_SIZE     4096
#define DEFAULT_QUEUE_SIZE   1024
#define DEFAULT_TIMEOUT_MS   5000
#define DEFAULT_RETRY_MAX    3
#define DEFAULT_RETRY_DELAY_MS 1000

/* Event queue entry */
typedef struct {
    webhook_event_type_t event_type;
    char payload[MAX_PAYLOAD_SIZE];
    int retries_left;
} webhook_event_t;

/* Webhook manager */
struct webhook_manager {
    webhook_config_t config;

    /* Event queue (ring buffer) */
    webhook_event_t *queue;
    int queue_capacity;
    int queue_head;
    int queue_tail;
    int queue_count;

    /* Threading */
    pthread_t worker_thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool running;
};

/* --------------- internal helpers --------------- */

/* Parse URL into host, port, path.  Only http:// is supported. */
static int parse_url(const char *url, char *host, size_t host_len,
                     uint16_t *port, char *path, size_t path_len)
{
    *port = 80;
    const char *p = url;

    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        LOG_WARN("Webhook: HTTPS not supported, use HTTP");
        return -1;
    }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_len) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = (uint16_t)atoi(colon + 1);
    } else if (slash) {
        size_t hlen = (size_t)(slash - p);
        if (hlen >= host_len) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
    } else {
        size_t len = strlen(p);
        if (len >= host_len) len = host_len - 1;
        memcpy(host, p, len);
        host[len] = '\0';
    }

    if (slash) {
        size_t len = strlen(slash);
        if (len >= path_len) len = path_len - 1;
        memcpy(path, slash, len);
        path[len] = '\0';
    } else {
        path[0] = '/';
        path[1] = '\0';
    }

    return 0;
}

static void write_json_escaped(FILE *fp, const char *value)
{
    if (fp == NULL || value == NULL) {
        return;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", fp);
            break;
        case '\\':
            fputs("\\\\", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*p >= 32 && *p < 127) {
                fputc(*p, fp);
            } else {
                fprintf(fp, "\\u%04x", *p);
            }
            break;
        }
    }
}

static void sync_dead_letter(FILE *fp, const char *path)
{
    if (fp == NULL) {
        return;
    }
    if (fflush(fp) != 0) {
        LOG_ERROR("Webhook: failed to flush dead-letter queue %s: %s",
                  path != NULL ? path : "-", strerror(errno));
        return;
    }
    if (fsync(fileno(fp)) != 0) {
        LOG_ERROR("Webhook: failed to sync dead-letter queue %s: %s",
                  path != NULL ? path : "-", strerror(errno));
    }
}

static void write_dead_letter(const webhook_config_t *config,
                              webhook_event_type_t event_type,
                              const char *payload,
                              int attempts)
{
    if (config == NULL || config->dead_letter_path[0] == '\0' ||
        payload == NULL) {
        return;
    }

    FILE *fp = fopen(config->dead_letter_path, "a");
    if (fp == NULL) {
        LOG_ERROR("Webhook: failed to open dead-letter queue %s: %s",
                  config->dead_letter_path, strerror(errno));
        return;
    }

    fprintf(fp,
            "{\"failed_at\":%ld,\"event\":\"%s\",\"attempts\":%d,\"payload\":\"",
            (long)time(NULL), webhook_event_name(event_type), attempts);
    write_json_escaped(fp, payload);
    fputs("\"}\n", fp);
    sync_dead_letter(fp, config->dead_letter_path);
    fclose(fp);
}

int webhook_sign_payload(const webhook_config_t *config,
                         const char *payload,
                         char *signature_hex,
                         size_t signature_hex_len)
{
    if (config == NULL || payload == NULL || signature_hex == NULL ||
        signature_hex_len < SHA256_HEX_SIZE + 1 ||
        config->hmac_secret[0] == '\0') {
        return -1;
    }

    uint8_t digest[SHA256_DIGEST_SIZE];
    hmac_sha256((const uint8_t *)config->hmac_secret,
                strlen(config->hmac_secret),
                (const uint8_t *)payload,
                strlen(payload),
                digest);
    hex_encode(digest, sizeof(digest), signature_hex);
    return SHA256_HEX_SIZE;
}

/* Send an HTTP POST with the given JSON payload.  Returns 0 on 2xx. */
static int send_http_post(const webhook_config_t *config, const char *payload)
{
    char host[256], path[256];
    uint16_t port;
    char signature[SHA256_HEX_SIZE + 1];
    bool has_signature = webhook_sign_payload(config, payload, signature,
                                              sizeof(signature)) > 0;

    if (parse_url(config->url, host, sizeof(host), &port,
                  path, sizeof(path)) != 0) {
        return -1;
    }

    /* Resolve host */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        LOG_ERROR("Webhook: DNS resolution failed for %s", host);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Set send/recv timeouts */
    int timeout_ms = config->timeout_ms > 0 ? config->timeout_ms
                                             : DEFAULT_TIMEOUT_MS;
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        LOG_ERROR("Webhook: Connect to %s:%u failed: %s",
                  host, (unsigned)port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /* Build HTTP request */
    int payload_len = (int)strlen(payload);
    char request[MAX_PAYLOAD_SIZE + 1024];
    int req_len = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "%s%s%s"
        "%s%s%s"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, (unsigned)port, payload_len,
        config->auth_header[0] ? "Authorization: " : "",
        config->auth_header[0] ? config->auth_header : "",
        config->auth_header[0] ? "\r\n" : "",
        has_signature ? "X-SSH-Proxy-Signature: sha256=" : "",
        has_signature ? signature : "",
        has_signature ? "\r\n" : "",
        payload);

    ssize_t sent = write(fd, request, (size_t)req_len);

    /* Read response – only the status line matters */
    char resp[1024];
    ssize_t received = read(fd, resp, sizeof(resp) - 1);
    close(fd);

    if (sent != req_len) return -1;
    if (received <= 0)   return -1;

    resp[received] = '\0';

    /* Check for 2xx status */
    int status = 0;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &status) == 1) {
        if (status >= 200 && status < 300) return 0;
        LOG_WARN("Webhook: HTTP %d response", status);
    }

    return -1;
}

/* --------------- worker thread --------------- */

static void *webhook_worker(void *arg)
{
    webhook_manager_t *mgr = (webhook_manager_t *)arg;

    while (true) {
        pthread_mutex_lock(&mgr->lock);

        while (mgr->running && mgr->queue_count == 0) {
            pthread_cond_wait(&mgr->cond, &mgr->lock);
        }

        if (!mgr->running && mgr->queue_count == 0) {
            pthread_mutex_unlock(&mgr->lock);
            break;
        }

        /* Dequeue event */
        webhook_event_t event = mgr->queue[mgr->queue_head];
        mgr->queue_head = (mgr->queue_head + 1) % mgr->queue_capacity;
        mgr->queue_count--;

        pthread_mutex_unlock(&mgr->lock);

        /* Attempt delivery with retries */
        int max_retries = event.retries_left;
        bool delivered  = false;

        for (int attempt = 0; attempt <= max_retries; attempt++) {
            if (attempt > 0) {
                int delay = mgr->config.retry_delay_ms > 0
                    ? mgr->config.retry_delay_ms : DEFAULT_RETRY_DELAY_MS;
                struct timespec ts;
                ts.tv_sec  = delay / 1000;
                ts.tv_nsec = (delay % 1000) * 1000000L;
                nanosleep(&ts, NULL);
                LOG_DEBUG("Webhook: Retry %d/%d for event %s",
                          attempt, max_retries,
                          webhook_event_name(event.event_type));
            }

            if (send_http_post(&mgr->config, event.payload) == 0) {
                delivered = true;
                LOG_DEBUG("Webhook: Successfully sent %s event",
                          webhook_event_name(event.event_type));
                break;
            }
        }

        if (!delivered) {
            LOG_WARN("Webhook: Failed to send %s event after %d attempts",
                     webhook_event_name(event.event_type), max_retries + 1);
            write_dead_letter(&mgr->config, event.event_type, event.payload,
                              max_retries + 1);
        }
    }

    return NULL;
}

/* --------------- public API --------------- */

webhook_manager_t *webhook_manager_create(const webhook_config_t *config)
{
    if (!config || !config->enabled) return NULL;

    webhook_manager_t *mgr = calloc(1, sizeof(webhook_manager_t));
    if (!mgr) return NULL;

    mgr->config = *config;
    mgr->queue_capacity = config->queue_size > 0
        ? config->queue_size : DEFAULT_QUEUE_SIZE;

    mgr->queue = calloc((size_t)mgr->queue_capacity, sizeof(webhook_event_t));
    if (!mgr->queue) {
        free(mgr);
        return NULL;
    }

    pthread_mutex_init(&mgr->lock, NULL);
    pthread_cond_init(&mgr->cond, NULL);
    mgr->running = true;

    if (pthread_create(&mgr->worker_thread, NULL, webhook_worker, mgr) != 0) {
        pthread_mutex_destroy(&mgr->lock);
        pthread_cond_destroy(&mgr->cond);
        free(mgr->queue);
        free(mgr);
        return NULL;
    }

    LOG_INFO("Webhook manager started (url=%s, events=0x%x)",
             config->url, config->event_mask);
    return mgr;
}

void webhook_manager_destroy(webhook_manager_t *mgr)
{
    if (!mgr) return;

    pthread_mutex_lock(&mgr->lock);
    mgr->running = false;
    pthread_cond_signal(&mgr->cond);
    pthread_mutex_unlock(&mgr->lock);

    pthread_join(mgr->worker_thread, NULL);

    pthread_mutex_destroy(&mgr->lock);
    pthread_cond_destroy(&mgr->cond);
    free(mgr->queue);
    free(mgr);

    LOG_INFO("Webhook manager stopped");
}

int webhook_notify(webhook_manager_t *mgr, webhook_event_type_t event_type,
                   const char *json_payload)
{
    if (!mgr || !json_payload) return -1;

    /* Check if this event type is subscribed */
    if (!(mgr->config.event_mask & (uint32_t)event_type)) return 0;

    pthread_mutex_lock(&mgr->lock);

    if (mgr->queue_count >= mgr->queue_capacity) {
        pthread_mutex_unlock(&mgr->lock);
        LOG_WARN("Webhook: Event queue full, spilling %s event to dead-letter queue",
                 webhook_event_name(event_type));
        write_dead_letter(&mgr->config, event_type, json_payload, 0);
        return -1;
    }

    webhook_event_t *ev = &mgr->queue[mgr->queue_tail];
    ev->event_type = event_type;
    strncpy(ev->payload, json_payload, MAX_PAYLOAD_SIZE - 1);
    ev->payload[MAX_PAYLOAD_SIZE - 1] = '\0';
    ev->retries_left = mgr->config.retry_max > 0
        ? mgr->config.retry_max : DEFAULT_RETRY_MAX;

    mgr->queue_tail = (mgr->queue_tail + 1) % mgr->queue_capacity;
    mgr->queue_count++;

    pthread_cond_signal(&mgr->cond);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

int webhook_build_payload(char *buf, size_t buf_size,
                          const char *event_name,
                          const char *username,
                          const char *client_addr,
                          const char *detail)
{
    if (!buf || buf_size == 0) return -1;

    time_t now = time(NULL);
    return snprintf(buf, buf_size,
        "{\"event\":\"%s\",\"timestamp\":%ld,"
        "\"username\":\"%s\",\"client_addr\":\"%s\","
        "\"detail\":\"%s\"}",
        event_name  ? event_name  : "unknown",
        (long)now,
        username    ? username    : "",
        client_addr ? client_addr : "",
        detail      ? detail      : "");
}

const char *webhook_event_name(webhook_event_type_t event_type)
{
    switch (event_type) {
    case WEBHOOK_EVENT_AUTH_SUCCESS:       return "auth.success";
    case WEBHOOK_EVENT_AUTH_FAILURE:       return "auth.failure";
    case WEBHOOK_EVENT_SESSION_START:      return "session.start";
    case WEBHOOK_EVENT_SESSION_END:        return "session.end";
    case WEBHOOK_EVENT_RATE_LIMIT:         return "rate_limit.triggered";
    case WEBHOOK_EVENT_IP_ACL_DENIED:      return "ip_acl.denied";
    case WEBHOOK_EVENT_UPSTREAM_UNHEALTHY: return "upstream.unhealthy";
    case WEBHOOK_EVENT_UPSTREAM_HEALTHY:   return "upstream.healthy";
    case WEBHOOK_EVENT_CONFIG_RELOADED:    return "config.reloaded";
    case WEBHOOK_EVENT_USER_CREATED:       return "user.created";
    case WEBHOOK_EVENT_USER_UPDATED:       return "user.updated";
    case WEBHOOK_EVENT_USER_DELETED:       return "user.deleted";
    case WEBHOOK_EVENT_POLICY_UPDATED:     return "policy.updated";
    case WEBHOOK_EVENT_CERT_ISSUED:        return "certificate.issued";
    default:                              return "unknown";
    }
}
