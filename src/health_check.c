/**
 * @file health_check.c
 * @brief Lightweight HTTP server for /health and /metrics endpoints
 */

#include "health_check.h"
#include "metrics.h"
#include "version.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <inttypes.h>

#define HC_BACKLOG      8
#define HC_BUF_SIZE     1024
#define HC_RESP_SIZE    4096

struct health_check {
    int listen_fd;
    pthread_t thread;
    volatile bool running;
    uint16_t port;
};

/* ------------------------------------------------------------------ */
/* Response helpers                                                    */
/* ------------------------------------------------------------------ */

static void send_response(int fd, const char *status, const char *content_type,
                           const char *body, size_t body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.1 %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        status, content_type, body_len);
    /* Best-effort write — this is a diagnostic endpoint */
    (void)write(fd, header, (size_t)hlen);
    if (body_len > 0) {
        (void)write(fd, body, body_len);
    }
}

/* GET /health — JSON health status */
static void handle_health(int fd)
{
    metrics_t *m = metrics_get();
    time_t uptime = time(NULL) - m->start_time;

    char body[HC_RESP_SIZE];
    int len = snprintf(body, sizeof(body),
        "{\n"
        "  \"status\": \"healthy\",\n"
        "  \"version\": \"%s\",\n"
        "  \"uptime_seconds\": %ld,\n"
        "  \"connections_active\": %" PRIuFAST64 ",\n"
        "  \"connections_total\": %" PRIuFAST64 "\n"
        "}\n",
        SSH_PROXY_VERSION_STRING,
        (long)uptime,
        METRICS_GET(connections_active),
        METRICS_GET(connections_total));

    send_response(fd, "200 OK", "application/json", body, (size_t)len);
}

/* GET /metrics — Prometheus text exposition format */
static void handle_metrics(int fd)
{
    metrics_t *m = metrics_get();
    time_t uptime = time(NULL) - m->start_time;

    char body[HC_RESP_SIZE];
    int len = snprintf(body, sizeof(body),
        "# HELP ssh_proxy_up Whether the SSH proxy is up (1 = up).\n"
        "# TYPE ssh_proxy_up gauge\n"
        "ssh_proxy_up 1\n"
        "# HELP ssh_proxy_uptime_seconds Time since process start.\n"
        "# TYPE ssh_proxy_uptime_seconds gauge\n"
        "ssh_proxy_uptime_seconds %ld\n"
        "# HELP ssh_proxy_connections_total Total accepted connections.\n"
        "# TYPE ssh_proxy_connections_total counter\n"
        "ssh_proxy_connections_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_connections_active Current active connections.\n"
        "# TYPE ssh_proxy_connections_active gauge\n"
        "ssh_proxy_connections_active %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_auth_success_total Successful authentications.\n"
        "# TYPE ssh_proxy_auth_success_total counter\n"
        "ssh_proxy_auth_success_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_auth_failure_total Failed authentications.\n"
        "# TYPE ssh_proxy_auth_failure_total counter\n"
        "ssh_proxy_auth_failure_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_bytes_upstream_total Bytes sent to upstream.\n"
        "# TYPE ssh_proxy_bytes_upstream_total counter\n"
        "ssh_proxy_bytes_upstream_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_bytes_downstream_total Bytes sent to client.\n"
        "# TYPE ssh_proxy_bytes_downstream_total counter\n"
        "ssh_proxy_bytes_downstream_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_sessions_rejected_total Sessions rejected by filters.\n"
        "# TYPE ssh_proxy_sessions_rejected_total counter\n"
        "ssh_proxy_sessions_rejected_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_config_reloads_total Successful config reloads.\n"
        "# TYPE ssh_proxy_config_reloads_total counter\n"
        "ssh_proxy_config_reloads_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_config_reload_errors_total Failed config reloads.\n"
        "# TYPE ssh_proxy_config_reload_errors_total counter\n"
        "ssh_proxy_config_reload_errors_total %" PRIuFAST64 "\n",
        (long)uptime,
        METRICS_GET(connections_total),
        METRICS_GET(connections_active),
        METRICS_GET(auth_success_total),
        METRICS_GET(auth_failure_total),
        METRICS_GET(bytes_upstream),
        METRICS_GET(bytes_downstream),
        METRICS_GET(sessions_rejected),
        METRICS_GET(config_reloads),
        METRICS_GET(config_reload_errors));

    send_response(fd, "200 OK",
                  "text/plain; version=0.0.4; charset=utf-8",
                  body, (size_t)len);
}

static void handle_not_found(int fd)
{
    const char *body = "404 Not Found\n";
    send_response(fd, "404 Not Found", "text/plain", body, strlen(body));
}

/* ------------------------------------------------------------------ */
/* Request dispatch                                                    */
/* ------------------------------------------------------------------ */

static void handle_request(int fd)
{
    char buf[HC_BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    /* Minimal HTTP parsing — only care about the request line */
    if (strncmp(buf, "GET /health", 11) == 0) {
        handle_health(fd);
    } else if (strncmp(buf, "GET /metrics", 12) == 0) {
        handle_metrics(fd);
    } else {
        handle_not_found(fd);
    }
}

/* ------------------------------------------------------------------ */
/* Server thread                                                       */
/* ------------------------------------------------------------------ */

static void *health_check_thread(void *arg)
{
    health_check_t *hc = (health_check_t *)arg;

    while (hc->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(hc->listen_fd,
                               (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            if (hc->running && errno != EINTR) {
                LOG_DEBUG("health_check accept error: %s", strerror(errno));
            }
            continue;
        }

        /* Set a short read timeout to avoid hanging on slow clients */
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        handle_request(client_fd);
        close(client_fd);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

health_check_t *health_check_start(const health_check_config_t *config)
{
    uint16_t port = (config && config->port) ? config->port : 9090;
    const char *bind_addr = (config && config->bind_addr) ? config->bind_addr
                                                          : "127.0.0.1";

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("health_check socket(): %s", strerror(errno));
        return NULL;
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        LOG_ERROR("health_check: invalid bind address '%s'", bind_addr);
        close(fd);
        return NULL;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("health_check bind(%s:%u): %s", bind_addr, port,
                  strerror(errno));
        close(fd);
        return NULL;
    }

    if (listen(fd, HC_BACKLOG) < 0) {
        LOG_ERROR("health_check listen(): %s", strerror(errno));
        close(fd);
        return NULL;
    }

    health_check_t *hc = calloc(1, sizeof(health_check_t));
    if (hc == NULL) {
        close(fd);
        return NULL;
    }

    hc->listen_fd = fd;
    hc->port = port;
    hc->running = true;

    if (pthread_create(&hc->thread, NULL, health_check_thread, hc) != 0) {
        LOG_ERROR("health_check pthread_create: %s", strerror(errno));
        close(fd);
        free(hc);
        return NULL;
    }

    LOG_INFO("Health check endpoint listening on %s:%u", bind_addr, port);
    return hc;
}

void health_check_stop(health_check_t *hc)
{
    if (hc == NULL) return;

    hc->running = false;

    /* Close the listening socket to unblock accept() */
    if (hc->listen_fd >= 0) {
        close(hc->listen_fd);
        hc->listen_fd = -1;
    }

    pthread_join(hc->thread, NULL);
    free(hc);
    LOG_DEBUG("Health check server stopped");
}
