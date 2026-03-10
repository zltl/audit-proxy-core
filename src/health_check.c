/**
 * @file health_check.c
 * @brief Lightweight HTTP server for /health and /metrics endpoints
 */

#include "health_check.h"
#include "metrics.h"
#include "version.h"
#include "logger.h"
#include "session.h"
#include "router.h"
#include "config.h"

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
#include <signal.h>

#define HC_BACKLOG      8
#define HC_BUF_SIZE     4096
#define HC_RESP_SIZE    8192

struct health_check {
    int listen_fd;
    pthread_t thread;
    volatile bool running;
    uint16_t port;
    health_check_config_t config;
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
        "ssh_proxy_config_reload_errors_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_total Total upstream connection retry attempts.\n"
        "# TYPE ssh_proxy_upstream_retries_total counter\n"
        "ssh_proxy_upstream_retries_total %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_success Successful connections after retry.\n"
        "# TYPE ssh_proxy_upstream_retries_success counter\n"
        "ssh_proxy_upstream_retries_success %" PRIuFAST64 "\n"
        "# HELP ssh_proxy_upstream_retries_exhausted Connections where all retries were exhausted.\n"
        "# TYPE ssh_proxy_upstream_retries_exhausted counter\n"
        "ssh_proxy_upstream_retries_exhausted %" PRIuFAST64 "\n",
        (long)uptime,
        METRICS_GET(connections_total),
        METRICS_GET(connections_active),
        METRICS_GET(auth_success_total),
        METRICS_GET(auth_failure_total),
        METRICS_GET(bytes_upstream),
        METRICS_GET(bytes_downstream),
        METRICS_GET(sessions_rejected),
        METRICS_GET(config_reloads),
        METRICS_GET(config_reload_errors),
        METRICS_GET(upstream_retries_total),
        METRICS_GET(upstream_retries_success),
        METRICS_GET(upstream_retries_exhausted));

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
/* Admin API helpers                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    char method[16];
    char path[512];
    char auth_header[512];
    int content_length;
} http_request_t;

static int parse_http_request(const char *raw, http_request_t *req)
{
    memset(req, 0, sizeof(*req));

    /* Parse request line: "METHOD /path HTTP/1.x\r\n" */
    const char *space1 = strchr(raw, ' ');
    if (!space1) return -1;

    size_t method_len = (size_t)(space1 - raw);
    if (method_len >= sizeof(req->method)) return -1;
    memcpy(req->method, raw, method_len);
    req->method[method_len] = '\0';

    const char *path_start = space1 + 1;
    const char *space2 = strchr(path_start, ' ');
    if (!space2) return -1;

    size_t path_len = (size_t)(space2 - path_start);
    if (path_len >= sizeof(req->path)) return -1;
    memcpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    /* Parse Authorization header */
    const char *auth = strstr(raw, "Authorization: Bearer ");
    if (auth) {
        auth += 22; /* skip "Authorization: Bearer " */
        const char *eol = strstr(auth, "\r\n");
        if (eol) {
            size_t len = (size_t)(eol - auth);
            if (len < sizeof(req->auth_header)) {
                memcpy(req->auth_header, auth, len);
                req->auth_header[len] = '\0';
            }
        }
    }

    return 0;
}

static bool check_admin_auth(const health_check_config_t *cfg,
                              const http_request_t *req)
{
    if (cfg->admin_auth_token[0] == '\0') return true;
    return strcmp(cfg->admin_auth_token, req->auth_header) == 0;
}

static void send_json_response(int client_fd, int status_code,
                                const char *status_text, const char *json_body)
{
    char header[512];
    int body_len = json_body ? (int)strlen(json_body) : 0;
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        status_code, status_text, body_len);
    (void)write(client_fd, header, (size_t)header_len);
    if (json_body && body_len > 0) {
        (void)write(client_fd, json_body, (size_t)body_len);
    }
}

/* ------------------------------------------------------------------ */
/* Admin API endpoint handlers                                         */
/* ------------------------------------------------------------------ */

static void handle_api_sessions_list(int client_fd, health_check_config_t *cfg)
{
    session_manager_t *mgr = (session_manager_t *)cfg->session_manager;
    if (!mgr) {
        send_json_response(client_fd, 503, "Service Unavailable",
                          "{\"error\":\"session manager not available\"}");
        return;
    }

    size_t count = session_manager_get_count(mgr);

    char body[HC_RESP_SIZE];
    snprintf(body, sizeof(body),
        "{\"sessions\":[],\"total\":%zu}", count);

    send_json_response(client_fd, 200, "OK", body);
}

static void handle_api_upstreams_list(int client_fd, health_check_config_t *cfg)
{
    router_t *router = (router_t *)cfg->router;
    if (!router) {
        send_json_response(client_fd, 503, "Service Unavailable",
                          "{\"error\":\"router not available\"}");
        return;
    }

    size_t n = router_get_upstream_count(router);

    char body[HC_RESP_SIZE];
    int pos = 0;
    pos += snprintf(body + pos, sizeof(body) - (size_t)pos, "{\"upstreams\":[");

    for (size_t i = 0; i < n; i++) {
        upstream_t *u = router_get_upstream(router, (int)i);
        if (!u) continue;
        if (i > 0) {
            pos += snprintf(body + pos, sizeof(body) - (size_t)pos, ",");
        }
        const char *health_str = "unknown";
        if (u->health == UPSTREAM_HEALTH_HEALTHY) health_str = "healthy";
        else if (u->health == UPSTREAM_HEALTH_UNHEALTHY) health_str = "unhealthy";

        pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
            "{\"host\":\"%s\",\"port\":%u,\"health\":\"%s\","
            "\"active_connections\":%zu,\"total_connections\":%zu,"
            "\"enabled\":%s}",
            u->config.host, u->config.port, health_str,
            u->active_connections, u->total_connections,
            u->config.enabled ? "true" : "false");
    }

    pos += snprintf(body + pos, sizeof(body) - (size_t)pos,
        "],\"total\":%zu}", n);

    send_json_response(client_fd, 200, "OK", body);
}

static void handle_api_reload(int client_fd)
{
    kill(getpid(), SIGHUP);
    send_json_response(client_fd, 200, "OK",
                      "{\"status\":\"reload triggered\"}");
}

static void handle_api_config(int client_fd, health_check_config_t *cfg)
{
    proxy_config_t *pcfg = (proxy_config_t *)cfg->config;
    if (!pcfg) {
        send_json_response(client_fd, 503, "Service Unavailable",
                          "{\"error\":\"config not available\"}");
        return;
    }

    int num_users = 0;
    for (config_user_t *u = pcfg->users; u; u = u->next) num_users++;

    int num_routes = 0;
    for (config_route_t *r = pcfg->routes; r; r = r->next) num_routes++;

    char body[4096];
    snprintf(body, sizeof(body),
        "{\"bind_addr\":\"%s\",\"port\":%u,\"num_users\":%d,\"num_routes\":%d}",
        pcfg->bind_addr, pcfg->port, num_users, num_routes);

    send_json_response(client_fd, 200, "OK", body);
}

/* ------------------------------------------------------------------ */
/* Request dispatch                                                    */
/* ------------------------------------------------------------------ */

static void handle_request(int fd, health_check_config_t *cfg)
{
    char buf[HC_BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    http_request_t req;
    if (parse_http_request(buf, &req) != 0) {
        send_json_response(fd, 400, "Bad Request",
                          "{\"error\":\"invalid request\"}");
        return;
    }

    /* Existing endpoints (no auth required) */
    if (strcmp(req.path, "/health") == 0 && strcmp(req.method, "GET") == 0) {
        handle_health(fd);
        return;
    }
    if (strcmp(req.path, "/metrics") == 0 && strcmp(req.method, "GET") == 0) {
        handle_metrics(fd);
        return;
    }

    /* Admin API endpoints */
    if (strncmp(req.path, "/api/v1/", 8) == 0) {
        if (!cfg->admin_api_enabled) {
            send_json_response(fd, 404, "Not Found",
                              "{\"error\":\"not found\"}");
            return;
        }

        if (!check_admin_auth(cfg, &req)) {
            send_json_response(fd, 401, "Unauthorized",
                              "{\"error\":\"invalid or missing auth token\"}");
            return;
        }

        if (strcmp(req.path, "/api/v1/sessions") == 0 &&
            strcmp(req.method, "GET") == 0) {
            handle_api_sessions_list(fd, cfg);
        } else if (strcmp(req.path, "/api/v1/upstreams") == 0 &&
                   strcmp(req.method, "GET") == 0) {
            handle_api_upstreams_list(fd, cfg);
        } else if (strcmp(req.path, "/api/v1/reload") == 0 &&
                   strcmp(req.method, "POST") == 0) {
            handle_api_reload(fd);
        } else if (strcmp(req.path, "/api/v1/config") == 0 &&
                   strcmp(req.method, "GET") == 0) {
            handle_api_config(fd, cfg);
        } else {
            send_json_response(fd, 404, "Not Found",
                              "{\"error\":\"endpoint not found\"}");
        }
        return;
    }

    handle_not_found(fd);
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

        handle_request(client_fd, &hc->config);
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

    if (config) {
        hc->config = *config;
    } else {
        memset(&hc->config, 0, sizeof(hc->config));
    }
    /* Preserve resolved values */
    hc->config.port = port;
    hc->config.bind_addr = bind_addr;

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
