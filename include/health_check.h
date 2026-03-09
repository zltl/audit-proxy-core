/**
 * @file health_check.h
 * @brief Lightweight HTTP health check and metrics endpoint
 *
 * Provides:
 *   GET /health  - JSON health status (200 OK / 503 unhealthy)
 *   GET /metrics - Prometheus text exposition format
 */

#ifndef HEALTH_CHECK_H
#define HEALTH_CHECK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct health_check health_check_t;

typedef struct {
    uint16_t port;      /* HTTP listen port (default 9090) */
    const char *bind_addr;  /* Bind address (default "127.0.0.1") */
} health_check_config_t;

/**
 * @brief Create and start the health check HTTP server
 * @param config Configuration (NULL for defaults)
 * @return Server handle or NULL on error
 */
health_check_t *health_check_start(const health_check_config_t *config);

/**
 * @brief Stop and destroy the health check server
 */
void health_check_stop(health_check_t *hc);

#ifdef __cplusplus
}
#endif

#endif /* HEALTH_CHECK_H */
