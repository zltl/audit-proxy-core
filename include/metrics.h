/**
 * @file metrics.h
 * @brief Runtime metrics with atomic counters for thread-safe access
 */

#ifndef METRICS_H
#define METRICS_H

#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Global metrics singleton
 */
typedef struct {
    time_t start_time;
    atomic_uint_fast64_t connections_total;
    atomic_uint_fast64_t connections_active;
    atomic_uint_fast64_t auth_success_total;
    atomic_uint_fast64_t auth_failure_total;
    atomic_uint_fast64_t bytes_upstream;
    atomic_uint_fast64_t bytes_downstream;
    atomic_uint_fast64_t sessions_rejected;
    atomic_uint_fast64_t config_reloads;
    atomic_uint_fast64_t config_reload_errors;
} metrics_t;

/**
 * @brief Initialize global metrics (call once at startup)
 */
void metrics_init(void);

/**
 * @brief Get pointer to global metrics singleton
 */
metrics_t *metrics_get(void);

/* Convenience increment macros */
#define METRICS_INC(field) \
    atomic_fetch_add_explicit(&metrics_get()->field, 1, memory_order_relaxed)

#define METRICS_DEC(field) \
    atomic_fetch_sub_explicit(&metrics_get()->field, 1, memory_order_relaxed)

#define METRICS_ADD(field, n) \
    atomic_fetch_add_explicit(&metrics_get()->field, (n), memory_order_relaxed)

#define METRICS_GET(field) \
    atomic_load_explicit(&metrics_get()->field, memory_order_relaxed)

#ifdef __cplusplus
}
#endif

#endif /* METRICS_H */
