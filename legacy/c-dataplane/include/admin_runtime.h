/**
 * @file admin_runtime.h
 * @brief Runtime wiring helpers for the data-plane admin API
 */

#ifndef SSH_PROXY_ADMIN_RUNTIME_H
#define SSH_PROXY_ADMIN_RUNTIME_H

#include "config.h"
#include "health_check.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Apply admin API settings from proxy config to the health-check server
 * @param dst Destination health-check config to update
 * @param src Source proxy config
 */
void admin_runtime_apply_health_config(health_check_config_t *dst, const proxy_config_t *src);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_ADMIN_RUNTIME_H */
