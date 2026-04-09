/**
 * @file webhook_runtime.h
 * @brief Thread-safe runtime wrapper around the webhook manager
 */
#ifndef SSH_PROXY_WEBHOOK_RUNTIME_H
#define SSH_PROXY_WEBHOOK_RUNTIME_H

#include <stdbool.h>
#include <pthread.h>

#include "config.h"
#include "webhook.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct webhook_runtime {
    pthread_mutex_t lock;
    webhook_manager_t *manager;
    bool initialized;
} webhook_runtime_t;

int webhook_runtime_init(webhook_runtime_t *runtime,
                         const webhook_config_t *config);
int webhook_runtime_reload(webhook_runtime_t *runtime,
                           const webhook_config_t *config);
void webhook_runtime_destroy(webhook_runtime_t *runtime);

int webhook_runtime_emit(webhook_runtime_t *runtime,
                         webhook_event_type_t event_type,
                         const char *username,
                         const char *client_addr,
                         const char *detail);

void webhook_runtime_emit_config_diff(webhook_runtime_t *runtime,
                                      const proxy_config_t *old_config,
                                      const proxy_config_t *new_config,
                                      const char *detail);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_WEBHOOK_RUNTIME_H */
