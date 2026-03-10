/**
 * @file webhook.h
 * @brief Webhook event notification system
 */
#ifndef WEBHOOK_H
#define WEBHOOK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Event types as bit flags for subscription mask */
typedef enum {
    WEBHOOK_EVENT_AUTH_SUCCESS       = (1 << 0),
    WEBHOOK_EVENT_AUTH_FAILURE       = (1 << 1),
    WEBHOOK_EVENT_SESSION_START      = (1 << 2),
    WEBHOOK_EVENT_SESSION_END        = (1 << 3),
    WEBHOOK_EVENT_RATE_LIMIT         = (1 << 4),
    WEBHOOK_EVENT_IP_ACL_DENIED      = (1 << 5),
    WEBHOOK_EVENT_UPSTREAM_UNHEALTHY = (1 << 6),
    WEBHOOK_EVENT_UPSTREAM_HEALTHY   = (1 << 7),
    WEBHOOK_EVENT_CONFIG_RELOADED    = (1 << 8),
    WEBHOOK_EVENT_ALL                = 0x1FF
} webhook_event_type_t;

/* Webhook configuration */
typedef struct {
    bool enabled;
    char url[512];                  /* Webhook endpoint URL */
    char auth_header[256];          /* Optional auth header value */
    uint32_t event_mask;            /* Bitmask of subscribed events */
    int retry_max;                  /* Max retries (default: 3) */
    int retry_delay_ms;             /* Retry delay in ms (default: 1000) */
    int timeout_ms;                 /* HTTP timeout in ms (default: 5000) */
    int queue_size;                 /* Max pending events (default: 1024) */
} webhook_config_t;

/* Opaque webhook manager handle */
typedef struct webhook_manager webhook_manager_t;

/**
 * @brief Create and start the webhook manager
 * @param config Webhook configuration
 * @return Webhook manager instance, or NULL on failure
 */
webhook_manager_t *webhook_manager_create(const webhook_config_t *config);

/**
 * @brief Destroy and stop the webhook manager
 * @param mgr Webhook manager to destroy
 */
void webhook_manager_destroy(webhook_manager_t *mgr);

/**
 * @brief Send a webhook notification (non-blocking, queues the event)
 * @param mgr Webhook manager
 * @param event_type Event type
 * @param json_payload JSON payload string (will be copied)
 * @return 0 on success (queued), -1 if queue full or disabled
 */
int webhook_notify(webhook_manager_t *mgr, webhook_event_type_t event_type,
                   const char *json_payload);

/**
 * @brief Build a standard event JSON payload
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @param event_name Event name string (e.g., "auth.failure")
 * @param username Username (may be NULL)
 * @param client_addr Client IP (may be NULL)
 * @param detail Additional detail string (may be NULL)
 * @return Length of JSON written, or -1 on error
 */
int webhook_build_payload(char *buf, size_t buf_size,
                          const char *event_name,
                          const char *username,
                          const char *client_addr,
                          const char *detail);

/**
 * @brief Get event name string from event type
 */
const char *webhook_event_name(webhook_event_type_t event_type);

#endif /* WEBHOOK_H */
