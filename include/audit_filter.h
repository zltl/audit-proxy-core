/**
 * @file audit_filter.h
 * @brief SSH Proxy Core - Audit Filter
 *
 * Provides session auditing including command logging, I/O recording
 * (asciicast format), and metadata logging.
 */

#ifndef SSH_PROXY_AUDIT_FILTER_H
#define SSH_PROXY_AUDIT_FILTER_H

#include "filter.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Audit event types */
typedef enum {
    AUDIT_EVENT_CONNECT = 0,
    AUDIT_EVENT_AUTH_SUCCESS,
    AUDIT_EVENT_AUTH_FAILURE,
    AUDIT_EVENT_SESSION_START,
    AUDIT_EVENT_COMMAND,
    AUDIT_EVENT_DATA_UPSTREAM,
    AUDIT_EVENT_DATA_DOWNSTREAM,
    AUDIT_EVENT_SESSION_END,
    AUDIT_EVENT_DISCONNECT
} audit_event_type_t;

/* Audit storage backend */
typedef enum {
    AUDIT_STORAGE_FILE = 0,     /* Local filesystem */
    AUDIT_STORAGE_SYSLOG,       /* Syslog */
    AUDIT_STORAGE_CALLBACK      /* Custom callback */
} audit_storage_t;

/* Forward declarations */
typedef struct audit_filter_config audit_filter_config_t;
typedef struct audit_event audit_event_t;

/* Audit event structure */
struct audit_event {
    audit_event_type_t type;
    uint64_t session_id;
    time_t timestamp;
    const char *username;
    const char *client_addr;
    const char *target_addr;
    const char *data;
    size_t data_len;
};

/**
 * @brief Callback for custom audit event handling
 */
typedef void (*audit_event_cb)(const audit_event_t *event, void *user_data);

/* Audit filter configuration */
struct audit_filter_config {
    audit_storage_t storage;    /* Storage backend */
    const char *log_dir;        /* Directory for log files */
    const char *log_prefix;     /* Log file prefix */
    bool record_input;          /* Record input (upstream) data */
    bool record_output;         /* Record output (downstream) data */
    bool record_commands;       /* Parse and record commands */
    bool enable_asciicast;      /* Enable asciicast recording */
    size_t max_file_size;       /* Max log file size (0 = unlimited) */
    uint32_t flush_interval;    /* Flush interval in seconds */

    /* Custom callback */
    audit_event_cb event_cb;
    void *cb_user_data;

    /* Audit log signing (HMAC-SHA256) */
    const char *signing_key;    /* Hex-encoded HMAC key (NULL = no signing) */
    bool enable_chain_hash;     /* Enable chain hashing (default true when signing) */
};

/* Asciicast header (v2 format) */
typedef struct asciicast_header {
    int version;
    int width;
    int height;
    time_t timestamp;
    const char *title;
    const char *env_shell;
    const char *env_term;
} asciicast_header_t;

/**
 * @brief Create audit filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *audit_filter_create(const audit_filter_config_t *config);

/**
 * @brief Write audit event
 * @param filter Audit filter instance
 * @param event Audit event
 */
void audit_write_event(filter_t *filter, const audit_event_t *event);

/**
 * @brief Start asciicast recording for a session
 * @param filter Audit filter instance
 * @param session_id Session ID
 * @param header Asciicast header
 * @return 0 on success, -1 on error
 */
int audit_start_recording(filter_t *filter, uint64_t session_id,
                          const asciicast_header_t *header);

/**
 * @brief Write asciicast frame
 * @param filter Audit filter instance
 * @param session_id Session ID
 * @param data Frame data
 * @param len Data length
 * @param is_input true for input, false for output
 * @return 0 on success, -1 on error
 */
int audit_write_frame(filter_t *filter, uint64_t session_id,
                      const void *data, size_t len, bool is_input);

/**
 * @brief Stop asciicast recording for a session
 * @param filter Audit filter instance
 * @param session_id Session ID
 */
void audit_stop_recording(filter_t *filter, uint64_t session_id);

/**
 * @brief Log a command execution to the command audit log
 * @param filter Audit filter instance
 * @param session_id Session ID
 * @param username Username who executed the command
 * @param upstream Target upstream server
 * @param command The command string
 */
void audit_log_command(filter_t *filter, uint64_t session_id,
                       const char *username, const char *upstream,
                       const char *command);

/**
 * @brief Get event type name
 * @param type Event type
 * @return Type name string
 */
const char *audit_event_type_name(audit_event_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_AUDIT_FILTER_H */
