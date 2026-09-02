/**
 * @file policy_filter.h
 * @brief SSH Proxy Core - Policy Filter
 *
 * Controls SSH feature access: shell, exec, scp, sftp, port forwarding,
 * git operations, file transfer logging, etc.
 */

#ifndef SSH_PROXY_POLICY_FILTER_H
#define SSH_PROXY_POLICY_FILTER_H

#include "filter.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum pattern lengths */
#define POLICY_MAX_PATTERN 256
#define POLICY_MAX_PATH 1024
#define POLICY_MAX_USERS 128

/* SSH feature flags - bitwise flags for permissions */
typedef enum {
    POLICY_FEAT_SHELL          = (1 << 0),   /* Interactive shell */
    POLICY_FEAT_EXEC           = (1 << 1),   /* Remote command execution */
    POLICY_FEAT_SCP_UPLOAD     = (1 << 2),   /* SCP upload (client -> server) */
    POLICY_FEAT_SCP_DOWNLOAD   = (1 << 3),   /* SCP download (server -> client) */
    POLICY_FEAT_SFTP_UPLOAD    = (1 << 4),   /* SFTP upload */
    POLICY_FEAT_SFTP_DOWNLOAD  = (1 << 5),   /* SFTP download */
    POLICY_FEAT_SFTP_LIST      = (1 << 6),   /* SFTP directory listing */
    POLICY_FEAT_SFTP_DELETE    = (1 << 7),   /* SFTP delete/rename */
    POLICY_FEAT_RSYNC_UPLOAD   = (1 << 8),   /* rsync upload */
    POLICY_FEAT_RSYNC_DOWNLOAD = (1 << 9),   /* rsync download */
    POLICY_FEAT_PORT_FORWARD_LOCAL  = (1 << 10), /* Local port forwarding (-L) */
    POLICY_FEAT_PORT_FORWARD_REMOTE = (1 << 11), /* Remote port forwarding (-R) */
    POLICY_FEAT_PORT_FORWARD_DYNAMIC = (1 << 12), /* Dynamic port forwarding (-D) */
    POLICY_FEAT_X11_FORWARD    = (1 << 13),  /* X11 forwarding */
    POLICY_FEAT_AGENT_FORWARD  = (1 << 14),  /* SSH agent forwarding */
    POLICY_FEAT_GIT_PUSH       = (1 << 15),  /* git push */
    POLICY_FEAT_GIT_PULL       = (1 << 16),  /* git pull/fetch/clone */
    POLICY_FEAT_GIT_ARCHIVE    = (1 << 17),  /* git archive */
    POLICY_FEAT_ALL            = 0x7FFFFFFF  /* All features allowed (max signed int) */
} policy_feature_t;

/* Shorthand for common feature groups */
#define POLICY_FEAT_SCP       (POLICY_FEAT_SCP_UPLOAD | POLICY_FEAT_SCP_DOWNLOAD)
#define POLICY_FEAT_SFTP      (POLICY_FEAT_SFTP_UPLOAD | POLICY_FEAT_SFTP_DOWNLOAD | \
                               POLICY_FEAT_SFTP_LIST | POLICY_FEAT_SFTP_DELETE)
#define POLICY_FEAT_RSYNC     (POLICY_FEAT_RSYNC_UPLOAD | POLICY_FEAT_RSYNC_DOWNLOAD)
#define POLICY_FEAT_PORT_FORWARD (POLICY_FEAT_PORT_FORWARD_LOCAL | \
                                  POLICY_FEAT_PORT_FORWARD_REMOTE | \
                                  POLICY_FEAT_PORT_FORWARD_DYNAMIC)
#define POLICY_FEAT_GIT       (POLICY_FEAT_GIT_PUSH | POLICY_FEAT_GIT_PULL | POLICY_FEAT_GIT_ARCHIVE)
#define POLICY_FEAT_UPLOAD    (POLICY_FEAT_SCP_UPLOAD | POLICY_FEAT_SFTP_UPLOAD | POLICY_FEAT_RSYNC_UPLOAD)
#define POLICY_FEAT_DOWNLOAD  (POLICY_FEAT_SCP_DOWNLOAD | POLICY_FEAT_SFTP_DOWNLOAD | POLICY_FEAT_RSYNC_DOWNLOAD)

/* File transfer event types */
typedef enum {
    TRANSFER_EVENT_START = 0,
    TRANSFER_EVENT_PROGRESS,
    TRANSFER_EVENT_COMPLETE,
    TRANSFER_EVENT_FAILED,
    TRANSFER_EVENT_DENIED
} transfer_event_type_t;

/* File transfer direction */
typedef enum {
    TRANSFER_DIR_UPLOAD = 0,    /* Client -> Server */
    TRANSFER_DIR_DOWNLOAD       /* Server -> Client */
} transfer_direction_t;

/* File transfer protocol */
typedef enum {
    TRANSFER_PROTO_SCP = 0,
    TRANSFER_PROTO_SFTP,
    TRANSFER_PROTO_RSYNC,
    TRANSFER_PROTO_GIT
} transfer_protocol_t;

/* File transfer record */
typedef struct transfer_record {
    uint64_t session_id;
    time_t timestamp;
    transfer_event_type_t event;
    transfer_direction_t direction;
    transfer_protocol_t protocol;
    char username[128];
    char remote_path[POLICY_MAX_PATH];
    char local_path[POLICY_MAX_PATH];
    uint64_t file_size;
    uint64_t bytes_transferred;
    char checksum[65];          /* SHA-256 hex string */
} transfer_record_t;

/* Port forward record */
typedef struct port_forward_record {
    uint64_t session_id;
    time_t timestamp;
    char username[128];
    bool is_local;              /* true = -L, false = -R */
    char bind_host[256];
    uint16_t bind_port;
    char target_host[256];
    uint16_t target_port;
    bool allowed;
} port_forward_record_t;

/* Forward declarations */
typedef struct policy_user_rule policy_user_rule_t;
typedef struct policy_filter_config policy_filter_config_t;

/* Transfer event callback */
typedef void (*policy_transfer_cb)(const transfer_record_t *record, void *user_data);

/* Port forward event callback */
typedef void (*policy_port_forward_cb)(const port_forward_record_t *record, void *user_data);

/* User policy rule */
struct policy_user_rule {
    char username_pattern[POLICY_MAX_PATTERN];  /* Username glob pattern */
    char upstream_pattern[POLICY_MAX_PATTERN];  /* Upstream host pattern (empty = any) */
    uint32_t allowed_features;                  /* Bitwise OR of policy_feature_t */
    uint32_t denied_features;                   /* Explicit denials (higher priority) */
    policy_user_rule_t *next;
};

/* Policy filter configuration */
struct policy_filter_config {
    /* Default features for unmatched users */
    uint32_t default_allowed;
    
    /* User rules */
    policy_user_rule_t *user_rules;
    
    /* Logging settings */
    bool log_transfers;             /* Log file transfers */
    bool log_port_forwards;         /* Log port forwarding */
    bool log_denied;                /* Log denied operations */
    const char *transfer_log_dir;   /* Directory for transfer logs */
    
    /* Callbacks */
    policy_transfer_cb transfer_cb;
    policy_port_forward_cb port_forward_cb;
    void *cb_user_data;
};

/**
 * @brief Create policy filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *policy_filter_create(const policy_filter_config_t *config);

/**
 * @brief Add user policy rule
 * @param config Configuration
 * @param username_pattern Username glob pattern
 * @param upstream_pattern Upstream host pattern (NULL = any upstream)
 * @param allowed_features Features to allow (bitwise OR)
 * @param denied_features Features to deny (bitwise OR, overrides allowed)
 * @return 0 on success, -1 on error
 */
int policy_add_user_rule(policy_filter_config_t *config,
                         const char *username_pattern,
                         const char *upstream_pattern,
                         uint32_t allowed_features,
                         uint32_t denied_features);

/**
 * @brief Check if feature is allowed for user
 * @param config Configuration
 * @param username Username
 * @param upstream Upstream host (can be NULL for user-only check)
 * @param feature Feature to check
 * @return true if allowed, false if denied
 */
bool policy_check_feature(const policy_filter_config_t *config,
                          const char *username,
                          const char *upstream,
                          policy_feature_t feature);

/**
 * @brief Get allowed features for user
 * @param config Configuration
 * @param username Username
 * @param upstream Upstream host (can be NULL)
 * @return Bitwise OR of allowed features
 */
uint32_t policy_get_allowed_features(const policy_filter_config_t *config,
                                     const char *username,
                                     const char *upstream);

/**
 * @brief Log file transfer event
 * @param filter Policy filter instance
 * @param record Transfer record
 */
void policy_log_transfer(filter_t *filter, const transfer_record_t *record);

/**
 * @brief Log port forward event
 * @param filter Policy filter instance
 * @param record Port forward record
 */
void policy_log_port_forward(filter_t *filter, const port_forward_record_t *record);

/**
 * @brief Parse command to detect operation type
 * @param command Command string (e.g., "scp -t /path")
 * @return Detected feature or 0 if not recognized
 */
policy_feature_t policy_detect_command(const char *command);

/**
 * @brief Get feature name as string
 * @param feature Feature flag
 * @return Feature name string
 */
const char *policy_feature_name(policy_feature_t feature);

/**
 * @brief Get transfer direction name
 * @param dir Transfer direction
 * @return Direction name string
 */
const char *policy_transfer_dir_name(transfer_direction_t dir);

/**
 * @brief Get transfer protocol name
 * @param proto Transfer protocol
 * @return Protocol name string
 */
const char *policy_transfer_proto_name(transfer_protocol_t proto);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_POLICY_FILTER_H */
