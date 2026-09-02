/**
 * @file session.h
 * @brief SSH Proxy Core - Session Manager
 *
 * Manages SSH session lifecycle. Each connection is abstracted as a Session,
 * containing both Client and Upstream endpoints.
 */

#ifndef SSH_PROXY_SESSION_H
#define SSH_PROXY_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <libssh/libssh.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum username length */
#define SESSION_MAX_USERNAME 128

/* Maximum address length */
#define SESSION_MAX_ADDR 256
#define SESSION_MAX_INSTANCE_ID 64
#define SESSION_MAX_STORE_PATH 256
#define SESSION_MAX_CLIENT_VERSION 256
#define SESSION_MAX_DEVICE_OS 64
#define SESSION_MAX_DEVICE_FINGERPRINT 64
#define SESSION_MAX_LDAP_ATTR 256
#define SESSION_MAX_LDAP_DN 512
#define SESSION_MAX_LDAP_GROUPS 2048

/* Session states */
typedef enum {
    SESSION_STATE_NEW = 0,          /* Just created */
    SESSION_STATE_HANDSHAKE,        /* SSH handshake in progress */
    SESSION_STATE_AUTH,             /* Authentication in progress */
    SESSION_STATE_AUTHENTICATED,    /* Client authenticated */
    SESSION_STATE_ROUTING,          /* Determining upstream target */
    SESSION_STATE_CONNECTING,       /* Connecting to upstream */
    SESSION_STATE_ACTIVE,           /* Bidirectional pipe established */
    SESSION_STATE_CLOSING,          /* Graceful shutdown */
    SESSION_STATE_CLOSED            /* Session terminated */
} session_state_t;

/* Session authentication method */
typedef enum {
    SESSION_AUTH_NONE = 0,
    SESSION_AUTH_PASSWORD,
    SESSION_AUTH_PUBLICKEY,
    SESSION_AUTH_KEYBOARD_INTERACTIVE
} session_auth_method_t;

/* Forward declarations */
typedef struct session session_t;
typedef struct session_manager session_manager_t;

/* Session metadata */
typedef struct session_metadata {
    char username[SESSION_MAX_USERNAME];
    char client_addr[SESSION_MAX_ADDR];
    uint16_t client_port;
    char target_addr[SESSION_MAX_ADDR];
    uint16_t target_port;
    session_auth_method_t auth_method;
    char client_version[SESSION_MAX_CLIENT_VERSION];
    char client_os[SESSION_MAX_DEVICE_OS];
    char device_fingerprint[SESSION_MAX_DEVICE_FINGERPRINT];
    char ldap_email[SESSION_MAX_LDAP_ATTR];
    char ldap_department[SESSION_MAX_LDAP_ATTR];
    char ldap_manager[SESSION_MAX_LDAP_DN];
    char ldap_groups[SESSION_MAX_LDAP_GROUPS];
} session_metadata_t;

/* Session statistics */
typedef struct session_stats {
    uint64_t bytes_sent;        /* Bytes sent to upstream */
    uint64_t bytes_received;    /* Bytes received from upstream */
    time_t start_time;          /* Session start timestamp */
    time_t last_activity;       /* Last activity timestamp */
} session_stats_t;

/* Serializable active session snapshot used by admin/status endpoints. */
typedef struct session_snapshot {
    uint64_t id;
    session_state_t state;
    char username[SESSION_MAX_USERNAME];
    char client_addr[SESSION_MAX_ADDR];
    uint16_t client_port;
    char target_addr[SESSION_MAX_ADDR];
    uint16_t target_port;
    char client_version[SESSION_MAX_CLIENT_VERSION];
    char client_os[SESSION_MAX_DEVICE_OS];
    char device_fingerprint[SESSION_MAX_DEVICE_FINGERPRINT];
    uint64_t bytes_sent;
    uint64_t bytes_received;
    time_t start_time;
    time_t last_activity;
    char instance_id[SESSION_MAX_INSTANCE_ID];
} session_snapshot_t;

typedef enum {
    SESSION_MANAGER_STORE_LOCAL = 0,
    SESSION_MANAGER_STORE_FILE
} session_manager_store_type_t;

/* Session manager configuration */
typedef struct session_manager_config {
    size_t max_sessions;        /* Maximum concurrent sessions */
    uint32_t session_timeout;   /* Session idle timeout (seconds) */
    uint32_t auth_timeout;      /* Authentication timeout (seconds) */
    session_manager_store_type_t store_type; /* Shared session backend */
    char store_path[SESSION_MAX_STORE_PATH]; /* Shared store path for file backend */
    char instance_id[SESSION_MAX_INSTANCE_ID]; /* Stable node identifier */
    int sync_interval_sec; /* Shared-store sync cadence */
} session_manager_config_t;

/**
 * @brief Create a new session manager
 * @param config Manager configuration
 * @return Session manager instance or NULL on error
 */
session_manager_t *session_manager_create(const session_manager_config_t *config);

/**
 * @brief Destroy session manager and all sessions
 * @param manager Session manager instance
 */
void session_manager_destroy(session_manager_t *manager);

/**
 * @brief Create a new session
 * @param manager Session manager
 * @param client_session libssh client session
 * @return New session or NULL on error
 */
session_t *session_manager_create_session(session_manager_t *manager,
                                          ssh_session client_session);

/**
 * @brief Remove and destroy a session
 * @param manager Session manager
 * @param session Session to remove
 */
void session_manager_remove_session(session_manager_t *manager,
                                    session_t *session);

/**
 * @brief Get current number of active sessions
 * @param manager Session manager
 * @return Number of active sessions
 */
size_t session_manager_get_count(const session_manager_t *manager);

/**
 * @brief Estimate the snapshot buffer size required for visible sessions.
 * @param manager Session manager instance
 * @return Snapshot capacity covering local and shared sessions
 */
size_t session_manager_snapshot_capacity(session_manager_t *manager);

/**
 * @brief Copy active sessions into a stable snapshot array.
 * @param manager Session manager instance
 * @param snapshots Output array
 * @param max_snapshots Maximum number of entries to copy
 * @return Number of snapshots copied
 */
int session_manager_snapshot(session_manager_t *manager, session_snapshot_t *snapshots,
                             int max_snapshots);

/**
 * @brief Count authenticated sessions for a user, including shared backends.
 * @param manager Session manager instance
 * @param username Username to count
 * @return Number of authenticated sessions for the user
 */
int session_manager_count_user(session_manager_t *manager, const char *username);

/**
 * @brief Find session by ID
 * @param manager Session manager
 * @param session_id Session ID
 * @return Session or NULL if not found
 */
session_t *session_manager_find(session_manager_t *manager, uint64_t session_id);

/**
 * @brief Cleanup timed-out sessions
 * @param manager Session manager
 * @return Number of sessions cleaned up
 */
size_t session_manager_cleanup(session_manager_t *manager);

/* Session operations */

/**
 * @brief Get session ID
 * @param session Session instance
 * @return Unique session ID
 */
uint64_t session_get_id(const session_t *session);

/**
 * @brief Get session state
 * @param session Session instance
 * @return Current session state
 */
session_state_t session_get_state(const session_t *session);

/**
 * @brief Set session state
 * @param session Session instance
 * @param state New state
 */
void session_set_state(session_t *session, session_state_t state);

/**
 * @brief Get client SSH session
 * @param session Session instance
 * @return libssh session for client
 */
ssh_session session_get_client(session_t *session);

/**
 * @brief Get upstream SSH session
 * @param session Session instance
 * @return libssh session for upstream (or NULL if not connected)
 */
ssh_session session_get_upstream(session_t *session);

/**
 * @brief Set upstream SSH session
 * @param session Session instance
 * @param upstream libssh session for upstream
 */
void session_set_upstream(session_t *session, ssh_session upstream);

/**
 * @brief Set session username
 * @param session Session instance
 * @param username Username string
 */
void session_set_username(session_t *session, const char *username);

/**
 * @brief Get session metadata
 * @param session Session instance
 * @return Pointer to session metadata
 */
session_metadata_t *session_get_metadata(session_t *session);

/**
 * @brief Get session statistics
 * @param session Session instance
 * @return Pointer to session statistics
 */
session_stats_t *session_get_stats(session_t *session);

/**
 * @brief Flush the current session metadata/statistics into the session store.
 * @param session Session instance
 */
void session_sync(session_t *session);

/**
 * @brief Update session activity timestamp
 * @param session Session instance
 */
void session_touch(session_t *session);

/**
 * @brief Check if session has timed out
 * @param session Session instance
 * @param timeout_seconds Timeout threshold
 * @return true if timed out
 */
bool session_is_timeout(const session_t *session, uint32_t timeout_seconds);

/**
 * @brief Get state name as string
 * @param state Session state
 * @return State name string
 */
const char *session_state_name(session_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_SESSION_H */
