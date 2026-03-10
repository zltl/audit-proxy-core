/**
 * @file session_store.h
 * @brief Distributed session storage abstraction
 *
 * Provides a pluggable storage backend for session data.
 * Supports local memory (default) and shared file storage.
 */
#ifndef SESSION_STORE_H
#define SESSION_STORE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Storage backend type */
typedef enum {
    SESSION_STORE_LOCAL,    /* In-memory only (default) */
    SESSION_STORE_FILE      /* Shared file storage (JSON + flock) */
} session_store_type_t;

/* Session record (serializable) */
typedef struct {
    uint64_t session_id;
    char username[128];
    char client_addr[64];
    char target_addr[256];
    char instance_id[64];       /* Which proxy instance owns this session */
    time_t created_at;
    time_t last_active;
    bool active;
} session_record_t;

/* Session store configuration */
typedef struct {
    session_store_type_t type;
    char store_path[256];       /* File path for FILE backend */
    char instance_id[64];       /* This instance's identifier */
    int sync_interval_sec;      /* How often to sync (default: 5) */
    int max_records;            /* Max records to store (default: 10000) */
} session_store_config_t;

/* Opaque session store handle */
typedef struct session_store session_store_t;

/**
 * @brief Create a session store
 * @param config Store configuration
 * @return Session store instance, or NULL on failure
 */
session_store_t *session_store_create(const session_store_config_t *config);

/**
 * @brief Destroy a session store
 * @param store Store to destroy
 */
void session_store_destroy(session_store_t *store);

/**
 * @brief Store/update a session record
 * @param store Session store
 * @param record Session record to store
 * @return 0 on success, -1 on failure
 */
int session_store_put(session_store_t *store, const session_record_t *record);

/**
 * @brief Get a session record by ID
 * @param store Session store
 * @param session_id Session ID to look up
 * @param record Output record (filled on success)
 * @return 0 if found, -1 if not found
 */
int session_store_get(session_store_t *store, uint64_t session_id,
                      session_record_t *record);

/**
 * @brief Remove a session record
 * @param store Session store
 * @param session_id Session ID to remove
 * @return 0 on success, -1 if not found
 */
int session_store_remove(session_store_t *store, uint64_t session_id);

/**
 * @brief List all active sessions
 * @param store Session store
 * @param records Output array
 * @param max_records Size of output array
 * @return Number of records returned
 */
int session_store_list(session_store_t *store, session_record_t *records,
                       int max_records);

/**
 * @brief Get count of active sessions
 * @param store Session store
 * @return Number of active sessions
 */
int session_store_count(session_store_t *store);

/**
 * @brief Sync local state with shared storage (for FILE backend)
 * @param store Session store
 * @return 0 on success, -1 on failure
 */
int session_store_sync(session_store_t *store);

/**
 * @brief Count sessions for a specific user across all instances
 * @param store Session store
 * @param username Username to count
 * @return Number of active sessions for the user
 */
int session_store_count_user(session_store_t *store, const char *username);

#endif /* SESSION_STORE_H */
