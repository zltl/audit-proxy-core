/**
 * @file session.c
 * @brief SSH Proxy Core - Session Manager Implementation
 */

#include "session.h"
#include "logger.h"
#include "session_store.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Session structure */
struct session {
    uint64_t id;                    /* Unique session ID */
    session_state_t state;          /* Current state */
    ssh_session client;             /* Client SSH session */
    ssh_session upstream;           /* Upstream SSH session */
    session_metadata_t metadata;    /* Session metadata */
    session_stats_t stats;          /* Session statistics */
    session_manager_t *manager;     /* Owning manager */
    session_t *next;                /* Linked list next pointer */
    session_t *prev;                /* Linked list prev pointer */
};

/* Session manager structure */
struct session_manager {
    session_manager_config_t config;
    session_t *sessions;            /* Linked list of sessions */
    size_t session_count;           /* Current local session count */
    uint32_t next_local_id;         /* Per-node session counter */
    uint64_t id_namespace;          /* Stable node prefix for global session IDs */
    session_store_t *store;         /* Optional shared session backend */
    pthread_t sync_thread;          /* Background shared-store heartbeat */
    bool sync_thread_started;
    bool stop_sync_thread;
    pthread_mutex_t lock;           /* Thread safety lock */
};

/* State names */
static const char *state_names[] = {
    "NEW",
    "HANDSHAKE",
    "AUTH",
    "AUTHENTICATED",
    "ROUTING",
    "CONNECTING",
    "ACTIVE",
    "CLOSING",
    "CLOSED"
};

static uint32_t session_hash_instance_id(const char *instance_id)
{
    uint32_t hash = 2166136261u;

    if (instance_id == NULL || instance_id[0] == '\0') {
        return 1u;
    }

    for (const unsigned char *p = (const unsigned char *)instance_id; *p != '\0'; p++) {
        hash ^= (uint32_t)(*p);
        hash *= 16777619u;
    }

    return hash == 0 ? 1u : hash;
}

static void ensure_instance_id(session_manager_config_t *config)
{
    if (config == NULL) {
        return;
    }
    if (config->instance_id[0] == '\0') {
        snprintf(config->instance_id, sizeof(config->instance_id), "node-%d", getpid());
    }
    if (config->sync_interval_sec <= 0) {
        config->sync_interval_sec = 5;
    }
}

static session_store_type_t session_store_type_from_manager(session_manager_store_type_t type)
{
    return type == SESSION_MANAGER_STORE_FILE ? SESSION_STORE_FILE : SESSION_STORE_LOCAL;
}

static void session_snapshot_from_session(const session_t *session, session_snapshot_t *snapshot)
{
    if (session == NULL || snapshot == NULL) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->id = session->id;
    snapshot->state = session->state;
    snapshot->client_port = session->metadata.client_port;
    snapshot->target_port = session->metadata.target_port;
    snapshot->bytes_sent = session->stats.bytes_sent;
    snapshot->bytes_received = session->stats.bytes_received;
    snapshot->start_time = session->stats.start_time;
    snapshot->last_activity = session->stats.last_activity;

    strncpy(snapshot->username, session->metadata.username, sizeof(snapshot->username) - 1);
    strncpy(snapshot->client_addr, session->metadata.client_addr, sizeof(snapshot->client_addr) - 1);
    strncpy(snapshot->target_addr, session->metadata.target_addr, sizeof(snapshot->target_addr) - 1);
    strncpy(snapshot->client_version, session->metadata.client_version,
            sizeof(snapshot->client_version) - 1);
    strncpy(snapshot->client_os, session->metadata.client_os, sizeof(snapshot->client_os) - 1);
    strncpy(snapshot->device_fingerprint, session->metadata.device_fingerprint,
            sizeof(snapshot->device_fingerprint) - 1);
    if (session->manager != NULL) {
        strncpy(snapshot->instance_id, session->manager->config.instance_id,
                sizeof(snapshot->instance_id) - 1);
    }
}

static void session_snapshot_from_record(const session_record_t *record, session_snapshot_t *snapshot)
{
    if (record == NULL || snapshot == NULL) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->id = record->session_id;
    snapshot->state = (session_state_t)record->state;
    snapshot->client_port = record->client_port;
    snapshot->target_port = record->target_port;
    snapshot->bytes_sent = record->bytes_sent;
    snapshot->bytes_received = record->bytes_received;
    snapshot->start_time = record->created_at;
    snapshot->last_activity = record->last_active;

    strncpy(snapshot->username, record->username, sizeof(snapshot->username) - 1);
    strncpy(snapshot->client_addr, record->client_addr, sizeof(snapshot->client_addr) - 1);
    strncpy(snapshot->target_addr, record->target_addr, sizeof(snapshot->target_addr) - 1);
    strncpy(snapshot->client_version, record->client_version, sizeof(snapshot->client_version) - 1);
    strncpy(snapshot->client_os, record->client_os, sizeof(snapshot->client_os) - 1);
    strncpy(snapshot->device_fingerprint, record->device_fingerprint,
            sizeof(snapshot->device_fingerprint) - 1);
    strncpy(snapshot->instance_id, record->instance_id, sizeof(snapshot->instance_id) - 1);
}

static void session_record_from_session(const session_t *session, session_record_t *record)
{
    if (session == NULL || record == NULL) {
        return;
    }

    memset(record, 0, sizeof(*record));
    record->session_id = session->id;
    record->client_port = session->metadata.client_port;
    record->target_port = session->metadata.target_port;
    record->created_at = session->stats.start_time;
    record->last_active = session->stats.last_activity;
    record->synced_at = time(NULL);
    record->state = (uint32_t)session->state;
    record->bytes_sent = session->stats.bytes_sent;
    record->bytes_received = session->stats.bytes_received;
    record->active = session->state != SESSION_STATE_CLOSED;

    strncpy(record->username, session->metadata.username, sizeof(record->username) - 1);
    strncpy(record->client_addr, session->metadata.client_addr, sizeof(record->client_addr) - 1);
    strncpy(record->target_addr, session->metadata.target_addr, sizeof(record->target_addr) - 1);
    strncpy(record->client_version, session->metadata.client_version,
            sizeof(record->client_version) - 1);
    strncpy(record->client_os, session->metadata.client_os, sizeof(record->client_os) - 1);
    strncpy(record->device_fingerprint, session->metadata.device_fingerprint,
            sizeof(record->device_fingerprint) - 1);

    if (session->manager != NULL) {
        strncpy(record->instance_id, session->manager->config.instance_id,
                sizeof(record->instance_id) - 1);
    }
}

static bool session_manager_should_stop_sync(session_manager_t *manager)
{
    if (manager == NULL) {
        return true;
    }

    pthread_mutex_lock(&manager->lock);
    bool stop = manager->stop_sync_thread;
    pthread_mutex_unlock(&manager->lock);
    return stop;
}

static void *session_manager_sync_loop(void *arg)
{
    session_manager_t *manager = (session_manager_t *)arg;
    if (manager == NULL || manager->store == NULL ||
        manager->config.store_type != SESSION_MANAGER_STORE_FILE) {
        return NULL;
    }

    int interval = manager->config.sync_interval_sec;
    if (interval <= 0) {
        interval = 5;
    }

    int elapsed = 0;
    while (!session_manager_should_stop_sync(manager)) {
        sleep(1);
        elapsed++;
        if (elapsed < interval) {
            continue;
        }
        elapsed = 0;
        session_store_sync(manager->store);
    }

    return NULL;
}

static void session_sync_internal(session_t *session, bool force)
{
    if (session == NULL || session->manager == NULL || session->manager->store == NULL) {
        return;
    }

    session_record_t record;
    session_record_from_session(session, &record);
    if (session_store_put(session->manager->store, &record) != 0) {
        LOG_WARN("Session %lu: failed to sync session state", session->id);
        return;
    }
    if (force && session->manager->config.store_type == SESSION_MANAGER_STORE_FILE) {
        session_store_sync(session->manager->store);
    }
}

session_manager_t *session_manager_create(const session_manager_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    session_manager_t *manager = calloc(1, sizeof(session_manager_t));
    if (manager == NULL) {
        return NULL;
    }

    manager->config = *config;
    ensure_instance_id(&manager->config);
    manager->sessions = NULL;
    manager->session_count = 0;
    manager->next_local_id = 1;
    manager->id_namespace = ((uint64_t)session_hash_instance_id(manager->config.instance_id)) << 32;

    if (pthread_mutex_init(&manager->lock, NULL) != 0) {
        free(manager);
        return NULL;
    }

    if (manager->config.store_type == SESSION_MANAGER_STORE_FILE &&
        manager->config.store_path[0] == '\0') {
        pthread_mutex_destroy(&manager->lock);
        free(manager);
        return NULL;
    }

    session_store_config_t store_config = {
        .type = session_store_type_from_manager(manager->config.store_type),
        .sync_interval_sec = manager->config.sync_interval_sec,
        .max_records = (int)(manager->config.max_sessions > 0 ? manager->config.max_sessions * 4 : 0),
    };
    strncpy(store_config.store_path, manager->config.store_path, sizeof(store_config.store_path) - 1);
    strncpy(store_config.instance_id, manager->config.instance_id,
            sizeof(store_config.instance_id) - 1);

    manager->store = session_store_create(&store_config);
    if (manager->store == NULL) {
        pthread_mutex_destroy(&manager->lock);
        free(manager);
        return NULL;
    }

    if (manager->config.store_type == SESSION_MANAGER_STORE_FILE) {
        if (pthread_create(&manager->sync_thread, NULL, session_manager_sync_loop, manager) == 0) {
            manager->sync_thread_started = true;
        } else {
            session_store_destroy(manager->store);
            pthread_mutex_destroy(&manager->lock);
            free(manager);
            return NULL;
        }
    }

    LOG_DEBUG("Session manager created, max_sessions=%zu instance=%s store=%s",
              config->max_sessions, manager->config.instance_id,
              manager->config.store_type == SESSION_MANAGER_STORE_FILE ? "file" : "local");
    return manager;
}

void session_manager_destroy(session_manager_t *manager)
{
    if (manager == NULL) {
        return;
    }

    if (manager->sync_thread_started) {
        pthread_mutex_lock(&manager->lock);
        manager->stop_sync_thread = true;
        pthread_mutex_unlock(&manager->lock);
        pthread_join(manager->sync_thread, NULL);
    }

    pthread_mutex_lock(&manager->lock);

    session_t *session = manager->sessions;
    while (session != NULL) {
        session_t *next = session->next;
        uint64_t session_id = session->id;

        if (session->upstream != NULL) {
            ssh_disconnect(session->upstream);
            ssh_free(session->upstream);
        }
        if (session->client != NULL) {
            ssh_disconnect(session->client);
            ssh_free(session->client);
        }
        if (manager->store != NULL) {
            session_store_remove(manager->store, session_id);
        }
        free(session);

        session = next;
    }

    pthread_mutex_unlock(&manager->lock);
    pthread_mutex_destroy(&manager->lock);

    session_store_destroy(manager->store);
    free(manager);
    LOG_DEBUG("Session manager destroyed");
}

session_t *session_manager_create_session(session_manager_t *manager, ssh_session client_session)
{
    if (manager == NULL || client_session == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&manager->lock);

    if (manager->session_count >= manager->config.max_sessions) {
        LOG_WARN("Maximum session limit reached (%zu)", manager->config.max_sessions);
        pthread_mutex_unlock(&manager->lock);
        return NULL;
    }

    session_t *session = calloc(1, sizeof(session_t));
    if (session == NULL) {
        pthread_mutex_unlock(&manager->lock);
        return NULL;
    }

    session->id = manager->id_namespace | (uint64_t)manager->next_local_id++;
    if (manager->next_local_id == 0) {
        manager->next_local_id = 1;
    }
    session->state = SESSION_STATE_NEW;
    session->client = client_session;
    session->upstream = NULL;
    session->manager = manager;
    session->stats.start_time = time(NULL);
    session->stats.last_activity = session->stats.start_time;

    session->next = manager->sessions;
    session->prev = NULL;
    if (manager->sessions != NULL) {
        manager->sessions->prev = session;
    }
    manager->sessions = session;
    manager->session_count++;

    LOG_DEBUG("Session %lu created, total=%zu", session->id, manager->session_count);

    pthread_mutex_unlock(&manager->lock);
    session_sync_internal(session, true);
    return session;
}

void session_manager_remove_session(session_manager_t *manager, session_t *session)
{
    if (manager == NULL || session == NULL) {
        return;
    }

    pthread_mutex_lock(&manager->lock);

    if (session->prev != NULL) {
        session->prev->next = session->next;
    } else {
        manager->sessions = session->next;
    }
    if (session->next != NULL) {
        session->next->prev = session->prev;
    }

    manager->session_count--;
    uint64_t session_id = session->id;

    if (session->upstream != NULL) {
        ssh_disconnect(session->upstream);
        ssh_free(session->upstream);
    }
    if (session->client != NULL) {
        ssh_disconnect(session->client);
        ssh_free(session->client);
    }

    free(session);

    LOG_DEBUG("Session %lu removed, remaining=%zu", session_id, manager->session_count);

    pthread_mutex_unlock(&manager->lock);
    if (manager->store != NULL) {
        session_store_remove(manager->store, session_id);
    }
}

size_t session_manager_get_count(const session_manager_t *manager)
{
    if (manager == NULL) {
        return 0;
    }
    return manager->session_count;
}

size_t session_manager_snapshot_capacity(session_manager_t *manager)
{
    if (manager == NULL) {
        return 0;
    }

    size_t capacity = manager->session_count;
    if (manager->config.store_type == SESSION_MANAGER_STORE_FILE && manager->store != NULL) {
        if (session_store_sync(manager->store) == 0) {
            capacity += (size_t)session_store_count(manager->store);
        }
    }
    return capacity;
}

int session_manager_snapshot(session_manager_t *manager, session_snapshot_t *snapshots,
                             int max_snapshots)
{
    if (manager == NULL || snapshots == NULL || max_snapshots <= 0) {
        return 0;
    }

    pthread_mutex_lock(&manager->lock);

    int count = 0;
    for (session_t *session = manager->sessions;
         session != NULL && count < max_snapshots;
         session = session->next) {
        session_snapshot_from_session(session, &snapshots[count++]);
    }

    pthread_mutex_unlock(&manager->lock);

    if (manager->config.store_type != SESSION_MANAGER_STORE_FILE || manager->store == NULL ||
        count >= max_snapshots) {
        return count;
    }

    if (session_store_sync(manager->store) != 0) {
        return count;
    }

    int store_count = session_store_count(manager->store);
    if (store_count <= 0) {
        return count;
    }

    session_record_t *records = calloc((size_t)store_count, sizeof(session_record_t));
    if (records == NULL) {
        return count;
    }

    int listed = session_store_list(manager->store, records, store_count);
    for (int i = 0; i < listed && count < max_snapshots; i++) {
        if (strcmp(records[i].instance_id, manager->config.instance_id) == 0) {
            continue;
        }
        session_snapshot_from_record(&records[i], &snapshots[count++]);
    }

    free(records);
    return count;
}

int session_manager_count_user(session_manager_t *manager, const char *username)
{
    if (manager == NULL || username == NULL || username[0] == '\0' || manager->store == NULL) {
        return 0;
    }

    if (manager->config.store_type == SESSION_MANAGER_STORE_FILE) {
        session_store_sync(manager->store);
    }

    int store_count = session_store_count(manager->store);
    if (store_count <= 0) {
        return 0;
    }

    session_record_t *records = calloc((size_t)store_count, sizeof(session_record_t));
    if (records == NULL) {
        return 0;
    }

    int listed = session_store_list(manager->store, records, store_count);
    int count = 0;
    for (int i = 0; i < listed; i++) {
        if (!records[i].active || strcmp(records[i].username, username) != 0) {
            continue;
        }
        if ((session_state_t)records[i].state < SESSION_STATE_AUTHENTICATED ||
            (session_state_t)records[i].state == SESSION_STATE_CLOSED) {
            continue;
        }
        count++;
    }

    free(records);
    return count;
}

session_t *session_manager_find(session_manager_t *manager, uint64_t session_id)
{
    if (manager == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&manager->lock);

    session_t *session = manager->sessions;
    while (session != NULL) {
        if (session->id == session_id) {
            pthread_mutex_unlock(&manager->lock);
            return session;
        }
        session = session->next;
    }

    pthread_mutex_unlock(&manager->lock);
    return NULL;
}

size_t session_manager_cleanup(session_manager_t *manager)
{
    if (manager == NULL) {
        return 0;
    }

    pthread_mutex_lock(&manager->lock);

    size_t cleaned = 0;
    time_t now = time(NULL);
    session_t *session = manager->sessions;

    while (session != NULL) {
        session_t *next = session->next;

        uint32_t timeout = manager->config.session_timeout;
        if (session->state < SESSION_STATE_AUTHENTICATED) {
            timeout = manager->config.auth_timeout;
        }

        if ((now - session->stats.last_activity) > timeout) {
            uint64_t session_id = session->id;
            LOG_INFO("Session %lu timed out (idle %ld seconds)", session->id,
                     now - session->stats.last_activity);

            if (session->prev != NULL) {
                session->prev->next = session->next;
            } else {
                manager->sessions = session->next;
            }
            if (session->next != NULL) {
                session->next->prev = session->prev;
            }

            manager->session_count--;

            if (session->upstream != NULL) {
                ssh_disconnect(session->upstream);
                ssh_free(session->upstream);
            }
            if (session->client != NULL) {
                ssh_disconnect(session->client);
                ssh_free(session->client);
            }
            free(session);
            if (manager->store != NULL) {
                session_store_remove(manager->store, session_id);
            }
            cleaned++;
        }

        session = next;
    }

    pthread_mutex_unlock(&manager->lock);

    if (cleaned > 0) {
        LOG_DEBUG("Cleaned up %zu timed-out sessions", cleaned);
    }

    return cleaned;
}

/* Session operations */

uint64_t session_get_id(const session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    return session->id;
}

session_state_t session_get_state(const session_t *session)
{
    if (session == NULL) {
        return SESSION_STATE_CLOSED;
    }
    return session->state;
}

void session_set_state(session_t *session, session_state_t state)
{
    if (session == NULL) {
        return;
    }

    LOG_DEBUG("Session %lu: %s -> %s", session->id, session_state_name(session->state),
              session_state_name(state));

    session->state = state;
    session_sync_internal(session, true);
}

ssh_session session_get_client(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return session->client;
}

ssh_session session_get_upstream(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return session->upstream;
}

void session_set_upstream(session_t *session, ssh_session upstream)
{
    if (session == NULL) {
        return;
    }
    session->upstream = upstream;
}

void session_set_username(session_t *session, const char *username)
{
    if (session == NULL || username == NULL) {
        return;
    }
    strncpy(session->metadata.username, username, SESSION_MAX_USERNAME - 1);
    session->metadata.username[SESSION_MAX_USERNAME - 1] = '\0';
    session_sync_internal(session, true);
}

session_metadata_t *session_get_metadata(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return &session->metadata;
}

session_stats_t *session_get_stats(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return &session->stats;
}

void session_sync(session_t *session)
{
    session_sync_internal(session, true);
}

void session_touch(session_t *session)
{
    if (session == NULL) {
        return;
    }
    session->stats.last_activity = time(NULL);
    session_sync_internal(session, false);
}

bool session_is_timeout(const session_t *session, uint32_t timeout_seconds)
{
    if (session == NULL) {
        return true;
    }
    time_t now = time(NULL);
    return (now - session->stats.last_activity) > timeout_seconds;
}

const char *session_state_name(session_state_t state)
{
    if (state >= 0 && state <= SESSION_STATE_CLOSED) {
        return state_names[state];
    }
    return "UNKNOWN";
}
