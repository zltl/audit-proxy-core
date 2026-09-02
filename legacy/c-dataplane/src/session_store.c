/**
 * @file session_store.c
 * @brief Distributed session storage implementation
 */
#include "session_store.h"
#include "logger.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define DEFAULT_MAX_RECORDS 10000
#define DEFAULT_SYNC_INTERVAL 5

/* Internal storage */
struct session_store {
    session_store_config_t config;

    /* In-memory record array */
    session_record_t *records;
    int record_count;
    int max_records;
    time_t last_sync_at;

    pthread_mutex_t lock;
};

/* ------------------------------------------------------------------ */
/* Simple NDJSON helpers (one JSON object per line)                    */
/* ------------------------------------------------------------------ */

static bool record_is_local(const session_store_t *store, const session_record_t *record)
{
    return store != NULL && record != NULL && store->config.instance_id[0] != '\0' &&
           strcmp(record->instance_id, store->config.instance_id) == 0;
}

static void normalize_record_instance(const session_store_t *store, session_record_t *record)
{
    if (store == NULL || record == NULL) {
        return;
    }
    if (record->instance_id[0] == '\0' && store->config.instance_id[0] != '\0') {
        strncpy(record->instance_id, store->config.instance_id, sizeof(record->instance_id) - 1);
        record->instance_id[sizeof(record->instance_id) - 1] = '\0';
    }
}

static time_t record_heartbeat(const session_record_t *record)
{
    if (record == NULL) {
        return 0;
    }
    if (record->synced_at > 0) {
        return record->synced_at;
    }
    if (record->last_active > 0) {
        return record->last_active;
    }
    return record->created_at;
}

static time_t stale_cutoff(const session_store_t *store)
{
    int interval = DEFAULT_SYNC_INTERVAL;
    if (store != NULL && store->config.sync_interval_sec > 0) {
        interval = store->config.sync_interval_sec;
    }
    if (interval < 1) {
        interval = 1;
    }
    return (time_t)(interval * 3 + 1);
}

static bool record_is_stale(const session_store_t *store, const session_record_t *record, time_t now)
{
    if (store == NULL || record == NULL || now <= 0) {
        return false;
    }
    time_t heartbeat = record_heartbeat(record);
    if (heartbeat <= 0) {
        return false;
    }
    return (now - heartbeat) > stale_cutoff(store);
}

static int write_record_json(FILE *f, const session_record_t *rec)
{
    return fprintf(
        f,
        "{\"id\":%" PRIu64 ",\"user\":\"%s\",\"client\":\"%s\",\"client_port\":%u,"
        "\"target\":\"%s\",\"target_port\":%u,\"instance\":\"%s\","
        "\"client_version\":\"%s\",\"client_os\":\"%s\","
        "\"device_fingerprint\":\"%s\",\"created\":%ld,\"last_active\":%ld,\"synced_at\":%ld,"
        "\"state\":%u,\"bytes_sent\":%" PRIu64 ",\"bytes_received\":%" PRIu64 ","
        "\"active\":%s}\n",
        rec->session_id, rec->username, rec->client_addr, (unsigned int)rec->client_port,
        rec->target_addr, (unsigned int)rec->target_port, rec->instance_id,
        rec->client_version, rec->client_os, rec->device_fingerprint, (long)rec->created_at,
        (long)rec->last_active, (long)rec->synced_at, rec->state, rec->bytes_sent,
        rec->bytes_received,
        rec->active ? "true" : "false");
}

static void parse_str_field(const char *line, const char *key, char *dst, size_t dst_size)
{
    const char *p = strstr(line, key);
    if (!p) {
        return;
    }
    p += strlen(key);
    const char *end = strchr(p, '"');
    if (!end) {
        return;
    }
    size_t len = (size_t)(end - p);
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, p, len);
    dst[len] = '\0';
}

static void parse_u64_field(const char *line, const char *key, uint64_t *dst)
{
    const char *p = strstr(line, key);
    if (p != NULL && dst != NULL) {
        *dst = (uint64_t)strtoull(p + strlen(key), NULL, 10);
    }
}

static void parse_u32_field(const char *line, const char *key, uint32_t *dst)
{
    const char *p = strstr(line, key);
    if (p != NULL && dst != NULL) {
        *dst = (uint32_t)strtoul(p + strlen(key), NULL, 10);
    }
}

static void parse_u16_field(const char *line, const char *key, uint16_t *dst)
{
    const char *p = strstr(line, key);
    if (p != NULL && dst != NULL) {
        *dst = (uint16_t)strtoul(p + strlen(key), NULL, 10);
    }
}

static void parse_time_field(const char *line, const char *key, time_t *dst)
{
    const char *p = strstr(line, key);
    if (p != NULL && dst != NULL) {
        *dst = (time_t)strtol(p + strlen(key), NULL, 10);
    }
}

static int parse_record_json(const char *line, session_record_t *rec)
{
    memset(rec, 0, sizeof(*rec));

    parse_u64_field(line, "\"id\":", &rec->session_id);
    parse_str_field(line, "\"user\":\"", rec->username, sizeof(rec->username));
    parse_str_field(line, "\"client\":\"", rec->client_addr, sizeof(rec->client_addr));
    parse_u16_field(line, "\"client_port\":", &rec->client_port);
    parse_str_field(line, "\"target\":\"", rec->target_addr, sizeof(rec->target_addr));
    parse_u16_field(line, "\"target_port\":", &rec->target_port);
    parse_str_field(line, "\"instance\":\"", rec->instance_id, sizeof(rec->instance_id));
    parse_str_field(line, "\"client_version\":\"", rec->client_version,
                    sizeof(rec->client_version));
    parse_str_field(line, "\"client_os\":\"", rec->client_os, sizeof(rec->client_os));
    parse_str_field(line, "\"device_fingerprint\":\"", rec->device_fingerprint,
                    sizeof(rec->device_fingerprint));
    parse_time_field(line, "\"created\":", &rec->created_at);
    parse_time_field(line, "\"last_active\":", &rec->last_active);
    parse_time_field(line, "\"synced_at\":", &rec->synced_at);
    parse_u32_field(line, "\"state\":", &rec->state);
    parse_u64_field(line, "\"bytes_sent\":", &rec->bytes_sent);
    parse_u64_field(line, "\"bytes_received\":", &rec->bytes_received);

    const char *active = strstr(line, "\"active\":");
    if (active != NULL) {
        rec->active = (strncmp(active + strlen("\"active\":"), "true", 4) == 0);
    }
    if (rec->synced_at == 0) {
        rec->synced_at = rec->last_active != 0 ? rec->last_active : rec->created_at;
    }

    return rec->session_id != 0 ? 0 : -1;
}

static int session_store_sync_if_due(session_store_t *store, bool force)
{
    if (store == NULL || store->config.type != SESSION_STORE_FILE) {
        return 0;
    }

    time_t now = time(NULL);
    if (!force && store->last_sync_at != 0 && store->config.sync_interval_sec > 0 &&
        (now - store->last_sync_at) < store->config.sync_interval_sec) {
        return 0;
    }

    return session_store_sync(store);
}

/* ------------------------------------------------------------------ */
/* File-based sync (flock for multi-process safety)                   */
/* ------------------------------------------------------------------ */

int session_store_sync(session_store_t *store)
{
    if (!store || store->config.type != SESSION_STORE_FILE) {
        return -1;
    }
    if (store->config.store_path[0] == '\0') {
        return -1;
    }

    pthread_mutex_lock(&store->lock);

    FILE *f = fopen(store->config.store_path, "r+");
    if (!f) {
        f = fopen(store->config.store_path, "w+");
        if (!f) {
            LOG_ERROR("Session store: cannot open %s: %s", store->config.store_path,
                      strerror(errno));
            pthread_mutex_unlock(&store->lock);
            return -1;
        }
    }

    int fd = fileno(f);
    if (flock(fd, LOCK_EX) != 0) {
        LOG_ERROR("Session store: flock failed: %s", strerror(errno));
        fclose(f);
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    session_record_t *local_records =
        calloc((size_t)store->max_records, sizeof(session_record_t));
    session_record_t *remote_records =
        calloc((size_t)store->max_records, sizeof(session_record_t));
    if (local_records == NULL || remote_records == NULL) {
        LOG_ERROR("Session store: calloc failed while syncing");
        free(local_records);
        free(remote_records);
        flock(fd, LOCK_UN);
        fclose(f);
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    int local_count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < store->record_count && local_count < store->max_records; i++) {
        if (!record_is_local(store, &store->records[i])) {
            continue;
        }
        local_records[local_count] = store->records[i];
        normalize_record_instance(store, &local_records[local_count]);
        local_records[local_count].synced_at = now;
        local_count++;
    }

    rewind(f);
    int remote_count = 0;
    char line[4096];
    while (fgets(line, (int)sizeof(line), f) != NULL && remote_count < store->max_records) {
        session_record_t rec;
        if (parse_record_json(line, &rec) != 0) {
            continue;
        }
        if (record_is_local(store, &rec)) {
            continue;
        }
        if (record_is_stale(store, &rec, now)) {
            LOG_INFO("Session store: dropping stale remote session %" PRIu64 " from %s",
                     rec.session_id, rec.instance_id);
            continue;
        }
        remote_records[remote_count++] = rec;
    }

    if (ftruncate(fd, 0) != 0) {
        LOG_ERROR("Session store: ftruncate failed: %s", strerror(errno));
        free(local_records);
        free(remote_records);
        flock(fd, LOCK_UN);
        fclose(f);
        pthread_mutex_unlock(&store->lock);
        return -1;
    }
    rewind(f);

    for (int i = 0; i < local_count; i++) {
        write_record_json(f, &local_records[i]);
    }
    for (int i = 0; i < remote_count; i++) {
        write_record_json(f, &remote_records[i]);
    }

    fflush(f);
    fsync(fd);
    flock(fd, LOCK_UN);
    fclose(f);

    store->record_count = 0;
    for (int i = 0; i < local_count && store->record_count < store->max_records; i++) {
        store->records[store->record_count++] = local_records[i];
    }
    for (int i = 0; i < remote_count && store->record_count < store->max_records; i++) {
        store->records[store->record_count++] = remote_records[i];
    }
    store->last_sync_at = time(NULL);

    free(local_records);
    free(remote_records);
    pthread_mutex_unlock(&store->lock);

    LOG_DEBUG("Session store: synced %d local + %d remote records", local_count, remote_count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

session_store_t *session_store_create(const session_store_config_t *config)
{
    if (!config) {
        return NULL;
    }

    session_store_t *store = calloc(1, sizeof(session_store_t));
    if (!store) {
        return NULL;
    }

    store->config = *config;
    store->max_records =
        config->max_records > 0 ? config->max_records : DEFAULT_MAX_RECORDS;
    if (store->config.sync_interval_sec <= 0) {
        store->config.sync_interval_sec = DEFAULT_SYNC_INTERVAL;
    }
    if (store->config.instance_id[0] == '\0') {
        snprintf(store->config.instance_id, sizeof(store->config.instance_id), "node-%d", getpid());
    }

    store->records =
        calloc((size_t)store->max_records, sizeof(session_record_t));
    if (!store->records) {
        free(store);
        return NULL;
    }

    pthread_mutex_init(&store->lock, NULL);

    if (store->config.type == SESSION_STORE_FILE && store->config.store_path[0] != '\0') {
        session_store_sync(store);
    }

    LOG_INFO("Session store created (type=%s, instance=%s, max_records=%d)",
             config->type == SESSION_STORE_LOCAL ? "local" : "file",
             store->config.instance_id, store->max_records);

    return store;
}

void session_store_destroy(session_store_t *store)
{
    if (!store) {
        return;
    }

    if (store->config.type == SESSION_STORE_FILE) {
        session_store_sync(store);
    }

    pthread_mutex_destroy(&store->lock);
    free(store->records);
    free(store);

    LOG_INFO("Session store destroyed");
}

/* ------------------------------------------------------------------ */
/* CRUD operations                                                    */
/* ------------------------------------------------------------------ */

int session_store_put(session_store_t *store, const session_record_t *record)
{
    if (!store || !record) {
        return -1;
    }

    session_record_t copy = *record;
    normalize_record_instance(store, &copy);

    pthread_mutex_lock(&store->lock);

    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].session_id == copy.session_id) {
            store->records[i] = copy;
            pthread_mutex_unlock(&store->lock);
            session_store_sync_if_due(store, false);
            return 0;
        }
    }

    if (store->record_count >= store->max_records) {
        pthread_mutex_unlock(&store->lock);
        LOG_WARN("Session store full (%d records)", store->max_records);
        return -1;
    }

    store->records[store->record_count++] = copy;
    pthread_mutex_unlock(&store->lock);
    session_store_sync_if_due(store, false);
    return 0;
}

int session_store_get(session_store_t *store, uint64_t session_id, session_record_t *record)
{
    if (!store || !record) {
        return -1;
    }

    pthread_mutex_lock(&store->lock);

    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].session_id == session_id) {
            *record = store->records[i];
            pthread_mutex_unlock(&store->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return -1;
}

int session_store_remove(session_store_t *store, uint64_t session_id)
{
    if (!store) {
        return -1;
    }

    pthread_mutex_lock(&store->lock);

    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].session_id == session_id) {
            if (i < store->record_count - 1) {
                store->records[i] = store->records[store->record_count - 1];
            }
            store->record_count--;
            pthread_mutex_unlock(&store->lock);
            session_store_sync_if_due(store, true);
            return 0;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return -1;
}

int session_store_list(session_store_t *store, session_record_t *records, int max_records)
{
    if (!store || !records || max_records <= 0) {
        return 0;
    }

    pthread_mutex_lock(&store->lock);

    int count = store->record_count < max_records ? store->record_count : max_records;
    memcpy(records, store->records, (size_t)count * sizeof(session_record_t));

    pthread_mutex_unlock(&store->lock);
    return count;
}

int session_store_count(session_store_t *store)
{
    if (!store) {
        return 0;
    }

    pthread_mutex_lock(&store->lock);
    int count = store->record_count;
    pthread_mutex_unlock(&store->lock);

    return count;
}

int session_store_count_user(session_store_t *store, const char *username)
{
    if (!store || !username) {
        return 0;
    }

    pthread_mutex_lock(&store->lock);

    int count = 0;
    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].active && strcmp(store->records[i].username, username) == 0) {
            count++;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return count;
}
