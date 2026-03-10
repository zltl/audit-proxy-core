/**
 * @file session_store.c
 * @brief Distributed session storage implementation
 */
#include "session_store.h"
#include "logger.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
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

    pthread_mutex_t lock;
};

/* ------------------------------------------------------------------ */
/* Simple NDJSON helpers (one JSON object per line)                    */
/* ------------------------------------------------------------------ */

static int write_record_json(FILE *f, const session_record_t *rec)
{
    return fprintf(f,
        "{\"id\":%" PRIu64 ",\"user\":\"%s\",\"client\":\"%s\","
        "\"target\":\"%s\",\"instance\":\"%s\","
        "\"created\":%ld,\"last_active\":%ld,\"active\":%s}\n",
        rec->session_id,
        rec->username, rec->client_addr, rec->target_addr,
        rec->instance_id, (long)rec->created_at, (long)rec->last_active,
        rec->active ? "true" : "false");
}

static void parse_str_field(const char *line, const char *key,
                            char *dst, size_t dst_size)
{
    const char *p = strstr(line, key);
    if (!p) return;
    p += strlen(key);
    const char *end = strchr(p, '"');
    if (!end) return;
    size_t len = (size_t)(end - p);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, p, len);
    dst[len] = '\0';
}

static int parse_record_json(const char *line, session_record_t *rec)
{
    const char *p;
    memset(rec, 0, sizeof(*rec));

    p = strstr(line, "\"id\":");
    if (p) rec->session_id = (uint64_t)strtoull(p + 5, NULL, 10);

    parse_str_field(line, "\"user\":\"",     rec->username,    sizeof(rec->username));
    parse_str_field(line, "\"client\":\"",   rec->client_addr, sizeof(rec->client_addr));
    parse_str_field(line, "\"target\":\"",   rec->target_addr, sizeof(rec->target_addr));
    parse_str_field(line, "\"instance\":\"", rec->instance_id, sizeof(rec->instance_id));

    p = strstr(line, "\"created\":");
    if (p) rec->created_at = (time_t)strtol(p + 10, NULL, 10);

    p = strstr(line, "\"last_active\":");
    if (p) rec->last_active = (time_t)strtol(p + 14, NULL, 10);

    p = strstr(line, "\"active\":");
    if (p) rec->active = (strncmp(p + 9, "true", 4) == 0);

    return (rec->session_id != 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* File-based sync (flock for multi-process safety)                   */
/* ------------------------------------------------------------------ */

int session_store_sync(session_store_t *store)
{
    if (!store || store->config.type != SESSION_STORE_FILE)
        return -1;
    if (store->config.store_path[0] == '\0')
        return -1;

    pthread_mutex_lock(&store->lock);

    /* Open file for read-write; create if missing */
    FILE *f = fopen(store->config.store_path, "r+");
    if (!f) {
        f = fopen(store->config.store_path, "w+");
        if (!f) {
            LOG_ERROR("Session store: cannot open %s: %s",
                      store->config.store_path, strerror(errno));
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

    /* Heap-allocate remote record buffer (too large for the stack) */
    int max_remote = store->max_records;
    session_record_t *remote_records = calloc((size_t)max_remote,
                                              sizeof(session_record_t));
    if (!remote_records) {
        LOG_ERROR("Session store: calloc failed for remote records");
        flock(fd, LOCK_UN);
        fclose(f);
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    /* Read existing records from other instances */
    int remote_count = 0;
    char line[2048];
    while (fgets(line, (int)sizeof(line), f) && remote_count < max_remote) {
        session_record_t rec;
        if (parse_record_json(line, &rec) == 0) {
            if (strcmp(rec.instance_id, store->config.instance_id) != 0) {
                remote_records[remote_count++] = rec;
            }
        }
    }

    /* Truncate and rewrite (keeps the same fd so flock stays valid) */
    if (ftruncate(fd, 0) != 0) {
        LOG_ERROR("Session store: ftruncate failed: %s", strerror(errno));
        free(remote_records);
        flock(fd, LOCK_UN);
        fclose(f);
        pthread_mutex_unlock(&store->lock);
        return -1;
    }
    rewind(f);

    /* Write our records */
    for (int i = 0; i < store->record_count; i++) {
        write_record_json(f, &store->records[i]);
    }

    /* Write remote records */
    for (int i = 0; i < remote_count; i++) {
        write_record_json(f, &remote_records[i]);
    }

    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);

    /* Merge remote records into our local view */
    for (int i = 0; i < remote_count &&
                    store->record_count < store->max_records; i++) {
        bool found = false;
        for (int j = 0; j < store->record_count; j++) {
            if (store->records[j].session_id == remote_records[i].session_id) {
                found = true;
                break;
            }
        }
        if (!found) {
            store->records[store->record_count++] = remote_records[i];
        }
    }

    int local_count = store->record_count - remote_count;
    free(remote_records);
    pthread_mutex_unlock(&store->lock);

    LOG_DEBUG("Session store: synced %d local + %d remote records",
              local_count, remote_count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

session_store_t *session_store_create(const session_store_config_t *config)
{
    if (!config) return NULL;

    session_store_t *store = calloc(1, sizeof(session_store_t));
    if (!store) return NULL;

    store->config = *config;
    store->max_records = config->max_records > 0
                             ? config->max_records
                             : DEFAULT_MAX_RECORDS;

    store->records = calloc((size_t)store->max_records,
                            sizeof(session_record_t));
    if (!store->records) {
        free(store);
        return NULL;
    }

    pthread_mutex_init(&store->lock, NULL);

    /* Defaults */
    if (store->config.sync_interval_sec <= 0)
        store->config.sync_interval_sec = DEFAULT_SYNC_INTERVAL;

    if (store->config.instance_id[0] == '\0')
        snprintf(store->config.instance_id,
                 sizeof(store->config.instance_id),
                 "node-%d", getpid());

    /* Load existing data from file if FILE backend */
    if (config->type == SESSION_STORE_FILE &&
        config->store_path[0] != '\0') {
        session_store_sync(store);
    }

    LOG_INFO("Session store created (type=%s, instance=%s, max_records=%d)",
             config->type == SESSION_STORE_LOCAL ? "local" : "file",
             store->config.instance_id, store->max_records);

    return store;
}

void session_store_destroy(session_store_t *store)
{
    if (!store) return;

    /* Final sync for file backend */
    if (store->config.type == SESSION_STORE_FILE)
        session_store_sync(store);

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
    if (!store || !record) return -1;

    pthread_mutex_lock(&store->lock);

    /* Update existing record */
    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].session_id == record->session_id) {
            store->records[i] = *record;
            pthread_mutex_unlock(&store->lock);
            return 0;
        }
    }

    /* Insert new record */
    if (store->record_count >= store->max_records) {
        pthread_mutex_unlock(&store->lock);
        LOG_WARN("Session store full (%d records)", store->max_records);
        return -1;
    }

    store->records[store->record_count++] = *record;
    pthread_mutex_unlock(&store->lock);
    return 0;
}

int session_store_get(session_store_t *store, uint64_t session_id,
                      session_record_t *record)
{
    if (!store || !record) return -1;

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
    if (!store) return -1;

    pthread_mutex_lock(&store->lock);

    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].session_id == session_id) {
            /* Swap with last element to fill the gap */
            if (i < store->record_count - 1)
                store->records[i] = store->records[store->record_count - 1];
            store->record_count--;
            pthread_mutex_unlock(&store->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return -1;
}

int session_store_list(session_store_t *store, session_record_t *records,
                       int max_records)
{
    if (!store || !records || max_records <= 0) return 0;

    pthread_mutex_lock(&store->lock);

    int count = store->record_count < max_records
                    ? store->record_count
                    : max_records;
    memcpy(records, store->records,
           (size_t)count * sizeof(session_record_t));

    pthread_mutex_unlock(&store->lock);
    return count;
}

int session_store_count(session_store_t *store)
{
    if (!store) return 0;

    pthread_mutex_lock(&store->lock);
    int count = store->record_count;
    pthread_mutex_unlock(&store->lock);

    return count;
}

int session_store_count_user(session_store_t *store, const char *username)
{
    if (!store || !username) return 0;

    pthread_mutex_lock(&store->lock);

    int count = 0;
    for (int i = 0; i < store->record_count; i++) {
        if (store->records[i].active &&
            strcmp(store->records[i].username, username) == 0) {
            count++;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return count;
}
