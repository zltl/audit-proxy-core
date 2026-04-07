/**
 * @file account_lock.c
 * @brief SSH Proxy Core - Account Lockout Implementation
 *
 * Uses an open-addressing hash table for O(1) username lookups.
 * All operations are protected by a pthread_mutex for thread safety.
 */

#include "account_lock.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* Hash table entry for tracking a single user */
typedef struct lock_entry {
    char username[128];     /* Username (empty string = unused slot) */
    uint32_t fail_count;    /* Number of consecutive failures */
    time_t last_failure;    /* Timestamp of most recent failure */
    time_t locked_until;    /* Lockout expiry (0 = not locked) */
} lock_entry_t;

/* Default hash table capacity */
#define LOCK_TABLE_CAPACITY 256

/* Module state */
static struct {
    lock_entry_t *table;
    size_t capacity;
    account_lock_config_t config;
    pthread_mutex_t mutex;
    bool initialized;
} g_lock;

/* FNV-1a hash */
static uint32_t hash_username(const char *username)
{
    uint32_t hash = 2166136261u;
    for (const char *p = username; *p != '\0'; p++) {
        hash ^= (uint32_t)(unsigned char)*p;
        hash *= 16777619u;
    }
    return hash;
}

/* Find or create entry for username (caller must hold mutex) */
static lock_entry_t *find_entry(const char *username, bool create)
{
    if (g_lock.table == NULL || username == NULL) {
        return NULL;
    }

    uint32_t h = hash_username(username);
    size_t idx = h % g_lock.capacity;
    lock_entry_t *first_empty = NULL;

    for (size_t i = 0; i < g_lock.capacity; i++) {
        size_t probe = (idx + i) % g_lock.capacity;
        lock_entry_t *entry = &g_lock.table[probe];

        if (entry->username[0] == '\0') {
            if (first_empty == NULL) {
                first_empty = entry;
            }
            /* In open addressing, an empty slot means the key is absent */
            break;
        }

        if (strcmp(entry->username, username) == 0) {
            return entry;
        }
    }

    if (create && first_empty != NULL) {
        strncpy(first_empty->username, username,
                sizeof(first_empty->username) - 1);
        first_empty->username[sizeof(first_empty->username) - 1] = '\0';
        first_empty->fail_count = 0;
        first_empty->last_failure = 0;
        first_empty->locked_until = 0;
        return first_empty;
    }

    return NULL;
}

int account_lock_init(const account_lock_config_t *config)
{
    if (g_lock.initialized) {
        account_lock_cleanup();
    }

    memset(&g_lock, 0, sizeof(g_lock));

    if (config != NULL) {
        g_lock.config = *config;
    } else {
        g_lock.config.lockout_enabled = false;
        g_lock.config.lockout_threshold = 5;
        g_lock.config.lockout_duration_sec = 300;
    }

    /* Ensure sane defaults */
    if (g_lock.config.lockout_threshold == 0) {
        g_lock.config.lockout_threshold = 5;
    }
    if (g_lock.config.lockout_duration_sec == 0) {
        g_lock.config.lockout_duration_sec = 300;
    }

    g_lock.capacity = LOCK_TABLE_CAPACITY;
    g_lock.table = calloc(g_lock.capacity, sizeof(lock_entry_t));
    if (g_lock.table == NULL) {
        LOG_ERROR("account_lock: failed to allocate table");
        return -1;
    }

    if (pthread_mutex_init(&g_lock.mutex, NULL) != 0) {
        free(g_lock.table);
        g_lock.table = NULL;
        LOG_ERROR("account_lock: failed to init mutex");
        return -1;
    }

    g_lock.initialized = true;
    LOG_INFO("Account lockout initialized (enabled=%s, threshold=%u, duration=%us)",
             g_lock.config.lockout_enabled ? "true" : "false",
             g_lock.config.lockout_threshold,
             g_lock.config.lockout_duration_sec);
    return 0;
}

void account_lock_cleanup(void)
{
    if (!g_lock.initialized) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);
    free(g_lock.table);
    g_lock.table = NULL;
    g_lock.capacity = 0;
    g_lock.initialized = false;
    pthread_mutex_unlock(&g_lock.mutex);

    pthread_mutex_destroy(&g_lock.mutex);
    LOG_DEBUG("Account lockout cleaned up");
}

bool account_is_locked(const char *username)
{
    if (!g_lock.initialized || !g_lock.config.lockout_enabled ||
        username == NULL) {
        return false;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(username, false);
    bool locked = false;

    if (entry != NULL && entry->locked_until > 0) {
        time_t now = time(NULL);
        if (now < entry->locked_until) {
            locked = true;
        } else {
            /* Lockout expired — reset */
            entry->locked_until = 0;
            entry->fail_count = 0;
        }
    }

    pthread_mutex_unlock(&g_lock.mutex);
    return locked;
}

void account_record_failure(const char *username)
{
    if (!g_lock.initialized || !g_lock.config.lockout_enabled ||
        username == NULL) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(username, true);
    if (entry == NULL) {
        LOG_WARN("account_lock: hash table full, cannot track '%s'", username);
        pthread_mutex_unlock(&g_lock.mutex);
        return;
    }

    entry->fail_count++;
    entry->last_failure = time(NULL);

    if (entry->fail_count >= g_lock.config.lockout_threshold) {
        entry->locked_until = entry->last_failure +
                              (time_t)g_lock.config.lockout_duration_sec;
        LOG_WARN("Account '%s' locked after %u failed attempts (until +%us)",
                 username, entry->fail_count,
                 g_lock.config.lockout_duration_sec);
    } else {
        LOG_DEBUG("Account '%s' failed attempt %u/%u",
                  username, entry->fail_count,
                  g_lock.config.lockout_threshold);
    }

    pthread_mutex_unlock(&g_lock.mutex);
}

void account_record_success(const char *username)
{
    if (!g_lock.initialized || !g_lock.config.lockout_enabled ||
        username == NULL) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(username, false);
    if (entry != NULL) {
        entry->fail_count = 0;
        entry->last_failure = 0;
        entry->locked_until = 0;
        LOG_DEBUG("Account '%s' failure count reset on success", username);
    }

    pthread_mutex_unlock(&g_lock.mutex);
}

int account_get_failures(const char *username)
{
    if (!g_lock.initialized || username == NULL) {
        return 0;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(username, false);
    int count = (entry != NULL) ? (int)entry->fail_count : 0;

    pthread_mutex_unlock(&g_lock.mutex);
    return count;
}
