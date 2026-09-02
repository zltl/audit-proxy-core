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

/* Hash table entry for tracking a single user/IP */
typedef struct lock_entry {
    char key[256];          /* Username/IP key (empty string = unused slot) */
    uint32_t fail_count;    /* Number of consecutive failures */
    time_t last_failure;    /* Timestamp of most recent failure */
    time_t locked_until;    /* Lockout expiry (0 = not locked) */
} lock_entry_t;

typedef struct lock_table {
    lock_entry_t *entries;
    size_t capacity;
} lock_table_t;

/* Default hash table capacity */
#define LOCK_TABLE_CAPACITY 256

/* Module state */
static struct {
    lock_table_t accounts;
    lock_table_t ips;
    account_lock_config_t config;
    pthread_mutex_t mutex;
    bool initialized;
} g_lock;

/* FNV-1a hash */
static uint32_t hash_key(const char *key)
{
    uint32_t hash = 2166136261u;
    for (const char *p = key; *p != '\0'; p++) {
        hash ^= (uint32_t)(unsigned char)*p;
        hash *= 16777619u;
    }
    return hash;
}

static void normalize_config(account_lock_config_t *config)
{
    if (config == NULL) {
        return;
    }
    if (config->lockout_threshold == 0) {
        config->lockout_threshold = 5;
    }
    if (config->lockout_duration_sec == 0) {
        config->lockout_duration_sec = 300;
    }
    if (config->ip_ban_threshold == 0) {
        config->ip_ban_threshold = 10;
    }
    if (config->ip_ban_duration_sec == 0) {
        config->ip_ban_duration_sec = 900;
    }
}

static void reset_table(lock_table_t *table)
{
    if (table == NULL || table->entries == NULL) {
        return;
    }
    memset(table->entries, 0, table->capacity * sizeof(lock_entry_t));
}

/* Find or create entry for key (caller must hold mutex) */
static lock_entry_t *find_entry(lock_table_t *table, const char *key, bool create)
{
    if (table == NULL || table->entries == NULL || key == NULL) {
        return NULL;
    }

    uint32_t h = hash_key(key);
    size_t idx = h % table->capacity;
    lock_entry_t *first_empty = NULL;

    for (size_t i = 0; i < table->capacity; i++) {
        size_t probe = (idx + i) % table->capacity;
        lock_entry_t *entry = &table->entries[probe];

        if (entry->key[0] == '\0') {
            if (first_empty == NULL) {
                first_empty = entry;
            }
            /* In open addressing, an empty slot means the key is absent */
            break;
        }

        if (strcmp(entry->key, key) == 0) {
            return entry;
        }
    }

    if (create && first_empty != NULL) {
        strncpy(first_empty->key, key, sizeof(first_empty->key) - 1);
        first_empty->key[sizeof(first_empty->key) - 1] = '\0';
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
        g_lock.config.ip_ban_enabled = false;
        g_lock.config.ip_ban_threshold = 10;
        g_lock.config.ip_ban_duration_sec = 900;
    }
    normalize_config(&g_lock.config);

    g_lock.accounts.capacity = LOCK_TABLE_CAPACITY;
    g_lock.accounts.entries = calloc(g_lock.accounts.capacity, sizeof(lock_entry_t));
    g_lock.ips.capacity = LOCK_TABLE_CAPACITY;
    g_lock.ips.entries = calloc(g_lock.ips.capacity, sizeof(lock_entry_t));
    if (g_lock.accounts.entries == NULL || g_lock.ips.entries == NULL) {
        LOG_ERROR("account_lock: failed to allocate tables");
        free(g_lock.accounts.entries);
        free(g_lock.ips.entries);
        g_lock.accounts.entries = NULL;
        g_lock.ips.entries = NULL;
        return -1;
    }

    if (pthread_mutex_init(&g_lock.mutex, NULL) != 0) {
        free(g_lock.accounts.entries);
        free(g_lock.ips.entries);
        g_lock.accounts.entries = NULL;
        g_lock.ips.entries = NULL;
        LOG_ERROR("account_lock: failed to init mutex");
        return -1;
    }

    g_lock.initialized = true;
    LOG_INFO("Account/IP lockout initialized (account=%s threshold=%u duration=%us, ip_ban=%s "
             "threshold=%u duration=%us)",
             g_lock.config.lockout_enabled ? "true" : "false",
             g_lock.config.lockout_threshold,
             g_lock.config.lockout_duration_sec,
             g_lock.config.ip_ban_enabled ? "true" : "false",
             g_lock.config.ip_ban_threshold,
             g_lock.config.ip_ban_duration_sec);
    return 0;
}

int account_lock_update_config(const account_lock_config_t *config)
{
    if (!g_lock.initialized) {
        return -1;
    }

    pthread_mutex_lock(&g_lock.mutex);

    account_lock_config_t next = {0};
    if (config != NULL) {
        next = *config;
    } else {
        next.lockout_enabled = false;
        next.lockout_threshold = 5;
        next.lockout_duration_sec = 300;
        next.ip_ban_enabled = false;
        next.ip_ban_threshold = 10;
        next.ip_ban_duration_sec = 900;
    }
    normalize_config(&next);

    if (!next.lockout_enabled) {
        reset_table(&g_lock.accounts);
    }
    if (!next.ip_ban_enabled) {
        reset_table(&g_lock.ips);
    }

    g_lock.config = next;

    pthread_mutex_unlock(&g_lock.mutex);
    return 0;
}

void account_lock_cleanup(void)
{
    if (!g_lock.initialized) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);
    free(g_lock.accounts.entries);
    free(g_lock.ips.entries);
    g_lock.accounts.entries = NULL;
    g_lock.ips.entries = NULL;
    g_lock.accounts.capacity = 0;
    g_lock.ips.capacity = 0;
    g_lock.initialized = false;
    pthread_mutex_unlock(&g_lock.mutex);

    pthread_mutex_destroy(&g_lock.mutex);
    LOG_DEBUG("Account lockout cleaned up");
}

static bool entry_is_locked(lock_table_t *table, const char *key)
{
    if (!g_lock.initialized || key == NULL) {
        return false;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(table, key, false);
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

bool account_is_locked(const char *username)
{
    if (!g_lock.config.lockout_enabled) {
        return false;
    }
    return entry_is_locked(&g_lock.accounts, username);
}

bool account_ip_is_blocked(const char *client_addr)
{
    if (!g_lock.config.ip_ban_enabled) {
        return false;
    }
    return entry_is_locked(&g_lock.ips, client_addr);
}

static void record_failure(lock_table_t *table, const char *key, bool enabled, uint32_t threshold,
                           uint32_t duration_sec, const char *subject_name)
{
    if (!g_lock.initialized || !enabled || key == NULL) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(table, key, true);
    if (entry == NULL) {
        LOG_WARN("account_lock: hash table full, cannot track %s '%s'", subject_name, key);
        pthread_mutex_unlock(&g_lock.mutex);
        return;
    }

    entry->fail_count++;
    entry->last_failure = time(NULL);

    if (entry->fail_count >= threshold) {
        entry->locked_until = entry->last_failure + (time_t)duration_sec;
        LOG_WARN("%s '%s' locked after %u failed attempts (until +%us)", subject_name, key,
                 entry->fail_count, duration_sec);
    } else {
        LOG_DEBUG("%s '%s' failed attempt %u/%u", subject_name, key, entry->fail_count, threshold);
    }

    pthread_mutex_unlock(&g_lock.mutex);
}

void account_record_failure(const char *username)
{
    record_failure(&g_lock.accounts, username, g_lock.config.lockout_enabled,
                   g_lock.config.lockout_threshold, g_lock.config.lockout_duration_sec, "Account");
}

void account_ip_record_failure(const char *client_addr)
{
    record_failure(&g_lock.ips, client_addr, g_lock.config.ip_ban_enabled,
                   g_lock.config.ip_ban_threshold, g_lock.config.ip_ban_duration_sec, "Client IP");
}

static void record_success(lock_table_t *table, const char *key, bool enabled, const char *subject_name)
{
    if (!g_lock.initialized || !enabled || key == NULL) {
        return;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(table, key, false);
    if (entry != NULL) {
        entry->fail_count = 0;
        entry->last_failure = 0;
        entry->locked_until = 0;
        LOG_DEBUG("%s '%s' failure count reset on success", subject_name, key);
    }

    pthread_mutex_unlock(&g_lock.mutex);
}

void account_record_success(const char *username)
{
    record_success(&g_lock.accounts, username, g_lock.config.lockout_enabled, "Account");
}

void account_ip_record_success(const char *client_addr)
{
    record_success(&g_lock.ips, client_addr, g_lock.config.ip_ban_enabled, "Client IP");
}

static int get_failures(lock_table_t *table, const char *key)
{
    if (!g_lock.initialized || key == NULL) {
        return 0;
    }

    pthread_mutex_lock(&g_lock.mutex);

    lock_entry_t *entry = find_entry(table, key, false);
    int count = (entry != NULL) ? (int)entry->fail_count : 0;

    pthread_mutex_unlock(&g_lock.mutex);
    return count;
}

int account_get_failures(const char *username)
{
    return get_failures(&g_lock.accounts, username);
}

int account_ip_get_failures(const char *client_addr)
{
    return get_failures(&g_lock.ips, client_addr);
}
