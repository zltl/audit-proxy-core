/**
 * @file audit_filter.c
 * @brief SSH Proxy Core - Audit Filter Implementation
 */

#include "audit_filter.h"
#include "audit_sign.h"
#include "logger.h"
#include "session.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* Maximum recording sessions */
#define MAX_RECORDINGS 256
#define MAX_RETENTION_FILES 1024
#define AUDIT_AES256_KEY_SIZE 32
#define AUDIT_GCM_NONCE_SIZE 12
#define AUDIT_GCM_TAG_SIZE 16

/* Recording session state */
typedef struct recording_session {
    uint64_t session_id;
    FILE *file;
    char path[512];
    struct timeval start_time;
    bool active;
    /* Command buffer for parsing input */
    char cmd_buf[4096];
    size_t cmd_len;
    char username[128];
    char target[256];
} recording_session_t;

/* Audit filter state */
typedef struct audit_filter_state {
    recording_session_t recordings[MAX_RECORDINGS];
    size_t recording_count;
    uint8_t event_prev_hash[SHA256_DIGEST_SIZE]; /* chain hash for event log */
    uint8_t cmd_prev_hash[SHA256_DIGEST_SIZE];   /* chain hash for command log */
    bool encryption_enabled;
    uint8_t encryption_key[AUDIT_AES256_KEY_SIZE];
} audit_filter_state_t;

/* Event type names */
static const char *event_type_names[] = {"CONNECT",         "AUTH_SUCCESS", "AUTH_FAILURE",
                                         "SESSION_START",   "COMMAND",      "DATA_UPSTREAM",
                                         "DATA_DOWNSTREAM", "SESSION_END",  "DISCONNECT"};

/* Forward declarations */
static filter_status_t audit_on_connect(filter_t *filter, filter_context_t *ctx);
static filter_status_t audit_on_auth(filter_t *filter, filter_context_t *ctx);
static filter_status_t audit_on_authenticated(filter_t *filter, filter_context_t *ctx);
static filter_status_t audit_on_data_upstream(filter_t *filter, filter_context_t *ctx,
                                              const uint8_t *data, size_t len);
static filter_status_t audit_on_data_downstream(filter_t *filter, filter_context_t *ctx,
                                                const uint8_t *data, size_t len);
static void audit_on_close(filter_t *filter, filter_context_t *ctx);
static void audit_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t audit_callbacks = {.on_connect = audit_on_connect,
                                                   .on_auth = audit_on_auth,
                                                   .on_authenticated = audit_on_authenticated,
                                                   .on_route = NULL,
                                                   .on_data_upstream = audit_on_data_upstream,
                                                   .on_data_downstream = audit_on_data_downstream,
                                                   .on_close = audit_on_close,
                                                   .destroy = audit_destroy};

/* Get timestamp for logging */
static void get_timestamp(char *buf, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000);
}

typedef struct retained_log_file {
    char path[PATH_MAX];
    time_t mtime;
} retained_log_file_t;

static void sort_retained_logs(retained_log_file_t *files, size_t count) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (files[j].mtime > files[i].mtime) {
                retained_log_file_t tmp = files[i];
                files[i] = files[j];
                files[j] = tmp;
            }
        }
    }
}

static void prune_archived_logs(const audit_filter_config_t *config, const char *active_path,
                                const char *prefix) {
    if (config == NULL || config->log_dir == NULL || prefix == NULL ||
        (config->max_archived_files == 0 && config->retention_days == 0)) {
        return;
    }

    DIR *dp = opendir(config->log_dir);
    if (dp == NULL) {
        return;
    }

    const char *active_name = strrchr(active_path, '/');
    active_name = (active_name != NULL) ? active_name + 1 : active_path;
    time_t now = time(NULL);

    retained_log_file_t archived[MAX_RETENTION_FILES];
    size_t archived_count = 0;

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) {
            continue;
        }
        if (strcmp(entry->d_name, active_name) == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", config->log_dir, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }

        if (config->retention_days > 0 &&
            st.st_mtime < now - (time_t)config->retention_days * 86400) {
            unlink(full_path);
            continue;
        }

        if (archived_count < MAX_RETENTION_FILES) {
            strncpy(archived[archived_count].path, full_path, sizeof(archived[archived_count].path) - 1);
            archived[archived_count].path[sizeof(archived[archived_count].path) - 1] = '\0';
            archived[archived_count].mtime = st.st_mtime;
            archived_count++;
        }
    }
    closedir(dp);

    if (config->max_archived_files == 0 || archived_count <= config->max_archived_files) {
        return;
    }

    sort_retained_logs(archived, archived_count);
    for (size_t i = config->max_archived_files; i < archived_count; i++) {
        unlink(archived[i].path);
    }
}

static int rotate_log_file_if_needed(const audit_filter_config_t *config, const char *path,
                                     size_t pending_write_len) {
    if (config == NULL || path == NULL || config->max_file_size == 0) {
        return 0;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    if ((size_t)st.st_size + pending_write_len <= config->max_file_size) {
        return 0;
    }

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    for (int suffix = 1; suffix <= 999; suffix++) {
        char archived[PATH_MAX];
        snprintf(archived, sizeof(archived), "%s.%04d%02d%02d%02d%02d%02d.%03d", path,
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                 suffix);

        if (access(archived, F_OK) == 0) {
            continue;
        }
        if (rename(path, archived) == 0) {
            LOG_INFO("Rotated audit log %s to %s", path, archived);
            return 0;
        }
        if (errno == ENOENT) {
            return 0;
        }
    }

    return -1;
}

static FILE *open_log_file_append(const audit_filter_config_t *config, const char *path,
                                  const char *prefix, size_t pending_write_len) {
    if (path == NULL) {
        return NULL;
    }

    if (rotate_log_file_if_needed(config, path, pending_write_len) != 0) {
        LOG_WARN("Failed to rotate audit log before append: %s: %s", path, strerror(errno));
    }
    prune_archived_logs(config, path, prefix);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return NULL;
    }

    FILE *f = fdopen(fd, "a");
    if (f == NULL) {
        close(fd);
        return NULL;
    }
    return f;
}

static void sync_stream(FILE *f, const char *label, const char *path)
{
    if (f == NULL) {
        return;
    }
    if (fflush(f) != 0) {
        LOG_WARN("Failed to flush %s %s: %s", label ? label : "stream",
                 path ? path : "-", strerror(errno));
        return;
    }
    if (fsync(fileno(f)) != 0) {
        LOG_WARN("Failed to sync %s %s: %s", label ? label : "stream",
                 path ? path : "-", strerror(errno));
    }
}

static int encrypt_log_line(const audit_filter_state_t *state, const char *plaintext,
                            char **out_line) {
    uint8_t nonce[AUDIT_GCM_NONCE_SIZE];
    uint8_t tag[AUDIT_GCM_TAG_SIZE];
    uint8_t *ciphertext = NULL;
    char *ciphertext_hex = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t plaintext_len = 0;
    size_t ciphertext_cap = 0;
    size_t ciphertext_len = 0;
    int out_len = 0;
    int final_len = 0;
    int written = 0;

    if (state == NULL || !state->encryption_enabled || plaintext == NULL || out_line == NULL) {
        return -1;
    }
    *out_line = NULL;

    plaintext_len = strlen(plaintext);
    ciphertext_cap = plaintext_len > 0 ? plaintext_len : 1;
    ciphertext = calloc(ciphertext_cap, 1);
    if (ciphertext == NULL) {
        return -1;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, state->encryption_key, nonce) != 1) {
        goto cleanup;
    }
    if (plaintext_len > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, (const unsigned char *)plaintext,
                          (int)plaintext_len) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) {
        goto cleanup;
    }
    ciphertext_len = (size_t)(out_len + final_len);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }

    ciphertext_hex = malloc(ciphertext_len * 2 + 1);
    if (ciphertext_hex == NULL) {
        goto cleanup;
    }

    char nonce_hex[AUDIT_GCM_NONCE_SIZE * 2 + 1];
    char tag_hex[AUDIT_GCM_TAG_SIZE * 2 + 1];
    hex_encode(nonce, sizeof(nonce), nonce_hex);
    hex_encode(tag, sizeof(tag), tag_hex);
    hex_encode(ciphertext, ciphertext_len, ciphertext_hex);

    written = snprintf(NULL, 0,
                       "{\"alg\":\"AES-256-GCM\",\"nonce\":\"%s\",\"ciphertext\":\"%s\","
                       "\"tag\":\"%s\"}",
                       nonce_hex, ciphertext_hex, tag_hex);
    if (written <= 0) {
        goto cleanup;
    }

    *out_line = malloc((size_t)written + 1);
    if (*out_line == NULL) {
        goto cleanup;
    }
    snprintf(*out_line, (size_t)written + 1,
             "{\"alg\":\"AES-256-GCM\",\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\"}",
             nonce_hex, ciphertext_hex, tag_hex);

    explicit_bzero(ciphertext, ciphertext_cap);
    explicit_bzero(ciphertext_hex, ciphertext_len * 2 + 1);
    free(ciphertext_hex);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(tag, sizeof(tag));
    return 0;

cleanup:
    if (*out_line != NULL) {
        explicit_bzero(*out_line, strlen(*out_line));
        free(*out_line);
        *out_line = NULL;
    }
    if (ciphertext_hex != NULL) {
        explicit_bzero(ciphertext_hex, ciphertext_len * 2 + 1);
        free(ciphertext_hex);
    }
    if (ciphertext != NULL) {
        explicit_bzero(ciphertext, ciphertext_cap);
        free(ciphertext);
    }
    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(tag, sizeof(tag));
    return -1;
}

static void write_log_line(const audit_filter_config_t *config, const audit_filter_state_t *state,
                           const char *path, const char *prefix, const char *line,
                           const char *label) {
    char *encrypted_line = NULL;
    const char *persisted_line = line;

    if (config == NULL || path == NULL || prefix == NULL || line == NULL || label == NULL) {
        return;
    }

    if (state != NULL && state->encryption_enabled) {
        if (encrypt_log_line(state, line, &encrypted_line) != 0) {
            LOG_ERROR("Failed to encrypt %s", label);
            return;
        }
        persisted_line = encrypted_line;
    }

    FILE *f = open_log_file_append(config, path, prefix, strlen(persisted_line) + 1);
    if (f == NULL) {
        LOG_ERROR("Failed to open %s: %s: %s", label, path, strerror(errno));
        if (encrypted_line != NULL) {
            explicit_bzero(encrypted_line, strlen(encrypted_line));
            free(encrypted_line);
        }
        return;
    }

    fprintf(f, "%s\n", persisted_line);
    sync_stream(f, label, path);
    fclose(f);

    if (encrypted_line != NULL) {
        explicit_bzero(encrypted_line, strlen(encrypted_line));
        free(encrypted_line);
    }
}

/* Write event to file */
static void write_event_file(const audit_filter_config_t *config, audit_filter_state_t *state,
                             const audit_event_t *event) {
    if (config->log_dir == NULL) {
        return;
    }

    /* Build log file path */
    char path[512];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    snprintf(path, sizeof(path), "%s/%s%04d%02d%02d.log", config->log_dir,
             config->log_prefix ? config->log_prefix : "audit_", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday);

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    char json_buf[4096];
    char line_buf[8192];
    const char *line = line_buf;

    if (config->signing_key != NULL) {
        /* JSON format with HMAC signing */
        int jlen = snprintf(json_buf, sizeof(json_buf),
                            "{\"timestamp\":\"%s\",\"type\":\"%s\",\"session\":%lu,"
                            "\"user\":\"%s\",\"client\":\"%s\",\"target\":\"%s\"}",
                            timestamp, audit_event_type_name(event->type), event->session_id,
                            event->username ? event->username : "-",
                            event->client_addr ? event->client_addr : "-",
                            event->target_addr ? event->target_addr : "-");

        if (jlen > 0 && (size_t)jlen < sizeof(json_buf)) {
            int slen = audit_sign_line(
                json_buf, config->signing_key, state ? state->event_prev_hash : NULL,
                config->enable_chain_hash ? 1 : 0, line_buf, sizeof(line_buf));

            if (slen > 0) {
                line = line_buf;
            } else {
                LOG_WARN("Failed to sign audit event, writing unsigned");
                line = json_buf;
            }
        } else {
            return;
        }
    } else {
        /* Legacy plain-text format */
        int written = snprintf(
            line_buf, sizeof(line_buf), "%s [%s] session=%lu user=%s client=%s target=%s",
            timestamp, audit_event_type_name(event->type), event->session_id,
            event->username ? event->username : "-", event->client_addr ? event->client_addr : "-",
            event->target_addr ? event->target_addr : "-");
        if (written < 0 || (size_t)written >= sizeof(line_buf)) {
            return;
        }

        if (event->data != NULL && event->data_len > 0) {
            /* Truncate long data */
            size_t print_len = event->data_len;
            if (print_len > 128) {
                print_len = 128;
            }
            written +=
                snprintf(line_buf + written, sizeof(line_buf) - (size_t)written, " data=\"%.*s%s\"",
                         (int)print_len, event->data, event->data_len > 128 ? "..." : "");
            if (written < 0 || (size_t)written >= sizeof(line_buf)) {
                return;
            }
        }
    }

    write_log_line(config, state, path, config->log_prefix ? config->log_prefix : "audit_", line,
                   "audit log");
}

/* Write event to syslog */
static void write_event_syslog(const audit_event_t *event) {
    /* Using LOG_INFO for now */
    LOG_INFO("[AUDIT] %s session=%lu user=%s", audit_event_type_name(event->type),
             event->session_id, event->username ? event->username : "-");
}

/* Internal event writer */
static void internal_write_event(filter_t *filter, const audit_event_t *event) {
    if (filter == NULL || event == NULL) {
        return;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL) {
        return;
    }

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;

    switch (config->storage) {
    case AUDIT_STORAGE_FILE:
        write_event_file(config, state, event);
        break;
    case AUDIT_STORAGE_SYSLOG:
        write_event_syslog(event);
        break;
    case AUDIT_STORAGE_CALLBACK:
        if (config->event_cb != NULL) {
            config->event_cb(event, config->cb_user_data);
        }
        break;
    }
}

/* Filter callbacks implementation */
static filter_status_t audit_on_connect(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return FILTER_CONTINUE;
    }

    session_metadata_t *meta = session_get_metadata(ctx->session);

    audit_event_t event = {.type = AUDIT_EVENT_CONNECT,
                           .session_id = session_get_id(ctx->session),
                           .timestamp = time(NULL),
                           .username = NULL,
                           .client_addr = meta ? meta->client_addr : NULL,
                           .target_addr = NULL,
                           .data = NULL,
                           .data_len = 0};

    internal_write_event(filter, &event);
    return FILTER_CONTINUE;
}

static filter_status_t audit_on_auth(filter_t *filter, filter_context_t *ctx) {
    /* Auth result is determined by auth filter, we just observe */
    (void)filter;
    (void)ctx;
    return FILTER_CONTINUE;
}

static filter_status_t audit_on_authenticated(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return FILTER_CONTINUE;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    session_metadata_t *meta = session_get_metadata(ctx->session);

    audit_event_t event = {.type = AUDIT_EVENT_AUTH_SUCCESS,
                           .session_id = session_get_id(ctx->session),
                           .timestamp = time(NULL),
                           .username = ctx->username,
                           .client_addr = meta ? meta->client_addr : NULL,
                           .target_addr = NULL,
                           .data = NULL,
                           .data_len = 0};

    internal_write_event(filter, &event);

    /* Start asciicast recording if enabled */
    if (config != NULL && config->enable_asciicast) {
        asciicast_header_t header = {.version = 2,
                                     .width = 80,
                                     .height = 24,
                                     .timestamp = time(NULL),
                                     .title = ctx->username ? ctx->username : "session",
                                     .env_term = "xterm-256color",
                                     .env_shell = "/bin/bash"};

        if (audit_start_recording(filter, session_get_id(ctx->session), &header) == 0) {
            LOG_INFO("Started session recording for session %lu", session_get_id(ctx->session));
        }
    }

    /* Store username/upstream in recording session for command logging */
    if (config != NULL && config->record_commands) {
        audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
        if (state != NULL) {
            uint64_t sid = session_get_id(ctx->session);
            for (size_t i = 0; i < MAX_RECORDINGS; i++) {
                if (state->recordings[i].active && state->recordings[i].session_id == sid) {
                    if (ctx->username != NULL) {
                        strncpy(state->recordings[i].username, ctx->username,
                                sizeof(state->recordings[i].username) - 1);
                        state->recordings[i].username[sizeof(state->recordings[i].username) - 1] =
                            '\0';
                    }
                    if (meta != NULL && meta->target_addr[0] != '\0') {
                        strncpy(state->recordings[i].target, meta->target_addr,
                                sizeof(state->recordings[i].target) - 1);
                        state->recordings[i].target[sizeof(state->recordings[i].target) - 1] = '\0';
                    }
                    break;
                }
            }
        }
    }

    return FILTER_CONTINUE;
}

static filter_status_t audit_on_data_upstream(filter_t *filter, filter_context_t *ctx,
                                              const uint8_t *data, size_t len) {
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL) {
        return FILTER_CONTINUE;
    }

    /* Record to asciicast if enabled */
    if (config->record_input && config->enable_asciicast && ctx->session != NULL) {
        audit_write_frame(filter, session_get_id(ctx->session), data, len, true);
    }

    /* Parse commands if enabled */
    if (config->record_commands && ctx->session != NULL) {
        audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
        if (state == NULL)
            return FILTER_CONTINUE;

        uint64_t sid = session_get_id(ctx->session);
        recording_session_t *rec = NULL;
        for (size_t i = 0; i < MAX_RECORDINGS; i++) {
            if (state->recordings[i].active && state->recordings[i].session_id == sid) {
                rec = &state->recordings[i];
                break;
            }
        }

        if (rec != NULL) {
            for (size_t i = 0; i < len; i++) {
                uint8_t c = data[i];

                if (c == '\r' || c == '\n') {
                    /* End of command - log it if non-empty */
                    if (rec->cmd_len > 0) {
                        rec->cmd_buf[rec->cmd_len] = '\0';

                        /* Trim leading/trailing whitespace */
                        char *cmd = rec->cmd_buf;
                        while (*cmd == ' ' || *cmd == '\t')
                            cmd++;
                        size_t clen = strlen(cmd);
                        while (clen > 0 && (cmd[clen - 1] == ' ' || cmd[clen - 1] == '\t')) {
                            cmd[--clen] = '\0';
                        }

                        if (clen > 0) {
                            const char *uname = rec->username[0] ? rec->username : NULL;
                            const char *tgt = rec->target[0] ? rec->target : NULL;
                            session_metadata_t *meta = session_get_metadata(ctx->session);
                            audit_log_command(filter, sid,
                                              uname ? uname
                                                    : (ctx->username
                                                           ? ctx->username
                                                           : (meta ? meta->username : NULL)),
                                              tgt ? tgt : (meta ? meta->target_addr : NULL), cmd);
                        }
                        rec->cmd_len = 0;
                    }
                } else if (c == 0x7f || c == '\b') {
                    /* Backspace - remove last character */
                    if (rec->cmd_len > 0) {
                        rec->cmd_len--;
                    }
                } else if (c >= 32 && c < 127) {
                    /* Printable character */
                    if (rec->cmd_len < sizeof(rec->cmd_buf) - 1) {
                        rec->cmd_buf[rec->cmd_len++] = (char)c;
                    }
                }
                /* Ignore other control characters (arrow keys, etc.) */
            }
        }
    }

    return FILTER_CONTINUE;
}

static filter_status_t audit_on_data_downstream(filter_t *filter, filter_context_t *ctx,
                                                const uint8_t *data, size_t len) {
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL || !config->record_output) {
        return FILTER_CONTINUE;
    }

    /* Record to asciicast if enabled */
    if (config->enable_asciicast && ctx->session != NULL) {
        audit_write_frame(filter, session_get_id(ctx->session), data, len, false);
    }

    return FILTER_CONTINUE;
}

static void audit_on_close(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return;
    }

    /* Stop recording if active */
    audit_stop_recording(filter, session_get_id(ctx->session));

    session_metadata_t *meta = session_get_metadata(ctx->session);

    audit_event_t event = {.type = AUDIT_EVENT_DISCONNECT,
                           .session_id = session_get_id(ctx->session),
                           .timestamp = time(NULL),
                           .username = ctx->username,
                           .client_addr = meta ? meta->client_addr : NULL,
                           .target_addr = meta ? meta->target_addr : NULL,
                           .data = NULL,
                           .data_len = 0};

    internal_write_event(filter, &event);
}

static void audit_destroy(filter_t *filter) {
    if (filter == NULL) {
        return;
    }

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
    if (state != NULL) {
        /* Close all recordings */
        for (size_t i = 0; i < MAX_RECORDINGS; i++) {
            if (state->recordings[i].active && state->recordings[i].file != NULL) {
                fclose(state->recordings[i].file);
            }
        }
        explicit_bzero(state->encryption_key, sizeof(state->encryption_key));
        free(state);
        filter->state = NULL;
    }

    /* Free config - it was allocated in audit_filter_create */
    if (filter->config != NULL) {
        audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
        free((void *)config->log_dir);
        free((void *)config->log_prefix);
        if (config->signing_key != NULL) {
            explicit_bzero((void *)config->signing_key, strlen(config->signing_key));
            free((void *)config->signing_key);
        }
        if (config->encryption_key != NULL) {
            explicit_bzero((void *)config->encryption_key, strlen(config->encryption_key));
            free((void *)config->encryption_key);
        }
        free(config);
        filter->config = NULL;
    }

    LOG_DEBUG("Audit filter destroyed");
}

filter_t *audit_filter_create(const audit_filter_config_t *config) {
    if (config == NULL) {
        return NULL;
    }

    /* Copy configuration */
    audit_filter_config_t *cfg_copy = calloc(1, sizeof(audit_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }
    *cfg_copy = *config;

    /* Duplicate strings */
    if (config->log_dir != NULL) {
        cfg_copy->log_dir = strdup(config->log_dir);
        if (cfg_copy->log_dir == NULL) {
            free(cfg_copy);
            return NULL;
        }
    }
    if (config->log_prefix != NULL) {
        cfg_copy->log_prefix = strdup(config->log_prefix);
        if (cfg_copy->log_prefix == NULL) {
            free((void *)cfg_copy->log_dir);
            free(cfg_copy);
            return NULL;
        }
    }
    if (config->signing_key != NULL) {
        cfg_copy->signing_key = strdup(config->signing_key);
        if (cfg_copy->signing_key == NULL) {
            free((void *)cfg_copy->log_dir);
            free((void *)cfg_copy->log_prefix);
            free(cfg_copy);
            return NULL;
        }
        /* Default: enable chain hash when signing is active */
        if (!config->enable_chain_hash) {
            cfg_copy->enable_chain_hash = true;
        }
    }
    if (config->encryption_key != NULL) {
        cfg_copy->encryption_key = strdup(config->encryption_key);
        if (cfg_copy->encryption_key == NULL) {
            free((void *)cfg_copy->log_dir);
            free((void *)cfg_copy->log_prefix);
            if (cfg_copy->signing_key != NULL) {
                explicit_bzero((void *)cfg_copy->signing_key, strlen(cfg_copy->signing_key));
                free((void *)cfg_copy->signing_key);
            }
            free(cfg_copy);
            return NULL;
        }
    }

    filter_t *filter = filter_create("audit", FILTER_TYPE_AUDIT, &audit_callbacks, cfg_copy);
    if (filter == NULL) {
        free((void *)cfg_copy->log_dir);
        free((void *)cfg_copy->log_prefix);
        free((void *)cfg_copy->signing_key);
        free(cfg_copy);
        return NULL;
    }

    /* Create state */
    audit_filter_state_t *state = calloc(1, sizeof(audit_filter_state_t));
    if (state == NULL) {
        free((void *)cfg_copy->log_dir);
        free((void *)cfg_copy->log_prefix);
        if (cfg_copy->signing_key != NULL) {
            explicit_bzero((void *)cfg_copy->signing_key, strlen(cfg_copy->signing_key));
            free((void *)cfg_copy->signing_key);
        }
        if (cfg_copy->encryption_key != NULL) {
            explicit_bzero((void *)cfg_copy->encryption_key, strlen(cfg_copy->encryption_key));
            free((void *)cfg_copy->encryption_key);
        }
        free(cfg_copy);
        free(filter);
        return NULL;
    }
    filter->state = state;

    if (cfg_copy->encryption_key != NULL) {
        int key_len = hex_decode(cfg_copy->encryption_key, state->encryption_key,
                                 sizeof(state->encryption_key));
        if (key_len != AUDIT_AES256_KEY_SIZE) {
            LOG_ERROR("Invalid audit encryption key: expected 32-byte hex key");
            explicit_bzero(state->encryption_key, sizeof(state->encryption_key));
            free(state);
            filter->state = NULL;
            free((void *)cfg_copy->log_dir);
            free((void *)cfg_copy->log_prefix);
            if (cfg_copy->signing_key != NULL) {
                explicit_bzero((void *)cfg_copy->signing_key, strlen(cfg_copy->signing_key));
                free((void *)cfg_copy->signing_key);
            }
            explicit_bzero((void *)cfg_copy->encryption_key, strlen(cfg_copy->encryption_key));
            free((void *)cfg_copy->encryption_key);
            free(cfg_copy);
            free(filter);
            return NULL;
        }
        state->encryption_enabled = true;
    }

    /* Create log directory if needed */
    if (config->log_dir != NULL) {
        mkdir(config->log_dir, 0755);
    }

    LOG_DEBUG("Audit filter created, storage=%d", config->storage);
    return filter;
}

void audit_write_event(filter_t *filter, const audit_event_t *event) {
    internal_write_event(filter, event);
}

int audit_start_recording(filter_t *filter, uint64_t session_id, const asciicast_header_t *header) {
    if (filter == NULL || header == NULL) {
        return -1;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
    if (config == NULL || state == NULL) {
        return -1;
    }

    /* Find free slot */
    recording_session_t *rec = NULL;
    for (size_t i = 0; i < MAX_RECORDINGS; i++) {
        if (!state->recordings[i].active) {
            rec = &state->recordings[i];
            break;
        }
    }

    if (rec == NULL) {
        LOG_WARN("Maximum recording sessions reached");
        return -1;
    }

    /* Build file path */
    char path[512];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(path, sizeof(path), "%s/session_%lu_%04d%02d%02d_%02d%02d%02d.cast",
             config->log_dir ? config->log_dir : "/tmp", session_id, tm->tm_year + 1900,
             tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    rec->file = fopen(path, "w");
    if (rec->file == NULL) {
        LOG_ERROR("Failed to create recording file: %s", path);
        return -1;
    }

    /* Write asciicast v2 header */
    fprintf(rec->file, "{\"version\": 2, \"width\": %d, \"height\": %d, \"timestamp\": %ld",
            header->width, header->height, (long)header->timestamp);
    if (header->title != NULL) {
        fprintf(rec->file, ", \"title\": \"%s\"", header->title);
    }
    fprintf(rec->file, "}\n");

    rec->session_id = session_id;
    strncpy(rec->path, path, sizeof(rec->path) - 1);
    rec->path[sizeof(rec->path) - 1] = '\0';
    gettimeofday(&rec->start_time, NULL);
    rec->active = true;
    state->recording_count++;
    sync_stream(rec->file, "session recording", rec->path);

    LOG_INFO("Started recording session %lu to %s", session_id, path);
    return 0;
}

int audit_write_frame(filter_t *filter, uint64_t session_id, const void *data, size_t len,
                      bool is_input) {
    if (filter == NULL || data == NULL || len == 0) {
        return -1;
    }

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
    if (state == NULL) {
        return -1;
    }

    /* Find recording */
    recording_session_t *rec = NULL;
    for (size_t i = 0; i < MAX_RECORDINGS; i++) {
        if (state->recordings[i].active && state->recordings[i].session_id == session_id) {
            rec = &state->recordings[i];
            break;
        }
    }

    if (rec == NULL || rec->file == NULL) {
        return -1;
    }

    /* Calculate elapsed time */
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed =
        (now.tv_sec - rec->start_time.tv_sec) + (now.tv_usec - rec->start_time.tv_usec) / 1000000.0;

    /* Write asciicast frame: [time, "o"/"i", "data"] */
    fprintf(rec->file, "[%.6f, \"%s\", \"", elapsed, is_input ? "i" : "o");

    /* Escape data */
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = bytes[i];
        if (c == '"' || c == '\\') {
            fprintf(rec->file, "\\%c", c);
        } else if (c == '\n') {
            fprintf(rec->file, "\\n");
        } else if (c == '\r') {
            fprintf(rec->file, "\\r");
        } else if (c == '\t') {
            fprintf(rec->file, "\\t");
        } else if (c >= 32 && c < 127) {
            fputc(c, rec->file);
        } else {
            fprintf(rec->file, "\\u%04x", c);
        }
    }

    fprintf(rec->file, "\"]\n");
    sync_stream(rec->file, "session recording", rec->path);

    return 0;
}

void audit_stop_recording(filter_t *filter, uint64_t session_id) {
    if (filter == NULL) {
        return;
    }

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
    if (state == NULL) {
        return;
    }

    for (size_t i = 0; i < MAX_RECORDINGS; i++) {
        if (state->recordings[i].active && state->recordings[i].session_id == session_id) {
            if (state->recordings[i].file != NULL) {
                sync_stream(state->recordings[i].file, "session recording", state->recordings[i].path);
                fclose(state->recordings[i].file);
                state->recordings[i].file = NULL;
            }
            state->recordings[i].active = false;
            state->recordings[i].path[0] = '\0';
            state->recording_count--;
            LOG_INFO("Stopped recording session %lu", session_id);
            return;
        }
    }
}

void audit_log_command(filter_t *filter, uint64_t session_id, const char *username,
                       const char *upstream, const char *command) {
    if (filter == NULL || command == NULL)
        return;

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL || config->log_dir == NULL)
        return;

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;

    /* Build command log file path */
    char path[512];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    snprintf(path, sizeof(path), "%s/commands_%04d%02d%02d.log", config->log_dir, tm.tm_year + 1900,
             tm.tm_mon + 1, tm.tm_mday);

    /* Sanitize command - copy to local buffer */
    char sanitized[4096];
    strncpy(sanitized, command, sizeof(sanitized) - 1);
    sanitized[sizeof(sanitized) - 1] = '\0';

    /* Build the JSON body with escaped command into a buffer */
    char json_buf[8192];
    int pos = snprintf(json_buf, sizeof(json_buf),
                       "{\"timestamp\":%ld,\"session\":%lu,\"user\":\"%s\","
                       "\"upstream\":\"%s\",\"type\":\"command\",\"command\":\"",
                       (long)now, session_id, username ? username : "-", upstream ? upstream : "-");

    /* JSON-escape the command string into json_buf */
    for (const char *p = sanitized; *p != '\0' && (size_t)pos < sizeof(json_buf) - 3; p++) {
        switch (*p) {
        case '"':
            pos += snprintf(json_buf + pos, sizeof(json_buf) - (size_t)pos, "\\\"");
            break;
        case '\\':
            pos += snprintf(json_buf + pos, sizeof(json_buf) - (size_t)pos, "\\\\");
            break;
        case '\n':
            pos += snprintf(json_buf + pos, sizeof(json_buf) - (size_t)pos, "\\n");
            break;
        case '\r':
            pos += snprintf(json_buf + pos, sizeof(json_buf) - (size_t)pos, "\\r");
            break;
        case '\t':
            pos += snprintf(json_buf + pos, sizeof(json_buf) - (size_t)pos, "\\t");
            break;
        default:
            if ((unsigned char)*p >= 32 && (size_t)pos < sizeof(json_buf) - 1) {
                json_buf[pos++] = *p;
            }
            break;
        }
    }
    if ((size_t)pos < sizeof(json_buf) - 2) {
        json_buf[pos++] = '"';
        json_buf[pos++] = '}';
        json_buf[pos] = '\0';
    }

    const char *line = json_buf;
    char signed_buf[8192];
    if (config->signing_key != NULL) {
        int slen =
            audit_sign_line(json_buf, config->signing_key, state ? state->cmd_prev_hash : NULL,
                            config->enable_chain_hash ? 1 : 0, signed_buf, sizeof(signed_buf));

        if (slen > 0) {
            line = signed_buf;
        } else {
            LOG_WARN("Failed to sign command log, writing unsigned");
        }
    }

    write_log_line(config, state, path, "commands_", line, "command log");
}

const char *audit_event_type_name(audit_event_type_t type) {
    if (type >= 0 && type <= AUDIT_EVENT_DISCONNECT) {
        return event_type_names[type];
    }
    return "UNKNOWN";
}
