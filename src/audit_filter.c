/**
 * @file audit_filter.c
 * @brief SSH Proxy Core - Audit Filter Implementation
 */

#include "audit_filter.h"
#include "session.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>

/* Maximum recording sessions */
#define MAX_RECORDINGS 256

/* Recording session state */
typedef struct recording_session {
    uint64_t session_id;
    FILE *file;
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
} audit_filter_state_t;

/* Event type names */
static const char *event_type_names[] = {
    "CONNECT",
    "AUTH_SUCCESS",
    "AUTH_FAILURE",
    "SESSION_START",
    "COMMAND",
    "DATA_UPSTREAM",
    "DATA_DOWNSTREAM",
    "SESSION_END",
    "DISCONNECT"
};

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
static const filter_callbacks_t audit_callbacks = {
    .on_connect = audit_on_connect,
    .on_auth = audit_on_auth,
    .on_authenticated = audit_on_authenticated,
    .on_route = NULL,
    .on_data_upstream = audit_on_data_upstream,
    .on_data_downstream = audit_on_data_downstream,
    .on_close = audit_on_close,
    .destroy = audit_destroy
};

/* Get timestamp for logging */
static void get_timestamp(char *buf, size_t len)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm = localtime(&tv.tv_sec);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec / 1000);
}

/* Write event to file */
static void write_event_file(const audit_filter_config_t *config,
                             const audit_event_t *event)
{
    if (config->log_dir == NULL) {
        return;
    }

    /* Build log file path */
    char path[512];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(path, sizeof(path), "%s/%s%04d%02d%02d.log",
             config->log_dir,
             config->log_prefix ? config->log_prefix : "audit_",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

    FILE *f = fopen(path, "a");
    if (f == NULL) {
        LOG_ERROR("Failed to open audit log: %s: %s", path, strerror(errno));
        return;
    }

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(f, "%s [%s] session=%lu user=%s client=%s target=%s",
            timestamp,
            audit_event_type_name(event->type),
            event->session_id,
            event->username ? event->username : "-",
            event->client_addr ? event->client_addr : "-",
            event->target_addr ? event->target_addr : "-");

    if (event->data != NULL && event->data_len > 0) {
        /* Truncate long data */
        size_t print_len = event->data_len;
        if (print_len > 128) {
            print_len = 128;
        }
        fprintf(f, " data=\"%.*s%s\"",
                (int)print_len, event->data,
                event->data_len > 128 ? "..." : "");
    }

    fprintf(f, "\n");
    fclose(f);
}

/* Write event to syslog */
static void write_event_syslog(const audit_event_t *event)
{
    /* Using LOG_INFO for now */
    LOG_INFO("[AUDIT] %s session=%lu user=%s",
             audit_event_type_name(event->type),
             event->session_id,
             event->username ? event->username : "-");
}

/* Internal event writer */
static void internal_write_event(filter_t *filter, const audit_event_t *event)
{
    if (filter == NULL || event == NULL) {
        return;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL) {
        return;
    }

    switch (config->storage) {
    case AUDIT_STORAGE_FILE:
        write_event_file(config, event);
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
static filter_status_t audit_on_connect(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return FILTER_CONTINUE;
    }

    session_metadata_t *meta = session_get_metadata(ctx->session);
    
    audit_event_t event = {
        .type = AUDIT_EVENT_CONNECT,
        .session_id = session_get_id(ctx->session),
        .timestamp = time(NULL),
        .username = NULL,
        .client_addr = meta ? meta->client_addr : NULL,
        .target_addr = NULL,
        .data = NULL,
        .data_len = 0
    };

    internal_write_event(filter, &event);
    return FILTER_CONTINUE;
}

static filter_status_t audit_on_auth(filter_t *filter, filter_context_t *ctx)
{
    /* Auth result is determined by auth filter, we just observe */
    (void)filter;
    (void)ctx;
    return FILTER_CONTINUE;
}

static filter_status_t audit_on_authenticated(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return FILTER_CONTINUE;
    }

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    session_metadata_t *meta = session_get_metadata(ctx->session);

    audit_event_t event = {
        .type = AUDIT_EVENT_AUTH_SUCCESS,
        .session_id = session_get_id(ctx->session),
        .timestamp = time(NULL),
        .username = ctx->username,
        .client_addr = meta ? meta->client_addr : NULL,
        .target_addr = NULL,
        .data = NULL,
        .data_len = 0
    };

    internal_write_event(filter, &event);
    
    /* Start asciicast recording if enabled */
    if (config != NULL && config->enable_asciicast) {
        asciicast_header_t header = {
            .version = 2,
            .width = 80,
            .height = 24,
            .timestamp = time(NULL),
            .title = ctx->username ? ctx->username : "session",
            .env_term = "xterm-256color",
            .env_shell = "/bin/bash"
        };
        
        if (audit_start_recording(filter, session_get_id(ctx->session), &header) == 0) {
            LOG_INFO("Started session recording for session %lu", 
                     session_get_id(ctx->session));
        }
    }

    /* Store username/upstream in recording session for command logging */
    if (config != NULL && config->record_commands) {
        audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
        if (state != NULL) {
            uint64_t sid = session_get_id(ctx->session);
            for (size_t i = 0; i < MAX_RECORDINGS; i++) {
                if (state->recordings[i].active &&
                    state->recordings[i].session_id == sid) {
                    if (ctx->username != NULL) {
                        strncpy(state->recordings[i].username, ctx->username,
                                sizeof(state->recordings[i].username) - 1);
                        state->recordings[i].username[sizeof(state->recordings[i].username) - 1] = '\0';
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
                                              const uint8_t *data, size_t len)
{
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
        if (state == NULL) return FILTER_CONTINUE;

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
                        while (*cmd == ' ' || *cmd == '\t') cmd++;
                        size_t clen = strlen(cmd);
                        while (clen > 0 && (cmd[clen - 1] == ' ' || cmd[clen - 1] == '\t')) {
                            cmd[--clen] = '\0';
                        }

                        if (clen > 0) {
                            const char *uname = rec->username[0] ? rec->username : NULL;
                            const char *tgt = rec->target[0] ? rec->target : NULL;
                            session_metadata_t *meta = session_get_metadata(ctx->session);
                            audit_log_command(filter, sid,
                                uname ? uname : (ctx->username ? ctx->username : (meta ? meta->username : NULL)),
                                tgt ? tgt : (meta ? meta->target_addr : NULL),
                                cmd);
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
                                                const uint8_t *data, size_t len)
{
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

static void audit_on_close(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL || ctx->session == NULL) {
        return;
    }

    /* Stop recording if active */
    audit_stop_recording(filter, session_get_id(ctx->session));

    session_metadata_t *meta = session_get_metadata(ctx->session);

    audit_event_t event = {
        .type = AUDIT_EVENT_DISCONNECT,
        .session_id = session_get_id(ctx->session),
        .timestamp = time(NULL),
        .username = ctx->username,
        .client_addr = meta ? meta->client_addr : NULL,
        .target_addr = meta ? meta->target_addr : NULL,
        .data = NULL,
        .data_len = 0
    };

    internal_write_event(filter, &event);
}

static void audit_destroy(filter_t *filter)
{
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
        free(state);
        filter->state = NULL;
    }

    /* Free config - it was allocated in audit_filter_create */
    if (filter->config != NULL) {
        audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
        /* Note: log_dir and log_prefix point to original strings, not strdup'd */
        free(config);
        filter->config = NULL;
    }

    LOG_DEBUG("Audit filter destroyed");
}

filter_t *audit_filter_create(const audit_filter_config_t *config)
{
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
    }
    if (config->log_prefix != NULL) {
        cfg_copy->log_prefix = strdup(config->log_prefix);
    }

    filter_t *filter = filter_create("audit", FILTER_TYPE_AUDIT,
                                     &audit_callbacks, cfg_copy);
    if (filter == NULL) {
        free((void *)cfg_copy->log_dir);
        free((void *)cfg_copy->log_prefix);
        free(cfg_copy);
        return NULL;
    }

    /* Create state */
    audit_filter_state_t *state = calloc(1, sizeof(audit_filter_state_t));
    if (state == NULL) {
        filter_chain_destroy(NULL); /* This won't work, need proper cleanup */
        free((void *)cfg_copy->log_dir);
        free((void *)cfg_copy->log_prefix);
        free(cfg_copy);
        free(filter);
        return NULL;
    }
    filter->state = state;

    /* Create log directory if needed */
    if (config->log_dir != NULL) {
        mkdir(config->log_dir, 0755);
    }

    LOG_DEBUG("Audit filter created, storage=%d", config->storage);
    return filter;
}

void audit_write_event(filter_t *filter, const audit_event_t *event)
{
    internal_write_event(filter, event);
}

int audit_start_recording(filter_t *filter, uint64_t session_id,
                          const asciicast_header_t *header)
{
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
             config->log_dir ? config->log_dir : "/tmp",
             session_id,
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);

    rec->file = fopen(path, "w");
    if (rec->file == NULL) {
        LOG_ERROR("Failed to create recording file: %s", path);
        return -1;
    }

    /* Write asciicast v2 header */
    fprintf(rec->file,
            "{\"version\": 2, \"width\": %d, \"height\": %d, \"timestamp\": %ld",
            header->width, header->height, (long)header->timestamp);
    if (header->title != NULL) {
        fprintf(rec->file, ", \"title\": \"%s\"", header->title);
    }
    fprintf(rec->file, "}\n");

    rec->session_id = session_id;
    gettimeofday(&rec->start_time, NULL);
    rec->active = true;
    state->recording_count++;

    LOG_INFO("Started recording session %lu to %s", session_id, path);
    return 0;
}

int audit_write_frame(filter_t *filter, uint64_t session_id,
                      const void *data, size_t len, bool is_input)
{
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
        if (state->recordings[i].active &&
            state->recordings[i].session_id == session_id) {
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
    double elapsed = (now.tv_sec - rec->start_time.tv_sec) +
                     (now.tv_usec - rec->start_time.tv_usec) / 1000000.0;

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
    fflush(rec->file);

    return 0;
}

void audit_stop_recording(filter_t *filter, uint64_t session_id)
{
    if (filter == NULL) {
        return;
    }

    audit_filter_state_t *state = (audit_filter_state_t *)filter->state;
    if (state == NULL) {
        return;
    }

    for (size_t i = 0; i < MAX_RECORDINGS; i++) {
        if (state->recordings[i].active &&
            state->recordings[i].session_id == session_id) {
            if (state->recordings[i].file != NULL) {
                fclose(state->recordings[i].file);
                state->recordings[i].file = NULL;
            }
            state->recordings[i].active = false;
            state->recording_count--;
            LOG_INFO("Stopped recording session %lu", session_id);
            return;
        }
    }
}

void audit_log_command(filter_t *filter, uint64_t session_id,
                       const char *username, const char *upstream,
                       const char *command)
{
    if (filter == NULL || command == NULL) return;

    audit_filter_config_t *config = (audit_filter_config_t *)filter->config;
    if (config == NULL || config->log_dir == NULL) return;

    /* Build command log file path */
    char path[512];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(path, sizeof(path), "%s/commands_%04d%02d%02d.log",
             config->log_dir,
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

    FILE *f = fopen(path, "a");
    if (f == NULL) {
        LOG_ERROR("Failed to open command log: %s: %s", path, strerror(errno));
        return;
    }

    /* Sanitize command - copy to local buffer */
    char sanitized[4096];
    strncpy(sanitized, command, sizeof(sanitized) - 1);
    sanitized[sizeof(sanitized) - 1] = '\0';

    /* Write JSON log entry */
    fprintf(f, "{\"timestamp\":%ld,\"session\":%lu,\"user\":\"%s\","
               "\"upstream\":\"%s\",\"type\":\"command\",\"command\":\"",
            (long)now, session_id,
            username ? username : "-",
            upstream ? upstream : "-");

    /* JSON-escape the command string */
    for (const char *p = sanitized; *p != '\0'; p++) {
        switch (*p) {
        case '"':  fprintf(f, "\\\""); break;
        case '\\': fprintf(f, "\\\\"); break;
        case '\n': fprintf(f, "\\n"); break;
        case '\r': fprintf(f, "\\r"); break;
        case '\t': fprintf(f, "\\t"); break;
        default:
            if ((unsigned char)*p >= 32) {
                fputc(*p, f);
            }
            break;
        }
    }

    fprintf(f, "\"}\n");
    fclose(f);
}

const char *audit_event_type_name(audit_event_type_t type)
{
    if (type >= 0 && type <= AUDIT_EVENT_DISCONNECT) {
        return event_type_names[type];
    }
    return "UNKNOWN";
}
