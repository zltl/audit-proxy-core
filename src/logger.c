/**
 * @file logger.c
 * @brief SSH Proxy Core - Logging System Implementation
 */

#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Logger state */
static struct {
    log_level_t level;
    FILE *file;
    int use_color;
    int use_timestamp;
    int initialized;
    log_format_t format;
} g_logger = {
    .level = LOG_LEVEL_INFO,
    .file = NULL,
    .use_color = 1,
    .use_timestamp = 1,
    .initialized = 0,
    .format = LOG_FORMAT_TEXT
};

/* Level names */
static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

/* ANSI color codes */
static const char *level_colors[] = {
    "\x1b[94m",  /* TRACE - bright blue */
    "\x1b[36m",  /* DEBUG - cyan */
    "\x1b[32m",  /* INFO  - green */
    "\x1b[33m",  /* WARN  - yellow */
    "\x1b[31m",  /* ERROR - red */
    "\x1b[35m"   /* FATAL - magenta */
};

static const char *color_reset = "\x1b[0m";

int log_init(log_level_t level, const char *file)
{
    g_logger.level = level;
    g_logger.use_color = isatty(STDERR_FILENO);
    g_logger.use_timestamp = 1;
    g_logger.initialized = 1;

    if (file != NULL) {
        g_logger.file = fopen(file, "a");
        if (g_logger.file == NULL) {
            return -1;
        }
    }

    return 0;
}

void log_shutdown(void)
{
    if (g_logger.file != NULL) {
        fclose(g_logger.file);
        g_logger.file = NULL;
    }
    g_logger.initialized = 0;
}

void log_set_level(log_level_t level)
{
    g_logger.level = level;
}

log_level_t log_get_level(void)
{
    return g_logger.level;
}

void log_set_color(int enable)
{
    g_logger.use_color = enable;
}

void log_set_timestamp(int enable)
{
    g_logger.use_timestamp = enable;
}

void log_set_format(log_format_t format)
{
    g_logger.format = format;
}

log_format_t log_get_format(void)
{
    return g_logger.format;
}

static void json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 6 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
        case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
        default:
            if (c < 0x20) {
                int written = snprintf(dst + j, dst_size - j, "\\u%04x", c);
                if (written > 0) {
                    j += (size_t)written;
                }
            } else {
                dst[j++] = (char)c;
            }
            break;
        }
    }
    dst[j] = '\0';
}

void log_write(log_level_t level, const char *file, int line,
               const char *fmt, ...)
{
    if (level < g_logger.level) {
        return;
    }

    /* Get timestamp */
    char timestamp[32] = "";
    if (g_logger.use_timestamp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    }

    /* Extract filename from path */
    const char *filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;

    /* Format message */
    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* JSON output path */
    if (g_logger.format == LOG_FORMAT_JSON) {
        char escaped_msg[1024];
        json_escape(message, escaped_msg, sizeof(escaped_msg));

        char ts[32];
        time_t now = time(NULL);
        struct tm *utc = gmtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", utc);

        fprintf(stderr,
                "{\"ts\":\"%s\",\"level\":\"%s\",\"file\":\"%s\","
                "\"line\":%d,\"msg\":\"%s\"}\n",
                ts, level_names[level], filename, line, escaped_msg);
        fflush(stderr);

        if (g_logger.file != NULL) {
            fprintf(g_logger.file,
                    "{\"ts\":\"%s\",\"level\":\"%s\",\"file\":\"%s\","
                    "\"line\":%d,\"msg\":\"%s\"}\n",
                    ts, level_names[level], filename, line, escaped_msg);
            fflush(g_logger.file);
        }
        return;
    }

    /* Write to stderr */
    FILE *out = stderr;
    if (g_logger.use_color) {
        if (g_logger.use_timestamp) {
            fprintf(out, "%s %s%-5s%s %s:%d: %s\n",
                    timestamp,
                    level_colors[level], level_names[level], color_reset,
                    filename, line, message);
        } else {
            fprintf(out, "%s%-5s%s %s:%d: %s\n",
                    level_colors[level], level_names[level], color_reset,
                    filename, line, message);
        }
    } else {
        if (g_logger.use_timestamp) {
            fprintf(out, "%s %-5s %s:%d: %s\n",
                    timestamp, level_names[level], filename, line, message);
        } else {
            fprintf(out, "%-5s %s:%d: %s\n",
                    level_names[level], filename, line, message);
        }
    }
    fflush(out);

    /* Write to file (no colors) */
    if (g_logger.file != NULL) {
        if (g_logger.use_timestamp) {
            fprintf(g_logger.file, "%s %-5s %s:%d: %s\n",
                    timestamp, level_names[level], filename, line, message);
        } else {
            fprintf(g_logger.file, "%-5s %s:%d: %s\n",
                    level_names[level], filename, line, message);
        }
        fflush(g_logger.file);
    }
}
