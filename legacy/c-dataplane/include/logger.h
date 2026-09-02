/**
 * @file logger.h
 * @brief SSH Proxy Core - Logging System
 */

#ifndef SSH_PROXY_LOGGER_H
#define SSH_PROXY_LOGGER_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_OFF
} log_level_t;

/* Log output format */
typedef enum {
    LOG_FORMAT_TEXT = 0,    /* Human-readable text (default) */
    LOG_FORMAT_JSON         /* Structured JSON */
} log_format_t;

/**
 * @brief Initialize the logging system
 * @param level Minimum log level to output
 * @param file Optional file to write logs (NULL for stderr only)
 * @return 0 on success, -1 on failure
 */
int log_init(log_level_t level, const char *file);

/**
 * @brief Shutdown the logging system
 */
void log_shutdown(void);

/**
 * @brief Set the current log level
 * @param level New log level
 */
void log_set_level(log_level_t level);

/**
 * @brief Get the current log level
 * @return Current log level
 */
log_level_t log_get_level(void);

/**
 * @brief Enable/disable colored output
 * @param enable true to enable colors
 */
void log_set_color(int enable);

/**
 * @brief Enable/disable timestamp in log output
 * @param enable true to enable timestamps
 */
void log_set_timestamp(int enable);

/**
 * @brief Set the log output format
 * @param format LOG_FORMAT_TEXT or LOG_FORMAT_JSON
 */
void log_set_format(log_format_t format);

/**
 * @brief Get the current log output format
 * @return Current format
 */
log_format_t log_get_format(void);

/**
 * @brief Core logging function
 */
void log_write(log_level_t level, const char *file, int line,
               const char *fmt, ...);

/* Convenience macros */
#define LOG_TRACE(...) log_write(LOG_LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_write(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_write(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_write(LOG_LEVEL_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_write(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) log_write(LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_LOGGER_H */
