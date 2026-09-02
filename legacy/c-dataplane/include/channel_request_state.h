/**
 * @file channel_request_state.h
 * @brief Tracks client channel requests before replaying them upstream.
 */

#ifndef SSH_PROXY_CHANNEL_REQUEST_STATE_H
#define SSH_PROXY_CHANNEL_REQUEST_STATE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHANNEL_REQUEST_STATE_MAX_TERM 64
#define CHANNEL_REQUEST_STATE_MAX_COMMAND 4096
#define CHANNEL_REQUEST_STATE_MAX_SUBSYSTEM 256
#define CHANNEL_REQUEST_STATE_MAX_ENVS 32
#define CHANNEL_REQUEST_STATE_MAX_ENV_NAME 256
#define CHANNEL_REQUEST_STATE_MAX_ENV_VALUE 1024

typedef enum {
    CHANNEL_REQUEST_NONE = 0,
    CHANNEL_REQUEST_SHELL,
    CHANNEL_REQUEST_EXEC,
    CHANNEL_REQUEST_SUBSYSTEM
} channel_request_type_t;

typedef struct channel_request_env {
    char name[CHANNEL_REQUEST_STATE_MAX_ENV_NAME];
    char value[CHANNEL_REQUEST_STATE_MAX_ENV_VALUE];
} channel_request_env_t;

typedef struct channel_request_state {
    char term[CHANNEL_REQUEST_STATE_MAX_TERM];
    int width;
    int height;
    bool has_pty;
    char command[CHANNEL_REQUEST_STATE_MAX_COMMAND];
    char subsystem[CHANNEL_REQUEST_STATE_MAX_SUBSYSTEM];
    channel_request_type_t request_type;
    channel_request_env_t envs[CHANNEL_REQUEST_STATE_MAX_ENVS];
    int env_count;
} channel_request_state_t;

void channel_request_state_init(channel_request_state_t *state);
void channel_request_state_set_shell(channel_request_state_t *state);
void channel_request_state_set_exec(channel_request_state_t *state, const char *command);
void channel_request_state_set_subsystem(channel_request_state_t *state, const char *subsystem);
void channel_request_state_set_pty(channel_request_state_t *state, const char *term, int width, int height);
void channel_request_state_update_window(channel_request_state_t *state, int width, int height);
void channel_request_state_add_env(channel_request_state_t *state, const char *name, const char *value);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_CHANNEL_REQUEST_STATE_H */
