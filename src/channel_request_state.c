/**
 * @file channel_request_state.c
 * @brief Tracks client channel requests before replaying them upstream.
 */

#include "channel_request_state.h"
#include <string.h>

static void copy_truncated(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

void channel_request_state_init(channel_request_state_t *state)
{
    if (state == NULL) {
        return;
    }

    memset(state, 0, sizeof(*state));
    copy_truncated(state->term, sizeof(state->term), "xterm-256color");
    state->width = 80;
    state->height = 24;
}

void channel_request_state_set_shell(channel_request_state_t *state)
{
    if (state == NULL) {
        return;
    }

    state->request_type = CHANNEL_REQUEST_SHELL;
    state->command[0] = '\0';
    state->subsystem[0] = '\0';
}

void channel_request_state_set_exec(channel_request_state_t *state, const char *command)
{
    if (state == NULL) {
        return;
    }

    state->request_type = CHANNEL_REQUEST_EXEC;
    copy_truncated(state->command, sizeof(state->command), command);
    state->subsystem[0] = '\0';
}

void channel_request_state_set_subsystem(channel_request_state_t *state, const char *subsystem)
{
    if (state == NULL) {
        return;
    }

    state->request_type = CHANNEL_REQUEST_SUBSYSTEM;
    copy_truncated(state->subsystem, sizeof(state->subsystem), subsystem);
    state->command[0] = '\0';
}

void channel_request_state_set_pty(channel_request_state_t *state, const char *term, int width, int height)
{
    if (state == NULL) {
        return;
    }

    if (term != NULL) {
        copy_truncated(state->term, sizeof(state->term), term);
    }
    state->width = width;
    state->height = height;
    state->has_pty = true;
}

void channel_request_state_update_window(channel_request_state_t *state, int width, int height)
{
    if (state == NULL) {
        return;
    }

    state->width = width;
    state->height = height;
}

void channel_request_state_add_env(channel_request_state_t *state, const char *name, const char *value)
{
    channel_request_env_t *env = NULL;

    if (state == NULL || name == NULL || value == NULL ||
        state->env_count >= CHANNEL_REQUEST_STATE_MAX_ENVS) {
        return;
    }

    env = &state->envs[state->env_count];
    copy_truncated(env->name, sizeof(env->name), name);
    copy_truncated(env->value, sizeof(env->value), value);
    state->env_count++;
}
