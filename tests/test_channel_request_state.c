/**
 * @file test_channel_request_state.c
 * @brief Tests for channel request state tracking.
 */

#include "test_utils.h"
#include "channel_request_state.h"
#include <stdio.h>
#include <string.h>

static int test_channel_request_state_defaults(void)
{
    channel_request_state_t state;

    channel_request_state_init(&state);

    ASSERT_EQ(state.request_type, CHANNEL_REQUEST_NONE);
    ASSERT_STR_EQ(state.term, "xterm-256color");
    ASSERT_EQ(state.width, 80);
    ASSERT_EQ(state.height, 24);
    ASSERT_EQ(state.has_pty, false);
    ASSERT_EQ(state.env_count, 0);
    ASSERT_STR_EQ(state.command, "");
    ASSERT_STR_EQ(state.subsystem, "");
    return 0;
}

static int test_channel_request_state_switches_request_type(void)
{
    channel_request_state_t state;

    channel_request_state_init(&state);
    channel_request_state_set_exec(&state, "whoami");
    ASSERT_EQ(state.request_type, CHANNEL_REQUEST_EXEC);
    ASSERT_STR_EQ(state.command, "whoami");
    ASSERT_STR_EQ(state.subsystem, "");

    channel_request_state_set_subsystem(&state, "sftp");
    ASSERT_EQ(state.request_type, CHANNEL_REQUEST_SUBSYSTEM);
    ASSERT_STR_EQ(state.command, "");
    ASSERT_STR_EQ(state.subsystem, "sftp");

    channel_request_state_set_shell(&state);
    ASSERT_EQ(state.request_type, CHANNEL_REQUEST_SHELL);
    ASSERT_STR_EQ(state.command, "");
    ASSERT_STR_EQ(state.subsystem, "");
    return 0;
}

static int test_channel_request_state_tracks_pty_and_window(void)
{
    channel_request_state_t state;

    channel_request_state_init(&state);
    channel_request_state_set_pty(&state, "vt100", 132, 43);
    ASSERT_EQ(state.has_pty, true);
    ASSERT_STR_EQ(state.term, "vt100");
    ASSERT_EQ(state.width, 132);
    ASSERT_EQ(state.height, 43);

    channel_request_state_update_window(&state, 200, 55);
    ASSERT_EQ(state.width, 200);
    ASSERT_EQ(state.height, 55);
    return 0;
}

static int test_channel_request_state_limits_envs(void)
{
    channel_request_state_t state;

    channel_request_state_init(&state);
    for (int i = 0; i < CHANNEL_REQUEST_STATE_MAX_ENVS + 5; i++) {
        char name[32];
        char value[32];
        snprintf(name, sizeof(name), "KEY_%d", i);
        snprintf(value, sizeof(value), "VALUE_%d", i);
        channel_request_state_add_env(&state, name, value);
    }

    ASSERT_EQ(state.env_count, CHANNEL_REQUEST_STATE_MAX_ENVS);
    ASSERT_STR_EQ(state.envs[0].name, "KEY_0");
    ASSERT_STR_EQ(state.envs[CHANNEL_REQUEST_STATE_MAX_ENVS - 1].value, "VALUE_31");
    return 0;
}

static int test_channel_request_state_truncates_long_values(void)
{
    channel_request_state_t state;
    char long_command[CHANNEL_REQUEST_STATE_MAX_COMMAND + 32];
    char long_subsystem[CHANNEL_REQUEST_STATE_MAX_SUBSYSTEM + 32];
    char long_env_name[CHANNEL_REQUEST_STATE_MAX_ENV_NAME + 32];
    char long_env_value[CHANNEL_REQUEST_STATE_MAX_ENV_VALUE + 32];

    memset(long_command, 'c', sizeof(long_command) - 1);
    long_command[sizeof(long_command) - 1] = '\0';
    memset(long_subsystem, 's', sizeof(long_subsystem) - 1);
    long_subsystem[sizeof(long_subsystem) - 1] = '\0';
    memset(long_env_name, 'n', sizeof(long_env_name) - 1);
    long_env_name[sizeof(long_env_name) - 1] = '\0';
    memset(long_env_value, 'v', sizeof(long_env_value) - 1);
    long_env_value[sizeof(long_env_value) - 1] = '\0';

    channel_request_state_init(&state);
    channel_request_state_set_exec(&state, long_command);
    ASSERT_EQ(strlen(state.command), (size_t)CHANNEL_REQUEST_STATE_MAX_COMMAND - 1);
    channel_request_state_set_subsystem(&state, long_subsystem);
    channel_request_state_add_env(&state, long_env_name, long_env_value);

    ASSERT_EQ(strlen(state.command), 0U);
    ASSERT_EQ(strlen(state.subsystem), (size_t)CHANNEL_REQUEST_STATE_MAX_SUBSYSTEM - 1);
    ASSERT_EQ(strlen(state.envs[0].name), (size_t)CHANNEL_REQUEST_STATE_MAX_ENV_NAME - 1);
    ASSERT_EQ(strlen(state.envs[0].value), (size_t)CHANNEL_REQUEST_STATE_MAX_ENV_VALUE - 1);
    return 0;
}

int main(void)
{
    TEST_BEGIN("Channel Request State Tests");

    RUN_TEST(test_channel_request_state_defaults);
    RUN_TEST(test_channel_request_state_switches_request_type);
    RUN_TEST(test_channel_request_state_tracks_pty_and_window);
    RUN_TEST(test_channel_request_state_limits_envs);
    RUN_TEST(test_channel_request_state_truncates_long_values);

    TEST_END();
}
