#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "logger.h"
#include "policy_filter.h"
#include "test_utils.h"

static void cleanup_filter(filter_t *filter) {
    if (filter == NULL) {
        return;
    }
    if (filter->callbacks.destroy != NULL) {
        filter->callbacks.destroy(filter);
    }
    free(filter);
}

static void cleanup_dir(const char *dir) {
    DIR *dp = opendir(dir);
    if (dp != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dp)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
            unlink(path);
        }
        closedir(dp);
    }
    rmdir(dir);
}

static int file_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static void build_port_forward_log_path(char *buf, size_t len, const char *dir, time_t ts) {
    struct tm tm;
    localtime_r(&ts, &tm);
    snprintf(buf, len, "%s/port_forwards_%04d%02d%02d.log", dir, tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday);
}

static int callback_calls = 0;
static port_forward_record_t callback_record;

static void port_forward_callback(const port_forward_record_t *record, void *user_data) {
    (void)user_data;
    if (record == NULL) {
        return;
    }
    callback_calls++;
    callback_record = *record;
}

static int test_port_forward_log_file(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-policy-portforward-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    policy_filter_config_t cfg = {
        .default_allowed = 0xFFFFFFFFu,
        .log_transfers = false,
        .log_port_forwards = true,
        .log_denied = true,
        .transfer_log_dir = dir,
    };
    filter_t *filter = policy_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    port_forward_record_t record = {
        .session_id = 42,
        .timestamp = time(NULL),
        .is_local = true,
        .bind_port = 10022,
        .target_port = 22,
        .allowed = true,
    };
    strncpy(record.username, "alice", sizeof(record.username) - 1);
    strncpy(record.bind_host, "127.0.0.1", sizeof(record.bind_host) - 1);
    strncpy(record.target_host, "10.0.0.15", sizeof(record.target_host) - 1);

    policy_log_port_forward(filter, &record);

    char path[512];
    build_port_forward_log_path(path, sizeof(path), dir, record.timestamp);

    ASSERT_TRUE(file_contains(path, "alice"));
    ASSERT_TRUE(file_contains(path, "127.0.0.1"));
    ASSERT_TRUE(file_contains(path, "10.0.0.15"));
    ASSERT_TRUE(file_contains(path, "10022"));

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_port_forward_callback(void) {
    TEST_START();

    callback_calls = 0;
    memset(&callback_record, 0, sizeof(callback_record));

    policy_filter_config_t cfg = {
        .default_allowed = 0xFFFFFFFFu,
        .log_transfers = false,
        .log_port_forwards = false,
        .log_denied = true,
        .transfer_log_dir = "/tmp",
        .port_forward_cb = port_forward_callback,
    };
    filter_t *filter = policy_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    port_forward_record_t record = {
        .session_id = 7,
        .timestamp = time(NULL),
        .is_local = false,
        .bind_port = 9443,
        .target_port = 443,
        .allowed = false,
    };
    strncpy(record.username, "bob", sizeof(record.username) - 1);
    strncpy(record.bind_host, "0.0.0.0", sizeof(record.bind_host) - 1);
    strncpy(record.target_host, "internal.example", sizeof(record.target_host) - 1);

    policy_log_port_forward(filter, &record);

    ASSERT_EQ(callback_calls, 1);
    ASSERT_STR_EQ(callback_record.username, "bob");
    ASSERT_FALSE(callback_record.is_local);
    ASSERT_EQ(callback_record.bind_port, 9443);
    ASSERT_EQ(callback_record.target_port, 443);
    ASSERT_FALSE(callback_record.allowed);

    cleanup_filter(filter);
    TEST_PASS();
}

static int test_detect_scp_and_sftp_features(void) {
    TEST_START();

    ASSERT_EQ(policy_detect_command("scp -t /tmp/upload.bin"), POLICY_FEAT_SCP_UPLOAD);
    ASSERT_EQ(policy_detect_command("scp -f /tmp/download.bin"), POLICY_FEAT_SCP_DOWNLOAD);
    ASSERT_EQ(policy_detect_command("scp /tmp/src /tmp/dst"),
              POLICY_FEAT_SCP_UPLOAD | POLICY_FEAT_SCP_DOWNLOAD);
    ASSERT_EQ(policy_detect_command("sftp"),
              POLICY_FEAT_SFTP_UPLOAD | POLICY_FEAT_SFTP_DOWNLOAD |
                  POLICY_FEAT_SFTP_LIST | POLICY_FEAT_SFTP_DELETE);
    ASSERT_EQ(policy_detect_command("/usr/libexec/sftp-server"),
              POLICY_FEAT_SFTP_UPLOAD | POLICY_FEAT_SFTP_DOWNLOAD |
                  POLICY_FEAT_SFTP_LIST | POLICY_FEAT_SFTP_DELETE);

    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Policy Filter Module Tests");

    RUN_TEST(test_port_forward_log_file);
    RUN_TEST(test_port_forward_callback);
    RUN_TEST(test_detect_scp_and_sftp_features);

    log_shutdown();

    TEST_END();
}
