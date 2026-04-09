/**
 * @file test_audit_filter.c
 * @brief Unit tests for audit log rotation and archival
 */

#include <dirent.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>

#include "audit_filter.h"
#include "audit_sign.h"
#include "logger.h"
#include "test_utils.h"

#define TEST_AUDIT_ENCRYPTION_KEY \
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#define TEST_AUDIT_GCM_NONCE_SIZE 12
#define TEST_AUDIT_GCM_TAG_SIZE 16

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

static void build_daily_log_name(char *buf, size_t len, const char *prefix) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    snprintf(buf, len, "%s%04d%02d%02d.log", prefix, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static int count_matching_files(const char *dir, const char *prefix) {
    int count = 0;
    DIR *dp = opendir(dir);
    if (dp == NULL) {
        return 0;
    }

    struct dirent *entry;
    size_t prefix_len = strlen(prefix);
    while ((entry = readdir(dp)) != NULL) {
        if (strncmp(entry->d_name, prefix, prefix_len) == 0) {
            count++;
        }
    }
    closedir(dp);
    return count;
}

static int find_archived_file(const char *dir, const char *active_name, char *out, size_t out_len) {
    DIR *dp = opendir(dir);
    if (dp == NULL) {
        return -1;
    }

    struct dirent *entry;
    size_t prefix_len = strlen(active_name);
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, active_name) == 0) {
            continue;
        }
        if (strncmp(entry->d_name, active_name, prefix_len) == 0) {
            snprintf(out, out_len, "%s/%s", dir, entry->d_name);
            closedir(dp);
            return 0;
        }
    }

    closedir(dp);
    return -1;
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

static int file_equals(const char *path, const char *expected) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strcmp(buf, expected) == 0;
}

static char *read_file_text(const char *path) {
    FILE *f = fopen(path, "r");
    long size = 0;
    char *buf = NULL;

    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    buf = calloc((size_t)size + 1, 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    return buf;
}

static int extract_json_string_field(const char *json, const char *field, char *out, size_t out_len) {
    char pattern[64];
    const char *start = NULL;
    const char *end = NULL;
    size_t len = 0;

    if (json == NULL || field == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    snprintf(pattern, sizeof(pattern), "\"%s\":\"", field);
    start = strstr(json, pattern);
    if (start == NULL) {
        return -1;
    }
    start += strlen(pattern);
    end = strchr(start, '"');
    if (end == NULL) {
        return -1;
    }
    len = (size_t)(end - start);
    if (len >= out_len) {
        return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static char *decrypt_audit_line(const char *line, const char *hex_key) {
    char nonce_hex[TEST_AUDIT_GCM_NONCE_SIZE * 2 + 1];
    char tag_hex[TEST_AUDIT_GCM_TAG_SIZE * 2 + 1];
    char *ciphertext_hex = NULL;
    size_t ciphertext_hex_cap = 16384;
    uint8_t key[32];
    uint8_t nonce[TEST_AUDIT_GCM_NONCE_SIZE];
    uint8_t tag[TEST_AUDIT_GCM_TAG_SIZE];
    uint8_t *ciphertext = NULL;
    uint8_t *plaintext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int key_len = 0;
    int ciphertext_len = 0;
    int out_len = 0;
    int final_len = 0;
    char *result = NULL;

    ciphertext_hex = calloc(ciphertext_hex_cap, 1);
    if (ciphertext_hex == NULL) {
        return NULL;
    }
    if (extract_json_string_field(line, "nonce", nonce_hex, sizeof(nonce_hex)) != 0 ||
        extract_json_string_field(line, "tag", tag_hex, sizeof(tag_hex)) != 0 ||
        extract_json_string_field(line, "ciphertext", ciphertext_hex, ciphertext_hex_cap) != 0) {
        goto cleanup;
    }

    key_len = hex_decode(hex_key, key, sizeof(key));
    if (key_len != 32 || hex_decode(nonce_hex, nonce, sizeof(nonce)) != TEST_AUDIT_GCM_NONCE_SIZE ||
        hex_decode(tag_hex, tag, sizeof(tag)) != TEST_AUDIT_GCM_TAG_SIZE) {
        goto cleanup;
    }

    ciphertext = calloc(strlen(ciphertext_hex) / 2 + 1, 1);
    if (ciphertext == NULL) {
        goto cleanup;
    }
    ciphertext_len = hex_decode(ciphertext_hex, ciphertext, strlen(ciphertext_hex) / 2 + 1);
    if (ciphertext_len < 0) {
        goto cleanup;
    }

    plaintext = calloc((size_t)ciphertext_len + 1, 1);
    if (plaintext == NULL) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        (ciphertext_len > 0 && EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len) != 1) ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        goto cleanup;
    }

    result = calloc((size_t)(out_len + final_len) + 1, 1);
    if (result == NULL) {
        goto cleanup;
    }
    memcpy(result, plaintext, (size_t)(out_len + final_len));

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(key, sizeof(key));
    if (ciphertext != NULL) {
        explicit_bzero(ciphertext, strlen(ciphertext_hex) / 2 + 1);
        free(ciphertext);
    }
    if (plaintext != NULL) {
        explicit_bzero(plaintext, (size_t)ciphertext_len + 1);
        free(plaintext);
    }
    if (ciphertext_hex != NULL) {
        explicit_bzero(ciphertext_hex, ciphertext_hex_cap);
        free(ciphertext_hex);
    }
    return result;
}

static void set_file_age_days(const char *path, int days) {
    struct utimbuf times;
    time_t when = time(NULL) - (time_t)days * 86400;
    times.actime = when;
    times.modtime = when;
    utime(path, &times);
}

static int test_event_log_rotation(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-events-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = false,
        .enable_asciicast = false,
        .max_file_size = 220,
        .flush_interval = 1,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_event_t first = {.type = AUDIT_EVENT_SESSION_START,
                           .session_id = 1,
                           .timestamp = time(NULL),
                           .username = "alice",
                           .client_addr = "10.0.0.1",
                           .target_addr = "host-a",
                           .data = "first-event-marker"};
    first.data_len = strlen(first.data);

    audit_event_t second = first;
    second.data = "second-event-marker";
    second.data_len = strlen(second.data);
    second.session_id = 2;

    audit_write_event(filter, &first);
    audit_write_event(filter, &second);

    char active_name[128];
    build_daily_log_name(active_name, sizeof(active_name), "audit_");
    char active_path[512];
    snprintf(active_path, sizeof(active_path), "%s/%s", dir, active_name);

    ASSERT_EQ(count_matching_files(dir, active_name), 2);
    ASSERT_TRUE(file_contains(active_path, "second-event-marker"));
    ASSERT_FALSE(file_contains(active_path, "first-event-marker"));

    char archived_path[512];
    ASSERT_EQ(find_archived_file(dir, active_name, archived_path, sizeof(archived_path)), 0);
    ASSERT_TRUE(file_contains(archived_path, "first-event-marker"));

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_command_log_rotation(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-commands-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = true,
        .enable_asciicast = false,
        .max_file_size = 180,
        .flush_interval = 1,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_log_command(filter, 1, "alice", "host-a",
                      "first-command-marker with enough padding to rotate");
    audit_log_command(filter, 2, "alice", "host-b",
                      "second-command-marker with enough padding to rotate");

    char active_name[128];
    build_daily_log_name(active_name, sizeof(active_name), "commands_");
    char active_path[512];
    snprintf(active_path, sizeof(active_path), "%s/%s", dir, active_name);

    ASSERT_EQ(count_matching_files(dir, active_name), 2);
    ASSERT_TRUE(file_contains(active_path, "second-command-marker"));
    ASSERT_FALSE(file_contains(active_path, "first-command-marker"));

    char archived_path[512];
    ASSERT_EQ(find_archived_file(dir, active_name, archived_path, sizeof(archived_path)), 0);
    ASSERT_TRUE(file_contains(archived_path, "first-command-marker"));

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_event_log_rejects_symlink_target(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-symlink-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    char active_name[128];
    build_daily_log_name(active_name, sizeof(active_name), "audit_");
    char active_path[512];
    snprintf(active_path, sizeof(active_path), "%s/%s", dir, active_name);

    char target_path[512];
    snprintf(target_path, sizeof(target_path), "%s/real.log", dir);
    FILE *target = fopen(target_path, "w");
    ASSERT_NOT_NULL(target);
    fputs("sentinel\n", target);
    fclose(target);

    ASSERT_EQ(symlink(target_path, active_path), 0);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = false,
        .enable_asciicast = false,
        .max_file_size = 0,
        .flush_interval = 1,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_event_t event = {.type = AUDIT_EVENT_SESSION_START,
                           .session_id = 7,
                           .timestamp = time(NULL),
                           .username = "alice",
                           .client_addr = "10.0.0.1",
                           .target_addr = "host-a",
                           .data = "symlink-marker"};
    event.data_len = strlen(event.data);

    audit_write_event(filter, &event);

    ASSERT_TRUE(file_equals(target_path, "sentinel\n"));
    ASSERT_FALSE(file_contains(target_path, "symlink-marker"));

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_event_log_encryption(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-encrypted-events-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = false,
        .enable_asciicast = false,
        .max_file_size = 0,
        .flush_interval = 1,
        .encryption_key = TEST_AUDIT_ENCRYPTION_KEY,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_event_t event = {.type = AUDIT_EVENT_SESSION_START,
                           .session_id = 3,
                           .timestamp = time(NULL),
                           .username = "alice",
                           .client_addr = "10.0.0.3",
                           .target_addr = "host-c",
                           .data = "secret-event-marker"};
    event.data_len = strlen(event.data);
    audit_write_event(filter, &event);

    char active_name[128];
    build_daily_log_name(active_name, sizeof(active_name), "audit_");
    char active_path[512];
    snprintf(active_path, sizeof(active_path), "%s/%s", dir, active_name);

    char *raw = read_file_text(active_path);
    ASSERT_NOT_NULL(raw);
    ASSERT_FALSE(strstr(raw, "secret-event-marker") != NULL);
    ASSERT_TRUE(strstr(raw, "\"alg\":\"AES-256-GCM\"") != NULL);

    char *plaintext = decrypt_audit_line(raw, TEST_AUDIT_ENCRYPTION_KEY);
    ASSERT_NOT_NULL(plaintext);
    ASSERT_TRUE(strstr(plaintext, "secret-event-marker") != NULL);

    explicit_bzero(plaintext, strlen(plaintext));
    free(plaintext);
    free(raw);
    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_command_log_encryption(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-encrypted-commands-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = true,
        .enable_asciicast = false,
        .max_file_size = 0,
        .flush_interval = 1,
        .encryption_key = TEST_AUDIT_ENCRYPTION_KEY,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_log_command(filter, 4, "alice", "host-d", "sensitive-command-marker");

    char active_name[128];
    build_daily_log_name(active_name, sizeof(active_name), "commands_");
    char active_path[512];
    snprintf(active_path, sizeof(active_path), "%s/%s", dir, active_name);

    char *raw = read_file_text(active_path);
    ASSERT_NOT_NULL(raw);
    ASSERT_FALSE(strstr(raw, "sensitive-command-marker") != NULL);
    ASSERT_TRUE(strstr(raw, "\"alg\":\"AES-256-GCM\"") != NULL);

    char *plaintext = decrypt_audit_line(raw, TEST_AUDIT_ENCRYPTION_KEY);
    ASSERT_NOT_NULL(plaintext);
    ASSERT_TRUE(strstr(plaintext, "sensitive-command-marker") != NULL);

    explicit_bzero(plaintext, strlen(plaintext));
    free(plaintext);
    free(raw);
    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_event_log_retention_days(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-retention-days-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    char old_path[512];
    snprintf(old_path, sizeof(old_path), "%s/audit_19990101.log", dir);
    FILE *old = fopen(old_path, "w");
    ASSERT_NOT_NULL(old);
    fputs("old-log\n", old);
    fclose(old);
    set_file_age_days(old_path, 10);

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = false,
        .enable_asciicast = false,
        .max_file_size = 0,
        .retention_days = 1,
        .flush_interval = 1,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_event_t event = {.type = AUDIT_EVENT_SESSION_START,
                           .session_id = 1,
                           .timestamp = time(NULL),
                           .username = "alice",
                           .client_addr = "10.0.0.1",
                           .target_addr = "host-a",
                           .data = "retention-marker"};
    event.data_len = strlen(event.data);
    audit_write_event(filter, &event);

    ASSERT_EQ(access(old_path, F_OK), -1);

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

static int test_event_log_retention_archived_count(void) {
    TEST_START();

    char dir_template[] = "/tmp/sshproxy-audit-retention-count-XXXXXX";
    char *dir = mkdtemp(dir_template);
    ASSERT_NOT_NULL(dir);

    const char *files[] = {
        "audit_20240101.log.001",
        "audit_20240101.log.002",
        "audit_20240101.log.003",
        "audit_20240101.log.004",
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        FILE *f = fopen(path, "w");
        ASSERT_NOT_NULL(f);
        fprintf(f, "archive-%zu\n", i + 1);
        fclose(f);
        set_file_age_days(path, (int)(sizeof(files) / sizeof(files[0]) - i));
    }

    audit_filter_config_t cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = dir,
        .log_prefix = "audit_",
        .record_input = false,
        .record_output = false,
        .record_commands = false,
        .enable_asciicast = false,
        .max_file_size = 0,
        .max_archived_files = 2,
        .flush_interval = 1,
    };
    filter_t *filter = audit_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    audit_event_t event = {.type = AUDIT_EVENT_SESSION_START,
                           .session_id = 2,
                           .timestamp = time(NULL),
                           .username = "bob",
                           .client_addr = "10.0.0.2",
                           .target_addr = "host-b",
                           .data = "count-marker"};
    event.data_len = strlen(event.data);
    audit_write_event(filter, &event);

    char path_oldest[512];
    char path_older[512];
    char path_newer1[512];
    char path_newer2[512];
    snprintf(path_oldest, sizeof(path_oldest), "%s/%s", dir, files[0]);
    snprintf(path_older, sizeof(path_older), "%s/%s", dir, files[1]);
    snprintf(path_newer1, sizeof(path_newer1), "%s/%s", dir, files[2]);
    snprintf(path_newer2, sizeof(path_newer2), "%s/%s", dir, files[3]);
    ASSERT_EQ(access(path_oldest, F_OK), -1);
    ASSERT_EQ(access(path_older, F_OK), -1);
    ASSERT_EQ(access(path_newer1, F_OK), 0);
    ASSERT_EQ(access(path_newer2, F_OK), 0);
    ASSERT_EQ(count_matching_files(dir, "audit_"), 3);

    cleanup_filter(filter);
    cleanup_dir(dir);
    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Audit Filter Module Tests");

    RUN_TEST(test_event_log_rotation);
    RUN_TEST(test_command_log_rotation);
    RUN_TEST(test_event_log_rejects_symlink_target);
    RUN_TEST(test_event_log_encryption);
    RUN_TEST(test_command_log_encryption);
    RUN_TEST(test_event_log_retention_days);
    RUN_TEST(test_event_log_retention_archived_count);

    log_shutdown();

    TEST_END();
}
