/**
 * @file test_session.c
 * @brief Unit tests for Session Manager
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <libssh/libssh.h>
#include "session.h"
#include "logger.h"
#include "test_utils.h"

static int test_session_manager_create(void)
{
    TEST_START();

    session_manager_config_t config = {
        .max_sessions = 100,
        .session_timeout = 3600,
        .auth_timeout = 60
    };

    session_manager_t *mgr = session_manager_create(&config);
    ASSERT_NOT_NULL(mgr);
    ASSERT_EQ(session_manager_get_count(mgr), 0);

    session_manager_destroy(mgr);
    TEST_PASS();
}

static int test_session_state_names(void)
{
    TEST_START();

    ASSERT_STR_EQ(session_state_name(SESSION_STATE_NEW), "NEW");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_HANDSHAKE), "HANDSHAKE");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_AUTH), "AUTH");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_AUTHENTICATED), "AUTHENTICATED");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_CLOSED), "CLOSED");

    TEST_PASS();
}

static int test_session_null_handling(void)
{
    TEST_START();

    /* All functions should handle NULL gracefully */
    ASSERT_EQ(session_get_id(NULL), 0);
    ASSERT_EQ(session_get_state(NULL), SESSION_STATE_CLOSED);
    ASSERT_NULL(session_get_client(NULL));
    ASSERT_NULL(session_get_upstream(NULL));
    ASSERT_NULL(session_get_metadata(NULL));
    ASSERT_NULL(session_get_stats(NULL));
    ASSERT_TRUE(session_is_timeout(NULL, 60));

    session_set_state(NULL, SESSION_STATE_ACTIVE);  /* Should not crash */
    session_touch(NULL);  /* Should not crash */

    ASSERT_NULL(session_manager_create(NULL));

    TEST_PASS();
}

static int test_session_manager_snapshot_copies_device_metadata(void)
{
    TEST_START();

    session_manager_config_t config = {
        .max_sessions = 8,
        .session_timeout = 3600,
        .auth_timeout = 60
    };
    session_manager_t *mgr = session_manager_create(&config);
    ASSERT_NOT_NULL(mgr);

    ssh_session client = ssh_new();
    ASSERT_NOT_NULL(client);

    session_t *session = session_manager_create_session(mgr, client);
    ASSERT_NOT_NULL(session);
    session_set_state(session, SESSION_STATE_ACTIVE);
    session_set_username(session, "alice");

    session_metadata_t *meta = session_get_metadata(session);
    ASSERT_NOT_NULL(meta);
    strncpy(meta->client_addr, "10.0.0.5", sizeof(meta->client_addr) - 1);
    meta->client_port = 54123;
    strncpy(meta->target_addr, "db.internal", sizeof(meta->target_addr) - 1);
    meta->target_port = 22;
    strncpy(meta->client_version, "OpenSSH_9.7p1 Ubuntu-7ubuntu4", sizeof(meta->client_version) - 1);
    strncpy(meta->client_os, "Ubuntu/Linux", sizeof(meta->client_os) - 1);
    strncpy(meta->device_fingerprint, "sshfp-deadbeefcafebabe",
            sizeof(meta->device_fingerprint) - 1);

    session_stats_t *stats = session_get_stats(session);
    ASSERT_NOT_NULL(stats);
    stats->bytes_sent = 1234;
    stats->bytes_received = 5678;
    stats->start_time = time(NULL) - 90;

    session_snapshot_t snapshots[2];
    memset(snapshots, 0, sizeof(snapshots));
    int count = session_manager_snapshot(mgr, snapshots, 2);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(snapshots[0].id, session_get_id(session));
    ASSERT_STR_EQ(snapshots[0].username, "alice");
    ASSERT_STR_EQ(snapshots[0].client_addr, "10.0.0.5");
    ASSERT_STR_EQ(snapshots[0].target_addr, "db.internal");
    ASSERT_STR_EQ(snapshots[0].client_version, "OpenSSH_9.7p1 Ubuntu-7ubuntu4");
    ASSERT_STR_EQ(snapshots[0].client_os, "Ubuntu/Linux");
    ASSERT_STR_EQ(snapshots[0].device_fingerprint, "sshfp-deadbeefcafebabe");
    ASSERT_EQ(snapshots[0].bytes_sent, (uint64_t)1234);
    ASSERT_EQ(snapshots[0].bytes_received, (uint64_t)5678);

    session_manager_destroy(mgr);
    TEST_PASS();
}

static session_snapshot_t *find_snapshot_by_username(session_snapshot_t *snapshots, int count,
                                                     const char *username)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(snapshots[i].username, username) == 0) {
            return &snapshots[i];
        }
    }
    return NULL;
}

static int test_session_manager_shared_snapshot_merges_remote_records(void)
{
    TEST_START();

    const char *path = "/tmp/test_session_manager_shared.ndjson";
    unlink(path);

    session_manager_config_t config1 = {
        .max_sessions = 8,
        .session_timeout = 3600,
        .auth_timeout = 60,
        .store_type = SESSION_MANAGER_STORE_FILE,
        .sync_interval_sec = 1
    };
    strncpy(config1.store_path, path, sizeof(config1.store_path) - 1);
    strncpy(config1.instance_id, "node-a", sizeof(config1.instance_id) - 1);

    session_manager_config_t config2 = config1;
    strncpy(config2.instance_id, "node-b", sizeof(config2.instance_id) - 1);

    session_manager_t *mgr1 = session_manager_create(&config1);
    session_manager_t *mgr2 = session_manager_create(&config2);
    ASSERT_NOT_NULL(mgr1);
    ASSERT_NOT_NULL(mgr2);

    session_t *session1 = session_manager_create_session(mgr1, ssh_new());
    session_t *session2 = session_manager_create_session(mgr2, ssh_new());
    ASSERT_NOT_NULL(session1);
    ASSERT_NOT_NULL(session2);

    session_set_username(session1, "alice");
    session_set_username(session2, "bob");
    session_set_state(session1, SESSION_STATE_ACTIVE);
    session_set_state(session2, SESSION_STATE_ACTIVE);

    session_metadata_t *meta1 = session_get_metadata(session1);
    session_metadata_t *meta2 = session_get_metadata(session2);
    ASSERT_NOT_NULL(meta1);
    ASSERT_NOT_NULL(meta2);

    strncpy(meta1->client_addr, "10.0.0.10", sizeof(meta1->client_addr) - 1);
    meta1->client_port = 40001;
    strncpy(meta1->target_addr, "db-a.internal", sizeof(meta1->target_addr) - 1);
    meta1->target_port = 22;
    strncpy(meta1->client_version, "OpenSSH_9.7p1", sizeof(meta1->client_version) - 1);
    strncpy(meta1->client_os, "Linux", sizeof(meta1->client_os) - 1);
    strncpy(meta1->device_fingerprint, "sshfp-alice", sizeof(meta1->device_fingerprint) - 1);

    strncpy(meta2->client_addr, "10.0.0.11", sizeof(meta2->client_addr) - 1);
    meta2->client_port = 40002;
    strncpy(meta2->target_addr, "db-b.internal", sizeof(meta2->target_addr) - 1);
    meta2->target_port = 2222;
    strncpy(meta2->client_version, "PuTTY_Release_0.80", sizeof(meta2->client_version) - 1);
    strncpy(meta2->client_os, "Windows", sizeof(meta2->client_os) - 1);
    strncpy(meta2->device_fingerprint, "sshfp-bob", sizeof(meta2->device_fingerprint) - 1);

    session_stats_t *stats1 = session_get_stats(session1);
    session_stats_t *stats2 = session_get_stats(session2);
    ASSERT_NOT_NULL(stats1);
    ASSERT_NOT_NULL(stats2);
    stats1->bytes_sent = 111;
    stats1->bytes_received = 222;
    stats2->bytes_sent = 333;
    stats2->bytes_received = 444;
    session_sync(session1);
    session_sync(session2);

    size_t capacity = session_manager_snapshot_capacity(mgr1);
    ASSERT_TRUE(capacity >= 2);
    session_snapshot_t *snapshots = calloc(capacity, sizeof(session_snapshot_t));
    ASSERT_NOT_NULL(snapshots);

    int count = session_manager_snapshot(mgr1, snapshots, (int)capacity);
    ASSERT_TRUE(count >= 2);

    session_snapshot_t *alice = find_snapshot_by_username(snapshots, count, "alice");
    session_snapshot_t *bob = find_snapshot_by_username(snapshots, count, "bob");
    ASSERT_NOT_NULL(alice);
    ASSERT_NOT_NULL(bob);
    ASSERT_STR_EQ(alice->instance_id, "node-a");
    ASSERT_STR_EQ(bob->instance_id, "node-b");
    ASSERT_STR_EQ(bob->target_addr, "db-b.internal");
    ASSERT_STR_EQ(bob->device_fingerprint, "sshfp-bob");
    ASSERT_EQ(bob->bytes_sent, (uint64_t)333);
    ASSERT_EQ(bob->bytes_received, (uint64_t)444);

    free(snapshots);
    session_manager_destroy(mgr2);
    session_manager_destroy(mgr1);
    unlink(path);
    TEST_PASS();
}

static int test_session_manager_background_sync_keeps_idle_remote_sessions_visible(void)
{
    TEST_START();

    const char *path = "/tmp/test_session_manager_background_sync.ndjson";
    unlink(path);

    session_manager_config_t config = {
        .max_sessions = 8,
        .session_timeout = 3600,
        .auth_timeout = 60,
        .store_type = SESSION_MANAGER_STORE_FILE,
        .sync_interval_sec = 1
    };
    strncpy(config.store_path, path, sizeof(config.store_path) - 1);
    strncpy(config.instance_id, "node-a", sizeof(config.instance_id) - 1);

    session_manager_config_t remote_config = config;
    strncpy(remote_config.instance_id, "node-b", sizeof(remote_config.instance_id) - 1);

    session_manager_t *mgr1 = session_manager_create(&config);
    session_manager_t *mgr2 = session_manager_create(&remote_config);
    ASSERT_NOT_NULL(mgr1);
    ASSERT_NOT_NULL(mgr2);

    session_t *session = session_manager_create_session(mgr1, ssh_new());
    ASSERT_NOT_NULL(session);
    session_set_username(session, "alice");
    session_set_state(session, SESSION_STATE_ACTIVE);

    sleep(5);

    size_t capacity = session_manager_snapshot_capacity(mgr2);
    ASSERT_TRUE(capacity >= 1);
    session_snapshot_t *snapshots = calloc(capacity, sizeof(session_snapshot_t));
    ASSERT_NOT_NULL(snapshots);

    int count = session_manager_snapshot(mgr2, snapshots, (int)capacity);
    ASSERT_TRUE(count >= 1);
    ASSERT_NOT_NULL(find_snapshot_by_username(snapshots, count, "alice"));

    free(snapshots);
    session_manager_destroy(mgr2);
    session_manager_destroy(mgr1);
    unlink(path);
    TEST_PASS();
}

static int test_session_manager_shared_snapshot_recovers_after_stale_remote_record(void)
{
    TEST_START();

    const char *path = "/tmp/test_session_manager_stale_remote.ndjson";
    unlink(path);

    session_manager_config_t config = {
        .max_sessions = 8,
        .session_timeout = 3600,
        .auth_timeout = 60,
        .store_type = SESSION_MANAGER_STORE_FILE,
        .sync_interval_sec = 1
    };
    strncpy(config.store_path, path, sizeof(config.store_path) - 1);
    strncpy(config.instance_id, "node-b", sizeof(config.instance_id) - 1);

    session_manager_t *mgr = session_manager_create(&config);
    ASSERT_NOT_NULL(mgr);

    session_t *local = session_manager_create_session(mgr, ssh_new());
    ASSERT_NOT_NULL(local);
    session_set_username(local, "bob");
    session_set_state(local, SESSION_STATE_ACTIVE);

    FILE *f = fopen(path, "a");
    ASSERT_NOT_NULL(f);
    time_t now = time(NULL);
    fprintf(f,
            "{\"id\":77,\"user\":\"alice\",\"client\":\"10.0.0.77\",\"client_port\":4022,"
            "\"target\":\"db.internal\",\"target_port\":22,\"instance\":\"node-a\","
            "\"client_version\":\"OpenSSH_9.7p1\",\"client_os\":\"Linux\","
            "\"device_fingerprint\":\"sshfp-alice\",\"created\":%ld,\"last_active\":%ld,"
            "\"synced_at\":%ld,\"state\":6,\"bytes_sent\":1,\"bytes_received\":2,\"active\":true}\n",
            (long)(now - 30), (long)(now - 30), (long)(now - 10));
    fclose(f);

    size_t capacity = session_manager_snapshot_capacity(mgr);
    ASSERT_TRUE(capacity >= 1);
    session_snapshot_t *snapshots = calloc(capacity, sizeof(session_snapshot_t));
    ASSERT_NOT_NULL(snapshots);

    int count = session_manager_snapshot(mgr, snapshots, (int)capacity);
    ASSERT_TRUE(count >= 1);
    ASSERT_NOT_NULL(find_snapshot_by_username(snapshots, count, "bob"));
    ASSERT_NULL(find_snapshot_by_username(snapshots, count, "alice"));

    free(snapshots);
    session_manager_destroy(mgr);
    unlink(path);
    TEST_PASS();
}

static int test_session_manager_count_user_uses_shared_authenticated_view(void)
{
    TEST_START();

    const char *path = "/tmp/test_session_manager_count_user.ndjson";
    unlink(path);

    session_manager_config_t config = {
        .max_sessions = 8,
        .session_timeout = 3600,
        .auth_timeout = 60,
        .store_type = SESSION_MANAGER_STORE_FILE,
        .sync_interval_sec = 1
    };
    strncpy(config.store_path, path, sizeof(config.store_path) - 1);
    strncpy(config.instance_id, "node-a", sizeof(config.instance_id) - 1);

    session_manager_config_t remote_config = config;
    strncpy(remote_config.instance_id, "node-b", sizeof(remote_config.instance_id) - 1);

    session_manager_t *mgr1 = session_manager_create(&config);
    session_manager_t *mgr2 = session_manager_create(&remote_config);
    ASSERT_NOT_NULL(mgr1);
    ASSERT_NOT_NULL(mgr2);

    session_t *authd = session_manager_create_session(mgr2, ssh_new());
    session_t *pending = session_manager_create_session(mgr2, ssh_new());
    ASSERT_NOT_NULL(authd);
    ASSERT_NOT_NULL(pending);

    session_set_username(authd, "ops");
    session_set_state(authd, SESSION_STATE_ACTIVE);
    session_set_username(pending, "ops");
    session_set_state(pending, SESSION_STATE_AUTH);

    ASSERT_EQ(session_manager_count_user(mgr1, "ops"), 1);

    session_manager_destroy(mgr2);
    session_manager_destroy(mgr1);
    unlink(path);
    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);
    printf("=== Session Manager Tests ===\n\n");

    int failed = 0;
    failed += test_session_manager_create();
    failed += test_session_state_names();
    failed += test_session_null_handling();
    failed += test_session_manager_snapshot_copies_device_metadata();
    failed += test_session_manager_shared_snapshot_merges_remote_records();
    failed += test_session_manager_background_sync_keeps_idle_remote_sessions_visible();
    failed += test_session_manager_shared_snapshot_recovers_after_stale_remote_record();
    failed += test_session_manager_count_user_uses_shared_authenticated_view();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failed);
    }

    log_shutdown();
    return failed;
}
