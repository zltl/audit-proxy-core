/**
 * @file test_session_store.c
 * @brief Tests for distributed session storage
 */
#include "test_utils.h"
#include "session_store.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int test_create_local(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100,
        .instance_id = "test-1"
    };

    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);
    ASSERT_EQ(session_store_count(store), 0);
    session_store_destroy(store);
    return 0;
}

static int test_create_null(void)
{
    ASSERT_NULL(session_store_create(NULL));
    return 0;
}

static int test_put_get(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    session_record_t rec = {
        .session_id = 42,
        .active = true,
        .created_at = 1000,
        .username = "admin",
        .client_addr = "192.168.1.1"
    };

    ASSERT_EQ(session_store_put(store, &rec), 0);
    ASSERT_EQ(session_store_count(store), 1);

    session_record_t out;
    ASSERT_EQ(session_store_get(store, 42, &out), 0);
    ASSERT_EQ(out.session_id, (uint64_t)42);
    ASSERT_STR_EQ(out.username, "admin");

    session_store_destroy(store);
    return 0;
}

static int test_put_update(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    session_record_t rec = { .session_id = 1, .active = true, .username = "user1" };
    session_store_put(store, &rec);

    strncpy(rec.username, "user1-updated", sizeof(rec.username) - 1);
    rec.username[sizeof(rec.username) - 1] = '\0';
    session_store_put(store, &rec);

    ASSERT_EQ(session_store_count(store), 1);

    session_record_t out;
    session_store_get(store, 1, &out);
    ASSERT_STR_EQ(out.username, "user1-updated");

    session_store_destroy(store);
    return 0;
}

static int test_remove(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    session_record_t rec = { .session_id = 1, .active = true };
    session_store_put(store, &rec);
    ASSERT_EQ(session_store_count(store), 1);

    ASSERT_EQ(session_store_remove(store, 1), 0);
    ASSERT_EQ(session_store_count(store), 0);
    ASSERT_EQ(session_store_remove(store, 999), -1);

    session_store_destroy(store);
    return 0;
}

static int test_list(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    for (int i = 0; i < 5; i++) {
        session_record_t rec = { .session_id = (uint64_t)(i + 1), .active = true };
        snprintf(rec.username, sizeof(rec.username), "user%d", i);
        session_store_put(store, &rec);
    }

    session_record_t list[10];
    int count = session_store_list(store, list, 10);
    ASSERT_EQ(count, 5);

    session_store_destroy(store);
    return 0;
}

static int test_count_user(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 100
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    for (int i = 0; i < 3; i++) {
        session_record_t rec = {
            .session_id = (uint64_t)(i + 1),
            .active = true,
            .username = "admin"
        };
        session_store_put(store, &rec);
    }

    session_record_t rec2 = {
        .session_id = 100,
        .active = true,
        .username = "other"
    };
    session_store_put(store, &rec2);

    ASSERT_EQ(session_store_count_user(store, "admin"), 3);
    ASSERT_EQ(session_store_count_user(store, "other"), 1);
    ASSERT_EQ(session_store_count_user(store, "nobody"), 0);

    session_store_destroy(store);
    return 0;
}

static int test_full_store(void)
{
    session_store_config_t config = {
        .type = SESSION_STORE_LOCAL,
        .max_records = 3
    };
    session_store_t *store = session_store_create(&config);
    ASSERT_NOT_NULL(store);

    for (int i = 0; i < 3; i++) {
        session_record_t rec = { .session_id = (uint64_t)(i + 1), .active = true };
        ASSERT_EQ(session_store_put(store, &rec), 0);
    }

    session_record_t overflow = { .session_id = 999, .active = true };
    ASSERT_EQ(session_store_put(store, &overflow), -1);

    session_store_destroy(store);
    return 0;
}

static int test_file_sync(void)
{
    const char *path = "/tmp/test_session_store.json";
    unlink(path);

    /* Instance 1 writes */
    session_store_config_t config1 = {
        .type = SESSION_STORE_FILE,
        .max_records = 100,
        .instance_id = "node-1"
    };
    strncpy(config1.store_path, path, sizeof(config1.store_path) - 1);

    session_store_t *store1 = session_store_create(&config1);
    ASSERT_NOT_NULL(store1);

    session_record_t rec1 = {
        .session_id = 1,
        .active = true,
        .username = "user1",
        .instance_id = "node-1"
    };
    session_store_put(store1, &rec1);
    session_store_sync(store1);
    session_store_destroy(store1);

    /* Instance 2 reads */
    session_store_config_t config2 = {
        .type = SESSION_STORE_FILE,
        .max_records = 100,
        .instance_id = "node-2"
    };
    strncpy(config2.store_path, path, sizeof(config2.store_path) - 1);

    session_store_t *store2 = session_store_create(&config2);
    ASSERT_NOT_NULL(store2);

    /* Should have loaded node-1's session */
    ASSERT_TRUE(session_store_count(store2) >= 1);

    session_store_destroy(store2);
    unlink(path);
    return 0;
}

static int test_null_operations(void)
{
    ASSERT_EQ(session_store_put(NULL, NULL), -1);
    ASSERT_EQ(session_store_get(NULL, 1, NULL), -1);
    ASSERT_EQ(session_store_remove(NULL, 1), -1);
    ASSERT_EQ(session_store_count(NULL), 0);
    ASSERT_EQ(session_store_count_user(NULL, "x"), 0);
    session_store_destroy(NULL); /* Should not crash */
    return 0;
}

int main(void)
{
    TEST_BEGIN("Session Store Tests");

    RUN_TEST(test_create_local);
    RUN_TEST(test_create_null);
    RUN_TEST(test_put_get);
    RUN_TEST(test_put_update);
    RUN_TEST(test_remove);
    RUN_TEST(test_list);
    RUN_TEST(test_count_user);
    RUN_TEST(test_full_store);
    RUN_TEST(test_file_sync);
    RUN_TEST(test_null_operations);

    TEST_END();
}
