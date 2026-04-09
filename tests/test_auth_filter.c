/**
 * @file test_auth_filter.c
 * @brief Unit tests for auth filter LDAP failover behavior.
 */

#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>

#include "account_lock.h"
#include "auth_filter.h"
#include "logger.h"
#include "session.h"
#include "test_utils.h"

typedef struct {
    const char *uri;
    auth_result_t result;
} ldap_mock_result_t;

typedef struct {
    ldap_mock_result_t results[8];
    size_t result_count;
    size_t call_count;
    char seen_uris[8][128];
    char last_bind_dn[512];
    int last_timeout;
    bool last_starttls;
    bool last_verify_cert;
    char last_ca_path[256];
} ldap_mock_t;

typedef struct {
    size_t call_count;
    char seen_uri[128];
    char seen_lookup_bind_dn[512];
    char seen_search_dn[512];
    char seen_group_attr[64];
    char seen_email_attr[64];
    char seen_department_attr[64];
    char seen_manager_attr[64];
    auth_ldap_identity_t identity;
} ldap_identity_mock_t;

static void destroy_filter_instance(filter_t *filter) {
    if (filter == NULL) {
        return;
    }
    if (filter->callbacks.destroy != NULL) {
        filter->callbacks.destroy(filter);
    }
    free(filter);
}

static auth_result_t mock_ldap_bind(const char *uri, const char *bind_dn, const char *password,
                                    int timeout_sec, bool starttls, bool verify_cert,
                                    const char *ca_path, void *user_data) {
    ldap_mock_t *mock = (ldap_mock_t *)user_data;

    (void)password;
    if (mock == NULL || uri == NULL || bind_dn == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    if (mock->call_count < 8) {
        strncpy(mock->seen_uris[mock->call_count], uri, sizeof(mock->seen_uris[0]) - 1);
    }
    strncpy(mock->last_bind_dn, bind_dn, sizeof(mock->last_bind_dn) - 1);
    mock->last_timeout = timeout_sec;
    mock->last_starttls = starttls;
    mock->last_verify_cert = verify_cert;
    if (ca_path != NULL) {
        strncpy(mock->last_ca_path, ca_path, sizeof(mock->last_ca_path) - 1);
    } else {
        mock->last_ca_path[0] = '\0';
    }
    mock->call_count++;

    for (size_t i = 0; i < mock->result_count; i++) {
        if (strcmp(mock->results[i].uri, uri) == 0) {
            return mock->results[i].result;
        }
    }
    return AUTH_RESULT_DENIED;
}

static auth_result_t mock_ldap_fetch_identity(const char *uri, const char *lookup_bind_dn,
                                              const char *lookup_password, const char *search_dn,
                                              int timeout_sec, bool starttls, bool verify_cert,
                                              const char *ca_path, const char *group_attr,
                                              const char *email_attr,
                                              const char *department_attr,
                                              const char *manager_attr,
                                              auth_ldap_identity_t *identity, void *user_data) {
    ldap_identity_mock_t *mock = (ldap_identity_mock_t *)user_data;

    (void)lookup_password;
    (void)timeout_sec;
    (void)starttls;
    (void)verify_cert;
    (void)ca_path;
    if (mock == NULL || uri == NULL || lookup_bind_dn == NULL || search_dn == NULL ||
        identity == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    mock->call_count++;
    strncpy(mock->seen_uri, uri, sizeof(mock->seen_uri) - 1);
    strncpy(mock->seen_lookup_bind_dn, lookup_bind_dn, sizeof(mock->seen_lookup_bind_dn) - 1);
    strncpy(mock->seen_search_dn, search_dn, sizeof(mock->seen_search_dn) - 1);
    strncpy(mock->seen_group_attr, group_attr, sizeof(mock->seen_group_attr) - 1);
    strncpy(mock->seen_email_attr, email_attr, sizeof(mock->seen_email_attr) - 1);
    strncpy(mock->seen_department_attr, department_attr, sizeof(mock->seen_department_attr) - 1);
    strncpy(mock->seen_manager_attr, manager_attr, sizeof(mock->seen_manager_attr) - 1);
    *identity = mock->identity;
    return AUTH_RESULT_SUCCESS;
}

static int test_ldap_failover_prefers_last_success(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {0};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    ldap_mock_t mock = {
        .results = {
            {"ldap://down-1.example.com:389", AUTH_RESULT_DENIED},
            {"ldap://good.example.com:389", AUTH_RESULT_SUCCESS},
            {"ldap://backup.example.com:389", AUTH_RESULT_SUCCESS},
        },
        .result_count = 3,
    };

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_LDAP,
        .allow_password = true,
        .allow_pubkey = false,
        .allow_keyboard = false,
        .max_attempts = 3,
        .timeout_sec = 60,
        .ldap_uri = "ldap://down-1.example.com:389, ldap://good.example.com:389, ldap://backup.example.com:389",
        .ldap_base_dn = "dc=example,dc=com",
        .ldap_user_filter = "uid=%s",
        .ldap_timeout = 9,
        .ldap_starttls = true,
        .ldap_verify_cert = false,
        .ldap_ca_path = "/tmp/test-ca.pem",
        .ldap_bind_cb = mock_ldap_bind,
        .ldap_bind_user_data = &mock,
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = NULL, .username = "alice", .password = "secret"};
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_CONTINUE);
    ASSERT_EQ(mock.call_count, 2);
    ASSERT_STR_EQ(mock.seen_uris[0], "ldap://down-1.example.com:389");
    ASSERT_STR_EQ(mock.seen_uris[1], "ldap://good.example.com:389");
    ASSERT_STR_EQ(mock.last_bind_dn, "uid=alice,dc=example,dc=com");
    ASSERT_EQ(mock.last_timeout, 9);
    ASSERT_TRUE(mock.last_starttls);
    ASSERT_FALSE(mock.last_verify_cert);
    ASSERT_STR_EQ(mock.last_ca_path, "/tmp/test-ca.pem");

    mock.call_count = 0;
    memset(mock.seen_uris, 0, sizeof(mock.seen_uris));

    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_CONTINUE);
    ASSERT_EQ(mock.call_count, 1);
    ASSERT_STR_EQ(mock.seen_uris[0], "ldap://good.example.com:389");

    destroy_filter_instance(filter);
    account_lock_cleanup();
    TEST_PASS();
}

static int test_ldap_invalid_credentials_do_not_failover(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {0};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    ldap_mock_t mock = {
        .results = {
            {"ldap://primary.example.com:389", AUTH_RESULT_FAILURE},
            {"ldap://secondary.example.com:389", AUTH_RESULT_SUCCESS},
        },
        .result_count = 2,
    };

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_LDAP,
        .allow_password = true,
        .max_attempts = 3,
        .timeout_sec = 60,
        .ldap_uri = "ldap://primary.example.com:389,ldap://secondary.example.com:389",
        .ldap_base_dn = "dc=example,dc=com",
        .ldap_bind_cb = mock_ldap_bind,
        .ldap_bind_user_data = &mock,
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = NULL, .username = "alice", .password = "bad-secret"};
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_EQ(mock.call_count, 1);
    ASSERT_STR_EQ(mock.seen_uris[0], "ldap://primary.example.com:389");

    destroy_filter_instance(filter);
    account_lock_cleanup();
    TEST_PASS();
}

static int test_ldap_failover_exhausts_all_targets(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {0};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    ldap_mock_t mock = {
        .results = {
            {"ldap://one.example.com:389", AUTH_RESULT_DENIED},
            {"ldap://two.example.com:389", AUTH_RESULT_DENIED},
        },
        .result_count = 2,
    };

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_LDAP,
        .allow_password = true,
        .max_attempts = 3,
        .timeout_sec = 60,
        .ldap_uri = "ldap://one.example.com:389, ldap://two.example.com:389",
        .ldap_base_dn = "dc=example,dc=com",
        .ldap_bind_cb = mock_ldap_bind,
        .ldap_bind_user_data = &mock,
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = NULL, .username = "alice", .password = "secret"};
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_EQ(mock.call_count, 2);
    ASSERT_STR_EQ(mock.seen_uris[0], "ldap://one.example.com:389");
    ASSERT_STR_EQ(mock.seen_uris[1], "ldap://two.example.com:389");

    destroy_filter_instance(filter);
    account_lock_cleanup();
    TEST_PASS();
}

static int test_ldap_identity_populates_session_metadata(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {0};
    session_manager_config_t sm_cfg = {.max_sessions = 4, .session_timeout = 60, .auth_timeout = 60};
    ldap_mock_t bind_mock = {
        .results = {
            {"ldap://down.example.com:389", AUTH_RESULT_DENIED},
            {"ldap://good.example.com:389", AUTH_RESULT_SUCCESS},
        },
        .result_count = 2,
    };
    ldap_identity_mock_t identity_mock = {0};

    ASSERT_EQ(account_lock_init(&lock_cfg), 0);
    session_manager_t *session_mgr = session_manager_create(&sm_cfg);
    ASSERT_NOT_NULL(session_mgr);
    ssh_session client = ssh_new();
    ASSERT_NOT_NULL(client);
    session_t *session = session_manager_create_session(session_mgr, client);
    ASSERT_NOT_NULL(session);

    strncpy(identity_mock.identity.user_dn, "uid=alice,dc=example,dc=com",
            sizeof(identity_mock.identity.user_dn) - 1);
    strncpy(identity_mock.identity.email, "alice@example.com",
            sizeof(identity_mock.identity.email) - 1);
    strncpy(identity_mock.identity.department, "Operations",
            sizeof(identity_mock.identity.department) - 1);
    strncpy(identity_mock.identity.manager, "uid=boss,dc=example,dc=com",
            sizeof(identity_mock.identity.manager) - 1);
    strncpy(identity_mock.identity.groups,
            "cn=admins,ou=groups,dc=example,dc=com\ncn=ops,ou=groups,dc=example,dc=com",
            sizeof(identity_mock.identity.groups) - 1);

    auth_filter_config_t cfg = {
        .backend = AUTH_BACKEND_LDAP,
        .allow_password = true,
        .allow_pubkey = false,
        .allow_keyboard = false,
        .max_attempts = 3,
        .timeout_sec = 60,
        .ldap_uri = "ldap://down.example.com:389, ldap://good.example.com:389",
        .ldap_base_dn = "dc=example,dc=com",
        .ldap_user_filter = "uid=%s",
        .ldap_bind_dn = "cn=svc,dc=example,dc=com",
        .ldap_bind_pw = "svc-secret",
        .ldap_group_attr = "memberOf",
        .ldap_email_attr = "mail",
        .ldap_department_attr = "department",
        .ldap_manager_attr = "manager",
        .ldap_bind_cb = mock_ldap_bind,
        .ldap_bind_user_data = &bind_mock,
        .ldap_fetch_identity_cb = mock_ldap_fetch_identity,
        .ldap_fetch_identity_user_data = &identity_mock,
    };

    filter_t *filter = auth_filter_create(&cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = session, .username = "alice", .password = "secret"};
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_CONTINUE);
    ASSERT_EQ(bind_mock.call_count, 2);
    ASSERT_EQ(identity_mock.call_count, 1);
    ASSERT_STR_EQ(identity_mock.seen_uri, "ldap://good.example.com:389");
    ASSERT_STR_EQ(identity_mock.seen_lookup_bind_dn, "cn=svc,dc=example,dc=com");
    ASSERT_STR_EQ(identity_mock.seen_search_dn, "uid=alice,dc=example,dc=com");
    ASSERT_STR_EQ(identity_mock.seen_group_attr, "memberOf");
    ASSERT_STR_EQ(identity_mock.seen_email_attr, "mail");
    ASSERT_STR_EQ(identity_mock.seen_department_attr, "department");
    ASSERT_STR_EQ(identity_mock.seen_manager_attr, "manager");

    session_metadata_t *meta = session_get_metadata(session);
    ASSERT_NOT_NULL(meta);
    ASSERT_STR_EQ(meta->ldap_email, "alice@example.com");
    ASSERT_STR_EQ(meta->ldap_department, "Operations");
    ASSERT_STR_EQ(meta->ldap_manager, "uid=boss,dc=example,dc=com");
    ASSERT_STR_EQ(meta->ldap_groups,
                  "cn=admins,ou=groups,dc=example,dc=com\ncn=ops,ou=groups,dc=example,dc=com");

    destroy_filter_instance(filter);
    session_manager_destroy(session_mgr);
    account_lock_cleanup();
    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Auth Filter Tests");

    RUN_TEST(test_ldap_failover_prefers_last_success);
    RUN_TEST(test_ldap_invalid_credentials_do_not_failover);
    RUN_TEST(test_ldap_failover_exhausts_all_targets);
    RUN_TEST(test_ldap_identity_populates_session_metadata);

    log_shutdown();
    TEST_END();
}
