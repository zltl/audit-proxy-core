/**
 * @file test_config_auth.c
 * @brief Unit tests for configuration-backed authentication
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <libssh/libssh.h>

#include "account_lock.h"
#include "auth_filter.h"
#include "config.h"
#include "config_auth.h"
#include "logger.h"
#include "session.h"
#include "test_utils.h"

#define TEST_AUTH_CONFIG_PATH "/tmp/test_config_auth_geo.conf"
#define TEST_AUTH_GEOIP_PATH "/tmp/test_config_auth_geoip.json"

static const char *kTestHash = "$6$saltsalt$U5d2t4MFT.Hn/auqLjcfU6R/lm2Y71FvBwABEOht/UpRtNzcFvzGl/"
                               "oU6V38pYgY8ZpicOa.0ESff5jRNylZM.";
static const char *kFixtureUserKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASktWAd+0f7+hOovUbXPDbXIL9jf3YTPSg8tahGGaoK";
static const char *kFixtureTrustedUserCA =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDbtnhwX0ejxhvKPjjivt+EnAILdLWeQYDXoXd7O0rzQ";
static const char *kFixtureOtherUserCA =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPyC5TEOvesubC86/XAjgNmINIihvvYG+AFI++WkcMBy";
static const char *kFixtureValidUserCert =
    "ssh-ed25519-cert-v01@openssh.com "
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMvjf4LQ11AhjdLl7H/4zsq+RV0Fd8ae1QlNXpmd51hSAAAAIASktWAd+0f7+hOovUbXPDbXIL9jf3YTPSg8tahGGaoKAAAAAAAAAAAAAAABAAAADWFsaWNlLWZpeHR1cmUAAAAJAAAABWFsaWNlAAAAAAAAAAD//////////wAAAAAAAAASAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgNu2eHBfR6PGG8o+OOK+34ScAgt0tZ5BgNehd3s7SvNAAAABTAAAAC3NzaC1lZDI1NTE5AAAAQAU2jecuBHF/4cfpEsmVNgGDENPu9+l09E6KDgeiAfHY0X9WuegWJDjk4gOJSC9H/NyW/5OS8PpX8mbVWLDsgQE=";
static const char *kFixtureSourceAddrCert =
    "ssh-ed25519-cert-v01@openssh.com "
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIPAI1MFjFy3hlmRKROkn0KY0lGcj0qHF9LHCFL4MhEdbAAAAIASktWAd+0f7+hOovUbXPDbXIL9jf3YTPSg8tahGGaoKAAAAAAAAAAAAAAABAAAADWFsaWNlLWZpeHR1cmUAAAAJAAAABWFsaWNlAAAAAAAAAAD//////////wAAADcAAAAOc291cmNlLWFkZHJlc3MAAAAhAAAAHTE5OC41MS4xMDAuMC8yNCwyMDAxOmRiODo6LzMyAAAAEgAAAApwZXJtaXQtcHR5AAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDbtnhwX0ejxhvKPjjivt+EnAILdLWeQYDXoXd7O0rzQAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBMMzvWokSYBgClXiSD6O8nDiPrfZyH0J/qcUHkuDqbXAwNwXss7CIFRiVQh7PWPAqKM/x2XNHDAHa3w8zDuNUC";
static const char *kFixtureUnsupportedOptionCert =
    "ssh-ed25519-cert-v01@openssh.com "
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHdEJb8CeAv+2Z5ggHaedvQJ4D/J9x3caZqfeBs6PiKcAAAAIASktWAd+0f7+hOovUbXPDbXIL9jf3YTPSg8tahGGaoKAAAAAAAAAAAAAAABAAAADWFsaWNlLWZpeHR1cmUAAAAJAAAABWFsaWNlAAAAAAAAAAD//////////wAAABsAAAANZm9yY2UtY29tbWFuZAAAAAYAAAACaWQAAAASAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgNu2eHBfR6PGG8o+OOK+34ScAgt0tZ5BgNehd3s7SvNAAAABTAAAAC3NzaC1lZDI1NTE5AAAAQOKZCEJepGSplOh14YkzOb+qcNTPcG2qayYcGEGfMMTJbeCb9y6pOAzGck/4Oi0fikkPpfx2vCgGOml9/0tDSwM=";
static const char *kFixtureExpiredUserCert =
    "ssh-ed25519-cert-v01@openssh.com "
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHiaYv+9ocMT7ECvwAFLYiUV5s/9eqp6R7WydVq+hIxmAAAAIASktWAd+0f7+hOovUbXPDbXIL9jf3YTPSg8tahGGaoKAAAAAAAAAAAAAAABAAAADWFsaWNlLWZpeHR1cmUAAAAJAAAABWFsaWNlAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAASAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgNu2eHBfR6PGG8o+OOK+34ScAgt0tZ5BgNehd3s7SvNAAAABTAAAAC3NzaC1lZDI1NTE5AAAAQCqB02uQwo+CoLS7kLdjk2BoFmKGRvNSgjLYoYXeU+EF39/mLuBhJHB93M/UyKTXyDcjLsr7r0VgXUJl0SUkxQs=";
static const char *kFixtureRevokedSerial = "0";

static proxy_config_t *create_test_config(void) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return NULL;
    }
    if (config_add_user(config, "alice", kTestHash, NULL) != 0) {
        config_destroy(config);
        return NULL;
    }
    return config;
}

static proxy_config_t *create_pubkey_config(const char *pubkeys, const char *trusted_user_ca_keys) {
    proxy_config_t *config = config_create();
    if (config == NULL) {
        return NULL;
    }

    if (config_add_user(config, "alice", NULL, pubkeys) != 0) {
        config_destroy(config);
        return NULL;
    }

    if (config_add_user(config, "bob", NULL, NULL) != 0) {
        config_destroy(config);
        return NULL;
    }

    if (trusted_user_ca_keys != NULL) {
        config->trusted_user_ca_keys = strdup(trusted_user_ca_keys);
        if (config->trusted_user_ca_keys == NULL) {
            config_destroy(config);
            return NULL;
        }
    }

    return config;
}

static time_t make_utc_time(int year, int month, int day, int hour, int minute, int second) {
    struct tm tm_value;

    memset(&tm_value, 0, sizeof(tm_value));
    tm_value.tm_year = year - 1900;
    tm_value.tm_mon = month - 1;
    tm_value.tm_mday = day;
    tm_value.tm_hour = hour;
    tm_value.tm_min = minute;
    tm_value.tm_sec = second;
    return timegm(&tm_value);
}

static auth_result_t config_password_cb(const char *username, const char *password,
                                        void *user_data) {
    return config_authenticate_password((const proxy_config_t *)user_data, username, password);
}

static auth_result_t deny_authorize_cb(const char *username, const char *client_addr,
                                       void *user_data) {
    (void)username;
    (void)client_addr;
    (void)user_data;
    return AUTH_RESULT_DENIED;
}

static const char *g_seen_client_addr = NULL;

static auth_result_t capture_client_addr_pubkey_cb(const char *username, const char *client_addr,
                                                   const void *pubkey_data, size_t pubkey_len,
                                                   void *user_data) {
    (void)username;
    (void)pubkey_data;
    (void)pubkey_len;
    (void)user_data;
    g_seen_client_addr = client_addr;
    return AUTH_RESULT_SUCCESS;
}

static int write_test_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs(content, fp);
    fclose(fp);
    return 0;
}

static int test_config_auth_success(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_password(config, "alice", "test123"), AUTH_RESULT_SUCCESS);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_auth_expired_password(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);

    config->password_policy.max_age_days = 30;
    config_user_t *user = config_find_user(config, "alice");
    ASSERT_NOT_NULL(user);
    user->password_changed_at = time(NULL) - (31 * 86400);
    user->password_changed_at_set = true;

    ASSERT_EQ(config_authenticate_password(config, "alice", "test123"), AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_auth_rotation_required(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);

    config_user_t *user = config_find_user(config, "alice");
    ASSERT_NOT_NULL(user);
    user->password_change_required = true;

    ASSERT_EQ(config_authenticate_password(config, "alice", "test123"), AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_auth_without_timestamp_preserves_access(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);

    config->password_policy.max_age_days = 30;

    ASSERT_EQ(config_authenticate_password(config, "alice", "test123"), AUTH_RESULT_SUCCESS);

    config_destroy(config);
    TEST_PASS();
}

static int test_auth_filter_denied_does_not_lock_account(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {
        .lockout_enabled = true, .lockout_threshold = 1, .lockout_duration_sec = 60};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);
    config->password_policy.max_age_days = 30;
    config_user_t *user = config_find_user(config, "alice");
    ASSERT_NOT_NULL(user);
    user->password_changed_at = time(NULL) - (31 * 86400);
    user->password_changed_at_set = true;

    auth_filter_config_t auth_cfg = {.backend = AUTH_BACKEND_CALLBACK,
                                     .allow_password = true,
                                     .allow_pubkey = false,
                                     .allow_keyboard = false,
                                     .max_attempts = 3,
                                     .timeout_sec = 60,
                                     .password_cb = config_password_cb,
                                     .cb_user_data = config};

    filter_t *filter = auth_filter_create(&auth_cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = NULL, .username = "alice", .password = "test123"};

    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_FALSE(account_is_locked("alice"));
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_FALSE(account_is_locked("alice"));

    if (filter->callbacks.destroy != NULL) {
        filter->callbacks.destroy(filter);
    }
    free(filter->config);
    free(filter);
    config_destroy(config);
    account_lock_cleanup();

    TEST_PASS();
}

static int test_auth_filter_authorize_cb_denied_does_not_lock_account(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {
        .lockout_enabled = true, .lockout_threshold = 1, .lockout_duration_sec = 60};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);

    auth_filter_config_t auth_cfg = {.backend = AUTH_BACKEND_CALLBACK,
                                     .allow_password = true,
                                     .allow_pubkey = false,
                                     .allow_keyboard = false,
                                     .max_attempts = 3,
                                     .timeout_sec = 60,
                                     .password_cb = config_password_cb,
                                     .cb_user_data = config,
                                     .authorize_cb = deny_authorize_cb};

    filter_t *filter = auth_filter_create(&auth_cfg);
    ASSERT_NOT_NULL(filter);

    filter_context_t ctx = {.session = NULL, .username = "alice", .password = "test123"};

    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_REJECT);
    ASSERT_FALSE(account_is_locked("alice"));

    if (filter->callbacks.destroy != NULL) {
        filter->callbacks.destroy(filter);
    }
    free(filter->config);
    free(filter);
    config_destroy(config);
    account_lock_cleanup();

    TEST_PASS();
}

static int test_config_authorize_login_respects_time_window(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);
    ASSERT_EQ(config_add_route(config, "alice", "prod.example.com", 22, "ubuntu", NULL), 0);
    ASSERT_EQ(config_add_policy(config, "alice", "prod.example.com", 0xFFFFFFFF, 0), 0);

    config_policy_t *policy = config_find_policy(config, "alice", "prod.example.com");
    ASSERT_NOT_NULL(policy);
    policy->login_window_enabled = true;
    policy->login_days_mask = CONFIG_POLICY_DAY_MON | CONFIG_POLICY_DAY_TUE |
                              CONFIG_POLICY_DAY_WED | CONFIG_POLICY_DAY_THU |
                              CONFIG_POLICY_DAY_FRI;
    policy->login_window_start_minute = 9 * 60;
    policy->login_window_end_minute = 18 * 60;
    policy->login_timezone_offset_minutes = 8 * 60;

    ASSERT_EQ(config_authorize_login_at(config, "alice", "203.0.113.10",
                                        make_utc_time(2024, 1, 8, 2, 30, 0)),
              AUTH_RESULT_SUCCESS);
    ASSERT_EQ(config_authorize_login_at(config, "alice", "203.0.113.10",
                                        make_utc_time(2024, 1, 8, 11, 30, 0)),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_authorize_login_respects_source_policy(void) {
    TEST_START();

    proxy_config_t *config = create_test_config();
    ASSERT_NOT_NULL(config);
    config->office_source_cidrs = strdup("10.0.0.0/8");
    config->vpn_source_cidrs = strdup("100.64.0.0/10");
    ASSERT_NOT_NULL(config->office_source_cidrs);
    ASSERT_NOT_NULL(config->vpn_source_cidrs);
    ASSERT_EQ(config_add_route(config, "alice", "prod.example.com", 22, "ubuntu", NULL), 0);
    ASSERT_EQ(config_add_policy(config, "alice", "prod.example.com", 0xFFFFFFFF, 0), 0);

    config_policy_t *policy = config_find_policy(config, "alice", "prod.example.com");
    ASSERT_NOT_NULL(policy);
    policy->allowed_source_types = CONFIG_POLICY_SOURCE_OFFICE | CONFIG_POLICY_SOURCE_VPN;
    policy->denied_source_types = CONFIG_POLICY_SOURCE_PUBLIC;

    ASSERT_EQ(config_authorize_login_at(config, "alice", "10.1.2.3", make_utc_time(2024, 1, 8, 2, 30, 0)),
              AUTH_RESULT_SUCCESS);
    ASSERT_EQ(config_authorize_login_at(config, "alice", "203.0.113.10",
                                        make_utc_time(2024, 1, 8, 2, 30, 0)),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_authorize_login_uses_geo_selected_route(void) {
    const char *geoipContent =
        "[\n"
        "  {\"cidr\":\"203.0.113.0/24\",\"country_code\":\"US\",\"country\":\"United States\",\"region\":\"California\",\"city\":\"San Francisco\",\"latitude\":37.7749,\"longitude\":-122.4194}\n"
        "]\n";
    const char *configContent =
        "[network_sources]\n"
        "office_cidrs = 10.0.0.0/8\n"
        "geoip_data_file = " TEST_AUTH_GEOIP_PATH "\n"
        "\n"
        "[route:alice]\n"
        "upstream = sfo.example.com\n"
        "country_code = US\n"
        "region = California\n"
        "city = San Francisco\n"
        "latitude = 37.7749\n"
        "longitude = -122.4194\n"
        "\n"
        "[route:alice]\n"
        "upstream = fra.example.com\n"
        "country_code = DE\n"
        "region = Hesse\n"
        "city = Frankfurt\n"
        "latitude = 50.1109\n"
        "longitude = 8.6821\n"
        "\n"
        "[policy:alice@sfo.example.com]\n"
        "allowed_source_types = public\n"
        "\n"
        "[policy:alice@fra.example.com]\n"
        "allowed_source_types = office\n";

    TEST_START();

    ASSERT_EQ(write_test_file(TEST_AUTH_GEOIP_PATH, geoipContent), 0);
    ASSERT_EQ(write_test_file(TEST_AUTH_CONFIG_PATH, configContent), 0);

    proxy_config_t *config = config_load(TEST_AUTH_CONFIG_PATH);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authorize_login_at(config, "alice", "203.0.113.55",
                                        make_utc_time(2024, 1, 8, 2, 30, 0)),
              AUTH_RESULT_SUCCESS);

    config_destroy(config);
    unlink(TEST_AUTH_CONFIG_PATH);
    unlink(TEST_AUTH_GEOIP_PATH);
    TEST_PASS();
}

static int test_config_authorize_login_skips_open_circuit_route(void) {
    proxy_config_t *config = NULL;
    config_route_t *primary = NULL;
    config_policy_t *policy = NULL;
    time_t now = time(NULL);

    TEST_START();

    config = create_test_config();
    ASSERT_NOT_NULL(config);
    config->router_circuit_breaker_enabled = true;
    config->router_circuit_breaker_failure_threshold = 1;
    config->router_circuit_breaker_open_seconds = 60;

    ASSERT_EQ(config_add_route(config, "alice", "node-a.example.com", 22, "ubuntu", NULL), 0);
    ASSERT_EQ(config_add_route(config, "alice", "node-b.example.com", 22, "ubuntu", NULL), 0);

    primary = config_find_route(config, "alice");
    ASSERT_NOT_NULL(primary);
    ASSERT_EQ(config_add_policy(config, "alice", primary->upstream_host, 0xFFFFFFFF, 0), 0);
    policy = config_find_policy(config, "alice", primary->upstream_host);
    ASSERT_NOT_NULL(policy);
    policy->allowed_source_types = CONFIG_POLICY_SOURCE_OFFICE;

    ASSERT_TRUE(config_route_circuit_record_failure(config, primary, now));
    ASSERT_EQ(config_authorize_login_at(config, "alice", "203.0.113.10", now), AUTH_RESULT_SUCCESS);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_pubkey_auth_success(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(kFixtureUserKey, NULL);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", NULL, kFixtureUserKey),
              AUTH_RESULT_SUCCESS);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_success(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureValidUserCert),
              AUTH_RESULT_SUCCESS);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_untrusted_ca(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureOtherUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureValidUserCert),
              AUTH_RESULT_FAILURE);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_principal_mismatch(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "bob", "203.0.113.10", kFixtureValidUserCert),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_source_address(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "198.51.100.77", kFixtureSourceAddrCert),
              AUTH_RESULT_SUCCESS);
    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.77", kFixtureSourceAddrCert),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_unsupported_option_denied(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(
        config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureUnsupportedOptionCert),
        AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_expired_denied(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureExpiredUserCert),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_revoked_denied(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);
    config->revoked_user_cert_serials = strdup(kFixtureRevokedSerial);
    ASSERT_NOT_NULL(config->revoked_user_cert_serials);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureValidUserCert),
              AUTH_RESULT_DENIED);

    config_destroy(config);
    TEST_PASS();
}

static int test_config_ssh_cert_auth_invalid_revocation_list_fails_closed(void) {
    TEST_START();

    proxy_config_t *config = create_pubkey_config(NULL, kFixtureTrustedUserCA);
    ASSERT_NOT_NULL(config);
    config->revoked_user_cert_serials = strdup("invalid");
    ASSERT_NOT_NULL(config->revoked_user_cert_serials);

    ASSERT_EQ(config_authenticate_pubkey(config, "alice", "203.0.113.10", kFixtureValidUserCert),
              AUTH_RESULT_FAILURE);

    config_destroy(config);
    TEST_PASS();
}

static int test_auth_filter_passes_client_addr_to_pubkey_cb(void) {
    TEST_START();

    account_lock_config_t lock_cfg = {0};
    ASSERT_EQ(account_lock_init(&lock_cfg), 0);

    auth_filter_config_t auth_cfg = {.backend = AUTH_BACKEND_CALLBACK,
                                     .allow_password = false,
                                     .allow_pubkey = true,
                                     .allow_keyboard = false,
                                     .max_attempts = 3,
                                     .timeout_sec = 60,
                                     .pubkey_cb = capture_client_addr_pubkey_cb};
    filter_t *filter = auth_filter_create(&auth_cfg);
    ASSERT_NOT_NULL(filter);

    session_manager_config_t manager_cfg = {.max_sessions = 4, .session_timeout = 60, .auth_timeout = 60};
    session_manager_t *manager = session_manager_create(&manager_cfg);
    ASSERT_NOT_NULL(manager);

    ssh_session client = ssh_new();
    ASSERT_NOT_NULL(client);

    session_t *session = session_manager_create_session(manager, client);
    ASSERT_NOT_NULL(session);
    session_metadata_t *meta = session_get_metadata(session);
    ASSERT_NOT_NULL(meta);
    strncpy(meta->client_addr, "198.51.100.123", sizeof(meta->client_addr) - 1);

    g_seen_client_addr = NULL;
    filter_context_t ctx = {.session = session,
                            .username = "alice",
                            .pubkey = kFixtureUserKey,
                            .pubkey_len = strlen(kFixtureUserKey)};
    ASSERT_EQ(filter->callbacks.on_auth(filter, &ctx), FILTER_CONTINUE);
    ASSERT_NOT_NULL(g_seen_client_addr);
    ASSERT_STR_EQ(g_seen_client_addr, "198.51.100.123");

    if (filter->callbacks.destroy != NULL) {
        filter->callbacks.destroy(filter);
    }
    free(filter->config);
    free(filter);
    session_manager_destroy(manager);
    account_lock_cleanup();

    TEST_PASS();
}

int main(void) {
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("Config Auth Module Tests");

    RUN_TEST(test_config_auth_success);
    RUN_TEST(test_config_auth_expired_password);
    RUN_TEST(test_config_auth_rotation_required);
    RUN_TEST(test_config_auth_without_timestamp_preserves_access);
    RUN_TEST(test_auth_filter_denied_does_not_lock_account);
    RUN_TEST(test_auth_filter_authorize_cb_denied_does_not_lock_account);
    RUN_TEST(test_config_authorize_login_respects_time_window);
    RUN_TEST(test_config_authorize_login_respects_source_policy);
    RUN_TEST(test_config_authorize_login_uses_geo_selected_route);
    RUN_TEST(test_config_authorize_login_skips_open_circuit_route);
    RUN_TEST(test_config_pubkey_auth_success);
    RUN_TEST(test_config_ssh_cert_auth_success);
    RUN_TEST(test_config_ssh_cert_auth_untrusted_ca);
    RUN_TEST(test_config_ssh_cert_auth_principal_mismatch);
    RUN_TEST(test_config_ssh_cert_auth_source_address);
    RUN_TEST(test_config_ssh_cert_auth_unsupported_option_denied);
    RUN_TEST(test_config_ssh_cert_auth_expired_denied);
    RUN_TEST(test_config_ssh_cert_auth_revoked_denied);
    RUN_TEST(test_config_ssh_cert_auth_invalid_revocation_list_fails_closed);
    RUN_TEST(test_auth_filter_passes_client_addr_to_pubkey_cb);

    log_shutdown();

    TEST_END();
}
