/**
 * @file test_ip_acl_filter.c
 * @brief Unit tests for IP ACL Filter
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip_acl_filter.h"
#include "logger.h"
#include "test_utils.h"

/* --- CIDR parsing tests --- */

static int test_add_entry_basic(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};
    ASSERT_EQ(ip_acl_add_entry(&config, "192.168.1.0/24", IP_ACL_ALLOW), 0);
    ASSERT_NOT_NULL(config.entries);
    ASSERT_STR_EQ(config.entries->cidr_str, "192.168.1.0/24");

    ip_acl_clear_entries(&config);
    TEST_PASS();
}

static int test_add_entry_single_ip(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};
    ASSERT_EQ(ip_acl_add_entry(&config, "10.0.0.1", IP_ACL_DENY), 0);
    ASSERT_NOT_NULL(config.entries);
    /* Single IP implies /32 mask = 0xFFFFFFFF */
    ASSERT_EQ(config.entries->mask, (uint32_t)0xFFFFFFFF);

    ip_acl_clear_entries(&config);
    TEST_PASS();
}

static int test_add_entry_various_prefixes(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};

    ASSERT_EQ(ip_acl_add_entry(&config, "10.0.0.0/8", IP_ACL_ALLOW), 0);
    ASSERT_EQ(ip_acl_add_entry(&config, "172.16.0.0/16", IP_ACL_ALLOW), 0);
    ASSERT_EQ(ip_acl_add_entry(&config, "192.168.1.0/24", IP_ACL_ALLOW), 0);
    ASSERT_EQ(ip_acl_add_entry(&config, "10.0.0.1/32", IP_ACL_ALLOW), 0);
    ASSERT_EQ(ip_acl_add_entry(&config, "0.0.0.0/0", IP_ACL_ALLOW), 0);

    /* Verify /8 mask */
    ip_acl_entry_t *e = config.entries;
    ASSERT_EQ(e->mask, (uint32_t)0xFF000000);
    ASSERT_EQ(e->network, (uint32_t)(10u << 24));

    /* Verify /16 mask */
    e = e->next;
    ASSERT_EQ(e->mask, (uint32_t)0xFFFF0000);

    /* Verify /24 mask */
    e = e->next;
    ASSERT_EQ(e->mask, (uint32_t)0xFFFFFF00);

    /* Verify /32 mask */
    e = e->next;
    ASSERT_EQ(e->mask, (uint32_t)0xFFFFFFFF);

    /* Verify /0 mask */
    e = e->next;
    ASSERT_EQ(e->mask, (uint32_t)0x00000000);
    ASSERT_EQ(e->network, (uint32_t)0x00000000);

    ip_acl_clear_entries(&config);
    TEST_PASS();
}

static int test_add_entry_invalid(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};

    /* Invalid CIDR notations */
    ASSERT_EQ(ip_acl_add_entry(&config, "not-an-ip", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "256.1.1.1", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "1.2.3.4/33", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "1.2.3.4/-1", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "1.2.3", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, "1.2.3.4/", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(NULL, "1.2.3.4", IP_ACL_ALLOW), -1);
    ASSERT_EQ(ip_acl_add_entry(&config, NULL, IP_ACL_ALLOW), -1);

    ASSERT_NULL(config.entries);
    TEST_PASS();
}

static int test_cidr_network_masking(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};

    /* Host bits should be masked off: 192.168.1.100/24 -> network 192.168.1.0 */
    ASSERT_EQ(ip_acl_add_entry(&config, "192.168.1.100/24", IP_ACL_ALLOW), 0);
    uint32_t expected_net = (192u << 24) | (168u << 16) | (1u << 8);
    ASSERT_EQ(config.entries->network, expected_net);

    ip_acl_clear_entries(&config);
    TEST_PASS();
}

/* --- Whitelist mode tests --- */

static int test_whitelist_allow_listed(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    ip_acl_add_entry(&config, "192.168.1.0/24", IP_ACL_ALLOW);
    ip_acl_add_entry(&config, "10.0.0.1", IP_ACL_ALLOW);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* Listed IPs should be allowed */
    ASSERT_TRUE(ip_acl_check(filter, "192.168.1.1"));
    ASSERT_TRUE(ip_acl_check(filter, "192.168.1.254"));
    ASSERT_TRUE(ip_acl_check(filter, "10.0.0.1"));

    /* Unlisted IPs should be denied */
    ASSERT_FALSE(ip_acl_check(filter, "172.16.0.1"));
    ASSERT_FALSE(ip_acl_check(filter, "10.0.0.2"));
    ASSERT_FALSE(ip_acl_check(filter, "192.168.2.1"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_whitelist_empty(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* Whitelist with no entries should deny everything */
    ASSERT_FALSE(ip_acl_check(filter, "1.2.3.4"));
    ASSERT_FALSE(ip_acl_check(filter, "192.168.1.1"));

    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

/* --- Blacklist mode tests --- */

static int test_blacklist_deny_listed(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_BLACKLIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    ip_acl_add_entry(&config, "10.0.0.0/8", IP_ACL_DENY);
    ip_acl_add_entry(&config, "192.168.1.50", IP_ACL_DENY);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* Listed IPs should be denied */
    ASSERT_FALSE(ip_acl_check(filter, "10.0.0.1"));
    ASSERT_FALSE(ip_acl_check(filter, "10.255.255.255"));
    ASSERT_FALSE(ip_acl_check(filter, "192.168.1.50"));

    /* Unlisted IPs should be allowed */
    ASSERT_TRUE(ip_acl_check(filter, "192.168.1.1"));
    ASSERT_TRUE(ip_acl_check(filter, "172.16.0.1"));
    ASSERT_TRUE(ip_acl_check(filter, "8.8.8.8"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_blacklist_empty(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_BLACKLIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* Blacklist with no entries should allow everything */
    ASSERT_TRUE(ip_acl_check(filter, "1.2.3.4"));
    ASSERT_TRUE(ip_acl_check(filter, "255.255.255.255"));

    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

/* --- First-match-wins ordering --- */

static int test_first_match_wins(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_BLACKLIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    /* Allow a specific IP, then deny entire subnet */
    ip_acl_add_entry(&config, "10.0.0.5", IP_ACL_ALLOW);
    ip_acl_add_entry(&config, "10.0.0.0/24", IP_ACL_DENY);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* 10.0.0.5 matches the first ALLOW rule */
    ASSERT_TRUE(ip_acl_check(filter, "10.0.0.5"));
    /* 10.0.0.6 matches the second DENY rule */
    ASSERT_FALSE(ip_acl_check(filter, "10.0.0.6"));
    /* Unmatched IP falls through to blacklist default (allow) */
    ASSERT_TRUE(ip_acl_check(filter, "172.16.0.1"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_first_match_wins_whitelist(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    /* Deny specific IP, then allow the whole subnet */
    ip_acl_add_entry(&config, "192.168.1.100", IP_ACL_DENY);
    ip_acl_add_entry(&config, "192.168.1.0/24", IP_ACL_ALLOW);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* 192.168.1.100 matches the first DENY rule */
    ASSERT_FALSE(ip_acl_check(filter, "192.168.1.100"));
    /* 192.168.1.50 matches the second ALLOW rule */
    ASSERT_TRUE(ip_acl_check(filter, "192.168.1.50"));
    /* Unmatched IP falls through to whitelist default (deny) */
    ASSERT_FALSE(ip_acl_check(filter, "10.0.0.1"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

/* --- Edge cases --- */

static int test_null_ip(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };
    ip_acl_add_entry(&config, "0.0.0.0/0", IP_ACL_ALLOW);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    /* NULL IP should be denied in whitelist mode */
    ASSERT_FALSE(ip_acl_check(filter, NULL));
    /* Empty IP should be denied in whitelist mode */
    ASSERT_FALSE(ip_acl_check(filter, ""));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);

    /* In blacklist mode, NULL/empty should be allowed */
    ip_acl_filter_config_t config2 = {
        .mode = IP_ACL_BLACKLIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };
    ip_acl_add_entry(&config2, "0.0.0.0/0", IP_ACL_DENY);

    filter_t *filter2 = ip_acl_filter_create(&config2);
    ASSERT_NOT_NULL(filter2);

    ASSERT_TRUE(ip_acl_check(filter2, NULL));
    ASSERT_TRUE(ip_acl_check(filter2, ""));

    ip_acl_clear_entries(&config2);
    filter2->callbacks.destroy(filter2);
    free(filter2->config);
    free(filter2);
    TEST_PASS();
}

static int test_null_filter(void)
{
    TEST_START();

    /* NULL filter should default to allow */
    ASSERT_TRUE(ip_acl_check(NULL, "1.2.3.4"));

    TEST_PASS();
}

static int test_slash_zero(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_BLACKLIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    /* /0 matches everything */
    ip_acl_add_entry(&config, "0.0.0.0/0", IP_ACL_DENY);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    ASSERT_FALSE(ip_acl_check(filter, "1.1.1.1"));
    ASSERT_FALSE(ip_acl_check(filter, "255.255.255.255"));
    ASSERT_FALSE(ip_acl_check(filter, "192.168.0.1"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_slash_32(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = false,
        .log_accepts = false
    };

    ip_acl_add_entry(&config, "10.20.30.40/32", IP_ACL_ALLOW);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    ASSERT_TRUE(ip_acl_check(filter, "10.20.30.40"));
    ASSERT_FALSE(ip_acl_check(filter, "10.20.30.41"));

    ip_acl_clear_entries(&config);
    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_filter_create_destroy(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {
        .mode = IP_ACL_WHITELIST,
        .entries = NULL,
        .log_rejections = true,
        .log_accepts = false
    };

    ip_acl_add_entry(&config, "10.0.0.0/8", IP_ACL_ALLOW);
    ip_acl_add_entry(&config, "192.168.0.0/16", IP_ACL_ALLOW);

    filter_t *filter = ip_acl_filter_create(&config);
    ASSERT_NOT_NULL(filter);
    ASSERT_STR_EQ(filter->name, "ip_acl");
    ASSERT_EQ(filter->type, FILTER_TYPE_CUSTOM);

    /* Verify the config was deep-copied (modifying original shouldn't affect filter) */
    ip_acl_clear_entries(&config);
    ASSERT_NULL(config.entries);

    /* Filter should still work with its own copy */
    ASSERT_TRUE(ip_acl_check(filter, "10.1.2.3"));

    filter->callbacks.destroy(filter);
    free(filter->config);
    free(filter);
    TEST_PASS();
}

static int test_filter_create_null(void)
{
    TEST_START();

    filter_t *filter = ip_acl_filter_create(NULL);
    ASSERT_NULL(filter);

    TEST_PASS();
}

static int test_clear_entries(void)
{
    TEST_START();

    ip_acl_filter_config_t config = {0};

    ip_acl_add_entry(&config, "1.2.3.4", IP_ACL_ALLOW);
    ip_acl_add_entry(&config, "5.6.7.8", IP_ACL_DENY);
    ASSERT_NOT_NULL(config.entries);

    ip_acl_clear_entries(&config);
    ASSERT_NULL(config.entries);

    /* Clearing empty list should be safe */
    ip_acl_clear_entries(&config);
    ip_acl_clear_entries(NULL);

    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("IP ACL Filter Tests");

    RUN_TEST(test_add_entry_basic);
    RUN_TEST(test_add_entry_single_ip);
    RUN_TEST(test_add_entry_various_prefixes);
    RUN_TEST(test_add_entry_invalid);
    RUN_TEST(test_cidr_network_masking);
    RUN_TEST(test_whitelist_allow_listed);
    RUN_TEST(test_whitelist_empty);
    RUN_TEST(test_blacklist_deny_listed);
    RUN_TEST(test_blacklist_empty);
    RUN_TEST(test_first_match_wins);
    RUN_TEST(test_first_match_wins_whitelist);
    RUN_TEST(test_null_ip);
    RUN_TEST(test_null_filter);
    RUN_TEST(test_slash_zero);
    RUN_TEST(test_slash_32);
    RUN_TEST(test_filter_create_destroy);
    RUN_TEST(test_filter_create_null);
    RUN_TEST(test_clear_entries);

    TEST_END();
}
