/**
 * @file test_ldap_auth.c
 * @brief Unit tests for LDAP authentication (URI parsing, BER encoding, TLS mode)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth_filter.h"
#include "logger.h"
#include "test_utils.h"

/* ── URI parsing tests ──────────────────────────────────────────────── */

static int test_parse_ldap_uri_plain(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldap://example.com", host, sizeof(host),
                             &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "example.com");
    ASSERT_EQ(port, 389);
    ASSERT_EQ(tls_mode, LDAP_TLS_NONE);
    TEST_PASS();
}

static int test_parse_ldap_uri_plain_with_port(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldap://ldap.example.com:3389", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "ldap.example.com");
    ASSERT_EQ(port, 3389);
    ASSERT_EQ(tls_mode, LDAP_TLS_NONE);
    TEST_PASS();
}

static int test_parse_ldaps_uri(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldaps://secure.example.com", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "secure.example.com");
    ASSERT_EQ(port, 636);
    ASSERT_EQ(tls_mode, LDAP_TLS_LDAPS);
    TEST_PASS();
}

static int test_parse_ldaps_uri_with_port(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldaps://secure.example.com:636", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "secure.example.com");
    ASSERT_EQ(port, 636);
    ASSERT_EQ(tls_mode, LDAP_TLS_LDAPS);
    TEST_PASS();
}

static int test_parse_ldaps_uri_custom_port(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldaps://host:6360", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "host");
    ASSERT_EQ(port, 6360);
    ASSERT_EQ(tls_mode, LDAP_TLS_LDAPS);
    TEST_PASS();
}

static int test_parse_ldap_uri_with_slash(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldap://example.com/dc=example,dc=com", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "example.com");
    ASSERT_EQ(port, 389);
    ASSERT_EQ(tls_mode, LDAP_TLS_NONE);
    TEST_PASS();
}

static int test_parse_ldap_uri_null(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri(NULL, host, sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, -1);
    TEST_PASS();
}

static int test_parse_ldap_uri_host_too_long(void)
{
    char host[4]; /* Intentionally small */
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("ldap://toolong.example.com", host,
                             sizeof(host), &port, &tls_mode);
    ASSERT_EQ(rc, -1);
    TEST_PASS();
}

static int test_parse_ldap_uri_no_scheme(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    int rc = parse_ldap_uri("myhost:1389", host, sizeof(host),
                             &port, &tls_mode);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(host, "myhost");
    ASSERT_EQ(port, 1389);
    ASSERT_EQ(tls_mode, LDAP_TLS_NONE);
    TEST_PASS();
}

/* ── TLS mode detection tests ──────────────────────────────────────── */

static int test_tls_mode_none_for_ldap(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    parse_ldap_uri("ldap://host", host, sizeof(host), &port, &tls_mode);
    ASSERT_EQ(tls_mode, LDAP_TLS_NONE);
    TEST_PASS();
}

static int test_tls_mode_ldaps(void)
{
    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;

    parse_ldap_uri("ldaps://host", host, sizeof(host), &port, &tls_mode);
    ASSERT_EQ(tls_mode, LDAP_TLS_LDAPS);
    TEST_PASS();
}

/* ── StartTLS Extended Request building ─────────────────────────────── */

static int test_build_starttls_request_basic(void)
{
    uint8_t buf[256];
    size_t len = build_starttls_request(buf, sizeof(buf), 1);

    /* Must produce output */
    ASSERT_TRUE(len > 0);

    /* Outer envelope: SEQUENCE tag */
    ASSERT_EQ(buf[0], 0x30);

    TEST_PASS();
}

static int test_build_starttls_request_contains_oid(void)
{
    uint8_t buf[256];
    size_t len = build_starttls_request(buf, sizeof(buf), 1);
    ASSERT_TRUE(len > 0);

    /* The OID "1.3.6.1.4.1.1466.20037" must appear in the buffer */
    const char *oid = "1.3.6.1.4.1.1466.20037";
    size_t oid_len = strlen(oid);
    int found = 0;
    for (size_t i = 0; i + oid_len <= len; i++) {
        if (memcmp(buf + i, oid, oid_len) == 0) {
            found = 1;
            break;
        }
    }
    ASSERT_TRUE(found);
    TEST_PASS();
}

static int test_build_starttls_request_structure(void)
{
    uint8_t buf[256];
    size_t len = build_starttls_request(buf, sizeof(buf), 1);
    ASSERT_TRUE(len > 0);

    /*
     * Expected structure (message ID = 1):
     * 30 xx                -- SEQUENCE
     *   02 01 01           -- INTEGER 1 (messageID)
     *   77 yy              -- [APPLICATION 23] ExtendedRequest
     *     80 zz OID...     -- [0] requestName
     */

    size_t pos = 0;
    ASSERT_EQ(buf[pos], 0x30); /* SEQUENCE */
    pos++;
    /* Skip SEQUENCE length */
    if (buf[pos] < 0x80) {
        pos++;
    } else {
        pos += 1 + (buf[pos] & 0x7F);
    }

    /* INTEGER tag for messageID */
    ASSERT_EQ(buf[pos], 0x02);
    pos++;
    ASSERT_EQ(buf[pos], 0x01); /* length = 1 */
    pos++;
    ASSERT_EQ(buf[pos], 0x01); /* value = 1 */
    pos++;

    /* ExtendedRequest APPLICATION 23 */
    ASSERT_EQ(buf[pos], 0x77);
    pos++;
    /* Skip ExtendedRequest length */
    if (buf[pos] < 0x80) {
        pos++;
    } else {
        pos += 1 + (buf[pos] & 0x7F);
    }

    /* requestName [0] (context-specific, primitive) */
    ASSERT_EQ(buf[pos], 0x80);
    pos++;

    /* OID length */
    size_t oid_len = strlen("1.3.6.1.4.1.1466.20037");
    ASSERT_EQ(buf[pos], (uint8_t)oid_len);
    pos++;

    /* OID value */
    ASSERT_TRUE(pos + oid_len <= len);
    ASSERT_TRUE(memcmp(buf + pos, "1.3.6.1.4.1.1466.20037", oid_len) == 0);

    TEST_PASS();
}

static int test_build_starttls_request_buffer_too_small(void)
{
    uint8_t buf[2]; /* Way too small */
    size_t len = build_starttls_request(buf, sizeof(buf), 1);
    ASSERT_EQ(len, 0);
    TEST_PASS();
}

static int test_build_starttls_request_msg_id(void)
{
    uint8_t buf1[256], buf2[256];
    size_t len1 = build_starttls_request(buf1, sizeof(buf1), 1);
    size_t len2 = build_starttls_request(buf2, sizeof(buf2), 5);

    ASSERT_TRUE(len1 > 0);
    ASSERT_TRUE(len2 > 0);

    /* Different message IDs should produce different output */
    ASSERT_TRUE(memcmp(buf1, buf2, len1 < len2 ? len1 : len2) != 0);

    TEST_PASS();
}

/* ── Extended Response parsing ──────────────────────────────────────── */

/*
 * Build a minimal ExtendedResponse for testing.
 * Structure:
 *   SEQUENCE {
 *     INTEGER messageID,
 *     [APPLICATION 24] {
 *       ENUMERATED resultCode,
 *       OCTET STRING "" (matchedDN),
 *       OCTET STRING "" (diagnosticMessage)
 *     }
 *   }
 */
static size_t build_test_extended_response(uint8_t *buf, int msg_id,
                                            int result_code)
{
    size_t pos = 0;

    /* We'll build inner-out, then wrap in SEQUENCE */

    /* ExtendedResponse content */
    uint8_t resp_content[64];
    size_t rc_pos = 0;

    /* ENUMERATED result code */
    resp_content[rc_pos++] = 0x0a; /* ENUMERATED tag */
    resp_content[rc_pos++] = 0x01; /* length 1 */
    resp_content[rc_pos++] = (uint8_t)result_code;

    /* matchedDN: OCTET STRING "" */
    resp_content[rc_pos++] = 0x04;
    resp_content[rc_pos++] = 0x00;

    /* diagnosticMessage: OCTET STRING "" */
    resp_content[rc_pos++] = 0x04;
    resp_content[rc_pos++] = 0x00;

    /* ExtendedResponse [APPLICATION 24] wrapper */
    uint8_t ext_resp[128];
    size_t ext_pos = 0;
    ext_resp[ext_pos++] = 0x78; /* APPLICATION 24 */
    ext_resp[ext_pos++] = (uint8_t)rc_pos;
    memcpy(ext_resp + ext_pos, resp_content, rc_pos);
    ext_pos += rc_pos;

    /* Message ID */
    uint8_t id_buf[8];
    size_t id_pos = 0;
    id_buf[id_pos++] = 0x02; /* INTEGER */
    id_buf[id_pos++] = 0x01;
    id_buf[id_pos++] = (uint8_t)msg_id;

    /* SEQUENCE envelope */
    size_t content_len = id_pos + ext_pos;
    buf[pos++] = 0x30;
    buf[pos++] = (uint8_t)content_len;
    memcpy(buf + pos, id_buf, id_pos);
    pos += id_pos;
    memcpy(buf + pos, ext_resp, ext_pos);
    pos += ext_pos;

    return pos;
}

static int test_parse_extended_response_success(void)
{
    uint8_t buf[128];
    size_t len = build_test_extended_response(buf, 1, 0);
    ASSERT_TRUE(len > 0);

    int rc = parse_extended_response(buf, len);
    ASSERT_EQ(rc, 0); /* LDAP_SUCCESS */
    TEST_PASS();
}

static int test_parse_extended_response_failure(void)
{
    uint8_t buf[128];
    size_t len = build_test_extended_response(buf, 1, 49); /* 49 = invalidCredentials */
    ASSERT_TRUE(len > 0);

    int rc = parse_extended_response(buf, len);
    ASSERT_EQ(rc, 49);
    TEST_PASS();
}

static int test_parse_extended_response_operations_error(void)
{
    uint8_t buf[128];
    size_t len = build_test_extended_response(buf, 1, 1); /* 1 = operationsError */
    ASSERT_TRUE(len > 0);

    int rc = parse_extended_response(buf, len);
    ASSERT_EQ(rc, 1);
    TEST_PASS();
}

static int test_parse_extended_response_empty(void)
{
    int rc = parse_extended_response(NULL, 0);
    ASSERT_EQ(rc, -1);
    TEST_PASS();
}

static int test_parse_extended_response_truncated(void)
{
    uint8_t buf[128];
    size_t len = build_test_extended_response(buf, 1, 0);
    ASSERT_TRUE(len > 0);

    /* Truncate the buffer */
    int rc = parse_extended_response(buf, 3);
    ASSERT_EQ(rc, -1);
    TEST_PASS();
}

static int test_parse_extended_response_wrong_tag(void)
{
    /* Build something that looks like a BindResponse (0x61) not ExtendedResponse */
    uint8_t buf[] = {
        0x30, 0x0c,       /* SEQUENCE length 12 */
        0x02, 0x01, 0x01, /* INTEGER 1 */
        0x61, 0x07,       /* BindResponse [APPLICATION 1] */
        0x0a, 0x01, 0x00, /* ENUMERATED 0 */
        0x04, 0x00,       /* matchedDN "" */
        0x04, 0x00        /* diagnosticMessage "" */
    };

    int rc = parse_extended_response(buf, sizeof(buf));
    ASSERT_EQ(rc, -1); /* Should fail - wrong APPLICATION tag */
    TEST_PASS();
}

/* ── Backward compatibility ─────────────────────────────────────────── */

static int test_ldap_simple_bind_null_args(void)
{
    /* ldap_simple_bind should handle NULL gracefully */
    auth_result_t r1 = ldap_simple_bind(NULL, "dn", "pw", 5);
    ASSERT_EQ(r1, AUTH_RESULT_FAILURE);

    auth_result_t r2 = ldap_simple_bind("ldap://host", NULL, "pw", 5);
    ASSERT_EQ(r2, AUTH_RESULT_FAILURE);

    auth_result_t r3 = ldap_simple_bind("ldap://host", "dn", NULL, 5);
    ASSERT_EQ(r3, AUTH_RESULT_FAILURE);

    TEST_PASS();
}

static int test_ldap_simple_bind_tls_null_args(void)
{
    auth_result_t r1 = ldap_simple_bind_tls(NULL, "dn", "pw", 5,
                                              false, true, NULL);
    ASSERT_EQ(r1, AUTH_RESULT_FAILURE);

    auth_result_t r2 = ldap_simple_bind_tls("ldap://host", NULL, "pw", 5,
                                              false, true, NULL);
    ASSERT_EQ(r2, AUTH_RESULT_FAILURE);

    TEST_PASS();
}

static int test_tls_mode_enum_values(void)
{
    /* Verify enum has expected values */
    ASSERT_EQ(LDAP_TLS_NONE, 0);
    ASSERT_TRUE(LDAP_TLS_LDAPS != LDAP_TLS_NONE);
    ASSERT_TRUE(LDAP_TLS_STARTTLS != LDAP_TLS_NONE);
    ASSERT_TRUE(LDAP_TLS_STARTTLS != LDAP_TLS_LDAPS);
    TEST_PASS();
}

static int test_config_struct_tls_fields(void)
{
    /* Verify the new TLS fields exist and can be set */
    auth_filter_config_t config;
    memset(&config, 0, sizeof(config));

    config.ldap_starttls = true;
    config.ldap_ca_path = "/path/to/ca.pem";
    config.ldap_verify_cert = true;

    ASSERT_TRUE(config.ldap_starttls);
    ASSERT_STR_EQ(config.ldap_ca_path, "/path/to/ca.pem");
    ASSERT_TRUE(config.ldap_verify_cert);

    /* Verify defaults from zero-init */
    auth_filter_config_t config2;
    memset(&config2, 0, sizeof(config2));
    ASSERT_FALSE(config2.ldap_starttls);
    ASSERT_NULL(config2.ldap_ca_path);
    ASSERT_FALSE(config2.ldap_verify_cert);

    TEST_PASS();
}

/* ── Main ───────────────────────────────────────────────────────────── */

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);

    TEST_BEGIN("LDAP Auth Tests");

    /* URI parsing */
    RUN_TEST(test_parse_ldap_uri_plain);
    RUN_TEST(test_parse_ldap_uri_plain_with_port);
    RUN_TEST(test_parse_ldaps_uri);
    RUN_TEST(test_parse_ldaps_uri_with_port);
    RUN_TEST(test_parse_ldaps_uri_custom_port);
    RUN_TEST(test_parse_ldap_uri_with_slash);
    RUN_TEST(test_parse_ldap_uri_null);
    RUN_TEST(test_parse_ldap_uri_host_too_long);
    RUN_TEST(test_parse_ldap_uri_no_scheme);

    /* TLS mode detection */
    RUN_TEST(test_tls_mode_none_for_ldap);
    RUN_TEST(test_tls_mode_ldaps);
    RUN_TEST(test_tls_mode_enum_values);

    /* StartTLS request building */
    RUN_TEST(test_build_starttls_request_basic);
    RUN_TEST(test_build_starttls_request_contains_oid);
    RUN_TEST(test_build_starttls_request_structure);
    RUN_TEST(test_build_starttls_request_buffer_too_small);
    RUN_TEST(test_build_starttls_request_msg_id);

    /* Extended response parsing */
    RUN_TEST(test_parse_extended_response_success);
    RUN_TEST(test_parse_extended_response_failure);
    RUN_TEST(test_parse_extended_response_operations_error);
    RUN_TEST(test_parse_extended_response_empty);
    RUN_TEST(test_parse_extended_response_truncated);
    RUN_TEST(test_parse_extended_response_wrong_tag);

    /* Backward compatibility / NULL handling */
    RUN_TEST(test_ldap_simple_bind_null_args);
    RUN_TEST(test_ldap_simple_bind_tls_null_args);

    /* Config struct fields */
    RUN_TEST(test_config_struct_tls_fields);

    log_shutdown();
    TEST_END();
}
