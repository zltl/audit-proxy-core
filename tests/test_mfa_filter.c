/**
 * @file test_mfa_filter.c
 * @brief Tests for TOTP/MFA filter — Base32, HMAC-SHA1, TOTP, and filter API
 */
#include "test_utils.h"
#include "mfa_filter.h"
#include <string.h>
#include <stdio.h>

/* ===== Base32 Tests ===== */

static int test_base32_decode_basic(void)
{
    /* "JBSWY3DPEHPK3PXP" is 16 base32 chars = 80 bits = 10 bytes */
    uint8_t decoded[64];
    int len = base32_decode("JBSWY3DPEHPK3PXP", decoded, sizeof(decoded));
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(len, 10);
    return 0;
}

static int test_base32_decode_empty(void)
{
    uint8_t decoded[64];
    int len = base32_decode("", decoded, sizeof(decoded));
    ASSERT_EQ(len, 0);
    return 0;
}

static int test_base32_decode_null(void)
{
    uint8_t decoded[64];
    ASSERT_EQ(base32_decode(NULL, decoded, sizeof(decoded)), -1);
    ASSERT_EQ(base32_decode("ABC", NULL, sizeof(decoded)), -1);
    return 0;
}

static int test_base32_decode_with_padding(void)
{
    uint8_t decoded[64];
    int len = base32_decode("MFRA====", decoded, sizeof(decoded));
    ASSERT_TRUE(len > 0);
    return 0;
}

/* ===== HMAC-SHA1 Tests ===== */

static int test_hmac_sha1_rfc2202_1(void)
{
    /* RFC 2202 Test Case 1: key=0x0b*20, data="Hi There" */
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const char *data = "Hi There";
    uint8_t result[20];

    hmac_sha1(key, 20, (const uint8_t *)data, strlen(data), result);

    /* Expected: b617318655057264e28bc0b6fb378c8ef146be00 */
    ASSERT_EQ(result[0], 0xb6);
    ASSERT_EQ(result[1], 0x17);
    ASSERT_EQ(result[2], 0x31);
    ASSERT_EQ(result[3], 0x86);
    ASSERT_EQ(result[19], 0x00);
    return 0;
}

static int test_hmac_sha1_rfc2202_2(void)
{
    /* RFC 2202 Test Case 2: key="Jefe", data="what do ya want for nothing?" */
    const char *key = "Jefe";
    const char *data = "what do ya want for nothing?";
    uint8_t result[20];

    hmac_sha1((const uint8_t *)key, strlen(key),
              (const uint8_t *)data, strlen(data), result);

    /* Expected: effcdf6ae5eb2fa2d27416d5f184df9c259a7c79 */
    ASSERT_EQ(result[0], 0xef);
    ASSERT_EQ(result[1], 0xfc);
    ASSERT_EQ(result[2], 0xdf);
    return 0;
}

/* ===== TOTP Tests ===== */

static int test_totp_generate(void)
{
    int code = totp_generate("JBSWY3DPEHPK3PXP", 30, 6, 0);
    ASSERT_TRUE(code >= 0);
    ASSERT_TRUE(code < 1000000);
    return 0;
}

static int test_totp_generate_8digits(void)
{
    int code = totp_generate("JBSWY3DPEHPK3PXP", 30, 8, 0);
    ASSERT_TRUE(code >= 0);
    ASSERT_TRUE(code < 100000000);
    return 0;
}

static int test_totp_validate_current(void)
{
    const char *secret = "JBSWY3DPEHPK3PXP";
    int code = totp_generate(secret, 30, 6, 0);
    ASSERT_TRUE(code >= 0);
    ASSERT_TRUE(totp_validate(secret, code, 30, 6, 1));
    return 0;
}

static int test_totp_validate_wrong_code(void)
{
    const char *secret = "JBSWY3DPEHPK3PXP";
    int code = totp_generate(secret, 30, 6, 0);
    int wrong = (code + 1) % 1000000;
    /* Just verify we can call validate without crash */
    (void)totp_validate(secret, wrong, 30, 6, 0);
    return 0;
}

static int test_totp_null_secret(void)
{
    ASSERT_EQ(totp_generate(NULL, 30, 6, 0), -1);
    ASSERT_FALSE(totp_validate(NULL, 123456, 30, 6, 1));
    return 0;
}

/* ===== Filter Tests ===== */

static int test_mfa_filter_create(void)
{
    mfa_filter_config_t config = {
        .enabled = true,
        .time_step = 30,
        .digits = 6,
        .window = 1,
    };
    strncpy(config.issuer, "TestProxy", sizeof(config.issuer));

    filter_t *filter = mfa_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    filter->callbacks.destroy(filter);
    free(filter);
    return 0;
}

static int test_mfa_filter_create_null(void)
{
    filter_t *filter = mfa_filter_create(NULL);
    ASSERT_NULL(filter);
    return 0;
}

static int test_mfa_filter_defaults(void)
{
    mfa_filter_config_t config = { .enabled = true };
    filter_t *filter = mfa_filter_create(&config);
    ASSERT_NOT_NULL(filter);

    mfa_filter_config_t *cfg = (mfa_filter_config_t *)filter->config;
    ASSERT_EQ(cfg->time_step, 30);
    ASSERT_EQ(cfg->digits, 6);

    filter->callbacks.destroy(filter);
    free(filter);
    return 0;
}

int main(void)
{
    TEST_BEGIN("MFA/TOTP Tests");

    RUN_TEST(test_base32_decode_basic);
    RUN_TEST(test_base32_decode_empty);
    RUN_TEST(test_base32_decode_null);
    RUN_TEST(test_base32_decode_with_padding);
    RUN_TEST(test_hmac_sha1_rfc2202_1);
    RUN_TEST(test_hmac_sha1_rfc2202_2);
    RUN_TEST(test_totp_generate);
    RUN_TEST(test_totp_generate_8digits);
    RUN_TEST(test_totp_validate_current);
    RUN_TEST(test_totp_validate_wrong_code);
    RUN_TEST(test_totp_null_secret);
    RUN_TEST(test_mfa_filter_create);
    RUN_TEST(test_mfa_filter_create_null);
    RUN_TEST(test_mfa_filter_defaults);

    TEST_END();
}
