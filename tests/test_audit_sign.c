/**
 * @file test_audit_sign.c
 * @brief Tests for audit log signing — SHA-256, HMAC-SHA256, signing, verification
 */
#include "test_utils.h"
#include "audit_sign.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test log directory (created/cleaned per test) */
#define TEST_LOG_DIR "build/test_audit_sign_logs"

/* Hex key for testing (32 bytes = 64 hex chars) */
#define TEST_HEX_KEY "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

static void setup_test_dir(void)
{
    mkdir(TEST_LOG_DIR, 0755);
}

static void cleanup_test_file(const char *path)
{
    unlink(path);
}

/* ===== SHA-256 Test Vectors (NIST FIPS 180-4) ===== */

static int test_sha256_empty(void)
{
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256((const uint8_t *)"", 0, digest);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(digest, SHA256_DIGEST_SIZE, hex);
    ASSERT_STR_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    return 0;
}

static int test_sha256_abc(void)
{
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256((const uint8_t *)"abc", 3, digest);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(digest, SHA256_DIGEST_SIZE, hex);
    ASSERT_STR_EQ(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    return 0;
}

static int test_sha256_two_blocks(void)
{
    /* SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
       = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256((const uint8_t *)msg, strlen(msg), digest);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(digest, SHA256_DIGEST_SIZE, hex);
    ASSERT_STR_EQ(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    return 0;
}

static int test_sha256_incremental(void)
{
    /* Same as two_blocks but using incremental API */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    /* Feed in chunks */
    sha256_update(&ctx, (const uint8_t *)msg, 10);
    sha256_update(&ctx, (const uint8_t *)msg + 10, strlen(msg) - 10);
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, digest);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(digest, SHA256_DIGEST_SIZE, hex);
    ASSERT_STR_EQ(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    return 0;
}

/* ===== HMAC-SHA256 Test Vectors (RFC 4231) ===== */

static int test_hmac_sha256_rfc4231_1(void)
{
    /* Test Case 1: key=0x0b*20, data="Hi There" */
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const char *data = "Hi There";
    uint8_t result[SHA256_DIGEST_SIZE];

    hmac_sha256(key, 20, (const uint8_t *)data, strlen(data), result);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(result, SHA256_DIGEST_SIZE, hex);
    /* Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
    ASSERT_STR_EQ(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    return 0;
}

static int test_hmac_sha256_rfc4231_2(void)
{
    /* Test Case 2: key="Jefe", data="what do ya want for nothing?" */
    const char *key_str = "Jefe";
    const char *data = "what do ya want for nothing?";
    uint8_t result[SHA256_DIGEST_SIZE];

    hmac_sha256((const uint8_t *)key_str, strlen(key_str),
                (const uint8_t *)data, strlen(data), result);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(result, SHA256_DIGEST_SIZE, hex);
    /* Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 */
    ASSERT_STR_EQ(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    return 0;
}

static int test_hmac_sha256_rfc4231_3(void)
{
    /* Test Case 3: key=0xaa*20, data=0xdd*50 */
    uint8_t key[20];
    memset(key, 0xaa, 20);
    uint8_t data[50];
    memset(data, 0xdd, 50);
    uint8_t result[SHA256_DIGEST_SIZE];

    hmac_sha256(key, 20, data, 50, result);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(result, SHA256_DIGEST_SIZE, hex);
    /* Expected: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe */
    ASSERT_STR_EQ(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    return 0;
}

static int test_hmac_sha256_rfc4231_4(void)
{
    /* Test Case 4: key=0x01..0x19 (25 bytes), data=0xcd*50 */
    uint8_t key[25];
    for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
    uint8_t data[50];
    memset(data, 0xcd, 50);
    uint8_t result[SHA256_DIGEST_SIZE];

    hmac_sha256(key, 25, data, 50, result);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(result, SHA256_DIGEST_SIZE, hex);
    /* Expected: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b */
    ASSERT_STR_EQ(hex, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    return 0;
}

static int test_hmac_sha256_long_key(void)
{
    /* Test Case 6 (RFC 4231): key=0xaa*131, data="Test Using Larger Than Block-Size Key - Hash Key First" */
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t result[SHA256_DIGEST_SIZE];

    hmac_sha256(key, 131, (const uint8_t *)data, strlen(data), result);

    char hex[SHA256_HEX_SIZE + 1];
    hex_encode(result, SHA256_DIGEST_SIZE, hex);
    /* Expected: 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54 */
    ASSERT_STR_EQ(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    return 0;
}

/* ===== Hex utility tests ===== */

static int test_hex_encode_decode(void)
{
    uint8_t bin[] = {0xde, 0xad, 0xbe, 0xef};
    char hex[9];
    hex_encode(bin, 4, hex);
    ASSERT_STR_EQ(hex, "deadbeef");

    uint8_t decoded[4];
    int len = hex_decode("deadbeef", decoded, sizeof(decoded));
    ASSERT_EQ(len, 4);
    ASSERT_TRUE(memcmp(bin, decoded, 4) == 0);
    return 0;
}

static int test_hex_decode_null(void)
{
    uint8_t buf[4];
    ASSERT_EQ(hex_decode(NULL, buf, sizeof(buf)), -1);
    ASSERT_EQ(hex_decode("aabb", NULL, sizeof(buf)), -1);
    return 0;
}

static int test_hex_decode_odd_length(void)
{
    uint8_t buf[4];
    ASSERT_EQ(hex_decode("abc", buf, sizeof(buf)), -1);
    return 0;
}

static int test_hex_decode_invalid_chars(void)
{
    uint8_t buf[4];
    ASSERT_EQ(hex_decode("gggg", buf, sizeof(buf)), -1);
    return 0;
}

/* ===== Signing tests ===== */

static int test_sign_single_line(void)
{
    const char *json = "{\"timestamp\":\"2025-01-01\",\"type\":\"AUTH_SUCCESS\"}";
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[4096];

    int len = audit_sign_line(json, TEST_HEX_KEY, prev, 1, out, sizeof(out));
    ASSERT_TRUE(len > 0);

    /* Output should contain _prev and _hmac fields */
    ASSERT_NOT_NULL(strstr(out, "\"_prev\":\""));
    ASSERT_NOT_NULL(strstr(out, "\"_hmac\":\""));

    /* First line's _prev should be all zeros */
    char zero_hash[SHA256_HEX_SIZE + 1];
    uint8_t zero_bytes[SHA256_DIGEST_SIZE];
    memset(zero_bytes, 0, SHA256_DIGEST_SIZE);
    hex_encode(zero_bytes, SHA256_DIGEST_SIZE, zero_hash);
    ASSERT_NOT_NULL(strstr(out, zero_hash));

    return 0;
}

static int test_sign_no_chain(void)
{
    const char *json = "{\"timestamp\":\"2025-01-01\",\"type\":\"AUTH_SUCCESS\"}";
    char out[4096];

    int len = audit_sign_line(json, TEST_HEX_KEY, NULL, 0, out, sizeof(out));
    ASSERT_TRUE(len > 0);

    /* Output should have _hmac but NOT _prev */
    ASSERT_NOT_NULL(strstr(out, "\"_hmac\":\""));
    ASSERT_NULL(strstr(out, "\"_prev\":\""));
    return 0;
}

static int test_sign_null_args(void)
{
    char out[4096];
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);

    ASSERT_EQ(audit_sign_line(NULL, TEST_HEX_KEY, prev, 1, out, sizeof(out)), -1);
    ASSERT_EQ(audit_sign_line("{}", NULL, prev, 1, out, sizeof(out)), -1);
    ASSERT_EQ(audit_sign_line("{}", TEST_HEX_KEY, prev, 1, NULL, sizeof(out)), -1);
    return 0;
}

static int test_sign_empty_key(void)
{
    const char *json = "{\"test\":1}";
    char out[4096];
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);

    /* Empty string is not a valid hex key */
    ASSERT_EQ(audit_sign_line(json, "", prev, 1, out, sizeof(out)), -1);
    return 0;
}

static int test_sign_invalid_json(void)
{
    char out[4096];
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);

    /* Missing closing brace */
    ASSERT_EQ(audit_sign_line("{\"test\":1", TEST_HEX_KEY, prev, 1, out, sizeof(out)), -1);
    /* Too short */
    ASSERT_EQ(audit_sign_line("x", TEST_HEX_KEY, prev, 1, out, sizeof(out)), -1);
    return 0;
}

/* ===== Sign + Verify integration ===== */

static int test_sign_verify_single(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/verify_single.log";
    cleanup_test_file(path);

    const char *json = "{\"timestamp\":\"2025-01-01\",\"type\":\"AUTH_SUCCESS\"}";
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[4096];

    int len = audit_sign_line(json, TEST_HEX_KEY, prev, 1, out, sizeof(out));
    ASSERT_TRUE(len > 0);

    /* Write to file */
    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "%s\n", out);
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_TRUE(result > 0);
    ASSERT_EQ(result, 1);

    cleanup_test_file(path);
    return 0;
}

static int test_sign_verify_chain(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/verify_chain.log";
    cleanup_test_file(path);

    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[4096];

    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);

    const char *lines[] = {
        "{\"timestamp\":\"2025-01-01 00:00:01\",\"type\":\"CONNECT\"}",
        "{\"timestamp\":\"2025-01-01 00:00:02\",\"type\":\"AUTH_SUCCESS\"}",
        "{\"timestamp\":\"2025-01-01 00:00:03\",\"type\":\"COMMAND\",\"cmd\":\"ls\"}",
        "{\"timestamp\":\"2025-01-01 00:00:04\",\"type\":\"DISCONNECT\"}",
    };
    int n = (int)(sizeof(lines) / sizeof(lines[0]));

    for (int i = 0; i < n; i++) {
        int len = audit_sign_line(lines[i], TEST_HEX_KEY, prev, 1, out, sizeof(out));
        ASSERT_TRUE(len > 0);
        fprintf(f, "%s\n", out);
    }
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_EQ(result, n);

    cleanup_test_file(path);
    return 0;
}

static int test_detect_tampered_content(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/tampered.log";
    cleanup_test_file(path);

    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out1[4096], out2[4096];

    int len1 = audit_sign_line(
        "{\"timestamp\":\"2025-01-01\",\"type\":\"AUTH_SUCCESS\",\"user\":\"alice\"}",
        TEST_HEX_KEY, prev, 1, out1, sizeof(out1));
    ASSERT_TRUE(len1 > 0);

    int len2 = audit_sign_line(
        "{\"timestamp\":\"2025-01-01\",\"type\":\"DISCONNECT\"}",
        TEST_HEX_KEY, prev, 1, out2, sizeof(out2));
    ASSERT_TRUE(len2 > 0);

    /* Tamper with first line: change alice to bob */
    char tampered[4096];
    strncpy(tampered, out1, sizeof(tampered) - 1);
    tampered[sizeof(tampered) - 1] = '\0';
    char *alice = strstr(tampered, "alice");
    if (alice != NULL) {
        memcpy(alice, "bobby", 5);  /* same length to keep structure */
    }

    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "%s\n%s\n", tampered, out2);
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_EQ(result, -1);
    ASSERT_EQ(audit_verify_error_line, 1);

    cleanup_test_file(path);
    return 0;
}

static int test_detect_deleted_line(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/deleted.log";
    cleanup_test_file(path);

    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[3][4096];

    const char *lines[] = {
        "{\"timestamp\":\"1\",\"type\":\"CONNECT\"}",
        "{\"timestamp\":\"2\",\"type\":\"AUTH_SUCCESS\"}",
        "{\"timestamp\":\"3\",\"type\":\"DISCONNECT\"}",
    };

    for (int i = 0; i < 3; i++) {
        int len = audit_sign_line(lines[i], TEST_HEX_KEY, prev, 1,
                                  out[i], sizeof(out[i]));
        ASSERT_TRUE(len > 0);
    }

    /* Write file with middle line deleted */
    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "%s\n%s\n", out[0], out[2]); /* skip out[1] */
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_EQ(result, -1);
    /* Second line should fail chain hash check */
    ASSERT_EQ(audit_verify_error_line, 2);

    cleanup_test_file(path);
    return 0;
}

static int test_detect_inserted_line(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/inserted.log";
    cleanup_test_file(path);

    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[2][4096];

    const char *lines[] = {
        "{\"timestamp\":\"1\",\"type\":\"CONNECT\"}",
        "{\"timestamp\":\"2\",\"type\":\"DISCONNECT\"}",
    };

    for (int i = 0; i < 2; i++) {
        int len = audit_sign_line(lines[i], TEST_HEX_KEY, prev, 1,
                                  out[i], sizeof(out[i]));
        ASSERT_TRUE(len > 0);
    }

    /* Create a separately-signed "inserted" line */
    uint8_t fake_prev[SHA256_DIGEST_SIZE];
    memset(fake_prev, 0, SHA256_DIGEST_SIZE);
    /* Hash the first line to get a plausible prev for the fake line */
    sha256((const uint8_t *)out[0], strlen(out[0]), fake_prev);
    char inserted[4096];
    int ilen = audit_sign_line(
        "{\"timestamp\":\"1.5\",\"type\":\"EVIL\"}",
        TEST_HEX_KEY, fake_prev, 1, inserted, sizeof(inserted));
    ASSERT_TRUE(ilen > 0);

    /* Write: line0, inserted, line1 */
    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "%s\n%s\n%s\n", out[0], inserted, out[1]);
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_EQ(result, -1);
    /* The original line1 should fail because its _prev won't match */
    ASSERT_EQ(audit_verify_error_line, 3);

    cleanup_test_file(path);
    return 0;
}

static int test_verify_null_args(void)
{
    ASSERT_EQ(audit_verify_log(NULL, TEST_HEX_KEY), -1);
    ASSERT_EQ(audit_verify_log("nonexistent.log", TEST_HEX_KEY), -1);
    ASSERT_EQ(audit_verify_log("nonexistent.log", NULL), -1);
    return 0;
}

static int test_verify_invalid_key(void)
{
    ASSERT_EQ(audit_verify_log("nonexistent.log", "zzzz"), -1);
    ASSERT_EQ(audit_verify_log("nonexistent.log", ""), -1);
    return 0;
}

static int test_verify_empty_file(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/empty.log";
    cleanup_test_file(path);

    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fclose(f);

    int result = audit_verify_log(path, TEST_HEX_KEY);
    /* Empty file has 0 lines verified */
    ASSERT_EQ(result, 0);

    cleanup_test_file(path);
    return 0;
}

static int test_sign_verify_no_chain(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/no_chain.log";
    cleanup_test_file(path);

    char out[4096];
    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);

    const char *lines[] = {
        "{\"timestamp\":\"1\",\"type\":\"CONNECT\"}",
        "{\"timestamp\":\"2\",\"type\":\"DISCONNECT\"}",
    };

    for (int i = 0; i < 2; i++) {
        int len = audit_sign_line(lines[i], TEST_HEX_KEY, NULL, 0,
                                  out, sizeof(out));
        ASSERT_TRUE(len > 0);
        fprintf(f, "%s\n", out);
    }
    fclose(f);

    /* Should still verify HMACs even without chain */
    int result = audit_verify_log(path, TEST_HEX_KEY);
    ASSERT_EQ(result, 2);

    cleanup_test_file(path);
    return 0;
}

static int test_verify_wrong_key(void)
{
    setup_test_dir();
    const char *path = TEST_LOG_DIR "/wrong_key.log";
    cleanup_test_file(path);

    const char *json = "{\"timestamp\":\"2025-01-01\",\"type\":\"AUTH_SUCCESS\"}";
    uint8_t prev[SHA256_DIGEST_SIZE];
    memset(prev, 0, SHA256_DIGEST_SIZE);
    char out[4096];

    int len = audit_sign_line(json, TEST_HEX_KEY, prev, 1, out, sizeof(out));
    ASSERT_TRUE(len > 0);

    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "%s\n", out);
    fclose(f);

    /* Verify with a different key should fail */
    const char *wrong_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    int result = audit_verify_log(path, wrong_key);
    ASSERT_EQ(result, -1);

    cleanup_test_file(path);
    return 0;
}

int main(void)
{
    TEST_BEGIN("Audit Signing Tests");

    /* SHA-256 */
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_two_blocks);
    RUN_TEST(test_sha256_incremental);

    /* HMAC-SHA256 */
    RUN_TEST(test_hmac_sha256_rfc4231_1);
    RUN_TEST(test_hmac_sha256_rfc4231_2);
    RUN_TEST(test_hmac_sha256_rfc4231_3);
    RUN_TEST(test_hmac_sha256_rfc4231_4);
    RUN_TEST(test_hmac_sha256_long_key);

    /* Hex utilities */
    RUN_TEST(test_hex_encode_decode);
    RUN_TEST(test_hex_decode_null);
    RUN_TEST(test_hex_decode_odd_length);
    RUN_TEST(test_hex_decode_invalid_chars);

    /* Signing */
    RUN_TEST(test_sign_single_line);
    RUN_TEST(test_sign_no_chain);
    RUN_TEST(test_sign_null_args);
    RUN_TEST(test_sign_empty_key);
    RUN_TEST(test_sign_invalid_json);

    /* Sign + Verify integration */
    RUN_TEST(test_sign_verify_single);
    RUN_TEST(test_sign_verify_chain);
    RUN_TEST(test_detect_tampered_content);
    RUN_TEST(test_detect_deleted_line);
    RUN_TEST(test_detect_inserted_line);
    RUN_TEST(test_verify_null_args);
    RUN_TEST(test_verify_invalid_key);
    RUN_TEST(test_verify_empty_file);
    RUN_TEST(test_sign_verify_no_chain);
    RUN_TEST(test_verify_wrong_key);

    TEST_END();
}
