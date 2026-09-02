/**
 * @file ssh_cert.c
 * @brief Minimal OpenSSH user-certificate validation helpers.
 */

#include "ssh_cert.h"
#include "ip_cidr.h"
#include "logger.h"

#include <errno.h>
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SSH_CERT_TYPE_USER 1U
#define SSH_CERT_TIME_INFINITY UINT64_MAX

typedef struct {
    const char *type;
    uint8_t *blob;
    size_t blob_len;
} key_line_t;

typedef struct {
    const uint8_t *signature_key_blob;
    size_t signature_key_blob_len;
    const uint8_t *signed_data;
    size_t signed_data_len;
    const uint8_t *signature_blob;
    size_t signature_blob_len;
    uint64_t serial;
    uint64_t valid_after;
    uint64_t valid_before;
    bool principal_matches;
    char *source_addresses;
} parsed_cert_t;

typedef enum {
    REVOCATION_CHECK_OK = 0,
    REVOCATION_CHECK_REVOKED,
    REVOCATION_CHECK_INVALID
} revocation_check_result_t;

static bool is_key_type_token(const char *token)
{
    return token != NULL &&
           (strncmp(token, "ssh-", 4) == 0 || strncmp(token, "ecdsa-", 6) == 0 ||
            strncmp(token, "sk-", 3) == 0 || strncmp(token, "rsa-sha2-", 10) == 0);
}

static int parse_key_line(const char *line, key_line_t *out)
{
    char *copy = NULL;
    char *saveptr = NULL;
    char *token = NULL;
    char *type = NULL;
    char *b64 = NULL;

    if (line == NULL || out == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    copy = strdup(line);
    if (copy == NULL) {
        return -1;
    }

    for (token = strtok_r(copy, " \t\r\n", &saveptr); token != NULL;
         token = strtok_r(NULL, " \t\r\n", &saveptr)) {
        if (*token == '#') {
            break;
        }
        if (!is_key_type_token(token)) {
            continue;
        }

        type = token;
        b64 = strtok_r(NULL, " \t\r\n", &saveptr);
        break;
    }

    if (type == NULL || b64 == NULL) {
        free(copy);
        return -1;
    }

    out->type = strdup(type);
    if (out->type == NULL) {
        free(copy);
        return -1;
    }

    size_t b64_len = strlen(b64);
    size_t max_len = ((b64_len + 3U) / 4U) * 3U + 1U;
    out->blob = malloc(max_len);
    if (out->blob == NULL) {
        free((char *)out->type);
        free(copy);
        return -1;
    }

    int decoded = EVP_DecodeBlock(out->blob, (const unsigned char *)b64, (int)b64_len);
    if (decoded < 0) {
        free((char *)out->type);
        free(out->blob);
        free(copy);
        return -1;
    }

    out->blob_len = (size_t)decoded;
    while (b64_len > 0 && b64[b64_len - 1] == '=') {
        out->blob_len--;
        b64_len--;
    }

    free(copy);
    return 0;
}

static void free_key_line(key_line_t *line)
{
    if (line == NULL) {
        return;
    }

    free((char *)line->type);
    free(line->blob);
    memset(line, 0, sizeof(*line));
}

static bool parse_u32(const uint8_t **cursor, size_t *remaining, uint32_t *out)
{
    if (cursor == NULL || *cursor == NULL || remaining == NULL || out == NULL || *remaining < 4) {
        return false;
    }

    *out = ((uint32_t)(*cursor)[0] << 24) | ((uint32_t)(*cursor)[1] << 16) |
           ((uint32_t)(*cursor)[2] << 8) | (uint32_t)(*cursor)[3];
    *cursor += 4;
    *remaining -= 4;
    return true;
}

static bool parse_u64(const uint8_t **cursor, size_t *remaining, uint64_t *out)
{
    if (cursor == NULL || *cursor == NULL || remaining == NULL || out == NULL || *remaining < 8) {
        return false;
    }

    *out = ((uint64_t)(*cursor)[0] << 56) | ((uint64_t)(*cursor)[1] << 48) |
           ((uint64_t)(*cursor)[2] << 40) | ((uint64_t)(*cursor)[3] << 32) |
           ((uint64_t)(*cursor)[4] << 24) | ((uint64_t)(*cursor)[5] << 16) |
           ((uint64_t)(*cursor)[6] << 8) | (uint64_t)(*cursor)[7];
    *cursor += 8;
    *remaining -= 8;
    return true;
}

static bool parse_string(const uint8_t **cursor, size_t *remaining, const uint8_t **out,
                         size_t *out_len)
{
    uint32_t len = 0;

    if (cursor == NULL || *cursor == NULL || remaining == NULL || out == NULL || out_len == NULL) {
        return false;
    }

    if (!parse_u32(cursor, remaining, &len) || *remaining < (size_t)len) {
        return false;
    }

    *out = *cursor;
    *out_len = (size_t)len;
    *cursor += len;
    *remaining -= len;
    return true;
}

static bool skip_string(const uint8_t **cursor, size_t *remaining)
{
    const uint8_t *value = NULL;
    size_t value_len = 0;
    return parse_string(cursor, remaining, &value, &value_len);
}

static bool skip_cert_key_fields(const char *cert_type, const uint8_t **cursor, size_t *remaining)
{
    if (cert_type == NULL || cursor == NULL || remaining == NULL) {
        return false;
    }

    if (strcmp(cert_type, "ssh-ed25519-cert-v01@openssh.com") == 0) {
        return skip_string(cursor, remaining);
    }
    if (strcmp(cert_type, "ssh-rsa-cert-v01@openssh.com") == 0) {
        return skip_string(cursor, remaining) && skip_string(cursor, remaining);
    }
    if (strcmp(cert_type, "ecdsa-sha2-nistp256-cert-v01@openssh.com") == 0 ||
        strcmp(cert_type, "ecdsa-sha2-nistp384-cert-v01@openssh.com") == 0 ||
        strcmp(cert_type, "ecdsa-sha2-nistp521-cert-v01@openssh.com") == 0) {
        return skip_string(cursor, remaining) && skip_string(cursor, remaining);
    }

    LOG_WARN("SSH cert auth: unsupported certificate key type '%s'", cert_type);
    return false;
}

static bool principal_matches_username(const uint8_t *blob, size_t blob_len, const char *username)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;
    bool saw_principal = false;

    if (username == NULL) {
        return false;
    }

    while (remaining > 0) {
        const uint8_t *principal = NULL;
        size_t principal_len = 0;
        if (!parse_string(&cursor, &remaining, &principal, &principal_len)) {
            return false;
        }
        saw_principal = true;
        if (principal_len == strlen(username) &&
            memcmp(principal, username, principal_len) == 0) {
            return true;
        }
    }

    return !saw_principal;
}

static char *decode_option_value(const uint8_t *blob, size_t blob_len)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;
    const uint8_t *value = NULL;
    size_t value_len = 0;
    char *out = NULL;

    if (!parse_string(&cursor, &remaining, &value, &value_len) || remaining != 0) {
        return NULL;
    }

    out = calloc(1, value_len + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, value, value_len);
    return out;
}

static ssh_cert_eval_result_t parse_critical_options(const uint8_t *blob, size_t blob_len,
                                                     char **source_addresses_out)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;

    while (remaining > 0) {
        const uint8_t *key = NULL;
        const uint8_t *value = NULL;
        size_t key_len = 0;
        size_t value_len = 0;
        char key_buf[64];

        if (!parse_string(&cursor, &remaining, &key, &key_len) ||
            !parse_string(&cursor, &remaining, &value, &value_len)) {
            LOG_WARN("SSH cert auth: malformed critical options");
            return SSH_CERT_EVAL_FAILURE;
        }

        if (key_len == 0 || key_len >= sizeof(key_buf)) {
            LOG_WARN("SSH cert auth: invalid critical option name");
            return SSH_CERT_EVAL_FAILURE;
        }

        memcpy(key_buf, key, key_len);
        key_buf[key_len] = '\0';

        if (strcmp(key_buf, "source-address") == 0) {
            if (*source_addresses_out != NULL) {
                LOG_WARN("SSH cert auth denied: duplicate source-address critical option");
                return SSH_CERT_EVAL_DENIED;
            }
            *source_addresses_out = decode_option_value(value, value_len);
            if (*source_addresses_out == NULL) {
                LOG_WARN("SSH cert auth: invalid source-address critical option");
                return SSH_CERT_EVAL_FAILURE;
            }
            continue;
        }

        LOG_WARN("SSH cert auth denied: unsupported critical option '%s'", key_buf);
        return SSH_CERT_EVAL_DENIED;
    }

    return SSH_CERT_EVAL_SUCCESS;
}

static bool parse_signature_blob(const uint8_t *blob, size_t blob_len, const uint8_t **format,
                                 size_t *format_len, const uint8_t **sig, size_t *sig_len)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;

    return parse_string(&cursor, &remaining, format, format_len) &&
           parse_string(&cursor, &remaining, sig, sig_len) && remaining == 0;
}

static bool parse_certificate_blob(const key_line_t *line, const char *username, parsed_cert_t *out)
{
    const uint8_t *cursor = NULL;
    size_t remaining = 0;
    const uint8_t *value = NULL;
    size_t value_len = 0;
    char *source_addresses = NULL;
    uint64_t serial = 0;
    uint32_t cert_type = 0;
    uint64_t valid_after = 0;
    uint64_t valid_before = 0;
    size_t signed_data_len = 0;
    ssh_cert_eval_result_t opt_result = SSH_CERT_EVAL_FAILURE;

    if (line == NULL || line->blob == NULL || out == NULL) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    cursor = line->blob;
    remaining = line->blob_len;

    if (!parse_string(&cursor, &remaining, &value, &value_len)) {
        LOG_WARN("SSH cert auth: malformed certificate key type");
        return false;
    }
    if (strlen(line->type) != value_len || memcmp(value, line->type, value_len) != 0) {
        LOG_WARN("SSH cert auth: certificate type mismatch");
        return false;
    }

    if (!skip_string(&cursor, &remaining) || !skip_cert_key_fields(line->type, &cursor, &remaining) ||
        !parse_u64(&cursor, &remaining, &serial) ||
        !parse_u32(&cursor, &remaining, &cert_type) || !skip_string(&cursor, &remaining) ||
        !parse_string(&cursor, &remaining, &value, &value_len)) {
        LOG_WARN("SSH cert auth: malformed certificate header");
        return false;
    }

    if (cert_type != SSH_CERT_TYPE_USER) {
        LOG_WARN("SSH cert auth: non-user certificate presented");
        return false;
    }

    out->principal_matches = principal_matches_username(value, value_len, username);

    if (!parse_u64(&cursor, &remaining, &valid_after) ||
        !parse_u64(&cursor, &remaining, &valid_before) ||
        !parse_string(&cursor, &remaining, &value, &value_len)) {
        LOG_WARN("SSH cert auth: malformed certificate validity");
        return false;
    }

    opt_result = parse_critical_options(value, value_len, &source_addresses);
    if (opt_result == SSH_CERT_EVAL_FAILURE) {
        return false;
    }
    if (opt_result == SSH_CERT_EVAL_DENIED) {
        out->source_addresses = source_addresses;
        out->serial = serial;
        out->valid_after = valid_after;
        out->valid_before = valid_before;
        out->principal_matches = false;
        out->signature_key_blob = NULL;
        return true;
    }

    if (!skip_string(&cursor, &remaining) || !skip_string(&cursor, &remaining)) {
        free(source_addresses);
        LOG_WARN("SSH cert auth: malformed certificate extensions/reserved field");
        return false;
    }

    if (!parse_string(&cursor, &remaining, &out->signature_key_blob, &out->signature_key_blob_len)) {
        free(source_addresses);
        LOG_WARN("SSH cert auth: malformed certificate signature key");
        return false;
    }

    signed_data_len = (size_t)(cursor - line->blob);
    if (!parse_string(&cursor, &remaining, &out->signature_blob, &out->signature_blob_len) ||
        remaining != 0) {
        free(source_addresses);
        LOG_WARN("SSH cert auth: malformed certificate signature");
        return false;
    }

    out->signed_data = line->blob;
    out->signed_data_len = signed_data_len;
    out->serial = serial;
    out->valid_after = valid_after;
    out->valid_before = valid_before;
    out->source_addresses = source_addresses;
    return true;
}

static void free_parsed_cert(parsed_cert_t *cert)
{
    if (cert == NULL) {
        return;
    }
    free(cert->source_addresses);
    memset(cert, 0, sizeof(*cert));
}

static const char *curve_name_for_ssh(const char *type)
{
    if (strcmp(type, "ecdsa-sha2-nistp256") == 0) {
        return "prime256v1";
    }
    if (strcmp(type, "ecdsa-sha2-nistp384") == 0) {
        return "secp384r1";
    }
    if (strcmp(type, "ecdsa-sha2-nistp521") == 0) {
        return "secp521r1";
    }
    return NULL;
}

static BIGNUM *mpint_to_bn(const uint8_t *blob, size_t blob_len)
{
    BIGNUM *bn = NULL;
    size_t offset = 0;

    if (blob == NULL) {
        return NULL;
    }
    if (blob_len == 0) {
        bn = BN_new();
        if (bn != NULL) {
            BN_zero(bn);
        }
        return bn;
    }

    if ((blob[0] & 0x80U) != 0U) {
        return NULL;
    }

    while (offset < blob_len && blob[offset] == 0) {
        offset++;
    }
    if (offset == blob_len) {
        bn = BN_new();
        if (bn != NULL) {
            BN_zero(bn);
        }
        return bn;
    }

    return BN_bin2bn(blob + offset, (int)(blob_len - offset), NULL);
}

static EVP_PKEY *build_rsa_public_key(const uint8_t *e_blob, size_t e_len, const uint8_t *n_blob,
                                      size_t n_len)
{
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    e = mpint_to_bn(e_blob, e_len);
    n = mpint_to_bn(n_blob, n_len);
    if (e == NULL || n == NULL) {
        goto cleanup;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n)) {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(e);
    BN_free(n);
    return pkey;
}

static EVP_PKEY *build_ec_public_key(const char *group_name, const uint8_t *point, size_t point_len)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (group_name == NULL || point == NULL || point_len == 0) {
        return NULL;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                                        group_name, 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, point_len)) {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

static EVP_PKEY *build_public_key_from_blob(const uint8_t *blob, size_t blob_len)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;
    const uint8_t *type = NULL;
    const uint8_t *field1 = NULL;
    const uint8_t *field2 = NULL;
    size_t type_len = 0;
    size_t field1_len = 0;
    size_t field2_len = 0;
    char type_buf[64];

    if (!parse_string(&cursor, &remaining, &type, &type_len) || type_len == 0 ||
        type_len >= sizeof(type_buf)) {
        return NULL;
    }

    memcpy(type_buf, type, type_len);
    type_buf[type_len] = '\0';

    if (strcmp(type_buf, "ssh-ed25519") == 0) {
        if (!parse_string(&cursor, &remaining, &field1, &field1_len) || remaining != 0) {
            return NULL;
        }
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, field1, field1_len);
    }

    if (strcmp(type_buf, "ssh-rsa") == 0) {
        if (!parse_string(&cursor, &remaining, &field1, &field1_len) ||
            !parse_string(&cursor, &remaining, &field2, &field2_len) || remaining != 0) {
            return NULL;
        }
        return build_rsa_public_key(field1, field1_len, field2, field2_len);
    }

    if (strncmp(type_buf, "ecdsa-sha2-", 11) == 0) {
        const char *group_name = curve_name_for_ssh(type_buf);
        if (!parse_string(&cursor, &remaining, &field1, &field1_len) ||
            !parse_string(&cursor, &remaining, &field2, &field2_len) || remaining != 0 ||
            field1_len != strlen(type_buf + 11) ||
            memcmp(field1, type_buf + 11, field1_len) != 0) {
            return NULL;
        }
        return build_ec_public_key(group_name, field2, field2_len);
    }

    return NULL;
}

static bool parse_ssh_mpint_pair(const uint8_t *blob, size_t blob_len, BIGNUM **r_out, BIGNUM **s_out)
{
    const uint8_t *cursor = blob;
    size_t remaining = blob_len;
    const uint8_t *r_blob = NULL;
    const uint8_t *s_blob = NULL;
    size_t r_len = 0;
    size_t s_len = 0;

    if (r_out == NULL || s_out == NULL) {
        return false;
    }

    if (!parse_string(&cursor, &remaining, &r_blob, &r_len) ||
        !parse_string(&cursor, &remaining, &s_blob, &s_len) || remaining != 0) {
        return false;
    }

    *r_out = mpint_to_bn(r_blob, r_len);
    *s_out = mpint_to_bn(s_blob, s_len);
    return *r_out != NULL && *s_out != NULL;
}

static bool convert_ecdsa_signature_to_der(const uint8_t *blob, size_t blob_len, uint8_t **out,
                                           size_t *out_len)
{
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    ECDSA_SIG *sig = NULL;
    uint8_t *der = NULL;
    unsigned char *der_cursor = NULL;
    int len = 0;

    if (out == NULL || out_len == NULL) {
        return false;
    }
    *out = NULL;
    *out_len = 0;

    if (!parse_ssh_mpint_pair(blob, blob_len, &r, &s)) {
        BN_free(r);
        BN_free(s);
        return false;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL || ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return false;
    }
    r = NULL;
    s = NULL;

    len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        ECDSA_SIG_free(sig);
        return false;
    }

    der = malloc((size_t)len);
    if (der == NULL) {
        ECDSA_SIG_free(sig);
        return false;
    }

    der_cursor = der;
    if (i2d_ECDSA_SIG(sig, &der_cursor) != len) {
        free(der);
        ECDSA_SIG_free(sig);
        return false;
    }

    *out = der;
    *out_len = (size_t)len;
    ECDSA_SIG_free(sig);
    return true;
}

static bool verify_signature_blob(EVP_PKEY *pkey, const char *signature_key_type,
                                  const uint8_t *format, size_t format_len,
                                  const uint8_t *sig_blob, size_t sig_blob_len,
                                  const uint8_t *data, size_t data_len)
{
    EVP_MD_CTX *ctx = NULL;
    bool ok = false;
    char format_buf[64];

    if (pkey == NULL || signature_key_type == NULL || format == NULL || sig_blob == NULL ||
        data == NULL || format_len == 0 || format_len >= sizeof(format_buf)) {
        return false;
    }

    memcpy(format_buf, format, format_len);
    format_buf[format_len] = '\0';

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    if (strcmp(signature_key_type, "ssh-ed25519") == 0) {
        if (strcmp(format_buf, "ssh-ed25519") == 0 &&
            EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig_blob, sig_blob_len, data, data_len) == 1) {
            ok = true;
        }
        EVP_MD_CTX_free(ctx);
        return ok;
    }

    if (strcmp(signature_key_type, "ssh-rsa") == 0) {
        const EVP_MD *md = NULL;
        if (strcmp(format_buf, "rsa-sha2-512") == 0) {
            md = EVP_sha512();
        } else if (strcmp(format_buf, "rsa-sha2-256") == 0) {
            md = EVP_sha256();
        } else if (strcmp(format_buf, "ssh-rsa") == 0) {
            md = EVP_sha1();
        }

        if (md != NULL && EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig_blob, sig_blob_len, data, data_len) == 1) {
            ok = true;
        }
        EVP_MD_CTX_free(ctx);
        return ok;
    }

    if (strncmp(signature_key_type, "ecdsa-sha2-", 11) == 0) {
        uint8_t *der_sig = NULL;
        size_t der_sig_len = 0;
        const EVP_MD *md = NULL;

        if (strcmp(format_buf, "ecdsa-sha2-nistp256") == 0) {
            md = EVP_sha256();
        } else if (strcmp(format_buf, "ecdsa-sha2-nistp384") == 0) {
            md = EVP_sha384();
        } else if (strcmp(format_buf, "ecdsa-sha2-nistp521") == 0) {
            md = EVP_sha512();
        }

        if (md != NULL && convert_ecdsa_signature_to_der(sig_blob, sig_blob_len, &der_sig, &der_sig_len) &&
            EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, der_sig, der_sig_len, data, data_len) == 1) {
            ok = true;
        }

        free(der_sig);
        EVP_MD_CTX_free(ctx);
        return ok;
    }

    EVP_MD_CTX_free(ctx);
    return false;
}

static bool source_addresses_match(const char *client_addr, const char *source_addresses)
{
    if (source_addresses == NULL) {
        return true;
    }
    if (client_addr == NULL || *client_addr == '\0') {
        return false;
    }
    return ip_cidr_list_match(client_addr, source_addresses);
}

static revocation_check_result_t serial_is_revoked(uint64_t serial, const char *revoked_serials)
{
    char *copy = NULL;
    char *saveptr = NULL;
    char *token = NULL;

    if (revoked_serials == NULL || revoked_serials[0] == '\0') {
        return REVOCATION_CHECK_OK;
    }

    copy = strdup(revoked_serials);
    if (copy == NULL) {
        return REVOCATION_CHECK_INVALID;
    }

    for (token = strtok_r(copy, ", \t\r\n", &saveptr); token != NULL;
         token = strtok_r(NULL, ", \t\r\n", &saveptr)) {
        char *end = NULL;
        unsigned long long parsed = 0;

        errno = 0;
        parsed = strtoull(token, &end, 10);
        if (errno != 0 || end == token || *end != '\0') {
            free(copy);
            return REVOCATION_CHECK_INVALID;
        }
        if ((uint64_t)parsed == serial) {
            free(copy);
            return REVOCATION_CHECK_REVOKED;
        }
    }

    free(copy);
    return REVOCATION_CHECK_OK;
}

static ssh_cert_eval_result_t verify_trusted_certificate(const parsed_cert_t *cert,
                                                         const char *client_addr,
                                                         const char *trusted_ca_keys,
                                                         const char *revoked_serials)
{
    uint64_t now = (uint64_t)time(NULL);
    char *copy = NULL;
    char *saveptr = NULL;
    char *line = NULL;
    ssh_cert_eval_result_t result = SSH_CERT_EVAL_FAILURE;
    const uint8_t *sig_format = NULL;
    const uint8_t *sig_blob = NULL;
    size_t sig_format_len = 0;
    size_t sig_blob_len = 0;

    if (cert == NULL || trusted_ca_keys == NULL || trusted_ca_keys[0] == '\0') {
        LOG_WARN("SSH cert auth failed: no trusted user CA keys configured");
        return SSH_CERT_EVAL_FAILURE;
    }

    if (!cert->principal_matches) {
        LOG_WARN("SSH cert auth denied: principal does not match requested username");
        return SSH_CERT_EVAL_DENIED;
    }

    if (now < cert->valid_after) {
        LOG_WARN("SSH cert auth denied: certificate is not yet valid");
        return SSH_CERT_EVAL_DENIED;
    }
    if (cert->valid_before != SSH_CERT_TIME_INFINITY && now >= cert->valid_before) {
        LOG_WARN("SSH cert auth denied: certificate has expired");
        return SSH_CERT_EVAL_DENIED;
    }
    if (!source_addresses_match(client_addr, cert->source_addresses)) {
        LOG_WARN("SSH cert auth denied: source-address restriction mismatch");
        return SSH_CERT_EVAL_DENIED;
    }

    if (!parse_signature_blob(cert->signature_blob, cert->signature_blob_len, &sig_format,
                              &sig_format_len, &sig_blob, &sig_blob_len)) {
        LOG_WARN("SSH cert auth failed: invalid signature blob");
        return SSH_CERT_EVAL_FAILURE;
    }

    copy = strdup(trusted_ca_keys);
    if (copy == NULL) {
        return SSH_CERT_EVAL_FAILURE;
    }

    for (line = strtok_r(copy, "\n", &saveptr); line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {
        key_line_t ca_line;
        EVP_PKEY *pkey = NULL;

        while (*line == ' ' || *line == '\t') {
            line++;
        }
        if (*line == '\0' || *line == '#') {
            continue;
        }

        if (parse_key_line(line, &ca_line) != 0) {
            continue;
        }

        if (ca_line.blob_len == cert->signature_key_blob_len &&
            memcmp(ca_line.blob, cert->signature_key_blob, cert->signature_key_blob_len) == 0) {
            pkey = build_public_key_from_blob(ca_line.blob, ca_line.blob_len);
            if (pkey != NULL && verify_signature_blob(pkey, ca_line.type, sig_format, sig_format_len,
                                                      sig_blob, sig_blob_len, cert->signed_data,
                                                      cert->signed_data_len)) {
                revocation_check_result_t revocation =
                    serial_is_revoked(cert->serial, revoked_serials);
                if (revocation == REVOCATION_CHECK_REVOKED) {
                    LOG_WARN("SSH cert auth denied: certificate serial %llu is revoked",
                             (unsigned long long)cert->serial);
                    result = SSH_CERT_EVAL_DENIED;
                } else if (revocation == REVOCATION_CHECK_INVALID) {
                    LOG_WARN("SSH cert auth failed: invalid revoked serial list");
                    result = SSH_CERT_EVAL_FAILURE;
                } else {
                    result = SSH_CERT_EVAL_SUCCESS;
                }
            } else {
                LOG_WARN("SSH cert auth failed: certificate signature verification failed");
            }
            EVP_PKEY_free(pkey);
            free_key_line(&ca_line);
            break;
        }

        free_key_line(&ca_line);
    }

    if (result != SSH_CERT_EVAL_SUCCESS) {
        LOG_WARN("SSH cert auth failed: signing CA is not trusted");
    }

    free(copy);
    return result;
}

ssh_cert_eval_result_t ssh_cert_evaluate_user(const char *authorized_key_line,
                                              const char *username,
                                              const char *client_addr,
                                              const char *trusted_ca_keys,
                                              const char *revoked_serials)
{
    key_line_t line = {0};
    parsed_cert_t cert = {0};
    ssh_cert_eval_result_t result = SSH_CERT_EVAL_FAILURE;

    if (authorized_key_line == NULL || username == NULL) {
        return SSH_CERT_EVAL_FAILURE;
    }

    if (parse_key_line(authorized_key_line, &line) != 0) {
        return SSH_CERT_EVAL_FAILURE;
    }

    if (strstr(line.type, "-cert-v01@openssh.com") == NULL) {
        free_key_line(&line);
        return SSH_CERT_EVAL_NOT_CERT;
    }

    if (!parse_certificate_blob(&line, username, &cert)) {
        free_key_line(&line);
        return SSH_CERT_EVAL_FAILURE;
    }

    if (cert.signature_key_blob == NULL) {
        result = SSH_CERT_EVAL_DENIED;
    } else {
        result = verify_trusted_certificate(&cert, client_addr, trusted_ca_keys,
                                            revoked_serials);
    }

    free_parsed_cert(&cert);
    free_key_line(&line);
    return result;
}
