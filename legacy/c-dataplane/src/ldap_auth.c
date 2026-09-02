/**
 * @file ldap_auth.c
 * @brief Minimal LDAP Simple Bind implementation for authentication
 *
 * Implements just enough LDAP protocol to perform Simple Bind operations
 * for password authentication. Uses raw TCP sockets - no libldap dependency.
 * Supports optional TLS via LDAPS (ldaps://) and StartTLS extension.
 *
 * Protocol: RFC 4511 (LDAPv3)
 * Supports: BindRequest/BindResponse, ExtendedRequest/ExtendedResponse (StartTLS)
 */

#include "auth_filter.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef TLS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* BER/ASN.1 tag constants */
#define BER_TAG_SEQUENCE     0x30
#define BER_TAG_INTEGER      0x02
#define BER_TAG_BOOLEAN      0x01
#define BER_TAG_OCTET_STRING 0x04
#define BER_TAG_CONTEXT_0    0x80  /* Simple auth in BindRequest / requestName */
#define BER_TAG_CONTEXT_7    0x87  /* Presence filter */
#define BER_TAG_ENUM         0x0a
#define BER_TAG_SET          0x31

/* LDAP operation constants */
#define LDAP_BIND_REQUEST       0x60  /* [APPLICATION 0] SEQUENCE */
#define LDAP_BIND_RESPONSE      0x61  /* [APPLICATION 1] SEQUENCE */
#define LDAP_SEARCH_REQUEST     0x63  /* [APPLICATION 3] SEQUENCE */
#define LDAP_SEARCH_RESULT_ENTRY 0x64 /* [APPLICATION 4] SEQUENCE */
#define LDAP_SEARCH_RESULT_DONE 0x65  /* [APPLICATION 5] SEQUENCE */
#define LDAP_EXTENDED_REQUEST   0x77  /* [APPLICATION 23] SEQUENCE */
#define LDAP_EXTENDED_RESPONSE  0x78  /* [APPLICATION 24] SEQUENCE */
#define LDAP_VERSION_3          3
#define LDAP_SUCCESS            0

/* Maximum buffer sizes */
#define LDAP_MAX_BUF         4096
#define LDAP_DEFAULT_PORT    389
#define LDAPS_DEFAULT_PORT   636
#define LDAP_DEFAULT_TIMEOUT 5

/* StartTLS OID */
#define STARTTLS_OID "1.3.6.1.4.1.1466.20037"

typedef struct ldap_connection {
    int fd;
    char host[256];
    ldap_tls_mode_t tls_mode;
#ifdef TLS_ENABLED
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif
} ldap_connection_t;

/* Write BER length encoding */
static size_t ber_write_length(uint8_t *buf, size_t len)
{
    if (len < 0x80) {
        buf[0] = (uint8_t)len;
        return 1;
    } else if (len < 0x100) {
        buf[0] = 0x81;
        buf[1] = (uint8_t)len;
        return 2;
    } else {
        buf[0] = 0x82;
        buf[1] = (uint8_t)(len >> 8);
        buf[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
}

/* Calculate BER length encoding size */
static size_t ber_length_size(size_t len)
{
    if (len < 0x80) return 1;
    if (len < 0x100) return 2;
    return 3;
}

/* Write a BER INTEGER */
static size_t ber_write_integer(uint8_t *buf, int value)
{
    buf[0] = BER_TAG_INTEGER;
    if (value < 128) {
        buf[1] = 1;  /* length */
        buf[2] = (uint8_t)value;
        return 3;
    }
    /* Handle up to 2 bytes */
    buf[1] = 2;
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)(value & 0xFF);
    return 4;
}

/* Write a BER OCTET STRING (or context-tagged string) */
static size_t ber_write_octet_string(uint8_t *buf, uint8_t tag,
                                      const char *str, size_t str_len)
{
    size_t pos = 0;
    buf[pos++] = tag;
    pos += ber_write_length(buf + pos, str_len);
    memcpy(buf + pos, str, str_len);
    return pos + str_len;
}

static size_t ber_write_boolean(uint8_t *buf, bool value)
{
    buf[0] = BER_TAG_BOOLEAN;
    buf[1] = 1;
    buf[2] = value ? 0xff : 0x00;
    return 3;
}

static size_t ber_write_enumerated(uint8_t *buf, int value)
{
    buf[0] = BER_TAG_ENUM;
    if (value < 128) {
        buf[1] = 1;
        buf[2] = (uint8_t)value;
        return 3;
    }
    buf[1] = 2;
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)(value & 0xFF);
    return 4;
}

/* Build LDAP BindRequest message */
static size_t build_bind_request(uint8_t *buf, size_t buf_size,
                                  int message_id,
                                  const char *bind_dn,
                                  const char *password)
{
    size_t dn_len = bind_dn ? strlen(bind_dn) : 0;
    size_t pw_len = password ? strlen(password) : 0;

    /*
     * BindRequest content:
     *   INTEGER version (3)
     *   OCTET STRING name (bind DN)
     *   [0] OCTET STRING simple password
     */
    uint8_t inner[LDAP_MAX_BUF];
    size_t inner_len = 0;

    inner_len += ber_write_integer(inner + inner_len, LDAP_VERSION_3);
    inner_len += ber_write_octet_string(inner + inner_len, BER_TAG_OCTET_STRING,
                                         bind_dn ? bind_dn : "", dn_len);
    inner_len += ber_write_octet_string(inner + inner_len, BER_TAG_CONTEXT_0,
                                         password ? password : "", pw_len);

    /* Wrap in BindRequest APPLICATION tag */
    uint8_t bind_req[LDAP_MAX_BUF];
    size_t bind_len = 0;
    bind_req[bind_len++] = LDAP_BIND_REQUEST;
    bind_len += ber_write_length(bind_req + bind_len, inner_len);
    memcpy(bind_req + bind_len, inner, inner_len);
    bind_len += inner_len;

    /*
     * LDAPMessage envelope:
     *   SEQUENCE {
     *     INTEGER messageID
     *     BindRequest { ... }
     *   }
     */
    uint8_t msg_id_buf[8];
    size_t msg_id_len = ber_write_integer(msg_id_buf, message_id);

    size_t envelope_content_len = msg_id_len + bind_len;

    if (1 + ber_length_size(envelope_content_len) + envelope_content_len > buf_size) {
        return 0; /* Buffer too small */
    }

    size_t pos = 0;
    buf[pos++] = BER_TAG_SEQUENCE;
    pos += ber_write_length(buf + pos, envelope_content_len);
    memcpy(buf + pos, msg_id_buf, msg_id_len);
    pos += msg_id_len;
    memcpy(buf + pos, bind_req, bind_len);
    pos += bind_len;

    return pos;
}

/* Build LDAP StartTLS Extended Request message */
size_t build_starttls_request(uint8_t *buf, size_t buf_size, int message_id)
{
    /*
     * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
     *     requestName  [0] LDAPOID  -- "1.3.6.1.4.1.1466.20037"
     * }
     *
     * Wrapped in LDAPMessage:
     *   SEQUENCE {
     *     INTEGER messageID,
     *     ExtendedRequest { [0] OID }
     *   }
     */
    size_t oid_len = strlen(STARTTLS_OID);

    /* requestName: [0] tag + length + OID string */
    size_t req_name_len = 1 + ber_length_size(oid_len) + oid_len;

    /* ExtendedRequest: APPLICATION 23 tag + length + requestName */
    size_t ext_req_content_len = req_name_len;

    /* Message ID */
    uint8_t msg_id_buf[8];
    size_t msg_id_len = ber_write_integer(msg_id_buf, message_id);

    /* Envelope content = messageID + ExtendedRequest */
    size_t ext_req_total = 1 + ber_length_size(ext_req_content_len) +
                           ext_req_content_len;
    size_t envelope_content_len = msg_id_len + ext_req_total;
    size_t total_len = 1 + ber_length_size(envelope_content_len) +
                       envelope_content_len;

    if (total_len > buf_size) {
        return 0;
    }

    size_t pos = 0;

    /* SEQUENCE envelope */
    buf[pos++] = BER_TAG_SEQUENCE;
    pos += ber_write_length(buf + pos, envelope_content_len);

    /* Message ID */
    memcpy(buf + pos, msg_id_buf, msg_id_len);
    pos += msg_id_len;

    /* ExtendedRequest [APPLICATION 23] */
    buf[pos++] = LDAP_EXTENDED_REQUEST;
    pos += ber_write_length(buf + pos, ext_req_content_len);

    /* requestName [0] (context-specific, primitive) */
    pos += ber_write_octet_string(buf + pos, BER_TAG_CONTEXT_0,
                                   STARTTLS_OID, oid_len);

    return pos;
}

size_t build_search_request(uint8_t *buf, size_t buf_size, int message_id,
                            const char *base_dn, const char *const *attributes,
                            size_t attribute_count)
{
    uint8_t inner[LDAP_MAX_BUF];
    uint8_t attr_buf[LDAP_MAX_BUF];
    uint8_t request[LDAP_MAX_BUF];
    uint8_t msg_id_buf[8];
    const char *search_base = (base_dn != NULL) ? base_dn : "";
    size_t inner_len = 0;
    size_t attr_len = 0;
    size_t request_len = 0;
    size_t msg_id_len = 0;

    if (buf == NULL || attributes == NULL || attribute_count == 0) {
        return 0;
    }

    inner_len += ber_write_octet_string(inner + inner_len, BER_TAG_OCTET_STRING, search_base,
                                        strlen(search_base));
    inner_len += ber_write_enumerated(inner + inner_len, 0); /* baseObject */
    inner_len += ber_write_enumerated(inner + inner_len, 0); /* neverDerefAliases */
    inner_len += ber_write_integer(inner + inner_len, 1);    /* sizeLimit */
    inner_len += ber_write_integer(inner + inner_len, 0);    /* timeLimit */
    inner_len += ber_write_boolean(inner + inner_len, false);
    inner_len += ber_write_octet_string(inner + inner_len, BER_TAG_CONTEXT_7, "objectClass",
                                        strlen("objectClass"));

    for (size_t i = 0; i < attribute_count; i++) {
        if (attributes[i] == NULL || attributes[i][0] == '\0') {
            continue;
        }
        attr_len += ber_write_octet_string(attr_buf + attr_len, BER_TAG_OCTET_STRING,
                                           attributes[i], strlen(attributes[i]));
    }

    request[request_len++] = BER_TAG_SEQUENCE;
    request_len += ber_write_length(request + request_len, attr_len);
    memcpy(request + request_len, attr_buf, attr_len);
    request_len += attr_len;

    if (inner_len + request_len >= sizeof(inner)) {
        return 0;
    }
    memcpy(inner + inner_len, request, request_len);
    inner_len += request_len;

    request_len = 0;
    request[request_len++] = LDAP_SEARCH_REQUEST;
    request_len += ber_write_length(request + request_len, inner_len);
    memcpy(request + request_len, inner, inner_len);
    request_len += inner_len;

    msg_id_len = ber_write_integer(msg_id_buf, message_id);
    if (1 + ber_length_size(msg_id_len + request_len) + msg_id_len + request_len > buf_size) {
        return 0;
    }

    size_t pos = 0;
    buf[pos++] = BER_TAG_SEQUENCE;
    pos += ber_write_length(buf + pos, msg_id_len + request_len);
    memcpy(buf + pos, msg_id_buf, msg_id_len);
    pos += msg_id_len;
    memcpy(buf + pos, request, request_len);
    pos += request_len;
    return pos;
}

/* Parse BER length */
static size_t ber_read_length(const uint8_t *buf, size_t buf_len, size_t *value)
{
    if (buf_len == 0) return 0;

    if (buf[0] < 0x80) {
        *value = buf[0];
        return 1;
    }

    size_t num_bytes = buf[0] & 0x7F;
    if (num_bytes + 1 > buf_len) return 0;

    *value = 0;
    for (size_t i = 0; i < num_bytes; i++) {
        *value = (*value << 8) | buf[1 + i];
    }
    return 1 + num_bytes;
}

static size_t ber_read_tlv(const uint8_t *buf, size_t buf_len, uint8_t expected_tag,
                           const uint8_t **value, size_t *value_len)
{
    size_t len = 0;
    size_t adv = 0;

    if (buf == NULL || value == NULL || value_len == NULL || buf_len == 0 || buf[0] != expected_tag) {
        return 0;
    }

    adv = ber_read_length(buf + 1, buf_len - 1, &len);
    if (adv == 0 || (1 + adv + len) > buf_len) {
        return 0;
    }

    *value = buf + 1 + adv;
    *value_len = len;
    return 1 + adv + len;
}

static size_t ldap_message_frame_length(const uint8_t *buf, size_t buf_len)
{
    const uint8_t *value = NULL;
    size_t value_len = 0;
    size_t consumed = ber_read_tlv(buf, buf_len, BER_TAG_SEQUENCE, &value, &value_len);
    (void)value;
    return consumed;
}

static int ldap_message_operation_tag(const uint8_t *buf, size_t buf_len, uint8_t *tag)
{
    const uint8_t *message = NULL;
    const uint8_t *value = NULL;
    size_t message_len = 0;
    size_t value_len = 0;
    size_t pos = 0;
    size_t consumed = 0;

    if (tag == NULL) {
        return -1;
    }

    consumed = ber_read_tlv(buf, buf_len, BER_TAG_SEQUENCE, &message, &message_len);
    if (consumed == 0) {
        return -1;
    }

    consumed = ber_read_tlv(message + pos, message_len - pos, BER_TAG_INTEGER, &value, &value_len);
    if (consumed == 0) {
        return -1;
    }
    pos += consumed;
    if (pos >= message_len) {
        return -1;
    }

    *tag = message[pos];
    return 0;
}

static void ldap_connection_init(ldap_connection_t *conn)
{
    if (conn == NULL) {
        return;
    }

    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
}

static void ldap_connection_close(ldap_connection_t *conn)
{
    if (conn == NULL) {
        return;
    }

#ifdef TLS_ENABLED
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ssl_ctx != NULL) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
#endif
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

static ssize_t ldap_connection_write(ldap_connection_t *conn, const uint8_t *buf, size_t len)
{
    if (conn == NULL || buf == NULL) {
        return -1;
    }

#ifdef TLS_ENABLED
    if (conn->ssl != NULL) {
        int ssl_sent = SSL_write(conn->ssl, buf, (int)len);
        return ssl_sent > 0 ? ssl_sent : -1;
    }
#endif
    return write(conn->fd, buf, len);
}

static ssize_t ldap_connection_read(ldap_connection_t *conn, uint8_t *buf, size_t len)
{
    if (conn == NULL || buf == NULL) {
        return -1;
    }

#ifdef TLS_ENABLED
    if (conn->ssl != NULL) {
        int ssl_recv = SSL_read(conn->ssl, buf, (int)len);
        return ssl_recv > 0 ? ssl_recv : (ssl_recv == 0 ? 0 : -1);
    }
#endif
    return read(conn->fd, buf, len);
}

/* Parse an LDAP response result code given a specific APPLICATION tag */
static int parse_ldap_response(const uint8_t *buf, size_t buf_len,
                                uint8_t expected_tag)
{
    size_t pos = 0;

    /* LDAPMessage SEQUENCE */
    if (pos >= buf_len || buf[pos] != BER_TAG_SEQUENCE) return -1;
    pos++;
    size_t seq_len;
    size_t adv = ber_read_length(buf + pos, buf_len - pos, &seq_len);
    if (adv == 0) return -1;
    pos += adv;

    /* MessageID INTEGER */
    if (pos >= buf_len || buf[pos] != BER_TAG_INTEGER) return -1;
    pos++;
    size_t id_len;
    adv = ber_read_length(buf + pos, buf_len - pos, &id_len);
    if (adv == 0) return -1;
    pos += adv;
    pos += id_len; /* Skip message ID value */

    /* Expected APPLICATION tag */
    if (pos >= buf_len || buf[pos] != expected_tag) return -1;
    pos++;
    size_t resp_len;
    adv = ber_read_length(buf + pos, buf_len - pos, &resp_len);
    if (adv == 0) return -1;
    pos += adv;

    /* Result code ENUMERATED */
    if (pos >= buf_len || buf[pos] != BER_TAG_ENUM) return -1;
    pos++;
    size_t rc_len;
    adv = ber_read_length(buf + pos, buf_len - pos, &rc_len);
    if (adv == 0) return -1;
    pos += adv;

    if (rc_len == 0 || pos >= buf_len) return -1;

    int result_code = 0;
    for (size_t i = 0; i < rc_len && (pos + i) < buf_len; i++) {
        result_code = (result_code << 8) | buf[pos + i];
    }

    return result_code;
}

/* Parse LDAP BindResponse and return result code (-1 on parse error) */
static int parse_bind_response(const uint8_t *buf, size_t buf_len)
{
    return parse_ldap_response(buf, buf_len, LDAP_BIND_RESPONSE);
}

/* Parse LDAP ExtendedResponse and return result code (-1 on parse error) */
int parse_extended_response(const uint8_t *buf, size_t buf_len)
{
    return parse_ldap_response(buf, buf_len, LDAP_EXTENDED_RESPONSE);
}

static void copy_ldap_string(char *dst, size_t dst_len, const uint8_t *src, size_t src_len)
{
    size_t copy_len = 0;

    if (dst == NULL || dst_len == 0) {
        return;
    }

    copy_len = src_len < (dst_len - 1) ? src_len : (dst_len - 1);
    if (src != NULL && copy_len > 0) {
        memcpy(dst, src, copy_len);
    }
    dst[copy_len] = '\0';
}

static void append_group_value(auth_ldap_identity_t *identity, const uint8_t *value, size_t value_len)
{
    size_t current_len = 0;
    size_t remaining = 0;
    size_t copy_len = 0;

    if (identity == NULL || value == NULL || value_len == 0) {
        return;
    }

    current_len = strlen(identity->groups);
    if (current_len >= sizeof(identity->groups) - 1) {
        return;
    }

    if (current_len > 0) {
        identity->groups[current_len++] = '\n';
    }

    remaining = sizeof(identity->groups) - current_len - 1;
    copy_len = value_len < remaining ? value_len : remaining;
    memcpy(identity->groups + current_len, value, copy_len);
    identity->groups[current_len + copy_len] = '\0';
}

static bool ldap_attr_matches(const char *expected, const uint8_t *name, size_t name_len)
{
    return expected != NULL && name != NULL && strlen(expected) == name_len &&
           memcmp(expected, name, name_len) == 0;
}

static const char *ldap_attr_or_default(const char *value, const char *fallback)
{
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

int parse_search_result_entry(const uint8_t *buf, size_t buf_len, const char *group_attr,
                              const char *email_attr, const char *department_attr,
                              const char *manager_attr, auth_ldap_identity_t *identity)
{
    const uint8_t *message = NULL;
    const uint8_t *entry = NULL;
    const uint8_t *attrs = NULL;
    const uint8_t *value = NULL;
    size_t message_len = 0;
    size_t entry_len = 0;
    size_t attrs_len = 0;
    size_t value_len = 0;
    size_t consumed = 0;
    size_t pos = 0;
    size_t attr_pos = 0;

    if (buf == NULL || identity == NULL) {
        return -1;
    }

    consumed = ber_read_tlv(buf, buf_len, BER_TAG_SEQUENCE, &message, &message_len);
    if (consumed == 0) {
        return -1;
    }
    consumed = ber_read_tlv(message + pos, message_len - pos, BER_TAG_INTEGER, &value, &value_len);
    if (consumed == 0) {
        return -1;
    }
    pos += consumed;
    consumed = ber_read_tlv(message + pos, message_len - pos, LDAP_SEARCH_RESULT_ENTRY, &entry,
                            &entry_len);
    if (consumed == 0) {
        return -1;
    }

    pos = 0;
    consumed = ber_read_tlv(entry + pos, entry_len - pos, BER_TAG_OCTET_STRING, &value, &value_len);
    if (consumed == 0) {
        return -1;
    }
    copy_ldap_string(identity->user_dn, sizeof(identity->user_dn), value, value_len);
    pos += consumed;

    consumed = ber_read_tlv(entry + pos, entry_len - pos, BER_TAG_SEQUENCE, &attrs, &attrs_len);
    if (consumed == 0) {
        return -1;
    }

    while (attr_pos < attrs_len) {
        const uint8_t *partial = NULL;
        const uint8_t *attr_name = NULL;
        const uint8_t *set_values = NULL;
        size_t partial_len = 0;
        size_t attr_name_len = 0;
        size_t set_len = 0;
        size_t partial_pos = 0;
        size_t set_pos = 0;

        consumed = ber_read_tlv(attrs + attr_pos, attrs_len - attr_pos, BER_TAG_SEQUENCE, &partial,
                                &partial_len);
        if (consumed == 0) {
            return -1;
        }
        attr_pos += consumed;

        consumed =
            ber_read_tlv(partial + partial_pos, partial_len - partial_pos, BER_TAG_OCTET_STRING,
                         &attr_name, &attr_name_len);
        if (consumed == 0) {
            return -1;
        }
        partial_pos += consumed;

        consumed =
            ber_read_tlv(partial + partial_pos, partial_len - partial_pos, BER_TAG_SET, &set_values,
                         &set_len);
        if (consumed == 0) {
            return -1;
        }

        while (set_pos < set_len) {
            const uint8_t *attr_value = NULL;
            size_t attr_value_len = 0;

            consumed =
                ber_read_tlv(set_values + set_pos, set_len - set_pos, BER_TAG_OCTET_STRING,
                             &attr_value, &attr_value_len);
            if (consumed == 0) {
                return -1;
            }
            set_pos += consumed;

            if (ldap_attr_matches(group_attr, attr_name, attr_name_len)) {
                append_group_value(identity, attr_value, attr_value_len);
            } else if (identity->email[0] == '\0' &&
                       ldap_attr_matches(email_attr, attr_name, attr_name_len)) {
                copy_ldap_string(identity->email, sizeof(identity->email), attr_value,
                                 attr_value_len);
            } else if (identity->department[0] == '\0' &&
                       ldap_attr_matches(department_attr, attr_name, attr_name_len)) {
                copy_ldap_string(identity->department, sizeof(identity->department), attr_value,
                                 attr_value_len);
            } else if (identity->manager[0] == '\0' &&
                       ldap_attr_matches(manager_attr, attr_name, attr_name_len)) {
                copy_ldap_string(identity->manager, sizeof(identity->manager), attr_value,
                                 attr_value_len);
            }
        }
    }

    return 0;
}

int parse_search_result_done(const uint8_t *buf, size_t buf_len)
{
    return parse_ldap_response(buf, buf_len, LDAP_SEARCH_RESULT_DONE);
}

/* Parse LDAP URI to extract host, port, and TLS mode */
int parse_ldap_uri(const char *uri, char *host, size_t host_len,
                    uint16_t *port, ldap_tls_mode_t *tls_mode)
{
    if (uri == NULL) return -1;

    *port = LDAP_DEFAULT_PORT;
    *tls_mode = LDAP_TLS_NONE;

    const char *p = uri;
    if (strncmp(p, "ldaps://", 8) == 0) {
        *port = LDAPS_DEFAULT_PORT;
        *tls_mode = LDAP_TLS_LDAPS;
        p += 8;
    } else if (strncmp(p, "ldap://", 7) == 0) {
        p += 7;
    }

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if (colon != NULL && (slash == NULL || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_len) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = (uint16_t)atoi(colon + 1);
    } else if (slash != NULL) {
        size_t hlen = (size_t)(slash - p);
        if (hlen >= host_len) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
    } else {
        size_t len = strlen(p);
        if (len >= host_len) return -1;
        memcpy(host, p, len);
        host[len] = '\0';
    }

    return 0;
}

#ifdef TLS_ENABLED
/* Create an OpenSSL TLS context */
static SSL_CTX *create_tls_context(bool verify_cert, const char *ca_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        LOG_ERROR("LDAP: Failed to create SSL context");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify_cert) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (ca_path) {
            if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
                LOG_ERROR("LDAP: Failed to load CA certificates from %s",
                          ca_path);
                SSL_CTX_free(ctx);
                return NULL;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

/* Upgrade a TCP socket to TLS */
static SSL *setup_tls_connection(SSL_CTX *ctx, int fd, const char *host)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        LOG_ERROR("LDAP: Failed to create SSL object");
        return NULL;
    }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        unsigned long err = ERR_get_error();
        LOG_ERROR("LDAP: TLS handshake failed: %s",
                  ERR_error_string(err, NULL));
        SSL_free(ssl);
        return NULL;
    }

    LOG_DEBUG("LDAP: TLS handshake completed (protocol: %s, cipher: %s)",
              SSL_get_version(ssl), SSL_get_cipher_name(ssl));
    return ssl;
}
#endif /* TLS_ENABLED */

static auth_result_t ldap_open_connection(const char *uri, int timeout_sec, bool starttls,
                                          bool verify_cert, const char *ca_path,
                                          ldap_connection_t *conn, int *next_message_id)
{
    uint16_t port = 0;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct timeval tv;
    char port_str[8];
    int gai_err = 0;

    if (uri == NULL || conn == NULL || next_message_id == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    ldap_connection_init(conn);
    *next_message_id = 1;

    if (parse_ldap_uri(uri, conn->host, sizeof(conn->host), &port, &conn->tls_mode) != 0) {
        LOG_ERROR("LDAP: Failed to parse URI: %s", uri);
        return AUTH_RESULT_DENIED;
    }

    if (starttls && conn->tls_mode == LDAP_TLS_NONE) {
        conn->tls_mode = LDAP_TLS_STARTTLS;
    } else if (starttls && conn->tls_mode == LDAP_TLS_LDAPS) {
        LOG_WARN("LDAP: StartTLS ignored for ldaps:// URI (already using TLS)");
    }

#ifndef TLS_ENABLED
    (void)verify_cert;
    (void)ca_path;
    if (conn->tls_mode != LDAP_TLS_NONE) {
        LOG_ERROR("LDAP: TLS support not compiled in (need TLS_ENABLED); cannot use %s",
                  conn->tls_mode == LDAP_TLS_LDAPS ? "ldaps://" : "StartTLS");
        return AUTH_RESULT_DENIED;
    }
#endif

    if (timeout_sec <= 0) {
        timeout_sec = LDAP_DEFAULT_TIMEOUT;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%u", port);
    gai_err = getaddrinfo(conn->host, port_str, &hints, &res);
    if (gai_err != 0) {
        LOG_ERROR("LDAP: DNS resolution failed for %s: %s", conn->host, gai_strerror(gai_err));
        return AUTH_RESULT_DENIED;
    }

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd < 0) {
        LOG_ERROR("LDAP: socket(): %s", strerror(errno));
        freeaddrinfo(res);
        return AUTH_RESULT_DENIED;
    }

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(conn->fd, res->ai_addr, res->ai_addrlen) != 0) {
        LOG_ERROR("LDAP: connect to %s:%u failed: %s", conn->host, port, strerror(errno));
        freeaddrinfo(res);
        ldap_connection_close(conn);
        return AUTH_RESULT_DENIED;
    }
    freeaddrinfo(res);

    LOG_DEBUG("LDAP: Connected to %s:%u", conn->host, port);

#ifdef TLS_ENABLED
    if (conn->tls_mode == LDAP_TLS_LDAPS) {
        conn->ssl_ctx = create_tls_context(verify_cert, ca_path);
        if (conn->ssl_ctx == NULL) {
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }
        conn->ssl = setup_tls_connection(conn->ssl_ctx, conn->fd, conn->host);
        if (conn->ssl == NULL) {
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }
        LOG_DEBUG("LDAP: LDAPS TLS connection established");
    }

    if (conn->tls_mode == LDAP_TLS_STARTTLS) {
        uint8_t starttls_buf[LDAP_MAX_BUF];
        uint8_t resp_buf[LDAP_MAX_BUF];
        size_t starttls_len = build_starttls_request(starttls_buf, sizeof(starttls_buf), 1);
        ssize_t sent = 0;
        ssize_t received = 0;
        int ext_result = 0;

        if (starttls_len == 0) {
            LOG_ERROR("LDAP: Failed to build StartTLS request");
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }

        sent = write(conn->fd, starttls_buf, starttls_len);
        if (sent != (ssize_t)starttls_len) {
            LOG_ERROR("LDAP: Failed to send StartTLS request: %s", strerror(errno));
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }

        received = read(conn->fd, resp_buf, sizeof(resp_buf));
        if (received <= 0) {
            LOG_ERROR("LDAP: Failed to read StartTLS response: %s",
                      received == 0 ? "connection closed" : strerror(errno));
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }

        ext_result = parse_extended_response(resp_buf, (size_t)received);
        if (ext_result != LDAP_SUCCESS) {
            LOG_ERROR("LDAP: StartTLS failed (result code: %d)", ext_result);
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }

        conn->ssl_ctx = create_tls_context(verify_cert, ca_path);
        if (conn->ssl_ctx == NULL) {
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }
        conn->ssl = setup_tls_connection(conn->ssl_ctx, conn->fd, conn->host);
        if (conn->ssl == NULL) {
            ldap_connection_close(conn);
            return AUTH_RESULT_DENIED;
        }
        *next_message_id = 2;
        LOG_DEBUG("LDAP: StartTLS TLS connection established");
    }
#endif

    return AUTH_RESULT_SUCCESS;
}

static auth_result_t ldap_bind_connection(ldap_connection_t *conn, int message_id,
                                          const char *bind_dn, const char *password)
{
    uint8_t req_buf[LDAP_MAX_BUF];
    uint8_t resp_buf[LDAP_MAX_BUF];
    size_t req_len = 0;
    ssize_t sent = 0;
    ssize_t received = 0;
    int result_code = 0;

    if (conn == NULL || bind_dn == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    req_len = build_bind_request(req_buf, sizeof(req_buf), message_id, bind_dn, password);
    if (req_len == 0) {
        LOG_ERROR("LDAP: Failed to build BindRequest");
        return AUTH_RESULT_DENIED;
    }

    sent = ldap_connection_write(conn, req_buf, req_len);
    if (sent != (ssize_t)req_len) {
        LOG_ERROR("LDAP: Failed to send BindRequest: %s", strerror(errno));
        return AUTH_RESULT_DENIED;
    }

    received = ldap_connection_read(conn, resp_buf, sizeof(resp_buf));
    if (received <= 0) {
        LOG_ERROR("LDAP: Failed to read BindResponse: %s",
                  received == 0 ? "connection closed" : strerror(errno));
        return AUTH_RESULT_DENIED;
    }

    result_code = parse_bind_response(resp_buf, (size_t)received);
    if (result_code < 0) {
        LOG_ERROR("LDAP: Failed to parse BindResponse");
        return AUTH_RESULT_DENIED;
    }

    if (result_code == LDAP_SUCCESS) {
        LOG_INFO("LDAP: Bind successful for DN: %s", bind_dn);
        return AUTH_RESULT_SUCCESS;
    }

    LOG_WARN("LDAP: Bind failed for DN: %s (result code: %d)", bind_dn, result_code);
    return AUTH_RESULT_FAILURE;
}

auth_result_t ldap_simple_bind_tls(const char *uri, const char *bind_dn,
                                    const char *password, int timeout_sec,
                                    bool starttls, bool verify_cert,
                                    const char *ca_path)
{
    ldap_connection_t conn;
    auth_result_t result = AUTH_RESULT_FAILURE;
    int next_message_id = 1;

    if (uri == NULL || bind_dn == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    result = ldap_open_connection(uri, timeout_sec, starttls, verify_cert, ca_path, &conn,
                                  &next_message_id);
    if (result != AUTH_RESULT_SUCCESS) {
        return result;
    }

    result = ldap_bind_connection(&conn, next_message_id, bind_dn, password);
    ldap_connection_close(&conn);
    return result;
}

auth_result_t ldap_fetch_identity_tls(const char *uri, const char *lookup_bind_dn,
                                      const char *lookup_password, const char *search_dn,
                                      int timeout_sec, bool starttls, bool verify_cert,
                                      const char *ca_path, const char *group_attr,
                                      const char *email_attr, const char *department_attr,
                                      const char *manager_attr, auth_ldap_identity_t *identity)
{
    ldap_connection_t conn;
    auth_result_t result = AUTH_RESULT_FAILURE;
    const char *attributes[4];
    size_t attribute_count = 0;
    int next_message_id = 1;
    uint8_t req_buf[LDAP_MAX_BUF];
    uint8_t resp_buf[LDAP_MAX_BUF * 2];
    size_t req_len = 0;
    size_t used = 0;
    int done_code = -1;
    bool have_entry = false;

    if (uri == NULL || lookup_bind_dn == NULL || lookup_password == NULL || search_dn == NULL ||
        identity == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    memset(identity, 0, sizeof(*identity));
    group_attr = ldap_attr_or_default(group_attr, LDAP_DEFAULT_GROUP_ATTR);
    email_attr = ldap_attr_or_default(email_attr, LDAP_DEFAULT_EMAIL_ATTR);
    department_attr = ldap_attr_or_default(department_attr, LDAP_DEFAULT_DEPARTMENT_ATTR);
    manager_attr = ldap_attr_or_default(manager_attr, LDAP_DEFAULT_MANAGER_ATTR);

    attributes[attribute_count++] = group_attr;
    attributes[attribute_count++] = email_attr;
    attributes[attribute_count++] = department_attr;
    attributes[attribute_count++] = manager_attr;

    result = ldap_open_connection(uri, timeout_sec, starttls, verify_cert, ca_path, &conn,
                                  &next_message_id);
    if (result != AUTH_RESULT_SUCCESS) {
        return result;
    }

    result = ldap_bind_connection(&conn, next_message_id, lookup_bind_dn, lookup_password);
    if (result != AUTH_RESULT_SUCCESS) {
        ldap_connection_close(&conn);
        return result;
    }
    next_message_id++;

    req_len = build_search_request(req_buf, sizeof(req_buf), next_message_id, search_dn, attributes,
                                   attribute_count);
    if (req_len == 0) {
        LOG_ERROR("LDAP: Failed to build SearchRequest");
        ldap_connection_close(&conn);
        return AUTH_RESULT_DENIED;
    }

    if (ldap_connection_write(&conn, req_buf, req_len) != (ssize_t)req_len) {
        LOG_ERROR("LDAP: Failed to send SearchRequest: %s", strerror(errno));
        ldap_connection_close(&conn);
        return AUTH_RESULT_DENIED;
    }

    while (done_code < 0) {
        ssize_t received = 0;

        if (used >= sizeof(resp_buf)) {
            LOG_ERROR("LDAP: Search response exceeded buffer");
            ldap_connection_close(&conn);
            return AUTH_RESULT_DENIED;
        }

        received = ldap_connection_read(&conn, resp_buf + used, sizeof(resp_buf) - used);
        if (received <= 0) {
            LOG_ERROR("LDAP: Failed to read SearchResponse: %s",
                      received == 0 ? "connection closed" : strerror(errno));
            ldap_connection_close(&conn);
            return AUTH_RESULT_DENIED;
        }
        used += (size_t)received;

        size_t consumed = 0;
        while (consumed < used) {
            size_t frame_len = ldap_message_frame_length(resp_buf + consumed, used - consumed);
            uint8_t op_tag = 0;

            if (frame_len == 0) {
                break;
            }
            if (ldap_message_operation_tag(resp_buf + consumed, frame_len, &op_tag) != 0) {
                ldap_connection_close(&conn);
                return AUTH_RESULT_DENIED;
            }

            if (op_tag == LDAP_SEARCH_RESULT_ENTRY) {
                if (parse_search_result_entry(resp_buf + consumed, frame_len, group_attr, email_attr,
                                              department_attr, manager_attr, identity) != 0) {
                    LOG_ERROR("LDAP: Failed to parse SearchResultEntry");
                    ldap_connection_close(&conn);
                    return AUTH_RESULT_DENIED;
                }
                have_entry = true;
            } else if (op_tag == LDAP_SEARCH_RESULT_DONE) {
                done_code = parse_search_result_done(resp_buf + consumed, frame_len);
                if (done_code < 0) {
                    LOG_ERROR("LDAP: Failed to parse SearchResultDone");
                    ldap_connection_close(&conn);
                    return AUTH_RESULT_DENIED;
                }
            }

            consumed += frame_len;
        }

        if (consumed > 0 && consumed < used) {
            memmove(resp_buf, resp_buf + consumed, used - consumed);
        }
        if (consumed > 0) {
            used -= consumed;
        }
    }

    ldap_connection_close(&conn);

    if (done_code != LDAP_SUCCESS) {
        LOG_WARN("LDAP: SearchResultDone returned %d for DN: %s", done_code, search_dn);
        return AUTH_RESULT_FAILURE;
    }
    if (!have_entry) {
        copy_ldap_string(identity->user_dn, sizeof(identity->user_dn),
                         (const uint8_t *)search_dn, strlen(search_dn));
    }
    return AUTH_RESULT_SUCCESS;
}

auth_result_t ldap_simple_bind(const char *uri, const char *bind_dn,
                                const char *password, int timeout_sec)
{
    return ldap_simple_bind_tls(uri, bind_dn, password, timeout_sec,
                                 false, true, NULL);
}
