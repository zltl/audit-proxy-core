/**
 * @file ldap_auth.c
 * @brief Minimal LDAP Simple Bind implementation for authentication
 *
 * Implements just enough LDAP protocol to perform Simple Bind operations
 * for password authentication. Uses raw TCP sockets - no libldap dependency.
 *
 * Protocol: RFC 4511 (LDAPv3)
 * Only supports: BindRequest/BindResponse with Simple authentication
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

/* BER/ASN.1 tag constants */
#define BER_TAG_SEQUENCE     0x30
#define BER_TAG_INTEGER      0x02
#define BER_TAG_OCTET_STRING 0x04
#define BER_TAG_CONTEXT_0    0x80  /* Simple auth in BindRequest */
#define BER_TAG_ENUM         0x0a

/* LDAP operation constants */
#define LDAP_BIND_REQUEST    0x60  /* [APPLICATION 0] SEQUENCE */
#define LDAP_BIND_RESPONSE   0x61  /* [APPLICATION 1] SEQUENCE */
#define LDAP_VERSION_3       3
#define LDAP_SUCCESS         0

/* Maximum buffer sizes */
#define LDAP_MAX_BUF         4096
#define LDAP_DEFAULT_PORT    389
#define LDAP_DEFAULT_TIMEOUT 5

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

/* Parse LDAP BindResponse and return result code (-1 on parse error) */
static int parse_bind_response(const uint8_t *buf, size_t buf_len)
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

    /* BindResponse APPLICATION 1 */
    if (pos >= buf_len || buf[pos] != LDAP_BIND_RESPONSE) return -1;
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

/* Parse LDAP URI to extract host and port */
static int parse_ldap_uri(const char *uri, char *host, size_t host_len,
                           uint16_t *port)
{
    if (uri == NULL) return -1;

    *port = LDAP_DEFAULT_PORT;

    const char *p = uri;
    if (strncmp(p, "ldap://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "ldaps://", 8) == 0) {
        LOG_WARN("LDAPS not supported, use ldap:// with StartTLS");
        return -1;
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

auth_result_t ldap_simple_bind(const char *uri, const char *bind_dn,
                                const char *password, int timeout_sec)
{
    if (uri == NULL || bind_dn == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    char host[256];
    uint16_t port;
    if (parse_ldap_uri(uri, host, sizeof(host), &port) != 0) {
        LOG_ERROR("LDAP: Failed to parse URI: %s", uri);
        return AUTH_RESULT_DENIED;
    }

    if (timeout_sec <= 0) timeout_sec = LDAP_DEFAULT_TIMEOUT;

    /* Resolve hostname */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int gai_err = getaddrinfo(host, port_str, &hints, &res);
    if (gai_err != 0) {
        LOG_ERROR("LDAP: DNS resolution failed for %s: %s",
                  host, gai_strerror(gai_err));
        return AUTH_RESULT_DENIED;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("LDAP: socket(): %s", strerror(errno));
        freeaddrinfo(res);
        return AUTH_RESULT_DENIED;
    }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        LOG_ERROR("LDAP: connect to %s:%u failed: %s",
                  host, port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return AUTH_RESULT_DENIED;
    }
    freeaddrinfo(res);

    LOG_DEBUG("LDAP: Connected to %s:%u", host, port);

    /* Build and send BindRequest */
    uint8_t req_buf[LDAP_MAX_BUF];
    size_t req_len = build_bind_request(req_buf, sizeof(req_buf),
                                         1, bind_dn, password);
    if (req_len == 0) {
        LOG_ERROR("LDAP: Failed to build BindRequest");
        close(fd);
        return AUTH_RESULT_DENIED;
    }

    ssize_t sent = write(fd, req_buf, req_len);
    if (sent != (ssize_t)req_len) {
        LOG_ERROR("LDAP: Failed to send BindRequest: %s", strerror(errno));
        close(fd);
        return AUTH_RESULT_DENIED;
    }

    /* Read BindResponse */
    uint8_t resp_buf[LDAP_MAX_BUF];
    ssize_t received = read(fd, resp_buf, sizeof(resp_buf));
    close(fd);

    if (received <= 0) {
        LOG_ERROR("LDAP: Failed to read BindResponse: %s",
                  received == 0 ? "connection closed" : strerror(errno));
        return AUTH_RESULT_DENIED;
    }

    int result_code = parse_bind_response(resp_buf, (size_t)received);
    if (result_code < 0) {
        LOG_ERROR("LDAP: Failed to parse BindResponse");
        return AUTH_RESULT_DENIED;
    }

    if (result_code == LDAP_SUCCESS) {
        LOG_INFO("LDAP: Bind successful for DN: %s", bind_dn);
        return AUTH_RESULT_SUCCESS;
    }

    LOG_WARN("LDAP: Bind failed for DN: %s (result code: %d)",
             bind_dn, result_code);
    return AUTH_RESULT_FAILURE;
}
