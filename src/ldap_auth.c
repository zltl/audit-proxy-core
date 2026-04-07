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
#define BER_TAG_OCTET_STRING 0x04
#define BER_TAG_CONTEXT_0    0x80  /* Simple auth in BindRequest / requestName */
#define BER_TAG_ENUM         0x0a

/* LDAP operation constants */
#define LDAP_BIND_REQUEST       0x60  /* [APPLICATION 0] SEQUENCE */
#define LDAP_BIND_RESPONSE      0x61  /* [APPLICATION 1] SEQUENCE */
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

auth_result_t ldap_simple_bind_tls(const char *uri, const char *bind_dn,
                                    const char *password, int timeout_sec,
                                    bool starttls, bool verify_cert,
                                    const char *ca_path)
{
    if (uri == NULL || bind_dn == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    char host[256];
    uint16_t port;
    ldap_tls_mode_t tls_mode;
    if (parse_ldap_uri(uri, host, sizeof(host), &port, &tls_mode) != 0) {
        LOG_ERROR("LDAP: Failed to parse URI: %s", uri);
        return AUTH_RESULT_DENIED;
    }

    /* Apply StartTLS if requested on plain ldap:// */
    if (starttls && tls_mode == LDAP_TLS_NONE) {
        tls_mode = LDAP_TLS_STARTTLS;
    } else if (starttls && tls_mode == LDAP_TLS_LDAPS) {
        LOG_WARN("LDAP: StartTLS ignored for ldaps:// URI (already using TLS)");
    }

#ifndef TLS_ENABLED
    (void)verify_cert;
    (void)ca_path;
    if (tls_mode != LDAP_TLS_NONE) {
        LOG_ERROR("LDAP: TLS support not compiled in (need TLS_ENABLED); "
                  "cannot use %s",
                  tls_mode == LDAP_TLS_LDAPS ? "ldaps://" : "StartTLS");
        return AUTH_RESULT_DENIED;
    }
#endif

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

#ifdef TLS_ENABLED
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    /* LDAPS: establish TLS immediately after TCP connect */
    if (tls_mode == LDAP_TLS_LDAPS) {
        ssl_ctx = create_tls_context(verify_cert, ca_path);
        if (!ssl_ctx) {
            close(fd);
            return AUTH_RESULT_DENIED;
        }
        ssl = setup_tls_connection(ssl_ctx, fd, host);
        if (!ssl) {
            SSL_CTX_free(ssl_ctx);
            close(fd);
            return AUTH_RESULT_DENIED;
        }
        LOG_DEBUG("LDAP: LDAPS TLS connection established");
    }

    /* StartTLS: send Extended Request, then upgrade to TLS */
    if (tls_mode == LDAP_TLS_STARTTLS) {
        uint8_t starttls_buf[LDAP_MAX_BUF];
        size_t starttls_len = build_starttls_request(starttls_buf,
                                                      sizeof(starttls_buf), 1);
        if (starttls_len == 0) {
            LOG_ERROR("LDAP: Failed to build StartTLS request");
            close(fd);
            return AUTH_RESULT_DENIED;
        }

        ssize_t sent = write(fd, starttls_buf, starttls_len);
        if (sent != (ssize_t)starttls_len) {
            LOG_ERROR("LDAP: Failed to send StartTLS request: %s",
                      strerror(errno));
            close(fd);
            return AUTH_RESULT_DENIED;
        }

        uint8_t resp_buf[LDAP_MAX_BUF];
        ssize_t received = read(fd, resp_buf, sizeof(resp_buf));
        if (received <= 0) {
            LOG_ERROR("LDAP: Failed to read StartTLS response: %s",
                      received == 0 ? "connection closed" : strerror(errno));
            close(fd);
            return AUTH_RESULT_DENIED;
        }

        int ext_result = parse_extended_response(resp_buf, (size_t)received);
        if (ext_result != LDAP_SUCCESS) {
            LOG_ERROR("LDAP: StartTLS failed (result code: %d)", ext_result);
            close(fd);
            return AUTH_RESULT_DENIED;
        }

        LOG_DEBUG("LDAP: StartTLS accepted, upgrading to TLS");

        ssl_ctx = create_tls_context(verify_cert, ca_path);
        if (!ssl_ctx) {
            close(fd);
            return AUTH_RESULT_DENIED;
        }
        ssl = setup_tls_connection(ssl_ctx, fd, host);
        if (!ssl) {
            SSL_CTX_free(ssl_ctx);
            close(fd);
            return AUTH_RESULT_DENIED;
        }
        LOG_DEBUG("LDAP: StartTLS TLS connection established");
    }
#endif /* TLS_ENABLED */

    /* Build and send BindRequest */
    uint8_t req_buf[LDAP_MAX_BUF];
    int bind_msg_id = (tls_mode == LDAP_TLS_STARTTLS) ? 2 : 1;
    size_t req_len = build_bind_request(req_buf, sizeof(req_buf),
                                         bind_msg_id, bind_dn, password);
    if (req_len == 0) {
        LOG_ERROR("LDAP: Failed to build BindRequest");
#ifdef TLS_ENABLED
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
#endif
        close(fd);
        return AUTH_RESULT_DENIED;
    }

    ssize_t sent;
    ssize_t received;

#ifdef TLS_ENABLED
    if (ssl) {
        int ssl_sent = SSL_write(ssl, req_buf, (int)req_len);
        sent = (ssl_sent > 0) ? ssl_sent : -1;
    } else {
        sent = write(fd, req_buf, req_len);
    }
#else
    sent = write(fd, req_buf, req_len);
#endif

    if (sent != (ssize_t)req_len) {
        LOG_ERROR("LDAP: Failed to send BindRequest: %s", strerror(errno));
#ifdef TLS_ENABLED
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
#endif
        close(fd);
        return AUTH_RESULT_DENIED;
    }

    /* Read BindResponse */
    uint8_t resp_buf[LDAP_MAX_BUF];

#ifdef TLS_ENABLED
    if (ssl) {
        int ssl_recv = SSL_read(ssl, resp_buf, sizeof(resp_buf));
        received = (ssl_recv > 0) ? ssl_recv : (ssl_recv == 0 ? 0 : -1);
    } else {
        received = read(fd, resp_buf, sizeof(resp_buf));
    }
#else
    received = read(fd, resp_buf, sizeof(resp_buf));
#endif

    /* Cleanup TLS and socket */
#ifdef TLS_ENABLED
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
#endif
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

auth_result_t ldap_simple_bind(const char *uri, const char *bind_dn,
                                const char *password, int timeout_sec)
{
    return ldap_simple_bind_tls(uri, bind_dn, password, timeout_sec,
                                 false, true, NULL);
}
