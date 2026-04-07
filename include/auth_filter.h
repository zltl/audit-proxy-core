/**
 * @file auth_filter.h
 * @brief SSH Proxy Core - Authentication Filter
 *
 * Handles user authentication (PublicKey, Password, Keyboard-Interactive).
 * Supports external identity sources (LDAP, OIDC, etc.).
 */

#ifndef SSH_PROXY_AUTH_FILTER_H
#define SSH_PROXY_AUTH_FILTER_H

#include "filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Authentication result */
typedef enum {
    AUTH_RESULT_SUCCESS = 0,
    AUTH_RESULT_FAILURE,
    AUTH_RESULT_PARTIAL,
    AUTH_RESULT_DENIED
} auth_result_t;

/* LDAP TLS mode */
typedef enum {
    LDAP_TLS_NONE = 0,       /* Plain TCP (ldap://) */
    LDAP_TLS_LDAPS,          /* TLS from start (ldaps://) */
    LDAP_TLS_STARTTLS        /* Upgrade via StartTLS extension */
} ldap_tls_mode_t;

/* Authentication backend type */
typedef enum {
    AUTH_BACKEND_LOCAL = 0,     /* Local user database */
    AUTH_BACKEND_LDAP,          /* LDAP/Active Directory */
    AUTH_BACKEND_OIDC,          /* OpenID Connect */
    AUTH_BACKEND_GITHUB,        /* GitHub OAuth */
    AUTH_BACKEND_CALLBACK       /* Custom callback */
} auth_backend_t;

/* Forward declaration */
typedef struct auth_filter_config auth_filter_config_t;

/**
 * @brief Callback for custom password authentication
 * @param username Username
 * @param password Password
 * @param user_data User-provided context
 * @return AUTH_RESULT_SUCCESS if authenticated
 */
typedef auth_result_t (*auth_password_cb)(const char *username,
                                          const char *password,
                                          void *user_data);

/**
 * @brief Callback for custom public key authentication
 * @param username Username
 * @param pubkey Public key blob
 * @param pubkey_len Public key length
 * @param user_data User-provided context
 * @return AUTH_RESULT_SUCCESS if authenticated
 */
typedef auth_result_t (*auth_pubkey_cb)(const char *username,
                                        const void *pubkey,
                                        size_t pubkey_len,
                                        void *user_data);

/* Local user entry */
typedef struct auth_local_user {
    char username[128];
    char password_hash[256];    /* bcrypt/argon2 hash */
    char *authorized_keys;      /* Authorized keys (OpenSSH format) */
    bool enabled;
    struct auth_local_user *next;
} auth_local_user_t;

/* Auth filter configuration */
struct auth_filter_config {
    auth_backend_t backend;     /* Authentication backend */
    bool allow_password;        /* Allow password auth */
    bool allow_pubkey;          /* Allow public key auth */
    bool allow_keyboard;        /* Allow keyboard-interactive */
    int max_attempts;           /* Maximum auth attempts */
    uint32_t timeout_sec;       /* Auth timeout in seconds */

    /* Local backend */
    auth_local_user_t *local_users;

    /* Custom callbacks */
    auth_password_cb password_cb;
    auth_pubkey_cb pubkey_cb;
    void *cb_user_data;

    /* LDAP settings (for LDAP backend) */
    const char *ldap_uri;
    const char *ldap_base_dn;
    const char *ldap_bind_dn;
    const char *ldap_bind_pw;

    /* LDAP extended settings */
    const char *ldap_user_filter;   /* User search filter, e.g. "uid=%s" */
    int ldap_timeout;               /* Connection timeout in seconds (default: 5) */

    /* LDAP TLS settings */
    bool ldap_starttls;             /* Use StartTLS (ldap:// only) */
    const char *ldap_ca_path;      /* CA certificate path for verification (optional) */
    bool ldap_verify_cert;         /* Verify server certificate (default true) */
};

/**
 * @brief Create authentication filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *auth_filter_create(const auth_filter_config_t *config);

/**
 * @brief Add a local user
 * @param config Auth filter configuration
 * @param username Username
 * @param password_hash Password hash (bcrypt)
 * @param authorized_keys Authorized keys (optional)
 * @return 0 on success, -1 on error
 */
int auth_filter_add_user(auth_filter_config_t *config,
                         const char *username,
                         const char *password_hash,
                         const char *authorized_keys);

/**
 * @brief Remove a local user
 * @param config Auth filter configuration
 * @param username Username to remove
 * @return 0 on success, -1 if not found
 */
int auth_filter_remove_user(auth_filter_config_t *config,
                            const char *username);

/**
 * @brief Perform LDAP Simple Bind authentication
 * @param uri LDAP URI (ldap://host:port)
 * @param bind_dn Bind DN
 * @param password Password
 * @param timeout_sec Timeout in seconds
 * @return Authentication result
 */
auth_result_t ldap_simple_bind(const char *uri, const char *bind_dn,
                                const char *password, int timeout_sec);

/**
 * @brief Perform LDAP Simple Bind authentication with TLS support
 * @param uri LDAP URI (ldap:// or ldaps://host:port)
 * @param bind_dn Bind DN
 * @param password Password
 * @param timeout_sec Timeout in seconds
 * @param starttls Use StartTLS upgrade (ldap:// only)
 * @param verify_cert Verify server certificate
 * @param ca_path CA certificate path (NULL for system default)
 * @return Authentication result
 */
auth_result_t ldap_simple_bind_tls(const char *uri, const char *bind_dn,
                                    const char *password, int timeout_sec,
                                    bool starttls, bool verify_cert,
                                    const char *ca_path);

/**
 * @brief Parse LDAP URI to extract host, port, and TLS mode
 * @param uri LDAP URI (ldap:// or ldaps://)
 * @param host Output buffer for hostname
 * @param host_len Size of host buffer
 * @param port Output port number
 * @param tls_mode Output TLS mode detected from URI
 * @return 0 on success, -1 on error
 */
int parse_ldap_uri(const char *uri, char *host, size_t host_len,
                    uint16_t *port, ldap_tls_mode_t *tls_mode);

/**
 * @brief Build LDAP StartTLS Extended Request message
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @param message_id LDAP message ID
 * @return Number of bytes written, 0 on error
 */
size_t build_starttls_request(uint8_t *buf, size_t buf_size, int message_id);

/**
 * @brief Parse LDAP Extended Response and return result code
 * @param buf Response buffer
 * @param buf_len Response length
 * @return Result code (0=success), -1 on parse error
 */
int parse_extended_response(const uint8_t *buf, size_t buf_len);

/**
 * @brief Hash a password using bcrypt (simple implementation)
 * @param password Plain text password
 * @param hash_out Output buffer for hash
 * @param hash_len Length of output buffer
 * @return 0 on success, -1 on error
 */
int auth_filter_hash_password(const char *password,
                              char *hash_out,
                              size_t hash_len);

/**
 * @brief Verify a password against a hash
 * @param password Plain text password
 * @param hash Password hash
 * @return true if matches
 */
bool auth_filter_verify_password(const char *password, const char *hash);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_AUTH_FILTER_H */
