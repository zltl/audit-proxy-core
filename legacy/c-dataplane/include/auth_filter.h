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

#define LDAP_IDENTITY_MAX_DN 512
#define LDAP_IDENTITY_MAX_ATTR 256
#define LDAP_IDENTITY_MAX_GROUPS 2048
#define LDAP_DEFAULT_GROUP_ATTR "memberOf"
#define LDAP_DEFAULT_EMAIL_ATTR "mail"
#define LDAP_DEFAULT_DEPARTMENT_ATTR "department"
#define LDAP_DEFAULT_MANAGER_ATTR "manager"

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
                                        const char *client_addr,
                                        const void *pubkey,
                                        size_t pubkey_len,
                                        void *user_data);

/**
 * @brief Callback invoked after credential verification but before the session is admitted
 * @param username Username supplied by the client
 * @param client_addr Client address if known (may be NULL)
 * @param user_data User-provided context
 * @return AUTH_RESULT_SUCCESS to continue, AUTH_RESULT_DENIED to block access
 */
typedef auth_result_t (*auth_authorize_cb)(const char *username,
                                           const char *client_addr,
                                           void *user_data);

typedef auth_result_t (*auth_ldap_bind_cb)(const char *uri,
                                           const char *bind_dn,
                                           const char *password,
                                           int timeout_sec,
                                           bool starttls,
                                           bool verify_cert,
                                           const char *ca_path,
                                           void *user_data);

typedef struct auth_ldap_identity {
    char user_dn[LDAP_IDENTITY_MAX_DN];
    char email[LDAP_IDENTITY_MAX_ATTR];
    char department[LDAP_IDENTITY_MAX_ATTR];
    char manager[LDAP_IDENTITY_MAX_DN];
    char groups[LDAP_IDENTITY_MAX_GROUPS]; /* Newline-delimited group values */
} auth_ldap_identity_t;

typedef auth_result_t (*auth_ldap_fetch_identity_cb)(const char *uri,
                                                     const char *lookup_bind_dn,
                                                     const char *lookup_password,
                                                     const char *search_dn,
                                                     int timeout_sec,
                                                     bool starttls,
                                                     bool verify_cert,
                                                     const char *ca_path,
                                                     const char *group_attr,
                                                     const char *email_attr,
                                                     const char *department_attr,
                                                     const char *manager_attr,
                                                     auth_ldap_identity_t *identity,
                                                     void *user_data);

/**
 * @brief Callback invoked after an authentication attempt is evaluated
 * @param username Username supplied by the client (may be NULL)
 * @param client_addr Client address if known (may be NULL)
 * @param result Authentication result
 * @param user_data User-provided context
 */
typedef void (*auth_event_cb)(const char *username,
                              const char *client_addr,
                              auth_result_t result,
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
    auth_authorize_cb authorize_cb;
    void *authorize_user_data;
    auth_event_cb event_cb;
    void *event_user_data;

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
    const char *ldap_group_attr;   /* Group membership attribute (default: memberOf) */
    const char *ldap_email_attr;   /* Email attribute (default: mail) */
    const char *ldap_department_attr; /* Department attribute (default: department) */
    const char *ldap_manager_attr; /* Manager attribute (default: manager) */
    auth_ldap_bind_cb ldap_bind_cb;/* Optional override for LDAP bind execution */
    void *ldap_bind_user_data;     /* User context for ldap_bind_cb */
    auth_ldap_fetch_identity_cb ldap_fetch_identity_cb; /* Optional identity lookup override */
    void *ldap_fetch_identity_user_data; /* User context for ldap_fetch_identity_cb */
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
 * @brief Build an LDAP SearchRequest for a single entry lookup
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @param message_id LDAP message ID
 * @param base_dn Search base DN
 * @param attributes Attribute names to request
 * @param attribute_count Number of attributes in attributes
 * @return Number of bytes written, 0 on error
 */
size_t build_search_request(uint8_t *buf, size_t buf_size, int message_id,
                            const char *base_dn, const char *const *attributes,
                            size_t attribute_count);

/**
 * @brief Parse LDAP Extended Response and return result code
 * @param buf Response buffer
 * @param buf_len Response length
 * @return Result code (0=success), -1 on parse error
 */
int parse_extended_response(const uint8_t *buf, size_t buf_len);

/**
 * @brief Parse an LDAP SearchResultEntry and extract identity attributes
 * @param buf Response buffer
 * @param buf_len Response length
 * @param group_attr Group attribute name
 * @param email_attr Email attribute name
 * @param department_attr Department attribute name
 * @param manager_attr Manager attribute name
 * @param identity Output identity structure
 * @return 0 on success, -1 on parse error
 */
int parse_search_result_entry(const uint8_t *buf, size_t buf_len, const char *group_attr,
                              const char *email_attr, const char *department_attr,
                              const char *manager_attr, auth_ldap_identity_t *identity);

/**
 * @brief Parse an LDAP SearchResultDone and return result code
 * @param buf Response buffer
 * @param buf_len Response length
 * @return Result code (0=success), -1 on parse error
 */
int parse_search_result_done(const uint8_t *buf, size_t buf_len);

/**
 * @brief Authenticate to LDAP and fetch user identity attributes from the bound user entry
 * @param uri LDAP URI (ldap:// or ldaps://host:port)
 * @param lookup_bind_dn Bind DN used for the lookup connection
 * @param lookup_password Password used for the lookup connection
 * @param search_dn User DN to search as the base object
 * @param timeout_sec Timeout in seconds
 * @param starttls Use StartTLS upgrade (ldap:// only)
 * @param verify_cert Verify server certificate
 * @param ca_path CA certificate path (NULL for system default)
 * @param group_attr Group attribute name (default memberOf when NULL)
 * @param email_attr Email attribute name (default mail when NULL)
 * @param department_attr Department attribute name (default department when NULL)
 * @param manager_attr Manager attribute name (default manager when NULL)
 * @param identity Output identity structure
 * @return AUTH_RESULT_SUCCESS on success, AUTH_RESULT_DENIED on network/protocol failure
 */
auth_result_t ldap_fetch_identity_tls(const char *uri, const char *lookup_bind_dn,
                                      const char *lookup_password, const char *search_dn,
                                      int timeout_sec, bool starttls, bool verify_cert,
                                      const char *ca_path, const char *group_attr,
                                      const char *email_attr, const char *department_attr,
                                      const char *manager_attr, auth_ldap_identity_t *identity);

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
