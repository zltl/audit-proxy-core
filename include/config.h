/**
 * @file config.h
 * @brief SSH Proxy Core - Configuration Module
 *
 * Loads user credentials, public keys, and user-to-upstream route mappings
 * from configuration files instead of hardcoding.
 */

#ifndef SSH_PROXY_CONFIG_H
#define SSH_PROXY_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#include "account_lock.h"
#include "password_policy.h"
#include "webhook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum lengths for config values */
#define CONFIG_MAX_USERNAME      128
#define CONFIG_MAX_PASSWORD_HASH 256
#define CONFIG_MAX_PUBKEY        8192
#define CONFIG_MAX_PRIVKEY_PATH  512
#define CONFIG_MAX_HOST          256
#define CONFIG_MAX_LINE          4096
#define CONFIG_MAX_GEO_TEXT      64
#define CONFIG_MAX_COUNTRY_CODE  8

#define CONFIG_POLICY_DAY_MON (1u << 0)
#define CONFIG_POLICY_DAY_TUE (1u << 1)
#define CONFIG_POLICY_DAY_WED (1u << 2)
#define CONFIG_POLICY_DAY_THU (1u << 3)
#define CONFIG_POLICY_DAY_FRI (1u << 4)
#define CONFIG_POLICY_DAY_SAT (1u << 5)
#define CONFIG_POLICY_DAY_SUN (1u << 6)
#define CONFIG_POLICY_DAY_ALL                                                       \
    (CONFIG_POLICY_DAY_MON | CONFIG_POLICY_DAY_TUE | CONFIG_POLICY_DAY_WED |        \
     CONFIG_POLICY_DAY_THU | CONFIG_POLICY_DAY_FRI | CONFIG_POLICY_DAY_SAT |        \
     CONFIG_POLICY_DAY_SUN)

#define CONFIG_POLICY_SOURCE_OFFICE (1u << 0)
#define CONFIG_POLICY_SOURCE_VPN    (1u << 1)
#define CONFIG_POLICY_SOURCE_PUBLIC (1u << 2)
#define CONFIG_POLICY_SOURCE_ALL                                                \
    (CONFIG_POLICY_SOURCE_OFFICE | CONFIG_POLICY_SOURCE_VPN |                   \
     CONFIG_POLICY_SOURCE_PUBLIC)

/* User entry in configuration */
typedef struct config_user {
    char username[CONFIG_MAX_USERNAME];
    char password_hash[CONFIG_MAX_PASSWORD_HASH];
    char *pubkeys;                 /* Authorized public keys (OpenSSH format) */
    time_t password_changed_at;    /* Unix epoch seconds of last password change */
    bool password_changed_at_set;  /* Whether password_changed_at is populated */
    bool password_change_required; /* Force password rotation on next password auth */
    bool password_hash_is_indirect;/* Loaded via env/file/encrypted reference */
    bool enabled;
    struct config_user *next;
} config_user_t;

typedef struct config_geo_db config_geo_db_t;

typedef enum config_route_circuit_state {
    CONFIG_ROUTE_CIRCUIT_CLOSED = 0,
    CONFIG_ROUTE_CIRCUIT_OPEN,
    CONFIG_ROUTE_CIRCUIT_HALF_OPEN
} config_route_circuit_state_t;

/* User to upstream route mapping */
typedef struct config_route {
    char proxy_user[CONFIG_MAX_USERNAME];       /* User connecting to proxy (supports glob) */
    char upstream_host[CONFIG_MAX_HOST];        /* Target upstream host */
    uint16_t upstream_port;                     /* Target upstream port */
    char upstream_user[CONFIG_MAX_USERNAME];    /* User to authenticate as on upstream */
    char privkey_path[CONFIG_MAX_PRIVKEY_PATH]; /* Private key for upstream auth (optional) */
    char geo_country_code[CONFIG_MAX_COUNTRY_CODE]; /* Preferred client country code */
    char geo_country[CONFIG_MAX_GEO_TEXT];          /* Preferred client country name */
    char geo_region[CONFIG_MAX_GEO_TEXT];           /* Preferred client region */
    char geo_city[CONFIG_MAX_GEO_TEXT];             /* Preferred client city */
    double geo_latitude;                            /* Preferred route latitude */
    double geo_longitude;                           /* Preferred route longitude */
    bool geo_latitude_set;                          /* Whether latitude is configured */
    bool geo_longitude_set;                         /* Whether longitude is configured */
    bool geo_has_coordinates;                       /* Whether latitude/longitude is configured */
    atomic_uint circuit_consecutive_failures;       /* Runtime circuit breaker failure counter */
    atomic_llong circuit_open_until_epoch;          /* Runtime circuit breaker cool-down */
    atomic_bool circuit_probe_inflight;             /* Half-open probe in progress */
    bool enabled;
    struct config_route *next;
} config_route_t;

/* Policy entry for user feature control */
typedef struct config_policy {
    char username_pattern[CONFIG_MAX_USERNAME]; /* User pattern (supports glob) */
    char upstream_pattern[CONFIG_MAX_HOST];     /* Upstream pattern (supports glob, empty = any) */
    uint32_t allowed_features;                  /* Bitwise OR of allowed features */
    uint32_t denied_features;                   /* Bitwise OR of denied features */
    bool login_window_enabled;                  /* Enable login window enforcement */
    uint8_t login_days_mask;                    /* Allowed days, CONFIG_POLICY_DAY_* bitmask */
    uint16_t login_window_start_minute;         /* Window start in minutes after midnight */
    uint16_t login_window_end_minute;           /* Window end in minutes after midnight */
    int16_t login_timezone_offset_minutes;      /* Fixed UTC offset for window evaluation */
    uint8_t allowed_source_types;               /* Allowed source categories */
    uint8_t denied_source_types;                /* Explicitly denied source categories */
    struct config_policy *next;
} config_policy_t;

/* Main configuration structure */
typedef struct proxy_config {
    /* Server settings */
    char bind_addr[64];
    uint16_t port;
    char host_key_path[CONFIG_MAX_PRIVKEY_PATH];

    /* Users */
    config_user_t *users;

    /* User to upstream routes */
    config_route_t *routes;

    /* User policies (feature control) */
    config_policy_t *policies;
    uint32_t default_policy; /* Default allowed features for unmatched users */
    char *office_source_cidrs; /* Comma-separated CIDRs classified as office */
    char *vpn_source_cidrs;    /* Comma-separated CIDRs classified as VPN */
    int router_retry_max;      /* Router retry rounds after the first attempt */
    uint32_t router_retry_initial_delay_ms; /* Initial retry delay (milliseconds) */
    uint32_t router_retry_max_delay_ms;     /* Maximum retry delay (milliseconds) */
    float router_retry_backoff_factor;      /* Exponential backoff multiplier */
    bool router_pool_enabled;               /* Reserved for router connection pooling */
    size_t router_pool_max_idle;            /* Reserved for router connection pooling */
    uint32_t router_pool_max_idle_time_sec; /* Reserved for router connection pooling */
    bool router_circuit_breaker_enabled;    /* Enable runtime per-route circuit breaker */
    uint32_t router_circuit_breaker_failure_threshold; /* Failures before open state */
    uint32_t router_circuit_breaker_open_seconds;      /* Open-state cool-down */
    char geoip_data_file[CONFIG_MAX_PRIVKEY_PATH]; /* CIDR->location JSON database */
    config_geo_db_t *geoip_db;                     /* Loaded GeoIP records */

    /* Logging */
    int log_level; /* 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR */
    char audit_log_dir[256];
    size_t audit_max_file_size;      /* Rotate audit logs after this size (0 = unlimited) */
    size_t audit_max_archived_files; /* Retain at most N archived files per family (0 = unlimited) */
    uint32_t audit_retention_days;   /* Remove archived logs older than N days (0 = unlimited) */
    char *audit_encryption_key;      /* Hex-encoded AES-256-GCM key for audit logs */
    bool audit_encryption_key_is_indirect; /* Loaded via env/file/encrypted reference */
    bool log_transfers;              /* Log file transfers */
    bool log_port_forwards;          /* Log port forwarding attempts */

    /* Limits */
    size_t max_sessions;
    uint32_t session_timeout;
    uint32_t auth_timeout;
    char session_store_type[16];         /* local | file */
    char session_store_path[256];        /* Shared session file path */
    int session_store_sync_interval;     /* Shared session sync cadence */
    char session_store_instance_id[64];  /* Stable node identifier */

    /* Banner/MOTD */
    char banner_path[CONFIG_MAX_PRIVKEY_PATH]; /* Pre-auth banner file path */
    char motd[1024];                           /* Post-auth message of the day */
    bool show_progress;                        /* Show connection progress to client */

    /* Security (P1.4 / P1.5) */
    account_lock_config_t lockout;     /* Account lockout settings */
    password_policy_t password_policy; /* Password complexity policy */
    char *trusted_user_ca_keys;        /* Trusted SSH user CA public keys (OpenSSH format) */
    char *revoked_user_cert_serials;   /* Revoked SSH user certificate serial numbers */

    /* Admin API */
    bool admin_api_enabled;
    char admin_auth_token[256];
    bool admin_auth_token_is_indirect; /* Loaded via env/file/encrypted reference */
    uint32_t admin_token_expiry_sec;
    bool admin_tls_enabled;
    char admin_tls_cert_path[CONFIG_MAX_PRIVKEY_PATH];
    char admin_tls_key_path[CONFIG_MAX_PRIVKEY_PATH];

    /* Webhook notifications */
    webhook_config_t webhook;
    bool webhook_hmac_secret_is_indirect; /* Loaded via env/file/encrypted reference */
} proxy_config_t;

/**
 * @brief Create an empty configuration with default values
 * @return Configuration instance or NULL on error
 */
proxy_config_t *config_create(void);

/**
 * @brief Load configuration from file
 * @param path Path to configuration file
 * @return Configuration instance or NULL on error
 */
proxy_config_t *config_load(const char *path);

/**
 * @brief Destroy configuration and free all memory
 * @param config Configuration instance
 */
void config_destroy(proxy_config_t *config);

/**
 * @brief Add a user to configuration
 * @param config Configuration instance
 * @param username Username
 * @param password_hash Password hash (crypt format)
 * @param pubkeys Authorized public keys (OpenSSH format, can be NULL)
 * @return 0 on success, -1 on error
 */
int config_add_user(proxy_config_t *config, const char *username, const char *password_hash,
                    const char *pubkeys);

/**
 * @brief Find a user by username
 * @param config Configuration instance
 * @param username Username to find
 * @return User entry or NULL if not found
 */
config_user_t *config_find_user(const proxy_config_t *config, const char *username);

/**
 * @brief Add a user to upstream route
 * @param config Configuration instance
 * @param proxy_user User pattern connecting to proxy (supports glob: *, ?)
 * @param upstream_host Target upstream host
 * @param upstream_port Target upstream port
 * @param upstream_user Username for upstream authentication
 * @param privkey_path Path to private key (optional, can be NULL)
 * @return 0 on success, -1 on error
 */
int config_add_route(proxy_config_t *config, const char *proxy_user, const char *upstream_host,
                     uint16_t upstream_port, const char *upstream_user, const char *privkey_path);

/**
 * @brief Find route for a proxy user
 * @param config Configuration instance
 * @param proxy_user Username connecting to proxy
 * @return Route entry or NULL if not found
 */
config_route_t *config_find_route(const proxy_config_t *config, const char *proxy_user);

/**
 * @brief Find the best route for a proxy user from a specific client address
 * @param config Configuration instance
 * @param proxy_user Username connecting to proxy
 * @param client_addr Client IP address for Geo-routing decisions (optional)
 * @return Route entry or NULL if not found
 */
config_route_t *config_find_route_for_client(const proxy_config_t *config, const char *proxy_user,
                                             const char *client_addr);

/**
 * @brief Get ordered route candidates for a proxy user and client address
 * @param config Configuration instance
 * @param proxy_user Username connecting to proxy
 * @param client_addr Client IP address for Geo-routing decisions (optional)
 * @param out_routes Receives a malloc'd array of config_route_t*; caller must free()
 * @return Number of candidates in out_routes
 */
size_t config_get_route_candidates_for_client(const proxy_config_t *config, const char *proxy_user,
                                              const char *client_addr, config_route_t ***out_routes);

/**
 * @brief Get the current circuit-breaker state for a route
 * @param config Configuration instance
 * @param route Route entry
 * @param now Current wall clock
 * @return Current circuit-breaker state
 */
config_route_circuit_state_t config_route_circuit_state(const proxy_config_t *config,
                                                        config_route_t *route, time_t now);

/**
 * @brief Try to acquire a route for connection, promoting eligible open circuits to half-open
 * @param config Configuration instance
 * @param route Route entry
 * @param now Current wall clock
 * @param half_open_probe Set true when this acquisition is a half-open recovery probe
 * @return true if the route may be attempted now
 */
bool config_route_circuit_try_acquire(const proxy_config_t *config, config_route_t *route,
                                      time_t now, bool *half_open_probe);

/**
 * @brief Release a half-open probe that never reached the upstream
 * @param route Route entry
 */
void config_route_circuit_release_probe(config_route_t *route);

/**
 * @brief Record a failed upstream TCP connection attempt for a route
 * @param config Configuration instance
 * @param route Route entry
 * @param now Current wall clock
 * @return true if the circuit transitioned to open
 */
bool config_route_circuit_record_failure(const proxy_config_t *config, config_route_t *route,
                                         time_t now);

/**
 * @brief Record a successful upstream TCP connection attempt for a route
 * @param route Route entry
 */
void config_route_circuit_record_success(config_route_t *route);

/**
 * @brief Add a user policy rule
 * @param config Configuration instance
 * @param username_pattern Username pattern (supports glob: *, ?)
 * @param upstream_pattern Upstream host pattern (supports glob, NULL = any upstream)
 * @param allowed_features Bitwise OR of allowed feature flags
 * @param denied_features Bitwise OR of denied feature flags (overrides allowed)
 * @return 0 on success, -1 on error
 */
int config_add_policy(proxy_config_t *config, const char *username_pattern,
                      const char *upstream_pattern, uint32_t allowed_features,
                      uint32_t denied_features);

/**
 * @brief Find policy for a user and upstream
 * @param config Configuration instance
 * @param username Username
 * @param upstream Upstream host (can be NULL for user-only match)
 * @return Policy entry or NULL if not found (use default_policy)
 */
config_policy_t *config_find_policy(const proxy_config_t *config, const char *username,
                                    const char *upstream);

/**
 * @brief Evaluate contextual connection policy for a user
 * @param config Configuration instance
 * @param username Username
 * @param upstream Upstream host if known
 * @param client_addr Client address if known
 * @param now Current timestamp
 * @param reason Optional denial reason buffer
 * @param reason_len Size of denial reason buffer
 * @return true when access is allowed, false when denied by policy
 */
bool config_policy_allows_connection(const proxy_config_t *config, const char *username,
                                     const char *upstream, const char *client_addr, time_t now,
                                     char *reason, size_t reason_len);

/**
 * @brief Reload configuration from file
 * @param config Existing configuration (will be modified)
 * @param path Path to configuration file
 * @return 0 on success, -1 on error
 */
int config_reload(proxy_config_t *config, const char *path);

/**
 * @brief Apply a previously loaded replacement configuration in-place
 * @param config Existing configuration to update
 * @param replacement Loaded configuration whose contents will be transferred
 * @return 0 on success, -1 on error
 */
int config_apply_loaded(proxy_config_t *config, proxy_config_t *replacement);

/**
 * @brief Expand environment variable and file references in a value
 *
 * Supports two expansion forms:
 *   ${env:VARNAME}    — replaced by the environment variable VARNAME
 *   ${file:/path}     — replaced by the first line of the given file
 *
 * @param value   Input string to expand
 * @param out     Output buffer for expanded string
 * @param out_len Size of output buffer
 * @return 0 on success, -1 on expansion error
 */
int config_expand_env(const char *value, char *out, size_t out_len);

/**
 * @brief Securely clear sensitive fields in configuration
 *
 * Overwrites password hashes and other sensitive data with zeros using
 * explicit_bzero() to prevent compiler optimisation from eliding the clear.
 *
 * @param config Configuration instance
 */
void config_clear_sensitive(proxy_config_t *config);

/* Configuration validation severity */
typedef enum { CONFIG_VALID_INFO = 0, CONFIG_VALID_WARN, CONFIG_VALID_ERROR } config_valid_level_t;

/* Single validation result */
typedef struct config_valid_result {
    config_valid_level_t level;
    char message[256];
    struct config_valid_result *next;
} config_valid_result_t;

/**
 * @brief Validate a configuration, returning a list of issues
 * @param config Configuration to validate
 * @param config_path Path to config file (for file-existence checks)
 * @return Linked list of validation results, or NULL if no issues.
 *         Caller must free with config_valid_free().
 */
config_valid_result_t *config_validate(const proxy_config_t *config, const char *config_path);

/**
 * @brief Free validation result list
 * @param results Result list from config_validate
 */
void config_valid_free(config_valid_result_t *results);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_CONFIG_H */
