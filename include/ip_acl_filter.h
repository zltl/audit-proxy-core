/**
 * @file ip_acl_filter.h
 * @brief SSH Proxy Core - IP Access Control List Filter
 *
 * Provides IP-based whitelist/blacklist filtering with CIDR support.
 * Runs as the first filter in the chain to reject connections early.
 */

#ifndef SSH_PROXY_IP_ACL_FILTER_H
#define SSH_PROXY_IP_ACL_FILTER_H

#include "filter.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ACL mode */
typedef enum {
    IP_ACL_WHITELIST = 0,   /* Only listed IPs allowed */
    IP_ACL_BLACKLIST         /* Listed IPs denied */
} ip_acl_mode_t;

/* ACL action */
typedef enum {
    IP_ACL_ALLOW = 0,
    IP_ACL_DENY
} ip_acl_action_t;

/* ACL entry - single rule */
typedef struct ip_acl_entry {
    uint32_t network;           /* Network address (host byte order) */
    uint32_t mask;              /* Subnet mask (host byte order) */
    ip_acl_action_t action;     /* Allow or deny */
    char cidr_str[64];          /* Original CIDR string for logging */
    struct ip_acl_entry *next;
} ip_acl_entry_t;

/* IP ACL filter configuration */
typedef struct {
    ip_acl_mode_t mode;         /* Whitelist or blacklist mode */
    ip_acl_entry_t *entries;    /* Rule entries (linked list) */
    bool log_rejections;        /* Log rejected connections */
    bool log_accepts;           /* Log accepted connections (verbose) */
} ip_acl_filter_config_t;

/**
 * @brief Create IP ACL filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *ip_acl_filter_create(const ip_acl_filter_config_t *config);

/**
 * @brief Add an ACL entry from CIDR notation
 * @param config Filter configuration
 * @param cidr CIDR string (e.g., "192.168.1.0/24" or "10.0.0.1")
 * @param action Allow or deny
 * @return 0 on success, -1 on error
 */
int ip_acl_add_entry(ip_acl_filter_config_t *config, const char *cidr,
                     ip_acl_action_t action);

/**
 * @brief Check if an IP address is allowed
 * @param filter IP ACL filter instance
 * @param ip_addr IP address string (e.g., "192.168.1.100")
 * @return true if allowed, false if denied
 */
bool ip_acl_check(filter_t *filter, const char *ip_addr);

/**
 * @brief Remove all ACL entries
 * @param config Filter configuration
 */
void ip_acl_clear_entries(ip_acl_filter_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_IP_ACL_FILTER_H */
