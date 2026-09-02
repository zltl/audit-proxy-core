/**
 * @file rbac_filter.h
 * @brief SSH Proxy Core - Role-Based Access Control Filter
 *
 * Implements RBAC for controlling access to target hosts based on
 * user identity, roles, and permissions.
 */

#ifndef SSH_PROXY_RBAC_FILTER_H
#define SSH_PROXY_RBAC_FILTER_H

#include "filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum name lengths */
#define RBAC_MAX_NAME 64
#define RBAC_MAX_PATTERN 256

/* Forward declarations */
typedef struct rbac_role rbac_role_t;
typedef struct rbac_policy rbac_policy_t;
typedef struct rbac_filter_config rbac_filter_config_t;

/* Permission action */
typedef enum {
    RBAC_ACTION_ALLOW = 0,
    RBAC_ACTION_DENY
} rbac_action_t;

/* Permission entry */
typedef struct rbac_permission {
    char target_pattern[RBAC_MAX_PATTERN];  /* Target host pattern */
    rbac_action_t action;                   /* Allow or deny */
    struct rbac_permission *next;
} rbac_permission_t;

/* Role definition */
struct rbac_role {
    char name[RBAC_MAX_NAME];           /* Role name */
    rbac_permission_t *permissions;     /* List of permissions */
    rbac_role_t *next;                  /* Next role */
};

/* User-role mapping */
typedef struct rbac_user_role {
    char username_pattern[RBAC_MAX_PATTERN];    /* Username pattern */
    char role_name[RBAC_MAX_NAME];              /* Assigned role */
    struct rbac_user_role *next;
} rbac_user_role_t;

/* RBAC filter configuration */
struct rbac_filter_config {
    rbac_action_t default_action;       /* Default action if no match */
    rbac_role_t *roles;                 /* List of roles */
    rbac_user_role_t *user_roles;       /* User-role mappings */
    bool log_denials;                   /* Log access denials */
};

/**
 * @brief Create RBAC filter
 * @param config Filter configuration
 * @return Filter instance or NULL on error
 */
filter_t *rbac_filter_create(const rbac_filter_config_t *config);

/**
 * @brief Add a role
 * @param config RBAC configuration
 * @param name Role name
 * @return 0 on success, -1 on error
 */
int rbac_add_role(rbac_filter_config_t *config, const char *name);

/**
 * @brief Add permission to a role
 * @param config RBAC configuration
 * @param role_name Role name
 * @param target_pattern Target pattern (glob)
 * @param action Allow or deny
 * @return 0 on success, -1 on error
 */
int rbac_add_permission(rbac_filter_config_t *config,
                        const char *role_name,
                        const char *target_pattern,
                        rbac_action_t action);

/**
 * @brief Assign role to user
 * @param config RBAC configuration
 * @param username_pattern Username pattern (glob)
 * @param role_name Role name
 * @return 0 on success, -1 on error
 */
int rbac_assign_role(rbac_filter_config_t *config,
                     const char *username_pattern,
                     const char *role_name);

/**
 * @brief Check if access is allowed
 * @param config RBAC configuration
 * @param username Username
 * @param target Target host
 * @return RBAC_ACTION_ALLOW or RBAC_ACTION_DENY
 */
rbac_action_t rbac_check_access(const rbac_filter_config_t *config,
                                const char *username,
                                const char *target);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_RBAC_FILTER_H */
