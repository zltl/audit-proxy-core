/**
 * @file rbac_filter.c
 * @brief SSH Proxy Core - RBAC Filter Implementation
 */

#include "rbac_filter.h"
#include "router.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>

/* Forward declarations */
static filter_status_t rbac_on_route(filter_t *filter, filter_context_t *ctx);
static void rbac_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t rbac_callbacks = {
    .on_connect = NULL,
    .on_auth = NULL,
    .on_authenticated = NULL,
    .on_route = rbac_on_route,
    .on_data_upstream = NULL,
    .on_data_downstream = NULL,
    .on_close = NULL,
    .destroy = rbac_destroy
};

/* Find role by name */
static rbac_role_t *find_role(const rbac_filter_config_t *config, const char *name)
{
    rbac_role_t *role = config->roles;
    while (role != NULL) {
        if (strcmp(role->name, name) == 0) {
            return role;
        }
        role = role->next;
    }
    return NULL;
}

/* Filter callbacks implementation */
static filter_status_t rbac_on_route(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    rbac_filter_config_t *config = (rbac_filter_config_t *)filter->config;
    if (config == NULL) {
        return FILTER_REJECT;
    }

    rbac_action_t action = rbac_check_access(config, ctx->username, ctx->target_host);

    if (action == RBAC_ACTION_DENY) {
        if (config->log_denials) {
            LOG_WARN("RBAC: Access denied for user '%s' to target '%s'",
                     ctx->username ? ctx->username : "(null)",
                     ctx->target_host ? ctx->target_host : "(null)");
        }
        return FILTER_REJECT;
    }

    LOG_DEBUG("RBAC: Access allowed for user '%s' to target '%s'",
              ctx->username ? ctx->username : "(null)",
              ctx->target_host ? ctx->target_host : "(null)");

    return FILTER_CONTINUE;
}

static void rbac_destroy(filter_t *filter)
{
    if (filter == NULL) {
        return;
    }

    rbac_filter_config_t *config = (rbac_filter_config_t *)filter->config;
    if (config != NULL) {
        /* Free roles */
        rbac_role_t *role = config->roles;
        while (role != NULL) {
            rbac_role_t *next_role = role->next;

            /* Free permissions */
            rbac_permission_t *perm = role->permissions;
            while (perm != NULL) {
                rbac_permission_t *next_perm = perm->next;
                free(perm);
                perm = next_perm;
            }

            free(role);
            role = next_role;
        }

        /* Free user-role mappings */
        rbac_user_role_t *ur = config->user_roles;
        while (ur != NULL) {
            rbac_user_role_t *next_ur = ur->next;
            free(ur);
            ur = next_ur;
        }
    }

    LOG_DEBUG("RBAC filter destroyed");
}

filter_t *rbac_filter_create(const rbac_filter_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    /* Deep copy configuration */
    rbac_filter_config_t *cfg_copy = calloc(1, sizeof(rbac_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }

    cfg_copy->default_action = config->default_action;
    cfg_copy->log_denials = config->log_denials;
    cfg_copy->roles = NULL;
    cfg_copy->user_roles = NULL;

    /* Copy roles */
    rbac_role_t *src_role = config->roles;
    rbac_role_t **dst_role = &cfg_copy->roles;
    while (src_role != NULL) {
        *dst_role = calloc(1, sizeof(rbac_role_t));
        if (*dst_role == NULL) {
            goto error;
        }
        strncpy((*dst_role)->name, src_role->name, RBAC_MAX_NAME - 1);
        (*dst_role)->permissions = NULL;
        (*dst_role)->next = NULL;

        /* Copy permissions */
        rbac_permission_t *src_perm = src_role->permissions;
        rbac_permission_t **dst_perm = &(*dst_role)->permissions;
        while (src_perm != NULL) {
            *dst_perm = calloc(1, sizeof(rbac_permission_t));
            if (*dst_perm == NULL) {
                goto error;
            }
            **dst_perm = *src_perm;
            (*dst_perm)->next = NULL;
            dst_perm = &(*dst_perm)->next;
            src_perm = src_perm->next;
        }

        dst_role = &(*dst_role)->next;
        src_role = src_role->next;
    }

    /* Copy user-role mappings */
    rbac_user_role_t *src_ur = config->user_roles;
    rbac_user_role_t **dst_ur = &cfg_copy->user_roles;
    while (src_ur != NULL) {
        *dst_ur = calloc(1, sizeof(rbac_user_role_t));
        if (*dst_ur == NULL) {
            goto error;
        }
        **dst_ur = *src_ur;
        (*dst_ur)->next = NULL;
        dst_ur = &(*dst_ur)->next;
        src_ur = src_ur->next;
    }

    filter_t *filter = filter_create("rbac", FILTER_TYPE_RBAC,
                                     &rbac_callbacks, cfg_copy);
    if (filter == NULL) {
        goto error;
    }

    LOG_DEBUG("RBAC filter created");
    return filter;

error:
    /* Cleanup on error */
    {
        rbac_role_t *r = cfg_copy->roles;
        while (r != NULL) {
            rbac_role_t *nr = r->next;
            rbac_permission_t *p = r->permissions;
            while (p != NULL) {
                rbac_permission_t *np = p->next;
                free(p);
                p = np;
            }
            free(r);
            r = nr;
        }
        rbac_user_role_t *u = cfg_copy->user_roles;
        while (u != NULL) {
            rbac_user_role_t *nu = u->next;
            free(u);
            u = nu;
        }
        free(cfg_copy);
    }
    return NULL;
}

int rbac_add_role(rbac_filter_config_t *config, const char *name)
{
    if (config == NULL || name == NULL) {
        return -1;
    }

    /* Check if already exists */
    if (find_role(config, name) != NULL) {
        return -1;
    }

    rbac_role_t *role = calloc(1, sizeof(rbac_role_t));
    if (role == NULL) {
        return -1;
    }

    strncpy(role->name, name, RBAC_MAX_NAME - 1);
    role->permissions = NULL;
    role->next = config->roles;
    config->roles = role;

    LOG_DEBUG("RBAC: Added role '%s'", name);
    return 0;
}

int rbac_add_permission(rbac_filter_config_t *config,
                        const char *role_name,
                        const char *target_pattern,
                        rbac_action_t action)
{
    if (config == NULL || role_name == NULL || target_pattern == NULL) {
        return -1;
    }

    rbac_role_t *role = find_role(config, role_name);
    if (role == NULL) {
        return -1;
    }

    rbac_permission_t *perm = calloc(1, sizeof(rbac_permission_t));
    if (perm == NULL) {
        return -1;
    }

    strncpy(perm->target_pattern, target_pattern, RBAC_MAX_PATTERN - 1);
    perm->action = action;
    perm->next = role->permissions;
    role->permissions = perm;

    LOG_DEBUG("RBAC: Added permission to role '%s': %s -> %s",
              role_name, target_pattern,
              action == RBAC_ACTION_ALLOW ? "ALLOW" : "DENY");

    return 0;
}

int rbac_assign_role(rbac_filter_config_t *config,
                     const char *username_pattern,
                     const char *role_name)
{
    if (config == NULL || username_pattern == NULL || role_name == NULL) {
        return -1;
    }

    /* Verify role exists */
    if (find_role(config, role_name) == NULL) {
        return -1;
    }

    rbac_user_role_t *ur = calloc(1, sizeof(rbac_user_role_t));
    if (ur == NULL) {
        return -1;
    }

    strncpy(ur->username_pattern, username_pattern, RBAC_MAX_PATTERN - 1);
    strncpy(ur->role_name, role_name, RBAC_MAX_NAME - 1);
    ur->next = config->user_roles;
    config->user_roles = ur;

    LOG_DEBUG("RBAC: Assigned role '%s' to users matching '%s'",
              role_name, username_pattern);

    return 0;
}

rbac_action_t rbac_check_access(const rbac_filter_config_t *config,
                                const char *username,
                                const char *target)
{
    if (config == NULL) {
        return RBAC_ACTION_DENY;
    }

    /* Find matching user-role mapping */
    rbac_user_role_t *ur = config->user_roles;
    while (ur != NULL) {
        if (router_glob_match(ur->username_pattern, username ? username : "")) {
            /* Found matching user, check role permissions */
            rbac_role_t *role = find_role(config, ur->role_name);
            if (role != NULL) {
                rbac_permission_t *perm = role->permissions;
                while (perm != NULL) {
                    if (router_glob_match(perm->target_pattern, target ? target : "")) {
                        return perm->action;
                    }
                    perm = perm->next;
                }
            }
        }
        ur = ur->next;
    }

    return config->default_action;
}
