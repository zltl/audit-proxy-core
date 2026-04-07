/**
 * @file auth_filter.c
 * @brief SSH Proxy Core - Authentication Filter Implementation
 */

#include "auth_filter.h"
#include "account_lock.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <crypt.h>

/* Auth filter state */
typedef struct auth_filter_state {
    int attempt_count;
    bool authenticated;
} auth_filter_state_t;

/* Forward declarations */
static filter_status_t auth_on_connect(filter_t *filter, filter_context_t *ctx);
static filter_status_t auth_on_auth(filter_t *filter, filter_context_t *ctx);
static void auth_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t auth_callbacks = {
    .on_connect = auth_on_connect,
    .on_auth = auth_on_auth,
    .on_authenticated = NULL,
    .on_route = NULL,
    .on_data_upstream = NULL,
    .on_data_downstream = NULL,
    .on_close = NULL,
    .destroy = auth_destroy
};

/* Local authentication */
static auth_result_t auth_local_password(auth_filter_config_t *config,
                                         const char *username,
                                         const char *password)
{
    if (config == NULL || username == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    auth_local_user_t *user = config->local_users;
    while (user != NULL) {
        if (user->enabled && strcmp(user->username, username) == 0) {
            if (auth_filter_verify_password(password, user->password_hash)) {
                LOG_DEBUG("Local auth success for user '%s'", username);
                return AUTH_RESULT_SUCCESS;
            }
            LOG_DEBUG("Local auth failed for user '%s': bad password", username);
            return AUTH_RESULT_FAILURE;
        }
        user = user->next;
    }

    LOG_DEBUG("Local auth failed: user '%s' not found", username);
    return AUTH_RESULT_FAILURE;
}

/* Callback authentication */
static auth_result_t auth_callback_password(auth_filter_config_t *config,
                                            const char *username,
                                            const char *password)
{
    if (config == NULL || config->password_cb == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    return config->password_cb(username, password, config->cb_user_data);
}

static auth_result_t auth_callback_pubkey(auth_filter_config_t *config,
                                          const char *username,
                                          const void *pubkey,
                                          size_t pubkey_len)
{
    if (config == NULL || config->pubkey_cb == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    return config->pubkey_cb(username, pubkey, pubkey_len, config->cb_user_data);
}

/* Filter callbacks implementation */
static filter_status_t auth_on_connect(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;

    /* Initialize per-session state if needed */
    LOG_DEBUG("Auth filter: new connection");
    return FILTER_CONTINUE;
}

static filter_status_t auth_on_auth(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    auth_filter_config_t *config = (auth_filter_config_t *)filter->config;
    if (config == NULL) {
        return FILTER_REJECT;
    }

    /* Check account lockout before attempting auth */
    if (ctx->username != NULL && account_is_locked(ctx->username)) {
        LOG_WARN("Authentication rejected: account '%s' is locked",
                 ctx->username);
        return FILTER_REJECT;
    }

    auth_result_t result = AUTH_RESULT_FAILURE;

    /* Password authentication */
    if (ctx->password != NULL && config->allow_password) {
        LOG_DEBUG("Auth filter: password auth for user '%s'", ctx->username);

        switch (config->backend) {
        case AUTH_BACKEND_LOCAL:
            result = auth_local_password(config, ctx->username, ctx->password);
            break;
        case AUTH_BACKEND_CALLBACK:
            result = auth_callback_password(config, ctx->username, ctx->password);
            break;
        case AUTH_BACKEND_LDAP: {
            if (config->ldap_uri == NULL) {
                LOG_ERROR("LDAP backend configured but ldap_uri not set");
                return FILTER_REJECT;
            }

            /* Build bind DN from user filter or direct DN */
            char bind_dn[512];
            if (config->ldap_user_filter != NULL && config->ldap_base_dn != NULL) {
                char user_rdn[256];
                snprintf(user_rdn, sizeof(user_rdn), config->ldap_user_filter,
                         ctx->username);
                snprintf(bind_dn, sizeof(bind_dn), "%s,%s",
                         user_rdn, config->ldap_base_dn);
            } else if (config->ldap_base_dn != NULL) {
                snprintf(bind_dn, sizeof(bind_dn), "uid=%s,%s",
                         ctx->username, config->ldap_base_dn);
            } else {
                LOG_ERROR("LDAP: ldap_base_dn not configured");
                return FILTER_REJECT;
            }

            int timeout = config->ldap_timeout > 0 ? config->ldap_timeout : 5;
            result = ldap_simple_bind(config->ldap_uri, bind_dn,
                                       ctx->password, timeout);
            break;
        }
        default:
            LOG_WARN("Auth backend %d not implemented for password", config->backend);
            break;
        }
    }
    /* Public key authentication */
    else if (ctx->pubkey != NULL && ctx->pubkey_len > 0 && config->allow_pubkey) {
        LOG_DEBUG("Auth filter: pubkey auth for user '%s'", ctx->username);

        switch (config->backend) {
        case AUTH_BACKEND_CALLBACK:
            result = auth_callback_pubkey(config, ctx->username,
                                          ctx->pubkey, ctx->pubkey_len);
            break;
        default:
            LOG_WARN("Auth backend %d not implemented for pubkey", config->backend);
            break;
        }
    }

    if (result == AUTH_RESULT_SUCCESS) {
        LOG_INFO("Authentication successful for user '%s'", ctx->username);
        account_record_success(ctx->username);
        return FILTER_CONTINUE;
    }

    LOG_WARN("Authentication failed for user '%s'", ctx->username);
    account_record_failure(ctx->username);
    return FILTER_REJECT;
}

static void auth_destroy(filter_t *filter)
{
    if (filter == NULL) {
        return;
    }

    auth_filter_config_t *config = (auth_filter_config_t *)filter->config;
    if (config != NULL) {
        /* Free local users list */
        auth_local_user_t *user = config->local_users;
        while (user != NULL) {
            auth_local_user_t *next = user->next;
            free(user->authorized_keys);
            free(user);
            user = next;
        }
        free(config);
        filter->config = NULL;
    }

    LOG_DEBUG("Auth filter destroyed");
}

filter_t *auth_filter_create(const auth_filter_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    /* Copy configuration */
    auth_filter_config_t *cfg_copy = calloc(1, sizeof(auth_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }
    *cfg_copy = *config;
    cfg_copy->local_users = NULL; /* Will be populated separately */

    /* Copy local users if any */
    auth_local_user_t *src = config->local_users;
    auth_local_user_t **dst = &cfg_copy->local_users;
    while (src != NULL) {
        *dst = calloc(1, sizeof(auth_local_user_t));
        if (*dst == NULL) {
            /* Cleanup on error */
            auth_local_user_t *u = cfg_copy->local_users;
            while (u != NULL) {
                auth_local_user_t *next = u->next;
                free(u->authorized_keys);
                free(u);
                u = next;
            }
            free(cfg_copy);
            return NULL;
        }
        **dst = *src;
        if (src->authorized_keys != NULL) {
            (*dst)->authorized_keys = strdup(src->authorized_keys);
        }
        (*dst)->next = NULL;
        dst = &(*dst)->next;
        src = src->next;
    }

    filter_t *filter = filter_create("auth", FILTER_TYPE_AUTH,
                                     &auth_callbacks, cfg_copy);
    if (filter == NULL) {
        /* Cleanup */
        auth_local_user_t *u = cfg_copy->local_users;
        while (u != NULL) {
            auth_local_user_t *next = u->next;
            free(u->authorized_keys);
            free(u);
            u = next;
        }
        free(cfg_copy);
        return NULL;
    }

    LOG_DEBUG("Auth filter created, backend=%d", config->backend);
    return filter;
}

int auth_filter_add_user(auth_filter_config_t *config,
                         const char *username,
                         const char *password_hash,
                         const char *authorized_keys)
{
    if (config == NULL || username == NULL) {
        return -1;
    }

    auth_local_user_t *user = calloc(1, sizeof(auth_local_user_t));
    if (user == NULL) {
        return -1;
    }

    strncpy(user->username, username, sizeof(user->username) - 1);
    if (password_hash != NULL) {
        strncpy(user->password_hash, password_hash, sizeof(user->password_hash) - 1);
    }
    if (authorized_keys != NULL) {
        user->authorized_keys = strdup(authorized_keys);
    }
    user->enabled = true;

    /* Add to list */
    user->next = config->local_users;
    config->local_users = user;

    LOG_DEBUG("Added local user '%s'", username);
    return 0;
}

int auth_filter_remove_user(auth_filter_config_t *config,
                            const char *username)
{
    if (config == NULL || username == NULL) {
        return -1;
    }

    auth_local_user_t *prev = NULL;
    auth_local_user_t *user = config->local_users;

    while (user != NULL) {
        if (strcmp(user->username, username) == 0) {
            if (prev == NULL) {
                config->local_users = user->next;
            } else {
                prev->next = user->next;
            }
            free(user->authorized_keys);
            free(user);
            LOG_DEBUG("Removed local user '%s'", username);
            return 0;
        }
        prev = user;
        user = user->next;
    }

    return -1;
}

int auth_filter_hash_password(const char *password,
                              char *hash_out,
                              size_t hash_len)
{
    if (password == NULL || hash_out == NULL || hash_len < 64) {
        return -1;
    }

    /* Use crypt with SHA-512 */
    /* Generate a simple salt - in production use a proper random salt */
    char salt[20];
    snprintf(salt, sizeof(salt), "$6$%.8s$", "saltsalt");

    struct crypt_data data;
    memset(&data, 0, sizeof(data));

    char *result = crypt_r(password, salt, &data);
    if (result == NULL) {
        return -1;
    }

    strncpy(hash_out, result, hash_len - 1);
    hash_out[hash_len - 1] = '\0';

    return 0;
}

bool auth_filter_verify_password(const char *password, const char *hash)
{
    if (password == NULL || hash == NULL) {
        return false;
    }

    struct crypt_data data;
    memset(&data, 0, sizeof(data));

    char *result = crypt_r(password, hash, &data);
    if (result == NULL) {
        return false;
    }

    return strcmp(result, hash) == 0;
}
