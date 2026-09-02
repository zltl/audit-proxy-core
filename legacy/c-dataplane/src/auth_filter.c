/**
 * @file auth_filter.c
 * @brief SSH Proxy Core - Authentication Filter Implementation
 */

#include "auth_filter.h"
#include "account_lock.h"
#include "logger.h"

#include <crypt.h>
#include <stdlib.h>
#include <string.h>

/* Auth filter state */
typedef struct auth_filter_state {
    int attempt_count;
    bool authenticated;
    size_t ldap_preferred_uri;
} auth_filter_state_t;

/* Forward declarations */
static filter_status_t auth_on_connect(filter_t *filter, filter_context_t *ctx);
static filter_status_t auth_on_auth(filter_t *filter, filter_context_t *ctx);
static void auth_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t auth_callbacks = {.on_connect = auth_on_connect,
                                                  .on_auth = auth_on_auth,
                                                  .on_authenticated = NULL,
                                                  .on_route = NULL,
                                                  .on_data_upstream = NULL,
                                                  .on_data_downstream = NULL,
                                                  .on_close = NULL,
                                                  .destroy = auth_destroy};

/* Local authentication */
static auth_result_t auth_local_password(auth_filter_config_t *config, const char *username,
                                         const char *password) {
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
static auth_result_t auth_callback_password(auth_filter_config_t *config, const char *username,
                                            const char *password) {
    if (config == NULL || config->password_cb == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    return config->password_cb(username, password, config->cb_user_data);
}

static auth_result_t auth_callback_pubkey(auth_filter_config_t *config, const char *username,
                                          const char *client_addr, const void *pubkey,
                                          size_t pubkey_len) {
    if (config == NULL || config->pubkey_cb == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    return config->pubkey_cb(username, client_addr, pubkey, pubkey_len, config->cb_user_data);
}

static const char *ldap_attr_or_default(const char *value, const char *fallback) {
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

static void auth_clear_ldap_identity(session_metadata_t *meta) {
    if (meta == NULL) {
        return;
    }

    explicit_bzero(meta->ldap_email, sizeof(meta->ldap_email));
    explicit_bzero(meta->ldap_department, sizeof(meta->ldap_department));
    explicit_bzero(meta->ldap_manager, sizeof(meta->ldap_manager));
    explicit_bzero(meta->ldap_groups, sizeof(meta->ldap_groups));
}

static void auth_store_ldap_identity(session_metadata_t *meta, const auth_ldap_identity_t *identity) {
    if (meta == NULL || identity == NULL) {
        return;
    }

    strncpy(meta->ldap_email, identity->email, sizeof(meta->ldap_email) - 1);
    strncpy(meta->ldap_department, identity->department, sizeof(meta->ldap_department) - 1);
    strncpy(meta->ldap_manager, identity->manager, sizeof(meta->ldap_manager) - 1);
    strncpy(meta->ldap_groups, identity->groups, sizeof(meta->ldap_groups) - 1);
}

static bool ldap_uri_list_get(const char *uris, size_t index, char *out, size_t out_len) {
    size_t current = 0;
    const char *cursor = NULL;

    if (uris == NULL || out == NULL || out_len == 0) {
        return false;
    }

    cursor = uris;
    while (*cursor != '\0') {
        const char *start = cursor;
        const char *end = NULL;
        size_t len = 0;

        while (*start == ' ' || *start == '\t' || *start == ',') {
            start++;
        }
        if (*start == '\0') {
            break;
        }

        end = start;
        while (*end != '\0' && *end != ',') {
            end++;
        }
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        if (current == index) {
            len = (size_t)(end - start);
            if (len == 0 || len >= out_len) {
                return false;
            }
            memcpy(out, start, len);
            out[len] = '\0';
            return true;
        }

        current++;
        cursor = (*end == ',') ? end + 1 : end;
    }

    return false;
}

static size_t ldap_uri_list_count(const char *uris) {
    size_t count = 0;
    char buf[512];

    while (ldap_uri_list_get(uris, count, buf, sizeof(buf))) {
        count++;
    }
    return count;
}

static auth_result_t auth_ldap_bind(auth_filter_config_t *config, auth_filter_state_t *state,
                                    const char *bind_dn, const char *password, char *successful_uri,
                                    size_t successful_uri_len) {
    size_t uri_count = 0;
    size_t start_index = 0;
    auth_result_t last_result = AUTH_RESULT_DENIED;
    int timeout = 0;

    if (config == NULL || bind_dn == NULL || password == NULL || config->ldap_uri == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    uri_count = ldap_uri_list_count(config->ldap_uri);
    if (uri_count == 0) {
        LOG_ERROR("LDAP backend configured but ldap_uri is empty");
        return AUTH_RESULT_DENIED;
    }

    timeout = config->ldap_timeout > 0 ? config->ldap_timeout : 5;
    start_index = (state != NULL && uri_count > 0) ? (state->ldap_preferred_uri % uri_count) : 0;

    for (size_t attempt = 0; attempt < uri_count; attempt++) {
        char uri[512];
        size_t uri_index = (start_index + attempt) % uri_count;
        auth_result_t result = AUTH_RESULT_DENIED;

        if (!ldap_uri_list_get(config->ldap_uri, uri_index, uri, sizeof(uri))) {
            continue;
        }

        if (config->ldap_bind_cb != NULL) {
            result = config->ldap_bind_cb(uri, bind_dn, password, timeout, config->ldap_starttls,
                                          config->ldap_verify_cert, config->ldap_ca_path,
                                          config->ldap_bind_user_data);
        } else {
            result = ldap_simple_bind_tls(uri, bind_dn, password, timeout, config->ldap_starttls,
                                          config->ldap_verify_cert, config->ldap_ca_path);
        }

        if (result == AUTH_RESULT_SUCCESS) {
            if (state != NULL) {
                state->ldap_preferred_uri = uri_index;
            }
            if (successful_uri != NULL && successful_uri_len > 0) {
                strncpy(successful_uri, uri, successful_uri_len - 1);
                successful_uri[successful_uri_len - 1] = '\0';
            }
            return AUTH_RESULT_SUCCESS;
        }
        if (result == AUTH_RESULT_FAILURE) {
            return AUTH_RESULT_FAILURE;
        }

        last_result = result;
        LOG_WARN("LDAP: backend '%s' unavailable, trying next failover target", uri);
    }

    return last_result;
}

static void auth_ldap_fetch_identity(auth_filter_config_t *config, session_metadata_t *meta,
                                     const char *successful_uri, const char *user_bind_dn,
                                     const char *user_password) {
    auth_ldap_identity_t identity;
    const char *lookup_bind_dn = NULL;
    const char *lookup_password = NULL;
    const char *group_attr = NULL;
    const char *email_attr = NULL;
    const char *department_attr = NULL;
    const char *manager_attr = NULL;
    auth_result_t result = AUTH_RESULT_FAILURE;
    int timeout = 0;

    if (config == NULL || meta == NULL || successful_uri == NULL || successful_uri[0] == '\0' ||
        user_bind_dn == NULL || user_password == NULL) {
        return;
    }

    memset(&identity, 0, sizeof(identity));
    timeout = config->ldap_timeout > 0 ? config->ldap_timeout : 5;
    group_attr = ldap_attr_or_default(config->ldap_group_attr, LDAP_DEFAULT_GROUP_ATTR);
    email_attr = ldap_attr_or_default(config->ldap_email_attr, LDAP_DEFAULT_EMAIL_ATTR);
    department_attr =
        ldap_attr_or_default(config->ldap_department_attr, LDAP_DEFAULT_DEPARTMENT_ATTR);
    manager_attr = ldap_attr_or_default(config->ldap_manager_attr, LDAP_DEFAULT_MANAGER_ATTR);

    lookup_bind_dn = user_bind_dn;
    lookup_password = user_password;
    if (config->ldap_bind_dn != NULL && config->ldap_bind_dn[0] != '\0' &&
        config->ldap_bind_pw != NULL && config->ldap_bind_pw[0] != '\0') {
        lookup_bind_dn = config->ldap_bind_dn;
        lookup_password = config->ldap_bind_pw;
    } else if ((config->ldap_bind_dn != NULL && config->ldap_bind_dn[0] != '\0') ||
               (config->ldap_bind_pw != NULL && config->ldap_bind_pw[0] != '\0')) {
        LOG_WARN("LDAP: ignoring partial lookup bind credentials; falling back to authenticated user");
    }

    if (config->ldap_fetch_identity_cb != NULL) {
        result = config->ldap_fetch_identity_cb(
            successful_uri, lookup_bind_dn, lookup_password, user_bind_dn, timeout,
            config->ldap_starttls, config->ldap_verify_cert, config->ldap_ca_path, group_attr,
            email_attr, department_attr, manager_attr, &identity,
            config->ldap_fetch_identity_user_data);
    } else {
        result = ldap_fetch_identity_tls(successful_uri, lookup_bind_dn, lookup_password,
                                         user_bind_dn, timeout, config->ldap_starttls,
                                         config->ldap_verify_cert, config->ldap_ca_path, group_attr,
                                         email_attr, department_attr, manager_attr, &identity);
    }

    if (result == AUTH_RESULT_SUCCESS) {
        auth_store_ldap_identity(meta, &identity);
        LOG_DEBUG("LDAP: populated identity metadata for '%s'", user_bind_dn);
    } else {
        LOG_WARN("LDAP: identity lookup failed for '%s'; continuing without group/attribute metadata",
                 user_bind_dn);
    }
}

/* Filter callbacks implementation */
static filter_status_t auth_on_connect(filter_t *filter, filter_context_t *ctx) {
    (void)filter;
    (void)ctx;

    /* Initialize per-session state if needed */
    LOG_DEBUG("Auth filter: new connection");
    return FILTER_CONTINUE;
}

static filter_status_t auth_on_auth(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    auth_filter_config_t *config = (auth_filter_config_t *)filter->config;
    if (config == NULL) {
        return FILTER_REJECT;
    }

    session_metadata_t *meta = NULL;
    if (ctx->session != NULL) {
        meta = session_get_metadata(ctx->session);
    }
    const char *client_addr =
        (meta != NULL && meta->client_addr[0] != '\0') ? meta->client_addr : NULL;

    if (client_addr != NULL && account_ip_is_blocked(client_addr)) {
        LOG_WARN("Authentication rejected: client IP '%s' is temporarily blocked", client_addr);
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, AUTH_RESULT_DENIED, config->event_user_data);
        }
        return FILTER_REJECT;
    }

    /* Check account lockout before attempting auth */
    if (ctx->username != NULL && account_is_locked(ctx->username)) {
        LOG_WARN("Authentication rejected: account '%s' is locked", ctx->username);
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, AUTH_RESULT_DENIED, config->event_user_data);
        }
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

            auth_filter_state_t *state = (auth_filter_state_t *)filter->state;
            char selected_uri[512] = {0};

            /* Build bind DN from user filter or direct DN */
            char bind_dn[512];
            if (config->ldap_user_filter != NULL && config->ldap_base_dn != NULL) {
                char user_rdn[256];
                snprintf(user_rdn, sizeof(user_rdn), config->ldap_user_filter, ctx->username);
                snprintf(bind_dn, sizeof(bind_dn), "%s,%s", user_rdn, config->ldap_base_dn);
            } else if (config->ldap_base_dn != NULL) {
                snprintf(bind_dn, sizeof(bind_dn), "uid=%s,%s", ctx->username,
                         config->ldap_base_dn);
            } else {
                LOG_ERROR("LDAP: ldap_base_dn not configured");
                return FILTER_REJECT;
            }

            auth_clear_ldap_identity(meta);
            if (ctx->session != NULL) {
                session_sync(ctx->session);
            }
            result = auth_ldap_bind(config, state, bind_dn, ctx->password, selected_uri,
                                    sizeof(selected_uri));
            if (result == AUTH_RESULT_SUCCESS && meta != NULL) {
                auth_ldap_fetch_identity(config, meta, selected_uri, bind_dn, ctx->password);
                if (ctx->session != NULL) {
                    session_sync(ctx->session);
                }
            }
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
            result = auth_callback_pubkey(config, ctx->username, client_addr, ctx->pubkey,
                                          ctx->pubkey_len);
            break;
        default:
            LOG_WARN("Auth backend %d not implemented for pubkey", config->backend);
            break;
        }
    }

    if (result == AUTH_RESULT_SUCCESS) {
        if (config->authorize_cb != NULL) {
            auth_result_t authorize_result =
                config->authorize_cb(ctx->username, client_addr, config->authorize_user_data);
            if (authorize_result != AUTH_RESULT_SUCCESS) {
                result = AUTH_RESULT_DENIED;
            }
        }
    }

    if (result == AUTH_RESULT_SUCCESS) {
        LOG_INFO("Authentication successful for user '%s'", ctx->username);
        account_record_success(ctx->username);
        account_ip_record_success(client_addr);
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, result, config->event_user_data);
        }
        return FILTER_CONTINUE;
    }

    if (result == AUTH_RESULT_DENIED) {
        LOG_WARN("Authentication denied for user '%s'", ctx->username);
        if (config->event_cb != NULL) {
            config->event_cb(ctx->username, client_addr, result, config->event_user_data);
        }
        return FILTER_REJECT;
    }

    LOG_WARN("Authentication failed for user '%s'", ctx->username);
    account_record_failure(ctx->username);
    account_ip_record_failure(client_addr);
    if (config->event_cb != NULL) {
        config->event_cb(ctx->username, client_addr, result, config->event_user_data);
    }
    return FILTER_REJECT;
}

static void auth_destroy(filter_t *filter) {
    if (filter == NULL) {
        return;
    }

    auth_filter_config_t *config = (auth_filter_config_t *)filter->config;
    auth_filter_state_t *state = (auth_filter_state_t *)filter->state;
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
    if (state != NULL) {
        free(state);
        filter->state = NULL;
    }

    LOG_DEBUG("Auth filter destroyed");
}

filter_t *auth_filter_create(const auth_filter_config_t *config) {
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

    filter_t *filter = filter_create("auth", FILTER_TYPE_AUTH, &auth_callbacks, cfg_copy);
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

    auth_filter_state_t *state = calloc(1, sizeof(auth_filter_state_t));
    if (state == NULL) {
        auth_local_user_t *u = cfg_copy->local_users;
        while (u != NULL) {
            auth_local_user_t *next = u->next;
            free(u->authorized_keys);
            free(u);
            u = next;
        }
        free(cfg_copy);
        free(filter);
        return NULL;
    }
    filter->state = state;

    LOG_DEBUG("Auth filter created, backend=%d", config->backend);
    return filter;
}

int auth_filter_add_user(auth_filter_config_t *config, const char *username,
                         const char *password_hash, const char *authorized_keys) {
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

int auth_filter_remove_user(auth_filter_config_t *config, const char *username) {
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

int auth_filter_hash_password(const char *password, char *hash_out, size_t hash_len) {
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

bool auth_filter_verify_password(const char *password, const char *hash) {
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
