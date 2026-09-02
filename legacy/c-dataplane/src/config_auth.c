/**
 * @file config_auth.c
 * @brief Configuration-backed authentication helpers
 */

#include "config_auth.h"
#include "logger.h"
#include "password_policy.h"
#include "ssh_cert.h"

#include <libssh/libssh.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

static int parse_key_material_line(const char *line, char *type, size_t type_len, char *b64,
                                   size_t b64_len)
{
    char *copy = NULL;
    char *saveptr = NULL;
    char *token = NULL;
    char *b64_token = NULL;

    if (line == NULL || type == NULL || type_len == 0 || b64 == NULL || b64_len == 0) {
        return -1;
    }

    copy = strdup(line);
    if (copy == NULL) {
        return -1;
    }

    for (token = strtok_r(copy, " \t\r\n", &saveptr); token != NULL;
         token = strtok_r(NULL, " \t\r\n", &saveptr)) {
        if (*token == '#') {
            break;
        }
        if (strncmp(token, "ssh-", 4) != 0 && strncmp(token, "ecdsa-", 6) != 0 &&
            strncmp(token, "sk-", 3) != 0 && strncmp(token, "rsa-sha2-", 10) != 0) {
            continue;
        }

        strncpy(type, token, type_len - 1);
        type[type_len - 1] = '\0';
        b64_token = strtok_r(NULL, " \t\r\n", &saveptr);
        if (b64_token != NULL) {
            strncpy(b64, b64_token, b64_len - 1);
            b64[b64_len - 1] = '\0';
        }
        free(copy);
        return b64_token != NULL ? 0 : -1;
    }

    free(copy);
    return -1;
}

static int import_key_line(const char *line, ssh_key *out)
{
    char type[64];
    char b64[8192];

    if (line == NULL || out == NULL ||
        parse_key_material_line(line, type, sizeof(type), b64, sizeof(b64)) != 0) {
        return SSH_ERROR;
    }

    if (strstr(type, "-cert-v01@openssh.com") != NULL) {
        return ssh_pki_import_cert_base64(b64, ssh_key_type_from_name(type), out);
    }

    return ssh_pki_import_pubkey_base64(b64, ssh_key_type_from_name(type), out);
}

auth_result_t config_authenticate_password(const proxy_config_t *config, const char *username,
                                           const char *password) {
    if (config == NULL || username == NULL || password == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    config_user_t *user = config_find_user(config, username);
    if (user == NULL) {
        LOG_WARN("Auth failed: user '%s' not found in config", username);
        return AUTH_RESULT_FAILURE;
    }

    if (user->password_hash[0] == '\0') {
        LOG_WARN("Auth failed for user '%s': no password hash configured", username);
        return AUTH_RESULT_FAILURE;
    }

    if (!auth_filter_verify_password(password, user->password_hash)) {
        LOG_DEBUG("Password verification failed for user '%s'", username);
        return AUTH_RESULT_FAILURE;
    }

    if (user->password_change_required) {
        LOG_WARN("Auth denied for user '%s': password rotation required", username);
        return AUTH_RESULT_DENIED;
    }

    if (password_policy_check_expiry(&config->password_policy, user->password_changed_at_set,
                                     user->password_changed_at, time(NULL)) != 0) {
        LOG_WARN("Auth denied for user '%s': %s", username, password_policy_error());
        return AUTH_RESULT_DENIED;
    }

    LOG_INFO("Config auth success for user '%s'", username);
    return AUTH_RESULT_SUCCESS;
}

auth_result_t config_authenticate_pubkey(const proxy_config_t *config, const char *username,
                                         const char *client_addr, const char *authorized_key_line)
{
    config_user_t *user = NULL;
    ssh_cert_eval_result_t cert_result = SSH_CERT_EVAL_FAILURE;
    ssh_key client_key = NULL;
    char *keys_copy = NULL;
    char *saveptr = NULL;
    char *line = NULL;

    if (config == NULL || username == NULL || authorized_key_line == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    user = config_find_user(config, username);
    if (user == NULL) {
        LOG_WARN("Pubkey auth failed: user '%s' not found in config", username);
        return AUTH_RESULT_FAILURE;
    }

    cert_result =
        ssh_cert_evaluate_user(authorized_key_line, username, client_addr,
                               config->trusted_user_ca_keys,
                               config->revoked_user_cert_serials);
    if (cert_result == SSH_CERT_EVAL_SUCCESS) {
        LOG_INFO("SSH certificate auth success for user '%s'", username);
        return AUTH_RESULT_SUCCESS;
    }
    if (cert_result == SSH_CERT_EVAL_DENIED) {
        return AUTH_RESULT_DENIED;
    }
    if (cert_result == SSH_CERT_EVAL_FAILURE &&
        strstr(authorized_key_line, "-cert-v01@openssh.com") != NULL) {
        return AUTH_RESULT_FAILURE;
    }

    if (user->pubkeys == NULL || user->pubkeys[0] == '\0') {
        LOG_DEBUG("No authorized public keys configured for user '%s'", username);
        return AUTH_RESULT_FAILURE;
    }

    if (import_key_line(authorized_key_line, &client_key) != SSH_OK || client_key == NULL) {
        LOG_WARN("Pubkey auth failed: could not import client key for user '%s'", username);
        return AUTH_RESULT_FAILURE;
    }

    keys_copy = strdup(user->pubkeys);
    if (keys_copy == NULL) {
        ssh_key_free(client_key);
        return AUTH_RESULT_FAILURE;
    }

    for (line = strtok_r(keys_copy, "\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\n", &saveptr)) {
        ssh_key configured_key = NULL;

        while (*line == ' ' || *line == '\t') {
            line++;
        }
        if (*line == '\0' || *line == '#') {
            continue;
        }

        if (import_key_line(line, &configured_key) != SSH_OK || configured_key == NULL) {
            continue;
        }
        if (ssh_key_cmp(client_key, configured_key, SSH_KEY_CMP_PUBLIC) == 0) {
            ssh_key_free(configured_key);
            ssh_key_free(client_key);
            free(keys_copy);
            LOG_INFO("Public key auth success for user '%s'", username);
            return AUTH_RESULT_SUCCESS;
        }
        ssh_key_free(configured_key);
    }

    free(keys_copy);
    ssh_key_free(client_key);
    LOG_DEBUG("Public key auth failed for user '%s': no configured key matched", username);
    return AUTH_RESULT_FAILURE;
}

auth_result_t config_authorize_login_at(const proxy_config_t *config, const char *username,
                                        const char *client_addr, time_t now) {
    config_route_t *route = NULL;
    const char *upstream = NULL;
    char reason[256];

    if (config == NULL || username == NULL) {
        return AUTH_RESULT_FAILURE;
    }

    route = config_find_route_for_client(config, username, client_addr);
    if (route != NULL && route->upstream_host[0] != '\0') {
        upstream = route->upstream_host;
    }

    if (!config_policy_allows_connection(config, username, upstream, client_addr, now, reason,
                                         sizeof(reason))) {
        LOG_WARN("Auth denied for user '%s': %s", username,
                 reason[0] != '\0' ? reason : "denied by contextual policy");
        return AUTH_RESULT_DENIED;
    }

    return AUTH_RESULT_SUCCESS;
}

auth_result_t config_authorize_login(const proxy_config_t *config, const char *username,
                                     const char *client_addr) {
    return config_authorize_login_at(config, username, client_addr, time(NULL));
}
