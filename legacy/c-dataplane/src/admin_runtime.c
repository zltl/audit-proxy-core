/**
 * @file admin_runtime.c
 * @brief Runtime wiring helpers for the data-plane admin API
 */

#include "admin_runtime.h"
#include "logger.h"

#include <string.h>

void admin_runtime_apply_health_config(health_check_config_t *dst, const proxy_config_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }

    dst->admin_api_enabled = false;
    dst->tls_enabled = false;
    dst->tls_cert_path = NULL;
    dst->tls_key_path = NULL;
    dst->token_expiry_sec = src->admin_token_expiry_sec;

    memset(dst->admin_auth_token, 0, sizeof(dst->admin_auth_token));
    strncpy(dst->admin_auth_token, src->admin_auth_token, sizeof(dst->admin_auth_token) - 1);

    if (!src->admin_api_enabled) {
        return;
    }

    if (!src->admin_tls_enabled) {
        LOG_WARN(
            "Admin API requires TLS; disabling admin API because [admin].tls_enabled is false");
        return;
    }

    if (src->admin_tls_cert_path[0] == '\0' || src->admin_tls_key_path[0] == '\0') {
        LOG_WARN("Admin API requires tls_cert and tls_key; disabling admin API");
        return;
    }

#ifdef TLS_ENABLED
    dst->admin_api_enabled = true;
    dst->tls_enabled = true;
    dst->tls_cert_path = src->admin_tls_cert_path;
    dst->tls_key_path = src->admin_tls_key_path;
#else
    LOG_WARN(
        "Admin API TLS requested but binary was built without TLS support; disabling admin API");
#endif
}
