/**
 * @file proxy_handler.c
 * @brief SSH Proxy Core - Connection Handler Implementation
 */

#include "proxy_handler.h"
#include "channel_request_state.h"
#include "logger.h"
#include "version.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

/* Suppress deprecated warnings for ssh_message functions */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define BUF_SIZE 16384
#define MAX_EPOLL_EVENTS 4

static void emit_session_webhook(proxy_handler_context_t *ctx,
                                 webhook_event_type_t event_type,
                                 const char *username,
                                 const char *upstream_user,
                                 const char *upstream_host,
                                 uint16_t upstream_port)
{
    if (ctx == NULL || ctx->webhooks == NULL) {
        return;
    }

    session_metadata_t *meta = (ctx->session != NULL)
        ? session_get_metadata(ctx->session) : NULL;

    char detail[256];
    snprintf(detail, sizeof(detail), "%s@%s:%u",
             upstream_user != NULL ? upstream_user : "unknown",
             upstream_host != NULL ? upstream_host : "unknown",
             (unsigned int)upstream_port);

    webhook_runtime_emit(ctx->webhooks,
                         event_type,
                         username != NULL ? username : (meta ? meta->username : NULL),
                         meta ? meta->client_addr : NULL,
                         detail);
}

static void normalize_client_version(const char *banner, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (banner == NULL || banner[0] == '\0') {
        return;
    }

    const char *version = banner;
    if (strncmp(version, "SSH-2.0-", 8) == 0) {
        version += 8;
    }

    size_t len = strlen(version);
    while (len > 0 &&
           (version[len - 1] == '\r' || version[len - 1] == '\n' ||
            version[len - 1] == ' ' || version[len - 1] == '\t')) {
        len--;
    }
    if (len >= out_size) {
        len = out_size - 1;
    }
    memcpy(out, version, len);
    out[len] = '\0';
}

static void infer_client_os(const char *banner, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (banner == NULL || banner[0] == '\0') {
        return;
    }

    char lower[SESSION_MAX_CLIENT_VERSION];
    size_t i = 0;
    for (; banner[i] != '\0' && i + 1 < sizeof(lower); i++) {
        lower[i] = (char)tolower((unsigned char)banner[i]);
    }
    lower[i] = '\0';

    const char *os = "Unknown";
    if (strstr(lower, "ubuntu") != NULL) {
        os = "Ubuntu/Linux";
    } else if (strstr(lower, "debian") != NULL) {
        os = "Debian/Linux";
    } else if (strstr(lower, "centos") != NULL) {
        os = "CentOS/Linux";
    } else if (strstr(lower, "red hat") != NULL || strstr(lower, "rhel") != NULL) {
        os = "RHEL/Linux";
    } else if (strstr(lower, "fedora") != NULL) {
        os = "Fedora/Linux";
    } else if (strstr(lower, "macos") != NULL || strstr(lower, "darwin") != NULL ||
               strstr(lower, "apple") != NULL) {
        os = "macOS";
    } else if (strstr(lower, "windows") != NULL || strstr(lower, "putty") != NULL ||
               strstr(lower, "winscp") != NULL || strstr(lower, "mobaxterm") != NULL ||
               strstr(lower, "securecrt") != NULL || strstr(lower, "teraterm") != NULL) {
        os = "Windows";
    } else if (strstr(lower, "freebsd") != NULL) {
        os = "FreeBSD";
    } else if (strstr(lower, "openbsd") != NULL) {
        os = "OpenBSD";
    } else if (strstr(lower, "netbsd") != NULL) {
        os = "NetBSD";
    } else if (strstr(lower, "linux") != NULL) {
        os = "Linux";
    }

    strncpy(out, os, out_size - 1);
    out[out_size - 1] = '\0';
}

static uint64_t fnv1a64_update(uint64_t hash, const char *value)
{
    if (value == NULL) {
        return hash;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        hash ^= (uint64_t)tolower(*p);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void build_device_fingerprint(const char *client_version, const char *client_os,
                                     char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';

    uint64_t hash = 1469598103934665603ULL;
    hash = fnv1a64_update(hash, client_version);
    hash ^= (uint64_t)'|';
    hash *= 1099511628211ULL;
    hash = fnv1a64_update(hash, client_os);

    snprintf(out, out_size, "sshfp-%016llx", (unsigned long long)hash);
}

static void capture_client_identity(proxy_handler_context_t *ctx)
{
    if (ctx == NULL || ctx->session == NULL) {
        return;
    }

    session_metadata_t *meta = session_get_metadata(ctx->session);
    ssh_session client_ssh = session_get_client(ctx->session);
    if (meta == NULL || client_ssh == NULL) {
        return;
    }

    int fd = (int)ssh_get_fd(client_ssh);
    if (fd >= 0) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        if (getpeername(fd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];
            if (getnameinfo((struct sockaddr *)&peer_addr, peer_len, host, sizeof(host), service,
                            sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                strncpy(meta->client_addr, host, sizeof(meta->client_addr) - 1);
                meta->client_port = (uint16_t)strtoul(service, NULL, 10);
            }
        }
    }

    char client_version[SESSION_MAX_CLIENT_VERSION];
    normalize_client_version(ssh_get_clientbanner(client_ssh), client_version,
                             sizeof(client_version));
    if (client_version[0] != '\0') {
        strncpy(meta->client_version, client_version, sizeof(meta->client_version) - 1);
    }

    infer_client_os(client_version, meta->client_os, sizeof(meta->client_os));
    if (meta->client_version[0] != '\0' || meta->client_os[0] != '\0') {
        build_device_fingerprint(meta->client_version, meta->client_os, meta->device_fingerprint,
                                 sizeof(meta->device_fingerprint));
    }
    session_sync(ctx->session);
}

void banner_expand_vars(const char *tmpl, char *output, size_t output_size,
                        const char *username, const char *client_ip)
{
    if (tmpl == NULL || output == NULL || output_size == 0) return;

    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);

    char datetime[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", tm_info);

    const char *version = SSH_PROXY_VERSION_STRING;
    const char *user = username ? username : "unknown";
    const char *ip = client_ip ? client_ip : "unknown";

    size_t pos = 0;
    const char *p = tmpl;
    while (*p != '\0' && pos < output_size - 1) {
        if (*p == '{') {
            const char *replacement = NULL;
            size_t skip = 0;

            if (strncmp(p, "{username}", 10) == 0) {
                replacement = user; skip = 10;
            } else if (strncmp(p, "{client_ip}", 11) == 0) {
                replacement = ip; skip = 11;
            } else if (strncmp(p, "{datetime}", 10) == 0) {
                replacement = datetime; skip = 10;
            } else if (strncmp(p, "{hostname}", 10) == 0) {
                replacement = hostname; skip = 10;
            } else if (strncmp(p, "{version}", 9) == 0) {
                replacement = version; skip = 9;
            }

            if (replacement != NULL) {
                size_t rlen = strlen(replacement);
                if (pos + rlen < output_size - 1) {
                    memcpy(output + pos, replacement, rlen);
                    pos += rlen;
                }
                p += skip;
                continue;
            }
        }
        output[pos++] = *p++;
    }
    output[pos] = '\0';
}

void banner_expand_vars_ctx(const char *tmpl, char *output, size_t output_size,
                            const banner_context_t *bctx)
{
    if (tmpl == NULL || output == NULL || output_size == 0) return;

    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);

    char datetime[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", tm_info);

    const char *version = SSH_PROXY_VERSION_STRING;
    const char *user = (bctx && bctx->username) ? bctx->username : "unknown";
    const char *ip = (bctx && bctx->client_ip) ? bctx->client_ip : "unknown";
    const char *up_host = (bctx && bctx->upstream_host) ? bctx->upstream_host : "unknown";
    const char *up_user = (bctx && bctx->upstream_user) ? bctx->upstream_user : "unknown";

    char up_port_str[16];
    snprintf(up_port_str, sizeof(up_port_str), "%u", bctx ? bctx->upstream_port : 0);

    char session_id_str[32];
    snprintf(session_id_str, sizeof(session_id_str), "%lu",
             bctx ? (unsigned long)bctx->session_id : 0UL);

    size_t pos = 0;
    const char *p = tmpl;
    while (*p != '\0' && pos < output_size - 1) {
        if (*p == '{') {
            const char *replacement = NULL;
            size_t skip = 0;

            if (strncmp(p, "{username}", 10) == 0) { replacement = user; skip = 10; }
            else if (strncmp(p, "{client_ip}", 11) == 0) { replacement = ip; skip = 11; }
            else if (strncmp(p, "{datetime}", 10) == 0) { replacement = datetime; skip = 10; }
            else if (strncmp(p, "{hostname}", 10) == 0) { replacement = hostname; skip = 10; }
            else if (strncmp(p, "{version}", 9) == 0) { replacement = version; skip = 9; }
            else if (strncmp(p, "{upstream_host}", 15) == 0) { replacement = up_host; skip = 15; }
            else if (strncmp(p, "{upstream_port}", 15) == 0) { replacement = up_port_str; skip = 15; }
            else if (strncmp(p, "{upstream_user}", 15) == 0) { replacement = up_user; skip = 15; }
            else if (strncmp(p, "{session_id}", 12) == 0) { replacement = session_id_str; skip = 12; }

            if (replacement != NULL) {
                size_t rlen = strlen(replacement);
                if (pos + rlen < output_size - 1) {
                    memcpy(output + pos, replacement, rlen);
                    pos += rlen;
                }
                p += skip;
                continue;
            }
        }
        output[pos++] = *p++;
    }
    output[pos] = '\0';
}

/**
 * @brief Send pre-auth banner to client
 */
static int send_banner(ssh_session client_ssh, const char *banner_path)
{
    if (banner_path == NULL || banner_path[0] == '\0') return 0;

    FILE *f = fopen(banner_path, "r");
    if (f == NULL) {
        LOG_WARN("Cannot open banner file: %s", banner_path);
        return -1;
    }

    char banner[4096];
    size_t n = fread(banner, 1, sizeof(banner) - 1, f);
    fclose(f);
    banner[n] = '\0';

    char expanded[4096];
    banner_expand_vars(banner, expanded, sizeof(expanded), NULL, NULL);

    ssh_string banner_str = ssh_string_from_char(expanded);
    if (banner_str == NULL) {
        LOG_WARN("Failed to allocate SSH string for banner");
        return -1;
    }
    int rc = ssh_send_issue_banner(client_ssh, banner_str);
    ssh_string_free(banner_str);
    if (rc != SSH_OK) {
        LOG_DEBUG("Failed to send banner: %d", rc);
    }
    return rc == SSH_OK ? 0 : -1;
}

/* Helper to clean up context */
static void free_context(proxy_handler_context_t *ctx) {
    if (ctx) {
        /* Session is managed by session_manager, but we need to remove it */
        if (ctx->session_mgr && ctx->session) {
            session_manager_remove_session(ctx->session_mgr, ctx->session);
        }
        free(ctx);
    }
}

/* Setup authentication callbacks and perform handshake */
static int setup_auth_and_handshake(proxy_handler_context_t *ctx, char **username_out) {
    ssh_session session = session_get_client(ctx->session);
    
    session_set_state(ctx->session, SESSION_STATE_AUTH);

    /* Send pre-auth banner if configured */
    if (ctx->config != NULL && ctx->config->banner_path[0] != '\0') {
        send_banner(session, ctx->config->banner_path);
    }

    /* Perform key exchange first */
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        LOG_ERROR("Key exchange failed: %s", ssh_get_error(session));
        return -1;
    }
    capture_client_identity(ctx);
    
    /* Handle authentication messages manually */
    ssh_message message;
    int auth_attempts = 0;
    const int max_attempts = 3;
    bool authenticated = false;
    
    while (!authenticated && auth_attempts < max_attempts) {
        message = ssh_message_get(session);
        if (!message) {
            continue; /* Wait for client to send auth request */
        }
        
        /* Handle authentication messages */
        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            const char *user = ssh_message_auth_user(message);
            if (user && *username_out == NULL) {
                *username_out = strdup(user);
                session_set_username(ctx->session, user);
            }
            
            int subtype = ssh_message_subtype(message);
            session_metadata_t *meta = session_get_metadata(ctx->session);
            filter_context_t filter_ctx = {
                .session = ctx->session,
                .username = user,
                .password = NULL,
                .pubkey = NULL,
                .pubkey_len = 0
            };
            
            if (subtype == SSH_AUTH_METHOD_PASSWORD) {
                if (meta != NULL) {
                    meta->auth_method = SESSION_AUTH_PASSWORD;
                }
                filter_ctx.password = ssh_message_auth_password(message);
                LOG_DEBUG("Password auth attempt for user '%s'", user);
                
                /* Run auth filters only for password/pubkey auth */
                filter_status_t status = filter_chain_on_auth(ctx->filters, &filter_ctx);
                
                if (status == FILTER_CONTINUE) {
                    filter_status_t authz_status = FILTER_CONTINUE;
                    if (ctx->filters != NULL) {
                        filter_context_t authenticated_ctx = {
                            .session = ctx->session,
                            .username = user,
                            .user_data = NULL
                        };
                        authz_status = filter_chain_on_authenticated(ctx->filters, &authenticated_ctx);
                    }

                    if (authz_status == FILTER_CONTINUE) {
                        authenticated = true;
                        ssh_message_auth_reply_success(message, 0);
                        LOG_INFO("User '%s' authenticated successfully", user);
                    } else {
                        auth_attempts++;
                        ssh_message_reply_default(message);
                        LOG_WARN("Post-authentication policy rejected user '%s' (attempt %d/%d)",
                                 user, auth_attempts, max_attempts);
                    }
                } else {
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    LOG_WARN("Authentication failed for user '%s' (attempt %d/%d)", 
                             user, auth_attempts, max_attempts);
                }
            } else if (subtype == SSH_AUTH_METHOD_PUBLICKEY) {
                if (meta != NULL) {
                    meta->auth_method = SESSION_AUTH_PUBLICKEY;
                }
                ssh_key client_pubkey = ssh_message_auth_pubkey(message);
                if (client_pubkey == NULL) {
                    LOG_DEBUG("No public key in auth message for user '%s'", user);
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                    continue;
                }

                /* Handle SSH_PUBLICKEY_STATE_VALID (signature present) vs query-only */
                enum ssh_publickey_state_e key_state = ssh_message_auth_publickey_state(message);

                if (key_state == SSH_PUBLICKEY_STATE_NONE) {
                    /* Client is querying if this key type is accepted — accept the probe */
                    ssh_message_auth_reply_pk_ok_simple(message);
                    ssh_message_free(message);
                    continue;
                }

                /* SSH_PUBLICKEY_STATE_VALID: signature verified by libssh, now check authorization */
                char *pubkey_b64 = NULL;
                const char *pubkey_type = ssh_key_type_to_char(ssh_key_type(client_pubkey));
                if (pubkey_type == NULL ||
                    ssh_pki_export_pubkey_base64(client_pubkey, &pubkey_b64) != SSH_OK ||
                    pubkey_b64 == NULL) {
                    LOG_WARN("Failed to export public key base64 for user '%s'", user);
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                    continue;
                }

                size_t line_len = strlen(pubkey_type) + 1 + strlen(pubkey_b64) + 1;
                char *pubkey_line = malloc(line_len);
                if (pubkey_line == NULL) {
                    ssh_string_free_char(pubkey_b64);
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                    continue;
                }

                snprintf(pubkey_line, line_len, "%s %s", pubkey_type, pubkey_b64);
                filter_ctx.pubkey = pubkey_line;
                filter_ctx.pubkey_len = strlen(pubkey_line);
                LOG_DEBUG("Public key auth attempt for user '%s' (type=%s len=%zu)", user,
                          pubkey_type, filter_ctx.pubkey_len);

                filter_status_t status = filter_chain_on_auth(ctx->filters, &filter_ctx);

                if (status == FILTER_CONTINUE) {
                    filter_status_t authz_status = FILTER_CONTINUE;
                    if (ctx->filters != NULL) {
                        filter_context_t authenticated_ctx = {
                            .session = ctx->session,
                            .username = user,
                            .user_data = NULL
                        };
                        authz_status = filter_chain_on_authenticated(ctx->filters, &authenticated_ctx);
                    }

                    if (authz_status == FILTER_CONTINUE) {
                        authenticated = true;
                        ssh_message_auth_reply_success(message, 0);
                        LOG_INFO("User '%s' authenticated successfully with public key", user);
                    } else {
                        auth_attempts++;
                        ssh_message_reply_default(message);
                        LOG_WARN("Post-authentication policy rejected user '%s' (attempt %d/%d)",
                                 user, auth_attempts, max_attempts);
                    }
                } else {
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    LOG_WARN("Public key authentication failed for user '%s' (attempt %d/%d)", 
                             user, auth_attempts, max_attempts);
                }
                free(pubkey_line);
                ssh_string_free_char(pubkey_b64);
            } else {
                /* Handle other auth methods (like "none") - just reject them */
                LOG_DEBUG("Unsupported auth method %d for user '%s'", subtype, user);
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        
        ssh_message_free(message);
    }
    
    return authenticated ? 0 : -1;
}

static void set_connect_result_target(connect_result_t *cr, const char *username,
                                      const char *upstream_host, uint16_t upstream_port,
                                      const char *upstream_user) {
    if (cr == NULL) {
        return;
    }
    memset(cr->host, 0, sizeof(cr->host));
    memset(cr->user, 0, sizeof(cr->user));
    if (upstream_host != NULL) {
        strncpy(cr->host, upstream_host, sizeof(cr->host) - 1);
    }
    cr->port = upstream_port;
    if (upstream_user != NULL) {
        strncpy(cr->user, upstream_user, sizeof(cr->user) - 1);
    } else if (username != NULL) {
        strncpy(cr->user, username, sizeof(cr->user) - 1);
    }
}

static bool upstream_error_retryable(upstream_error_t error) {
    return error == UPSTREAM_ERR_CONNECT_FAILED || error == UPSTREAM_ERR_CIRCUIT_OPEN;
}

static void sleep_retry_delay_ms(uint32_t delay_ms) {
    struct timespec ts;

    if (delay_ms == 0) {
        return;
    }
    ts.tv_sec = (time_t)(delay_ms / 1000);
    ts.tv_nsec = (long)(delay_ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static ssh_session connect_resolved_upstream(proxy_handler_context_t *ctx, const char *username,
                                             const char *client_addr, session_metadata_t *meta,
                                             const char *upstream_host, uint16_t upstream_port,
                                             const char *upstream_user,
                                             const char *privkey_path, config_route_t *route,
                                             bool half_open_probe, connect_result_t *cr) {
    ssh_session upstream;
    int rc = SSH_AUTH_DENIED;

    set_connect_result_target(cr, username, upstream_host, upstream_port, upstream_user);
    if (meta != NULL) {
        strncpy(meta->target_addr, upstream_host, sizeof(meta->target_addr) - 1);
        meta->target_port = upstream_port;
        session_sync(ctx->session);
    }

    if (ctx->config != NULL) {
        char reason[256];
        if (!config_policy_allows_connection(ctx->config, username, upstream_host, client_addr,
                                             time(NULL), reason, sizeof(reason))) {
            if (half_open_probe) {
                config_route_circuit_release_probe(route);
            }
            cr->error = UPSTREAM_ERR_POLICY_DENIED;
            snprintf(cr->stage, sizeof(cr->stage), "Policy evaluation");
            snprintf(cr->detail, sizeof(cr->detail), "%s",
                     reason[0] != '\0' ? reason : "connection denied by policy");
            return NULL;
        }
    }

    upstream = ssh_new();
    if (upstream == NULL) {
        if (half_open_probe) {
            config_route_circuit_release_probe(route);
        }
        LOG_ERROR("Failed to create upstream SSH session");
        cr->error = UPSTREAM_ERR_SESSION_ALLOC;
        snprintf(cr->stage, sizeof(cr->stage), "Session allocation");
        snprintf(cr->detail, sizeof(cr->detail), "Failed to create SSH session object");
        return NULL;
    }

    ssh_options_set(upstream, SSH_OPTIONS_HOST, upstream_host);
    ssh_options_set(upstream, SSH_OPTIONS_PORT, &upstream_port);
    if (upstream_user != NULL) {
        ssh_options_set(upstream, SSH_OPTIONS_USER, upstream_user);
    }

    if (half_open_probe) {
        LOG_INFO("Probing half-open circuit for %s:%u", upstream_host, upstream_port);
    }
    LOG_DEBUG("Connecting to upstream %s:%u", upstream_host, upstream_port);
    cr->attempts++;

    if (ssh_connect(upstream) != SSH_OK) {
        if (route != NULL) {
            config_route_circuit_record_failure(ctx->config, route, time(NULL));
        } else if (half_open_probe) {
            config_route_circuit_release_probe(route);
        }
        LOG_ERROR("Failed to connect to upstream %s:%u: %s", upstream_host, upstream_port,
                  ssh_get_error(upstream));
        cr->error = UPSTREAM_ERR_CONNECT_FAILED;
        snprintf(cr->stage, sizeof(cr->stage), "TCP connection");
        snprintf(cr->detail, sizeof(cr->detail), "%s", ssh_get_error(upstream));
        ssh_free(upstream);
        return NULL;
    }

    if (route != NULL) {
        config_route_circuit_record_success(route);
    }
    LOG_INFO("Connected to upstream %s:%u", upstream_host, upstream_port);

    if (privkey_path != NULL) {
        LOG_DEBUG("Trying private key auth with %s", privkey_path);
        ssh_key privkey = NULL;
        if (ssh_pki_import_privkey_file(privkey_path, NULL, NULL, NULL, &privkey) == SSH_OK) {
            rc = ssh_userauth_publickey(upstream, upstream_user, privkey);
            ssh_key_free(privkey);
            if (rc == SSH_AUTH_SUCCESS) {
                LOG_INFO("Upstream auth successful with private key");
                return upstream;
            }
            cr->error = UPSTREAM_ERR_AUTH_PRIVKEY;
            snprintf(cr->stage, sizeof(cr->stage), "Private key authentication");
            snprintf(cr->detail, sizeof(cr->detail), "%s", ssh_get_error(upstream));
        } else {
            LOG_WARN("Failed to load private key: %s", privkey_path);
            cr->error = UPSTREAM_ERR_AUTH_PRIVKEY_LOAD;
            snprintf(cr->stage, sizeof(cr->stage), "Private key loading");
            snprintf(cr->detail, sizeof(cr->detail), "Failed to load key: %.230s", privkey_path);
        }
    }

    if (rc != SSH_AUTH_SUCCESS) {
        rc = ssh_userauth_publickey_auto(upstream, upstream_user, NULL);
        if (rc == SSH_AUTH_SUCCESS) {
            LOG_INFO("Upstream auth successful with auto publickey");
            return upstream;
        }
        cr->error = UPSTREAM_ERR_AUTH_AUTO;
        snprintf(cr->stage, sizeof(cr->stage), "Auto key authentication");
        snprintf(cr->detail, sizeof(cr->detail), "%s", ssh_get_error(upstream));
    }

    if (rc != SSH_AUTH_SUCCESS) {
        rc = ssh_userauth_none(upstream, upstream_user);
        if (rc == SSH_AUTH_SUCCESS) {
            LOG_INFO("Upstream auth successful with none");
            return upstream;
        }
    }

    LOG_ERROR("Failed to authenticate to upstream %s:%u", upstream_host, upstream_port);
    cr->error = UPSTREAM_ERR_AUTH_ALL_FAILED;
    snprintf(cr->stage, sizeof(cr->stage), "Upstream authentication");
    snprintf(cr->detail, sizeof(cr->detail), "All auth methods failed for %.200s:%u",
             upstream_host, upstream_port);
    ssh_disconnect(upstream);
    ssh_free(upstream);
    return NULL;
}

/* Connect to upstream */
static ssh_session connect_upstream(proxy_handler_context_t *ctx, const char *username,
                                    connect_result_t *cr) {
    static const uint32_t kDefaultRetryInitialDelayMs = 100;
    static const uint32_t kDefaultRetryMaxDelayMs = 5000;
    static const float kDefaultRetryBackoff = 2.0f;
    const char *default_host = "127.0.0.1";
    uint16_t default_port = 22;
    session_metadata_t *meta = session_get_metadata(ctx->session);
    const char *client_addr =
        (meta != NULL && meta->client_addr[0] != '\0') ? meta->client_addr : NULL;
    int max_retries = 0;
    uint32_t delay_ms = kDefaultRetryInitialDelayMs;
    uint32_t max_delay_ms = kDefaultRetryMaxDelayMs;
    float backoff = kDefaultRetryBackoff;

    memset(cr, 0, sizeof(*cr));
    cr->error = UPSTREAM_ERR_NONE;

    if (ctx->config != NULL) {
        max_retries = ctx->config->router_retry_max;
        delay_ms = ctx->config->router_retry_initial_delay_ms > 0
                       ? ctx->config->router_retry_initial_delay_ms
                       : kDefaultRetryInitialDelayMs;
        max_delay_ms = ctx->config->router_retry_max_delay_ms >= delay_ms
                           ? ctx->config->router_retry_max_delay_ms
                           : delay_ms;
        backoff = ctx->config->router_retry_backoff_factor >= 1.0f
                      ? ctx->config->router_retry_backoff_factor
                      : kDefaultRetryBackoff;
    }
    if (max_retries < 0) {
        max_retries = 0;
    }

    for (int round = 0; round <= max_retries; round++) {
        config_route_t **routes = NULL;
        size_t route_count = 0;
        bool attempted_route = false;
        bool skipped_open = false;

        if (ctx->config != NULL) {
            route_count =
                config_get_route_candidates_for_client(ctx->config, username, client_addr, &routes);
        }

        if (route_count == 0) {
            if (round == 0) {
                LOG_WARN("No route found for user '%s', using default", username);
            }
            free(routes);
            return connect_resolved_upstream(ctx, username, client_addr, meta, default_host,
                                             default_port, NULL, NULL, NULL, false, cr);
        }

        for (size_t i = 0; i < route_count; i++) {
            config_route_t *route = routes[i];
            bool half_open_probe = false;

            if (!config_route_circuit_try_acquire(ctx->config, route, time(NULL),
                                                  &half_open_probe)) {
                skipped_open = true;
                LOG_WARN("Skipping route '%s' -> %s:%u because its circuit is open",
                         route->proxy_user, route->upstream_host, route->upstream_port);
                continue;
            }

            attempted_route = true;
            LOG_INFO("Route candidate for user '%s' from %s -> %s:%u (user=%s%s%s%s%s%s)",
                     username, client_addr != NULL ? client_addr : "unknown",
                     route->upstream_host, route->upstream_port,
                     route->upstream_user[0] != '\0' ? route->upstream_user : "(default)",
                     route->geo_city[0] != '\0' ? ", city=" : "",
                     route->geo_city[0] != '\0' ? route->geo_city : "",
                     route->geo_region[0] != '\0' ? ", region=" : "",
                     route->geo_region[0] != '\0' ? route->geo_region : "",
                     half_open_probe ? ", circuit=half-open" : "");

            ssh_session upstream =
                connect_resolved_upstream(ctx, username, client_addr, meta, route->upstream_host,
                                          route->upstream_port,
                                          route->upstream_user[0] != '\0'
                                              ? route->upstream_user
                                              : NULL,
                                          route->privkey_path[0] != '\0' ? route->privkey_path
                                                                          : NULL,
                                          route, half_open_probe, cr);
            if (upstream != NULL) {
                free(routes);
                return upstream;
            }
            if (!upstream_error_retryable(cr->error)) {
                free(routes);
                return NULL;
            }
        }

        free(routes);
        if (!attempted_route && skipped_open) {
            cr->error = UPSTREAM_ERR_CIRCUIT_OPEN;
            snprintf(cr->stage, sizeof(cr->stage), "Circuit breaker");
            snprintf(cr->detail, sizeof(cr->detail),
                     "All matching upstream circuits are open; waiting for recovery");
        }
        if (round >= max_retries || !upstream_error_retryable(cr->error)) {
            break;
        }
        LOG_INFO("Retrying upstream connect for user '%s' (%d/%d) after %u ms",
                 username != NULL ? username : "unknown", round + 1, max_retries, delay_ms);
        sleep_retry_delay_ms(delay_ms);
        if ((float)delay_ms * backoff > (float)max_delay_ms) {
            delay_ms = max_delay_ms;
        } else {
            delay_ms = (uint32_t)((float)delay_ms * backoff);
        }
    }

    return NULL;
}

/* Forwarding loop with epoll and audit recording */
static void forward_loop(proxy_handler_context_t *ctx, 
                         ssh_channel client_chan, 
                         ssh_channel upstream_channel,
                         const char *username) {
    char buf[BUF_SIZE];
    int nbytes, rc;
    
    /* Create filter context for data callbacks */
    filter_context_t filter_ctx = {
        .session = ctx->session,
        .username = username,
        .user_data = NULL
    };
    session_stats_t *stats = session_get_stats(ctx->session);

    /* Get socket file descriptors for epoll */
    ssh_session client_session = session_get_client(ctx->session);
    ssh_session upstream_session = session_get_upstream(ctx->session);
    
    socket_t client_fd = ssh_get_fd(client_session);
    socket_t upstream_fd = ssh_get_fd(upstream_session);
    
    if (client_fd < 0 || upstream_fd < 0) {
        LOG_ERROR("Failed to get socket fds: client=%d, upstream=%d", 
                  client_fd, upstream_fd);
        return;
    }
    
    /* Create epoll instance */
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        LOG_ERROR("epoll_create1 failed: %s", strerror(errno));
        return;
    }
    
    /* Add client socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl add client_fd failed: %s", strerror(errno));
        close(epoll_fd);
        return;
    }
    
    /* Add upstream socket to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = upstream_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl add upstream_fd failed: %s", strerror(errno));
        close(epoll_fd);
        return;
    }
    
    LOG_DEBUG("Forward loop started: client_fd=%d, upstream_fd=%d", client_fd, upstream_fd);

    /* Event-driven forwarding loop */
    struct epoll_event events[MAX_EPOLL_EVENTS];
    
    while (ssh_channel_is_open(client_chan) && ssh_channel_is_open(upstream_channel)) {
        /* Check for EOF before waiting */
        if (ssh_channel_is_eof(client_chan) || ssh_channel_is_eof(upstream_channel)) {
            break;
        }
        
        /* Wait for events with 100ms timeout to allow periodic checks */
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 100);
        
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted, retry */
            }
            LOG_ERROR("epoll_wait failed: %s", strerror(errno));
            break;
        }
        
        /* Process events or handle data even on timeout (libssh may have buffered data) */
        
        /* Always try to read from client channel (libssh buffers data internally) */
        while ((nbytes = ssh_channel_read_nonblocking(client_chan, buf, sizeof(buf), 0)) > 0) {
            /* Call filter chain for upstream data (client -> upstream) */
            if (ctx->filters != NULL) {
                filter_chain_on_data_upstream(ctx->filters, &filter_ctx, 
                                              (const uint8_t *)buf, (size_t)nbytes);
            }
            
            rc = ssh_channel_write(upstream_channel, buf, nbytes);
            if (rc < 0) {
                LOG_DEBUG("Write to upstream failed");
                goto end_loop;
            }
            if (stats != NULL) {
                stats->bytes_sent += (uint64_t)rc;
            }
            session_touch(ctx->session);
        }
        if (nbytes < 0 && nbytes != SSH_AGAIN) {
            LOG_DEBUG("Read from client failed: %d", nbytes);
            break;
        }

        /* Also check client stderr channel */
        while ((nbytes = ssh_channel_read_nonblocking(client_chan, buf, sizeof(buf), 1)) > 0) {
            rc = ssh_channel_write_stderr(upstream_channel, buf, nbytes);
            if (rc < 0) {
                goto end_loop;
            }
            if (stats != NULL) {
                stats->bytes_sent += (uint64_t)rc;
            }
            session_touch(ctx->session);
        }

        /* Always try to read from upstream channel */
        while ((nbytes = ssh_channel_read_nonblocking(upstream_channel, buf, sizeof(buf), 0)) > 0) {
            /* Call filter chain for downstream data (upstream -> client) */
            if (ctx->filters != NULL) {
                filter_chain_on_data_downstream(ctx->filters, &filter_ctx,
                                                (const uint8_t *)buf, (size_t)nbytes);
            }
            
            rc = ssh_channel_write(client_chan, buf, nbytes);
            if (rc < 0) {
                LOG_DEBUG("Write to client failed");
                goto end_loop;
            }
            if (stats != NULL) {
                stats->bytes_received += (uint64_t)rc;
            }
            session_touch(ctx->session);
        }
        if (nbytes < 0 && nbytes != SSH_AGAIN) {
            LOG_DEBUG("Read from upstream failed: %d", nbytes);
            break;
        }

        /* Also check upstream stderr channel */
        while ((nbytes = ssh_channel_read_nonblocking(upstream_channel, buf, sizeof(buf), 1)) > 0) {
            rc = ssh_channel_write_stderr(client_chan, buf, nbytes);
            if (rc < 0) {
                goto end_loop;
            }
            if (stats != NULL) {
                stats->bytes_received += (uint64_t)rc;
            }
            session_touch(ctx->session);
        }
    }

end_loop:
    close(epoll_fd);
    LOG_DEBUG("Forward loop ended");
}

/* Write formatted message to client channel */
static void send_channel_msg(ssh_channel ch, const char *fmt, ...) {
    if (ch == NULL) return;
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        ssh_channel_write(ch, buf, (uint32_t)n);
    }
}

/* Send connection status header to client */
static void send_connection_header(ssh_channel ch, const char *username,
                                   const char *client_ip, const char *upstream_host,
                                   uint16_t upstream_port, const char *upstream_user,
                                   uint64_t session_id)
{
    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);

    char datetime[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", tm_info);

    send_channel_msg(ch,
        "\r\n"
        "\033[1;36m"
        "========================================\r\n"
        "  SSH Proxy v%s @ %s\r\n"
        "========================================\r\n"
        "\033[0m"
        "  User:    \033[1;33m%s\033[0m\r\n"
        "  From:    %s\r\n"
        "  Route:   %s -> %s:%u (user: %s)\r\n"
        "  Session: #%lu | %s\r\n"
        "\033[1;36m----------------------------------------\033[0m\r\n",
        SSH_PROXY_VERSION_STRING, hostname,
        username ? username : "unknown",
        client_ip ? client_ip : "unknown",
        username ? username : "unknown",
        upstream_host ? upstream_host : "unknown",
        upstream_port,
        upstream_user ? upstream_user : "(default)",
        (unsigned long)session_id, datetime);
}

/* Get human-readable error stage */
static const char *upstream_error_stage(upstream_error_t err) {
    switch (err) {
        case UPSTREAM_ERR_ROUTE_NOT_FOUND:   return "Route Lookup";
        case UPSTREAM_ERR_SESSION_ALLOC:     return "Session Allocation";
        case UPSTREAM_ERR_CONNECT_FAILED:    return "TCP Connection";
        case UPSTREAM_ERR_HOST_KEY:          return "Host Key Verification";
        case UPSTREAM_ERR_AUTH_PRIVKEY_LOAD: return "Private Key Loading";
        case UPSTREAM_ERR_AUTH_PRIVKEY:      return "Private Key Authentication";
        case UPSTREAM_ERR_AUTH_AUTO:         return "Automatic Key Authentication";
        case UPSTREAM_ERR_AUTH_NONE:         return "Server Authentication";
        case UPSTREAM_ERR_AUTH_ALL_FAILED:   return "Upstream Authentication";
        case UPSTREAM_ERR_POLICY_DENIED:     return "Policy Evaluation";
        case UPSTREAM_ERR_CIRCUIT_OPEN:      return "Circuit Breaker";
        case UPSTREAM_ERR_CHANNEL_OPEN:      return "Channel Setup";
        case UPSTREAM_ERR_CHANNEL_REQUEST:   return "Channel Request";
        default:                             return "Unknown";
    }
}

/* Send error report to client channel */
static void send_connection_error(ssh_channel ch, const connect_result_t *result)
{
    send_channel_msg(ch,
        "  \033[1;31m[" "\xe2\x9c\x97" "] %s failed\033[0m\r\n"
        "      Error: %s\r\n"
        "\r\n"
        "  \033[1mStage:\033[0m %s\r\n",
        result->stage,
        result->detail[0] ? result->detail : "Unknown error",
        upstream_error_stage(result->error));

    send_channel_msg(ch, "  \033[1mPossible causes:\033[0m\r\n");

    switch (result->error) {
        case UPSTREAM_ERR_ROUTE_NOT_FOUND:
            send_channel_msg(ch,
                "    * No route configured for user '%s'\r\n"
                "    * Check [route:] sections in proxy configuration\r\n",
                result->user);
            break;
        case UPSTREAM_ERR_CONNECT_FAILED:
            send_channel_msg(ch,
                "    * Upstream server %s:%u may be down\r\n"
                "    * Port %u may be blocked by firewall\r\n"
                "    * DNS resolution for '%s' may have failed\r\n",
                result->host, result->port, result->port, result->host);
            break;
        case UPSTREAM_ERR_HOST_KEY:
            send_channel_msg(ch,
                "    * Upstream host key has changed\r\n"
                "    * Host key not in known_hosts\r\n");
            break;
        case UPSTREAM_ERR_AUTH_PRIVKEY_LOAD:
            send_channel_msg(ch,
                "    * Private key file may not exist or is unreadable\r\n"
                "    * Key file permissions may be incorrect\r\n");
            break;
        case UPSTREAM_ERR_AUTH_PRIVKEY:
        case UPSTREAM_ERR_AUTH_AUTO:
        case UPSTREAM_ERR_AUTH_ALL_FAILED:
            send_channel_msg(ch,
                "    * Upstream server %s rejected authentication\r\n"
                "    * Private key may not be authorized on upstream\r\n"
                "    * Upstream user '%s' may not exist\r\n",
                result->host,
                result->user[0] ? result->user : "(default)");
            break;
        case UPSTREAM_ERR_POLICY_DENIED:
            send_channel_msg(ch,
                "    * Access is blocked by a contextual policy\r\n"
                "    * Check login window or source-network restrictions for '%s'\r\n",
                result->user[0] ? result->user : "(default)");
            break;
        case UPSTREAM_ERR_CIRCUIT_OPEN:
            send_channel_msg(ch,
                "    * All matching upstream nodes are temporarily marked unhealthy\r\n"
                "    * Wait for the circuit-breaker cool-down window to expire\r\n"
                "    * Check upstream node health or route pool size for '%s'\r\n",
                result->user[0] ? result->user : "(default)");
            break;
        case UPSTREAM_ERR_SESSION_ALLOC:
            send_channel_msg(ch,
                "    * Proxy server out of memory\r\n"
                "    * Too many concurrent connections\r\n");
            break;
        case UPSTREAM_ERR_CHANNEL_OPEN:
            send_channel_msg(ch,
                "    * Upstream server denied channel open request\r\n"
                "    * Upstream MaxSessions limit may be reached\r\n");
            break;
        case UPSTREAM_ERR_CHANNEL_REQUEST:
            send_channel_msg(ch,
                "    * Upstream server rejected the requested shell, exec, or subsystem\r\n"
                "    * The requested subsystem may not be installed on upstream\r\n"
                "    * The upstream account may not be allowed to start that service\r\n");
            break;
        default:
            send_channel_msg(ch, "    * An unexpected error occurred\r\n");
            break;
    }

    send_channel_msg(ch,
        "\r\n"
        "  \033[1mSuggestions:\033[0m\r\n"
        "    * Contact your system administrator\r\n"
        "    * Try again later\r\n");

    if (result->host[0] && result->port > 0) {
        send_channel_msg(ch,
            "    * Verify: ssh -p %u %s%s%s\r\n",
            result->port,
            result->user[0] ? result->user : "",
            result->user[0] ? "@" : "",
            result->host);
    }

    send_channel_msg(ch,
        "\033[1;36m========================================\033[0m\r\n\r\n");
}

static void report_channel_request_error(ssh_session upstream_session,
                                         ssh_channel client_channel,
                                         bool show_progress,
                                         const connect_result_t *base_result,
                                         const char *stage)
{
    connect_result_t req_err = {0};

    req_err.error = UPSTREAM_ERR_CHANNEL_REQUEST;
    snprintf(req_err.stage, sizeof(req_err.stage), "%s", stage);
    snprintf(req_err.detail, sizeof(req_err.detail), "%s", ssh_get_error(upstream_session));
    if (base_result != NULL) {
        strncpy(req_err.host, base_result->host, sizeof(req_err.host) - 1);
        req_err.port = base_result->port;
        strncpy(req_err.user, base_result->user, sizeof(req_err.user) - 1);
    }

    LOG_ERROR("%s failed: %s", stage, req_err.detail);
    if (show_progress && client_channel != NULL) {
        send_connection_error(client_channel, &req_err);
    }
}

/* Send success footer to client */
static void send_connection_success(ssh_channel ch)
{
    send_channel_msg(ch,
        "\033[1;36m========================================\033[0m\r\n\r\n");
}

void *proxy_handler_run(void *arg) {
    proxy_handler_context_t *ctx = (proxy_handler_context_t *)arg;
    ssh_session client_session = session_get_client(ctx->session);
    char *username = NULL;
    ssh_session upstream_session = NULL;
    ssh_channel client_channel = NULL;
    ssh_channel upstream_channel = NULL;
    channel_request_state_t request_state;

    LOG_INFO("Handler started for session %lu", session_get_id(ctx->session));
    channel_request_state_init(&request_state);

    /* 1. Setup auth callbacks and perform handshake/auth */
    if (setup_auth_and_handshake(ctx, &username) != 0) {
        goto cleanup;
    }
    session_set_state(ctx->session, SESSION_STATE_AUTHENTICATED);

    /* 2. Open Channel - Wait for channel open request from client */
    /* (Moved BEFORE upstream connect so we can send status messages) */
    ssh_message message;
    while ((message = ssh_message_get(client_session))) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            client_channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (client_channel == NULL) {
        LOG_ERROR("Client did not request session channel");
        goto cleanup;
    }

    /* 3. Handle PTY/Shell/Exec requests from client */
    /* Save these for later replay to upstream after connection is established */
    while ((message = ssh_message_get(client_session))) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
            ssh_message_channel_request_channel(message) == client_channel) {
            
            int subtype = ssh_message_subtype(message);
            if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
                channel_request_state_set_shell(&request_state);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            } else if (subtype == SSH_CHANNEL_REQUEST_EXEC) {
                const char *cmd = ssh_message_channel_request_command(message);
                channel_request_state_set_exec(&request_state, cmd);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            } else if (subtype == SSH_CHANNEL_REQUEST_SUBSYSTEM) {
                const char *subsystem = ssh_message_channel_request_subsystem(message);
                channel_request_state_set_subsystem(&request_state, subsystem);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            } else if (subtype == SSH_CHANNEL_REQUEST_PTY) {
                const char *term = ssh_message_channel_request_pty_term(message);
                int width = ssh_message_channel_request_pty_width(message);
                int height = ssh_message_channel_request_pty_height(message);
                
                LOG_DEBUG("PTY request: term=%s, size=%dx%d", 
                          term ? term : "unknown", width, height);
                
                channel_request_state_set_pty(&request_state, term, width, height);
                
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                continue;
            } else if (subtype == SSH_CHANNEL_REQUEST_ENV) {
                const char *env_name = ssh_message_channel_request_env_name(message);
                const char *env_value = ssh_message_channel_request_env_value(message);
                channel_request_state_add_env(&request_state, env_name, env_value);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                continue;
            } else if (subtype == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
                /* Save as PTY size update */
                channel_request_state_update_window(&request_state,
                                                    ssh_message_channel_request_pty_width(message),
                                                    ssh_message_channel_request_pty_height(message));
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                continue;
            }
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    /* 4. Look up route info for display */
    const char *disp_upstream_host = "127.0.0.1";
    uint16_t disp_upstream_port = 22;
    const char *disp_upstream_user = NULL;
    if (ctx->config != NULL) {
        session_metadata_t *meta = session_get_metadata(ctx->session);
        const char *client_addr =
            (meta != NULL && meta->client_addr[0] != '\0') ? meta->client_addr : NULL;
        config_route_t *route = config_find_route_for_client(ctx->config, username, client_addr);
        if (route != NULL) {
            disp_upstream_host = route->upstream_host;
            disp_upstream_port = route->upstream_port;
            disp_upstream_user = route->upstream_user[0] ? route->upstream_user : NULL;
        }
    }

    /* 5. Send connection progress header */
    bool show_progress = (ctx->config == NULL || ctx->config->show_progress);
    if (show_progress && client_channel != NULL) {
        session_metadata_t *meta = session_get_metadata(ctx->session);
        send_connection_header(client_channel, username,
                               meta ? meta->client_addr : NULL,
                               disp_upstream_host, disp_upstream_port,
                               disp_upstream_user,
                               session_get_id(ctx->session));
        send_channel_msg(client_channel,
            "  \033[1;32m[" "\xe2\x9c\x93" "]\033[0m Authentication successful\r\n"
            "  \033[1;33m[" "\xc2\xb7" "]\033[0m Connecting to upstream %s:%u...\r\n",
            disp_upstream_host, disp_upstream_port);
    }

    /* 6. Connect to Upstream */
    connect_result_t cr;
    upstream_session = connect_upstream(ctx, username, &cr);
    if (upstream_session == NULL) {
        LOG_ERROR("Failed to connect to upstream: %s (stage: %s)", 
                  cr.detail, cr.stage);
        if (show_progress && client_channel != NULL) {
            send_connection_error(client_channel, &cr);
        }
        goto cleanup;
    }
    session_set_upstream(ctx->session, upstream_session);

    if (show_progress && client_channel != NULL) {
        send_channel_msg(client_channel,
            "  \033[1;32m[" "\xe2\x9c\x93" "]\033[0m Upstream connection established\r\n"
            "  \033[1;32m[" "\xe2\x9c\x93" "]\033[0m Upstream authentication successful\r\n");
    }

    /* 7. Open upstream channel and forward saved requests */
    upstream_channel = ssh_channel_new(upstream_session);
    if (ssh_channel_open_session(upstream_channel) != SSH_OK) {
        LOG_ERROR("Failed to open upstream channel");
        if (show_progress && client_channel != NULL) {
            connect_result_t ch_err = {0};
            ch_err.error = UPSTREAM_ERR_CHANNEL_OPEN;
            snprintf(ch_err.stage, sizeof(ch_err.stage), "Open upstream channel");
            snprintf(ch_err.detail, sizeof(ch_err.detail), "%s", ssh_get_error(upstream_session));
            strncpy(ch_err.host, cr.host, sizeof(ch_err.host) - 1);
            ch_err.port = cr.port;
            strncpy(ch_err.user, cr.user, sizeof(ch_err.user) - 1);
            send_connection_error(client_channel, &ch_err);
        }
        goto cleanup;
    }
    
    /* Replay saved requests to upstream */
    if (request_state.has_pty &&
        ssh_channel_request_pty_size(upstream_channel, request_state.term,
                                     request_state.width, request_state.height) != SSH_OK) {
        report_channel_request_error(upstream_session, client_channel, show_progress, &cr,
                                     "Replay PTY request");
        goto cleanup;
    }
    for (int i = 0; i < request_state.env_count; i++) {
        if (ssh_channel_request_env(upstream_channel, request_state.envs[i].name,
                                    request_state.envs[i].value) != SSH_OK) {
            report_channel_request_error(upstream_session, client_channel, show_progress, &cr,
                                         "Replay environment request");
            goto cleanup;
        }
    }
    switch (request_state.request_type) {
        case CHANNEL_REQUEST_EXEC:
            if (ssh_channel_request_exec(upstream_channel, request_state.command) != SSH_OK) {
                report_channel_request_error(upstream_session, client_channel, show_progress, &cr,
                                             "Replay exec request");
                goto cleanup;
            }
            break;
        case CHANNEL_REQUEST_SUBSYSTEM:
            if (ssh_channel_request_subsystem(upstream_channel, request_state.subsystem) != SSH_OK) {
                report_channel_request_error(upstream_session, client_channel, show_progress, &cr,
                                             "Replay subsystem request");
                goto cleanup;
            }
            break;
        case CHANNEL_REQUEST_SHELL:
            if (ssh_channel_request_shell(upstream_channel) != SSH_OK) {
                report_channel_request_error(upstream_session, client_channel, show_progress, &cr,
                                             "Replay shell request");
                goto cleanup;
            }
            break;
        case CHANNEL_REQUEST_NONE:
        default:
            break;
    }

    if (show_progress && client_channel != NULL) {
        send_connection_success(client_channel);
    }

    session_set_state(ctx->session, SESSION_STATE_ACTIVE);
    LOG_INFO("Session %lu active, forwarding...", session_get_id(ctx->session));
    emit_session_webhook(ctx, WEBHOOK_EVENT_SESSION_START,
                         username, disp_upstream_user,
                         disp_upstream_host, disp_upstream_port);

    /* 8. Send MOTD after connection established */
    if (ctx->config != NULL && ctx->config->motd[0] != '\0') {
        session_metadata_t *meta = session_get_metadata(ctx->session);
        banner_context_t bctx = {
            .username = meta ? meta->username : username,
            .client_ip = meta ? meta->client_addr : NULL,
            .upstream_host = disp_upstream_host,
            .upstream_port = disp_upstream_port,
            .upstream_user = disp_upstream_user,
            .session_id = session_get_id(ctx->session)
        };
        char motd_expanded[1024];
        banner_expand_vars_ctx(ctx->config->motd, motd_expanded, sizeof(motd_expanded), &bctx);
        size_t mlen = strlen(motd_expanded);
        if (mlen < sizeof(motd_expanded) - 2) {
            motd_expanded[mlen] = '\n';
            motd_expanded[mlen + 1] = '\0';
            mlen++;
        }
        if (client_channel != NULL) {
            ssh_channel_write(client_channel, motd_expanded, (uint32_t)mlen);
        }
        LOG_DEBUG("MOTD sent to session %lu", session_get_id(ctx->session));
    }

    /* 9. Forward Data with audit recording */
    forward_loop(ctx, client_channel, upstream_channel, username);

cleanup:
    LOG_INFO("Session %lu ending", session_get_id(ctx->session));
    emit_session_webhook(ctx, WEBHOOK_EVENT_SESSION_END,
                         username, disp_upstream_user,
                         disp_upstream_host, disp_upstream_port);
    
    if (client_channel) {
        ssh_channel_send_eof(client_channel);
        ssh_channel_close(client_channel);
        ssh_channel_free(client_channel);
    }
    if (upstream_channel) {
        ssh_channel_close(upstream_channel);
        ssh_channel_free(upstream_channel);
    }
    if (upstream_session) {
        ssh_disconnect(upstream_session);
        /* ssh_free(upstream_session); - Managed by session_manager */
    }
    
    /* Notify filters of session close */
    if (ctx->filters != NULL) {
        filter_context_t close_ctx = {
            .session = ctx->session,
            .username = username,
            .user_data = NULL
        };
        filter_chain_on_close(ctx->filters, &close_ctx);
    }
    
    /* Client session is freed by session_manager_remove_session in free_context */
    /* But we should disconnect it */
    ssh_disconnect(client_session);
    
    if (username) free(username);
    free_context(ctx);
    return NULL;
}
