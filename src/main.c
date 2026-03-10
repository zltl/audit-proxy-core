/**
 * @file main.c
 * @brief SSH Proxy Core - Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "audit_filter.h"
#include "auth_filter.h"
#include "config.h"
#include "filter.h"
#include "health_check.h"
#include "logger.h"
#include "metrics.h"
#include "proxy_handler.h"
#include "rate_limit_filter.h"
#include "rbac_filter.h"
#include "router.h"
#include "session.h"
#include "ssh_server.h"
#include "version.h"
#include <pthread.h>
#include <sys/stat.h>
#include <libssh/libssh.h>

#define DEFAULT_HOST_KEY "/tmp/ssh_proxy_host_key"
#define DEFAULT_CONFIG_FILE "/etc/ssh-proxy/config.ini"

static proxy_config_t *g_config = NULL;
static const char *g_config_path = NULL;  /* path for SIGHUP reload */

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -h, --help         Show this help message\n");
    printf("  -v, --version      Show version information\n");
    printf("  -d, --debug        Enable debug logging\n");
    printf("  -c, --config FILE  Configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
    printf("  -p, --port PORT    Listen port (default: 2222)\n");
    printf("  -k, --key FILE     Host key file (default: auto-generate)\n");
    printf("  -t, --check        Validate configuration and exit\n");
}

static int ensure_host_key(const char *path) {
    if (access(path, R_OK) == 0) {
        LOG_DEBUG("Using existing host key: %s", path);
        return 0;
    }

    LOG_INFO("Generating new host key: %s", path);
    return ssh_server_generate_key(path, 4096);
}

/* Warn if a sensitive file has overly permissive permissions */
static void check_file_permissions(const char *path, const char *description) {
    struct stat st;
    if (stat(path, &st) != 0) return;

    if (st.st_mode & S_IROTH) {
        LOG_WARN("%s '%s' is world-readable (mode %04o). "
                 "Consider: chmod 600 %s",
                 description, path, st.st_mode & 0777, path);
    }
    if (st.st_mode & S_IWOTH) {
        LOG_WARN("%s '%s' is world-writable (mode %04o). "
                 "This is a security risk!",
                 description, path, st.st_mode & 0777);
    }
}

/* Config-based auth callback */
static auth_result_t config_auth_cb(const char *username, const char *password, void *user_data) {
    proxy_config_t *config = (proxy_config_t *)user_data;
    LOG_DEBUG("config_auth_cb called: user='%s', config=%p", username, (void*)config);
    
    if (config == NULL) {
        LOG_WARN("config_auth_cb: config is NULL");
        return AUTH_RESULT_FAILURE;
    }
    
    config_user_t *user = config_find_user(config, username);
    if (user == NULL) {
        LOG_WARN("Auth failed: user '%s' not found in config", username);
        return AUTH_RESULT_FAILURE;
    }
    
    LOG_DEBUG("Found user '%s', hash='%.20s...'", username, user->password_hash);
    
    /* Verify password if hash is set */
    if (user->password_hash[0] != '\0') {
        if (auth_filter_verify_password(password, user->password_hash)) {
            LOG_INFO("Config auth success for user '%s'", username);
            return AUTH_RESULT_SUCCESS;
        }
        LOG_DEBUG("Password verification failed for user '%s'", username);
    }
    
    LOG_WARN("Auth failed for user '%s': bad password", username);
    return AUTH_RESULT_FAILURE;
}

/* Config-based public key auth callback */
static auth_result_t config_pubkey_cb(const char *username, const void *pubkey_data,
                                       size_t pubkey_len, void *user_data) {
    proxy_config_t *config = (proxy_config_t *)user_data;
    if (config == NULL || username == NULL || pubkey_data == NULL || pubkey_len == 0) {
        return AUTH_RESULT_FAILURE;
    }

    config_user_t *user = config_find_user(config, username);
    if (user == NULL || user->pubkeys == NULL || user->pubkeys[0] == '\0') {
        LOG_DEBUG("No authorized keys configured for user '%s'", username);
        return AUTH_RESULT_FAILURE;
    }

    /* The pubkey_data is a base64-encoded public key string from proxy_handler */
    const char *client_b64 = (const char *)pubkey_data;

    /* Import the client's public key from base64 */
    ssh_key client_key = NULL;
    if (ssh_pki_import_pubkey_base64(client_b64, SSH_KEYTYPE_UNKNOWN,
                                      &client_key) != SSH_OK) {
        LOG_WARN("Failed to import client public key for user '%s'", username);
        return AUTH_RESULT_FAILURE;
    }

    /* Parse each line of configured authorized keys and compare */
    char *keys_copy = strdup(user->pubkeys);
    if (keys_copy == NULL) {
        ssh_key_free(client_key);
        return AUTH_RESULT_FAILURE;
    }

    auth_result_t result = AUTH_RESULT_FAILURE;
    char *saveptr = NULL;
    char *line = strtok_r(keys_copy, "\n", &saveptr);

    while (line != NULL) {
        /* Skip leading whitespace */
        while (*line == ' ' || *line == '\t') line++;
        /* Skip empty lines and comments */
        if (*line == '\0' || *line == '#') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* OpenSSH format: "type base64data comment" — skip the type prefix */
        const char *b64_start = line;
        /* Skip type field (e.g., "ssh-rsa", "ssh-ed25519") */
        char *space = strchr(line, ' ');
        if (space != NULL) {
            b64_start = space + 1;
            /* Trim trailing comment if present */
            char *next_space = strchr(b64_start, ' ');
            if (next_space != NULL) *next_space = '\0';
        }

        ssh_key configured_key = NULL;
        if (ssh_pki_import_pubkey_base64(b64_start, SSH_KEYTYPE_UNKNOWN,
                                          &configured_key) == SSH_OK) {
            if (ssh_key_cmp(client_key, configured_key, SSH_KEY_CMP_PUBLIC) == 0) {
                LOG_INFO("Public key match for user '%s'", username);
                ssh_key_free(configured_key);
                result = AUTH_RESULT_SUCCESS;
                break;
            }
            ssh_key_free(configured_key);
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(keys_copy);
    ssh_key_free(client_key);
    return result;
}

/* Fallback auth callback for testing (when no config) */
static auth_result_t test_auth_cb(const char *username, const char *password, void *user_data) {
    (void)user_data;
    LOG_INFO("Auth request: user='%s' password='%s'", username, password);
    /* Accept 'test' user with 'test' password */
    if (strcmp(username, "test") == 0 && strcmp(password, "test") == 0) {
        return AUTH_RESULT_SUCCESS;
    }
    return AUTH_RESULT_FAILURE;
}

int main(int argc, char *argv[]) {
    log_level_t log_level = LOG_LEVEL_INFO;
    uint16_t port = 0;  /* 0 means use config or default */
    const char *host_key = NULL;
    const char *config_file = NULL;
    bool check_mode = false;

    /* Handle command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("%s\n", SSH_PROXY_VERSION_FULL);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            log_level = LOG_LEVEL_DEBUG;
        }
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_file = argv[++i];
        }
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        }
        if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
            host_key = argv[++i];
        }
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--check") == 0) {
            check_mode = true;
        }
    }

    /* Initialize logging */
    log_init(log_level, NULL);

    /* Initialize runtime metrics */
    metrics_init();

    /* Note: Signal handling is done via signalfd in ssh_server */

    LOG_INFO("SSH Proxy Core %s starting...", SSH_PROXY_VERSION_STRING);

    /* Load configuration file if specified */
    if (config_file != NULL) {
        g_config = config_load(config_file);
        if (g_config == NULL) {
            LOG_FATAL("Failed to load configuration file: %s", config_file);
            log_shutdown();
            return EXIT_FAILURE;
        }
        LOG_INFO("Loaded configuration from %s", config_file);
        g_config_path = config_file;
    } else {
        /* Try default config file, but don't fail if not found */
        if (access(DEFAULT_CONFIG_FILE, R_OK) == 0) {
            g_config = config_load(DEFAULT_CONFIG_FILE);
            if (g_config != NULL) {
                LOG_INFO("Loaded configuration from %s", DEFAULT_CONFIG_FILE);
                g_config_path = DEFAULT_CONFIG_FILE;
            }
        }
    }

    /* Apply config values (command line overrides config file) */
    if (port == 0) {
        port = (g_config != NULL) ? g_config->port : 2222;
    }
    if (host_key == NULL) {
        host_key = (g_config != NULL && g_config->host_key_path[0] != '\0') 
                   ? g_config->host_key_path : DEFAULT_HOST_KEY;
    }

    /* Config validation mode */
    if (check_mode) {
        if (g_config == NULL) {
            fprintf(stderr, "Error: No configuration file loaded. Use -c to specify one.\n");
            log_shutdown();
            return EXIT_FAILURE;
        }

        printf("Validating configuration: %s\n", g_config_path ? g_config_path : "(unknown)");
        config_valid_result_t *results = config_validate(g_config, g_config_path);

        int errors = 0, warnings = 0, infos = 0;
        config_valid_result_t *r = results;
        while (r != NULL) {
            const char *prefix = "INFO";
            if (r->level == CONFIG_VALID_WARN) { prefix = "WARN"; warnings++; }
            else if (r->level == CONFIG_VALID_ERROR) { prefix = "ERROR"; errors++; }
            else { infos++; }
            printf("  [%s] %s\n", prefix, r->message);
            r = r->next;
        }

        config_valid_free(results);

        if (errors > 0) {
            printf("\nConfiguration INVALID: %d error(s), %d warning(s)\n", errors, warnings);
            config_destroy(g_config);
            log_shutdown();
            return EXIT_FAILURE;
        } else if (warnings > 0) {
            printf("\nConfiguration valid with %d warning(s)\n", warnings);
            config_destroy(g_config);
            log_shutdown();
            return 2;  /* Warnings exit code */
        } else {
            printf("\nConfiguration OK\n");
            config_destroy(g_config);
            log_shutdown();
            return EXIT_SUCCESS;
        }
    }

    /* Check sensitive file permissions */
    if (config_file != NULL) {
        check_file_permissions(config_file, "Config file");
    }
    check_file_permissions(host_key, "Host key");

    /* Ensure host key exists */
    if (ensure_host_key(host_key) != 0) {
        LOG_FATAL("Failed to prepare host key");
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create SSH server configuration */
    ssh_server_config_t server_config = {.bind_addr = (g_config != NULL) ? g_config->bind_addr : "0.0.0.0",
                                         .port = port,
                                         .host_key_rsa = host_key,
                                         .host_key_ecdsa = NULL,
                                         .host_key_ed25519 = NULL,
                                         .log_verbosity = (log_level <= LOG_LEVEL_DEBUG) ? 1 : 0};

    /* Create session manager */
    session_manager_config_t session_config = {
        .max_sessions = (g_config != NULL) ? g_config->max_sessions : 1000,
        .session_timeout = (g_config != NULL) ? g_config->session_timeout : 3600,
        .auth_timeout = (g_config != NULL) ? g_config->auth_timeout : 60};
    session_manager_t *session_mgr = session_manager_create(&session_config);
    if (session_mgr == NULL) {
        LOG_FATAL("Failed to create session manager");
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create filter chain */
    filter_chain_t *filters = filter_chain_create();
    if (filters == NULL) {
        LOG_FATAL("Failed to create filter chain");
        session_manager_destroy(session_mgr);
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Add rate limit filter */
    rate_limit_filter_config_t rate_cfg = {.global_max_connections = 100,
                                           .global_max_rate = 10,
                                           .global_interval_sec = 1,
                                           .log_rejections = true,
                                           .rules = NULL};
    filter_t *rate_filter = rate_limit_filter_create(&rate_cfg);
    if (rate_filter != NULL) {
        filter_chain_add(filters, rate_filter);
    }

    /* Add auth filter - use config-based auth if config loaded, otherwise test callback */
    auth_filter_config_t auth_cfg = {.backend = AUTH_BACKEND_CALLBACK,
                                     .allow_password = true,
                                     .allow_pubkey = true,
                                     .allow_keyboard = false,
                                     .max_attempts = 3,
                                     .timeout_sec = (g_config != NULL) ? g_config->auth_timeout : 60,
                                     .local_users = NULL,
                                     .password_cb = (g_config != NULL) ? config_auth_cb : test_auth_cb,
                                     .pubkey_cb = (g_config != NULL) ? config_pubkey_cb : NULL,
                                     .cb_user_data = g_config};
    filter_t *auth_filter = auth_filter_create(&auth_cfg);
    if (auth_filter != NULL) {
        filter_chain_add(filters, auth_filter);
    }

    /* Add audit filter */
    audit_filter_config_t audit_cfg = {.storage = AUDIT_STORAGE_FILE,
                                       .log_dir = (g_config != NULL && g_config->audit_log_dir[0] != '\0') 
                                                  ? g_config->audit_log_dir : "/tmp/ssh_proxy_audit",
                                       .log_prefix = "audit_",
                                       .record_input = true,
                                       .record_output = true,
                                       .record_commands = true,
                                       .enable_asciicast = true,
                                       .max_file_size = 0,
                                       .flush_interval = 5,
                                       .event_cb = NULL,
                                       .cb_user_data = NULL};
    filter_t *audit_filter = audit_filter_create(&audit_cfg);
    if (audit_filter != NULL) {
        filter_chain_add(filters, audit_filter);
    }

    /* Create router */
    router_config_t router_cfg = {.lb_policy = LB_POLICY_ROUND_ROBIN,
                                  .connect_timeout_ms = 10000,
                                  .health_check_interval = 30,
                                  .max_retries = 3,
                                  .health_check_enabled = false};
    router_t *router = router_create(&router_cfg);
    if (router == NULL) {
        LOG_FATAL("Failed to create router");
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Add default upstream (localhost:22 for testing) */
    upstream_config_t upstream_cfg = {
        .host = "127.0.0.1", .port = 22, .weight = 1, .enabled = true};
    strncpy(upstream_cfg.host, "127.0.0.1", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream_cfg);

    LOG_INFO("Initialized: session_mgr, %zu filters, router with %zu upstreams",
             filter_chain_count(filters), router_get_upstream_count(router));

    /* Create SSH server */
    ssh_server_t *server = ssh_server_create(&server_config);
    if (server == NULL) {
        LOG_FATAL("Failed to create SSH server");
        router_destroy(router);
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Start SSH server */
    if (ssh_server_start(server) != 0) {
        LOG_FATAL("Failed to start SSH server: %s", ssh_server_get_error(server));
        ssh_server_destroy(server);
        router_destroy(router);
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    LOG_INFO("SSH server ready, waiting for connections...");
    LOG_INFO("Press Ctrl+C to stop, send SIGHUP to reload config");

    /* Start health check / metrics HTTP endpoint */
    health_check_config_t hc_cfg = {.port = 9090, .bind_addr = "127.0.0.1"};
    health_check_t *hc = health_check_start(&hc_cfg);
    if (hc == NULL) {
        LOG_WARN("Failed to start health check endpoint (non-fatal)");
    }

    /* Main loop - accept connections */
    while (ssh_server_is_running(server)) {
        /* Check for SIGHUP reload request */
        if (ssh_server_reload_requested(server)) {
            if (g_config != NULL && g_config_path != NULL) {
                LOG_INFO("Reloading configuration from %s", g_config_path);
                if (config_reload(g_config, g_config_path) == 0) {
                    LOG_INFO("Configuration reloaded successfully");
                    METRICS_INC(config_reloads);
                } else {
                    LOG_ERROR("Configuration reload failed, keeping old config");
                    METRICS_INC(config_reload_errors);
                }
            } else {
                LOG_WARN("SIGHUP received but no config file loaded, ignoring");
            }
        }

        ssh_session client_ssh = ssh_server_accept(server);
        if (client_ssh == NULL) {
            /* NULL means signal received or error - check if still running */
            if (ssh_server_is_running(server)) {
                /* Periodically cleanup timed-out sessions */
                session_manager_cleanup(session_mgr);
            }
            continue;
        }

        METRICS_INC(connections_total);
        METRICS_INC(connections_active);
        LOG_INFO("New connection accepted");

        /* Create session */
        session_t *session = session_manager_create_session(session_mgr, client_ssh);
        if (session == NULL) {
            LOG_WARN("Failed to create session (limit reached?)");
            METRICS_INC(sessions_rejected);
            METRICS_DEC(connections_active);
            ssh_disconnect(client_ssh);
            ssh_free(client_ssh);
            continue;
        }

        session_set_state(session, SESSION_STATE_HANDSHAKE);

        /* Run filter chain on connect */
        filter_context_t ctx = {.session = session,
                                .user_data = NULL,
                                .username = NULL,
                                .password = NULL,
                                .pubkey = NULL,
                                .pubkey_len = 0,
                                .target_host = NULL,
                                .target_port = 0};

        filter_status_t status = filter_chain_on_connect(filters, &ctx);
        if (status == FILTER_REJECT) {
            LOG_WARN("Connection rejected by filter");
            METRICS_INC(sessions_rejected);
            METRICS_DEC(connections_active);
            session_manager_remove_session(session_mgr, session);
            continue;
        }

        /* Spawn thread for proxy handler */
        proxy_handler_context_t *handler_ctx = malloc(sizeof(proxy_handler_context_t));
        if (handler_ctx == NULL) {
            LOG_ERROR("Failed to allocate handler context");
            METRICS_DEC(connections_active);
            session_manager_remove_session(session_mgr, session);
            continue;
        }

        handler_ctx->session_mgr = session_mgr;
        handler_ctx->filters = filters;
        handler_ctx->router = router;
        handler_ctx->session = session;
        handler_ctx->config = g_config;

        pthread_t thread;
        if (pthread_create(&thread, NULL, proxy_handler_run, handler_ctx) != 0) {
            LOG_ERROR("Failed to create proxy thread");
            free(handler_ctx);
            METRICS_DEC(connections_active);
            session_manager_remove_session(session_mgr, session);
            continue;
        }
        pthread_detach(thread);
    }

    /* ---- Graceful shutdown ---- */
    LOG_INFO("Shutting down...");
    
    /* 1. Stop accepting new connections (server already stopped by signalfd) */
    
    /* 2. Stop health check endpoint */
    health_check_stop(hc);

    /* 3. Drain active sessions with a configurable timeout */
    uint32_t drain_timeout_sec = (g_config != NULL) ? g_config->session_timeout : 30;
    if (drain_timeout_sec > 30) drain_timeout_sec = 30;  /* cap at 30s */

    if (session_manager_get_count(session_mgr) > 0) {
        LOG_INFO("Draining %zu active sessions (timeout %us)...",
                 session_manager_get_count(session_mgr), drain_timeout_sec);

        struct timespec wait_time = {0, 100000000};  /* 100ms */
        uint32_t max_iterations = drain_timeout_sec * 10;

        for (uint32_t i = 0; i < max_iterations; i++) {
            session_manager_cleanup(session_mgr);
            if (session_manager_get_count(session_mgr) == 0) {
                LOG_INFO("All sessions drained");
                break;
            }
            nanosleep(&wait_time, NULL);

            /* Progress log every 5 seconds */
            if (i > 0 && i % 50 == 0) {
                LOG_INFO("Still draining: %zu sessions remaining",
                         session_manager_get_count(session_mgr));
            }
        }

        if (session_manager_get_count(session_mgr) > 0) {
            LOG_WARN("Forcing shutdown with %zu active sessions",
                     session_manager_get_count(session_mgr));
        }
    }
    
    /* 4. Destroy resources in reverse creation order */
    ssh_server_destroy(server);
    router_destroy(router);
    filter_chain_destroy(filters);
    session_manager_destroy(session_mgr);
    if (g_config != NULL) {
        config_destroy(g_config);
    }
    log_shutdown();

    return EXIT_SUCCESS;
}
