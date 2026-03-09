/**
 * @file ssh_server.c
 * @brief SSH Server - libssh based SSH server implementation
 * 
 * Uses epoll + signalfd for proper event-driven signal handling.
 */

#include "ssh_server.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_EPOLL_EVENTS 16

/* Internal server structure */
struct ssh_server {
    ssh_server_config_t config;
    ssh_bind sshbind;
    int listen_fd;
    int epoll_fd;       /* epoll instance */
    int signal_fd;      /* signalfd for SIGINT/SIGTERM/SIGHUP */
    bool running;
    bool reload_requested;  /* set on SIGHUP, cleared by caller */
    char error_msg[256];
};

/* Set error message */
static void set_error(ssh_server_t *server, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(server->error_msg, sizeof(server->error_msg), fmt, args);
    va_end(args);
}

ssh_server_t *ssh_server_create(const ssh_server_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    ssh_server_t *server = calloc(1, sizeof(ssh_server_t));
    if (server == NULL) {
        return NULL;
    }

    /* Copy configuration */
    server->config = *config;
    server->sshbind = NULL;
    server->listen_fd = -1;
    server->epoll_fd = -1;
    server->signal_fd = -1;
    server->running = false;
    server->reload_requested = false;
    server->error_msg[0] = '\0';

    /* Initialize libssh */
    if (ssh_init() != SSH_OK) {
        set_error(server, "Failed to initialize libssh");
        free(server);
        return NULL;
    }

    /* Create SSH bind */
    server->sshbind = ssh_bind_new();
    if (server->sshbind == NULL) {
        set_error(server, "Failed to create SSH bind");
        ssh_finalize();
        free(server);
        return NULL;
    }

    /* Configure bind options */
    ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_BINDADDR,
                         config->bind_addr ? config->bind_addr : "0.0.0.0");
    ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_BINDPORT,
                         &config->port);

    /* Set log verbosity */
    if (config->log_verbosity > 0) {
        ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY,
                             &config->log_verbosity);
    }

    /* Set host keys */
    if (config->host_key_rsa != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_rsa) != SSH_OK) {
            LOG_WARN("Failed to set RSA host key: %s", config->host_key_rsa);
        }
    }

    if (config->host_key_ecdsa != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_ecdsa) != SSH_OK) {
            LOG_WARN("Failed to set ECDSA host key: %s", config->host_key_ecdsa);
        }
    }

    if (config->host_key_ed25519 != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_ed25519) != SSH_OK) {
            LOG_WARN("Failed to set Ed25519 host key: %s", config->host_key_ed25519);
        }
    }

    LOG_DEBUG("SSH server created, bind_addr=%s, port=%d",
              config->bind_addr ? config->bind_addr : "0.0.0.0",
              config->port);

    return server;
}

void ssh_server_destroy(ssh_server_t *server)
{
    if (server == NULL) {
        return;
    }

    if (server->running) {
        ssh_server_stop(server);
    }

    if (server->signal_fd >= 0) {
        close(server->signal_fd);
        server->signal_fd = -1;
    }

    if (server->epoll_fd >= 0) {
        close(server->epoll_fd);
        server->epoll_fd = -1;
    }

    if (server->sshbind != NULL) {
        ssh_bind_free(server->sshbind);
        server->sshbind = NULL;
    }

    ssh_finalize();
    free(server);

    LOG_DEBUG("SSH server destroyed");
}

int ssh_server_start(ssh_server_t *server)
{
    if (server == NULL) {
        return -1;
    }

    if (server->running) {
        set_error(server, "Server is already running");
        return -1;
    }

    /* Bind to port */
    if (ssh_bind_listen(server->sshbind) < 0) {
        set_error(server, "Failed to listen: %s",
                  ssh_get_error(server->sshbind));
        LOG_ERROR("SSH bind listen failed: %s", ssh_get_error(server->sshbind));
        return -1;
    }

    /* Get the listening socket fd */
    server->listen_fd = ssh_bind_get_fd(server->sshbind);
    if (server->listen_fd < 0) {
        set_error(server, "Failed to get bind fd");
        return -1;
    }

    /* Create epoll instance */
    server->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (server->epoll_fd < 0) {
        set_error(server, "epoll_create1 failed: %s", strerror(errno));
        LOG_ERROR("epoll_create1 failed: %s", strerror(errno));
        return -1;
    }

    /* Add listening socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server->listen_fd;
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &ev) < 0) {
        set_error(server, "epoll_ctl add listen_fd failed: %s", strerror(errno));
        LOG_ERROR("epoll_ctl failed: %s", strerror(errno));
        close(server->epoll_fd);
        server->epoll_fd = -1;
        return -1;
    }

    /* Setup signalfd for SIGINT, SIGTERM and SIGHUP */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);

    /* Block these signals so they are delivered via signalfd */
    /* Use pthread_sigmask for thread-safe signal blocking */
    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) < 0) {
        set_error(server, "pthread_sigmask failed: %s", strerror(errno));
        LOG_ERROR("pthread_sigmask failed: %s", strerror(errno));
        close(server->epoll_fd);
        server->epoll_fd = -1;
        return -1;
    }

    server->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (server->signal_fd < 0) {
        set_error(server, "signalfd failed: %s", strerror(errno));
        LOG_ERROR("signalfd failed: %s", strerror(errno));
        close(server->epoll_fd);
        server->epoll_fd = -1;
        return -1;
    }
    
    LOG_DEBUG("signalfd created: fd=%d", server->signal_fd);

    /* Add signalfd to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = server->signal_fd;
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->signal_fd, &ev) < 0) {
        set_error(server, "epoll_ctl add signal_fd failed: %s", strerror(errno));
        LOG_ERROR("epoll_ctl signal_fd failed: %s", strerror(errno));
        close(server->signal_fd);
        server->signal_fd = -1;
        close(server->epoll_fd);
        server->epoll_fd = -1;
        return -1;
    }

    server->running = true;
    LOG_INFO("SSH server listening on %s:%d",
             server->config.bind_addr ? server->config.bind_addr : "0.0.0.0",
             server->config.port);

    return 0;
}

void ssh_server_stop(ssh_server_t *server)
{
    if (server == NULL) {
        return;
    }

    server->running = false;
    
    /* Close epoll to interrupt any blocking epoll_wait() */
    if (server->epoll_fd >= 0) {
        /* Removing fds and closing will wake up epoll_wait */
        close(server->epoll_fd);
        server->epoll_fd = -1;
    }
}

ssh_session ssh_server_accept(ssh_server_t *server)
{
    if (server == NULL || !server->running) {
        return NULL;
    }

    if (server->epoll_fd < 0) {
        return NULL;
    }

    /* Wait for events using epoll */
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int nfds = epoll_wait(server->epoll_fd, events, MAX_EPOLL_EVENTS, -1);
    
    if (nfds < 0) {
        if (errno == EINTR || errno == EBADF) {
            /* Interrupted or epoll closed - check running flag */
            return NULL;
        }
        set_error(server, "epoll_wait failed: %s", strerror(errno));
        return NULL;
    }
    
    /* Process events */
    for (int i = 0; i < nfds; i++) {
        int fd = events[i].data.fd;
        
        /* Check for signal */
        if (fd == server->signal_fd) {
            struct signalfd_siginfo siginfo;
            ssize_t s = read(server->signal_fd, &siginfo, sizeof(siginfo));
            if (s == sizeof(siginfo)) {
                if (siginfo.ssi_signo == SIGHUP) {
                    LOG_INFO("Received SIGHUP, requesting config reload");
                    server->reload_requested = true;
                    /* Don't stop the server, just flag reload */
                } else {
                    LOG_INFO("Received signal %d (%s)",
                             siginfo.ssi_signo,
                             siginfo.ssi_signo == SIGINT ? "SIGINT" : "SIGTERM");
                    server->running = false;
                    return NULL;
                }
            }
            continue;
        }
        
        /* Check for new connection */
        if (fd == server->listen_fd && (events[i].events & EPOLLIN)) {
            if (!server->running) {
                return NULL;
            }

            /* Create new session for incoming connection */
            ssh_session session = ssh_new();
            if (session == NULL) {
                set_error(server, "Failed to create SSH session");
                return NULL;
            }

            /* Accept connection */
            int rc = ssh_bind_accept(server->sshbind, session);
            if (rc != SSH_OK) {
                if (!server->running) {
                    ssh_free(session);
                    return NULL;
                }
                ssh_free(session);
                return NULL;
            }

            LOG_DEBUG("Accepted new SSH connection");
            return session;
        }
    }
    
    return NULL;
}

bool ssh_server_is_running(const ssh_server_t *server)
{
    if (server == NULL) {
        return false;
    }
    return server->running;
}

const char *ssh_server_get_error(const ssh_server_t *server)
{
    if (server == NULL) {
        return "Invalid server instance";
    }
    return server->error_msg;
}

bool ssh_server_reload_requested(ssh_server_t *server)
{
    if (server == NULL) {
        return false;
    }
    if (server->reload_requested) {
        server->reload_requested = false;
        return true;
    }
    return false;
}

int ssh_server_generate_key(const char *path, int bits)
{
    if (path == NULL) {
        return -1;
    }

    if (bits <= 0) {
        bits = 4096;
    }

    ssh_key key = NULL;
    int rc = ssh_pki_generate(SSH_KEYTYPE_RSA, bits, &key);
    if (rc != SSH_OK) {
        LOG_ERROR("Failed to generate RSA key");
        return -1;
    }

    rc = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, path);
    ssh_key_free(key);

    if (rc != SSH_OK) {
        LOG_ERROR("Failed to export private key to %s", path);
        return -1;
    }

    LOG_INFO("Generated %d-bit RSA host key: %s", bits, path);
    return 0;
}
