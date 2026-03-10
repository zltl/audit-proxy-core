/**
 * @file config.c
 * @brief SSH Proxy Core - Configuration Module Implementation
 *
 * Simple INI-style configuration file parser with support for:
 * - [section] headers
 * - key = value pairs
 * - # comments
 * - Multi-line values with \
 */

#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>

/* Configuration sections */
typedef enum {
    SECTION_NONE = 0,
    SECTION_SERVER,
    SECTION_LOGGING,
    SECTION_LIMITS,
    SECTION_USER,
    SECTION_ROUTE,
    SECTION_POLICY
} config_section_t;

/* Helper: trim whitespace */
static char *trim(char *str)
{
    if (str == NULL) return NULL;
    
    /* Trim leading */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return str;
    
    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

/* Helper: check if line is empty or comment */
static bool is_empty_or_comment(const char *line)
{
    while (isspace((unsigned char)*line)) line++;
    return (*line == '\0' || *line == '#' || *line == ';');
}

/* Helper: parse section header [section] */
static config_section_t parse_section(const char *line)
{
    if (line[0] != '[') return SECTION_NONE;
    
    char section[64] = {0};
    const char *start = line + 1;
    const char *end = strchr(start, ']');
    if (end == NULL) return SECTION_NONE;
    
    size_t len = end - start;
    if (len >= sizeof(section)) len = sizeof(section) - 1;
    strncpy(section, start, len);
    
    if (strcmp(section, "server") == 0) return SECTION_SERVER;
    if (strcmp(section, "logging") == 0) return SECTION_LOGGING;
    if (strcmp(section, "limits") == 0) return SECTION_LIMITS;
    if (strncmp(section, "user:", 5) == 0) return SECTION_USER;
    if (strncmp(section, "route:", 6) == 0) return SECTION_ROUTE;
    if (strncmp(section, "policy:", 7) == 0) return SECTION_POLICY;
    
    return SECTION_NONE;
}

/* Helper: extract section parameter (e.g., "user:testuser" -> "testuser") */
static const char *get_section_param(const char *line)
{
    const char *colon = strchr(line + 1, ':');
    if (colon == NULL) return NULL;
    
    static char param[256];
    const char *start = colon + 1;
    const char *end = strchr(start, ']');
    if (end == NULL) return NULL;
    
    size_t len = end - start;
    if (len >= sizeof(param)) len = sizeof(param) - 1;
    strncpy(param, start, len);
    param[len] = '\0';
    
    return trim(param);
}

/* Helper: parse key = value */
static int parse_key_value(const char *line, char *key, size_t key_len,
                           char *value, size_t value_len)
{
    const char *eq = strchr(line, '=');
    if (eq == NULL) return -1;
    
    /* Extract key */
    size_t klen = eq - line;
    if (klen >= key_len) klen = key_len - 1;
    strncpy(key, line, klen);
    key[klen] = '\0';
    
    /* Trim key */
    char *k = trim(key);
    if (k != key) memmove(key, k, strlen(k) + 1);
    
    /* Extract value */
    const char *v = eq + 1;
    while (isspace((unsigned char)*v)) v++;
    
    strncpy(value, v, value_len - 1);
    value[value_len - 1] = '\0';
    
    /* Trim value */
    char *val = trim(value);
    if (val != value) memmove(value, val, strlen(val) + 1);
    
    /* Remove quotes if present */
    size_t vlen = strlen(value);
    if (vlen >= 2 && ((value[0] == '"' && value[vlen-1] == '"') ||
                      (value[0] == '\'' && value[vlen-1] == '\''))) {
        memmove(value, value + 1, vlen - 2);
        value[vlen - 2] = '\0';
    }
    
    return 0;
}

proxy_config_t *config_create(void)
{
    proxy_config_t *config = calloc(1, sizeof(proxy_config_t));
    if (config == NULL) return NULL;
    
    /* Set defaults */
    strncpy(config->bind_addr, "0.0.0.0", sizeof(config->bind_addr) - 1);
    config->port = 2222;
    strncpy(config->host_key_path, "/tmp/ssh_proxy_host_key", 
            sizeof(config->host_key_path) - 1);
    
    config->log_level = 1;  /* INFO */
    strncpy(config->audit_log_dir, "/tmp/ssh_proxy_audit",
            sizeof(config->audit_log_dir) - 1);
    
    config->max_sessions = 1000;
    config->session_timeout = 3600;
    config->auth_timeout = 60;
    
    config->users = NULL;
    config->routes = NULL;
    config->policies = NULL;
    config->default_policy = 0xFFFFFFFF;  /* All features allowed by default */
    config->log_transfers = true;
    config->log_port_forwards = true;
    
    return config;
}

void config_destroy(proxy_config_t *config)
{
    if (config == NULL) return;
    
    /* Free users */
    config_user_t *user = config->users;
    while (user != NULL) {
        config_user_t *next = user->next;
        free(user->pubkeys);
        free(user);
        user = next;
    }
    
    /* Free routes */
    config_route_t *route = config->routes;
    while (route != NULL) {
        config_route_t *next = route->next;
        free(route);
        route = next;
    }
    
    /* Free policies */
    config_policy_t *policy = config->policies;
    while (policy != NULL) {
        config_policy_t *next = policy->next;
        free(policy);
        policy = next;
    }
    
    free(config);
}

int config_add_user(proxy_config_t *config,
                    const char *username,
                    const char *password_hash,
                    const char *pubkeys)
{
    if (config == NULL || username == NULL) return -1;
    
    config_user_t *user = calloc(1, sizeof(config_user_t));
    if (user == NULL) return -1;
    
    strncpy(user->username, username, sizeof(user->username) - 1);
    if (password_hash != NULL) {
        strncpy(user->password_hash, password_hash, sizeof(user->password_hash) - 1);
    }
    if (pubkeys != NULL) {
        user->pubkeys = strdup(pubkeys);
    }
    user->enabled = true;
    
    /* Add to head of list */
    user->next = config->users;
    config->users = user;
    
    return 0;
}

config_user_t *config_find_user(const proxy_config_t *config,
                                const char *username)
{
    if (config == NULL || username == NULL) return NULL;
    
    config_user_t *user = config->users;
    while (user != NULL) {
        if (user->enabled && strcmp(user->username, username) == 0) {
            return user;
        }
        user = user->next;
    }
    return NULL;
}

/* Simple glob matching for route patterns */
static bool glob_match(const char *pattern, const char *str)
{
    if (pattern == NULL || str == NULL) return false;
    
    while (*pattern && *str) {
        if (*pattern == '*') {
            while (*pattern == '*') pattern++;
            if (*pattern == '\0') return true;
            while (*str) {
                if (glob_match(pattern, str)) return true;
                str++;
            }
            return false;
        } else if (*pattern == '?' || *pattern == *str) {
            pattern++;
            str++;
        } else {
            return false;
        }
    }
    
    while (*pattern == '*') pattern++;
    return (*pattern == '\0' && *str == '\0');
}

/* Parse policy feature flags from comma-separated string */
static uint32_t parse_policy_features(const char *value)
{
    if (value == NULL || value[0] == '\0') return 0;
    
    uint32_t features = 0;
    char buf[1024];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    char *saveptr = NULL;
    char *token = strtok_r(buf, ",|+& \t", &saveptr);
    while (token != NULL) {
        /* Trim token */
        while (*token && isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';
        
        /* Match feature name */
        if (strcmp(token, "all") == 0 || strcmp(token, "*") == 0) {
            features = 0xFFFFFFFF;
        } else if (strcmp(token, "none") == 0) {
            features = 0;
        } else if (strcmp(token, "shell") == 0) {
            features |= (1 << 0);
        } else if (strcmp(token, "exec") == 0) {
            features |= (1 << 1);
        } else if (strcmp(token, "scp_upload") == 0 || strcmp(token, "scp-upload") == 0) {
            features |= (1 << 2);
        } else if (strcmp(token, "scp_download") == 0 || strcmp(token, "scp-download") == 0) {
            features |= (1 << 3);
        } else if (strcmp(token, "scp") == 0) {
            features |= (1 << 2) | (1 << 3);
        } else if (strcmp(token, "sftp_upload") == 0 || strcmp(token, "sftp-upload") == 0) {
            features |= (1 << 4);
        } else if (strcmp(token, "sftp_download") == 0 || strcmp(token, "sftp-download") == 0) {
            features |= (1 << 5);
        } else if (strcmp(token, "sftp_list") == 0 || strcmp(token, "sftp-list") == 0) {
            features |= (1 << 6);
        } else if (strcmp(token, "sftp_delete") == 0 || strcmp(token, "sftp-delete") == 0) {
            features |= (1 << 7);
        } else if (strcmp(token, "sftp") == 0) {
            features |= (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);
        } else if (strcmp(token, "rsync_upload") == 0 || strcmp(token, "rsync-upload") == 0) {
            features |= (1 << 8);
        } else if (strcmp(token, "rsync_download") == 0 || strcmp(token, "rsync-download") == 0) {
            features |= (1 << 9);
        } else if (strcmp(token, "rsync") == 0) {
            features |= (1 << 8) | (1 << 9);
        } else if (strcmp(token, "port_forward_local") == 0 || strcmp(token, "local-forward") == 0) {
            features |= (1 << 10);
        } else if (strcmp(token, "port_forward_remote") == 0 || strcmp(token, "remote-forward") == 0) {
            features |= (1 << 11);
        } else if (strcmp(token, "port_forward_dynamic") == 0 || strcmp(token, "dynamic-forward") == 0) {
            features |= (1 << 12);
        } else if (strcmp(token, "port_forward") == 0 || strcmp(token, "forward") == 0) {
            features |= (1 << 10) | (1 << 11) | (1 << 12);
        } else if (strcmp(token, "x11") == 0 || strcmp(token, "x11_forward") == 0) {
            features |= (1 << 13);
        } else if (strcmp(token, "agent") == 0 || strcmp(token, "agent_forward") == 0) {
            features |= (1 << 14);
        } else if (strcmp(token, "git_push") == 0 || strcmp(token, "git-push") == 0) {
            features |= (1 << 15);
        } else if (strcmp(token, "git_pull") == 0 || strcmp(token, "git-pull") == 0) {
            features |= (1 << 16);
        } else if (strcmp(token, "git_archive") == 0 || strcmp(token, "git-archive") == 0) {
            features |= (1 << 17);
        } else if (strcmp(token, "git") == 0) {
            features |= (1 << 15) | (1 << 16) | (1 << 17);
        } else if (strcmp(token, "upload") == 0) {
            features |= (1 << 2) | (1 << 4) | (1 << 8);  /* scp_upload, sftp_upload, rsync_upload */
        } else if (strcmp(token, "download") == 0) {
            features |= (1 << 3) | (1 << 5) | (1 << 9);  /* scp_download, sftp_download, rsync_download */
        }
        
        token = strtok_r(NULL, ",|+& \t", &saveptr);
    }
    
    return features;
}

int config_add_route(proxy_config_t *config,
                     const char *proxy_user,
                     const char *upstream_host,
                     uint16_t upstream_port,
                     const char *upstream_user,
                     const char *privkey_path)
{
    if (config == NULL || proxy_user == NULL || upstream_host == NULL) return -1;
    
    config_route_t *route = calloc(1, sizeof(config_route_t));
    if (route == NULL) return -1;
    
    strncpy(route->proxy_user, proxy_user, sizeof(route->proxy_user) - 1);
    strncpy(route->upstream_host, upstream_host, sizeof(route->upstream_host) - 1);
    route->upstream_port = upstream_port > 0 ? upstream_port : 22;
    if (upstream_user != NULL) {
        strncpy(route->upstream_user, upstream_user, sizeof(route->upstream_user) - 1);
    }
    if (privkey_path != NULL) {
        strncpy(route->privkey_path, privkey_path, sizeof(route->privkey_path) - 1);
    }
    route->enabled = true;
    
    /* Add to head of list */
    route->next = config->routes;
    config->routes = route;
    
    return 0;
}

config_route_t *config_find_route(const proxy_config_t *config,
                                  const char *proxy_user)
{
    if (config == NULL || proxy_user == NULL) return NULL;
    
    config_route_t *wildcard_match = NULL;
    
    /* First pass: look for exact match (no wildcards in pattern) */
    config_route_t *route = config->routes;
    while (route != NULL) {
        if (route->enabled) {
            /* Check if pattern contains wildcards */
            bool has_wildcard = (strchr(route->proxy_user, '*') != NULL ||
                                 strchr(route->proxy_user, '?') != NULL);
            
            if (!has_wildcard && strcmp(route->proxy_user, proxy_user) == 0) {
                return route;  /* Exact match, return immediately */
            }
            
            /* Remember first wildcard match for fallback */
            if (has_wildcard && wildcard_match == NULL && 
                glob_match(route->proxy_user, proxy_user)) {
                wildcard_match = route;
            }
        }
        route = route->next;
    }
    
    /* Return wildcard match if no exact match found */
    return wildcard_match;
}

int config_add_policy(proxy_config_t *config,
                      const char *username_pattern,
                      const char *upstream_pattern,
                      uint32_t allowed_features,
                      uint32_t denied_features)
{
    if (config == NULL || username_pattern == NULL) return -1;
    
    config_policy_t *policy = calloc(1, sizeof(config_policy_t));
    if (policy == NULL) return -1;
    
    strncpy(policy->username_pattern, username_pattern, 
            sizeof(policy->username_pattern) - 1);
    if (upstream_pattern != NULL) {
        strncpy(policy->upstream_pattern, upstream_pattern,
                sizeof(policy->upstream_pattern) - 1);
    }
    policy->allowed_features = allowed_features;
    policy->denied_features = denied_features;
    
    /* Add to head of list */
    policy->next = config->policies;
    config->policies = policy;
    
    return 0;
}

config_policy_t *config_find_policy(const proxy_config_t *config,
                                    const char *username,
                                    const char *upstream)
{
    if (config == NULL || username == NULL) return NULL;
    
    config_policy_t *user_only_match = NULL;
    config_policy_t *wildcard_match = NULL;
    
    /* Priority order:
     * 1. Exact user + exact upstream match
     * 2. Exact user + wildcard upstream match
     * 3. Exact user + no upstream specified (user-only policy)
     * 4. Wildcard user + exact upstream match
     * 5. Wildcard user + wildcard upstream match
     * 6. Wildcard user + no upstream specified
     */
    config_policy_t *policy = config->policies;
    while (policy != NULL) {
        bool user_has_wildcard = (strchr(policy->username_pattern, '*') != NULL ||
                                  strchr(policy->username_pattern, '?') != NULL);
        bool upstream_has_wildcard = (strchr(policy->upstream_pattern, '*') != NULL ||
                                      strchr(policy->upstream_pattern, '?') != NULL);
        bool has_upstream_pattern = (policy->upstream_pattern[0] != '\0');
        
        /* Check if user matches */
        bool user_matches = user_has_wildcard ? 
                            glob_match(policy->username_pattern, username) :
                            (strcmp(policy->username_pattern, username) == 0);
        
        if (!user_matches) {
            policy = policy->next;
            continue;
        }
        
        /* User matches, now check upstream */
        if (!has_upstream_pattern) {
            /* Policy applies to any upstream for this user */
            if (!user_has_wildcard) {
                /* Exact user match with no upstream - good fallback */
                if (user_only_match == NULL) {
                    user_only_match = policy;
                }
            } else if (wildcard_match == NULL) {
                wildcard_match = policy;
            }
        } else if (upstream != NULL) {
            /* Policy has upstream pattern, check if it matches */
            bool upstream_matches = upstream_has_wildcard ?
                                    glob_match(policy->upstream_pattern, upstream) :
                                    (strcmp(policy->upstream_pattern, upstream) == 0);
            
            if (upstream_matches) {
                /* Both user and upstream match */
                if (!user_has_wildcard && !upstream_has_wildcard) {
                    return policy;  /* Best match: exact user + exact upstream */
                }
                if (!user_has_wildcard) {
                    /* Exact user + wildcard/exact upstream */
                    if (user_only_match == NULL || 
                        policy->upstream_pattern[0] != '\0') {
                        user_only_match = policy;
                    }
                } else if (wildcard_match == NULL) {
                    wildcard_match = policy;
                }
            }
        }
        
        policy = policy->next;
    }
    
    /* Return best match found */
    return user_only_match ? user_only_match : wildcard_match;
}

proxy_config_t *config_load(const char *path)
{
    if (path == NULL) return NULL;
    
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        LOG_ERROR("Failed to open config file: %s", path);
        return NULL;
    }
    
    proxy_config_t *config = config_create();
    if (config == NULL) {
        fclose(fp);
        return NULL;
    }
    
    char line[CONFIG_MAX_LINE];
    config_section_t current_section = SECTION_NONE;
    config_user_t *current_user = NULL;
    config_route_t *current_route = NULL;
    config_policy_t *current_policy = NULL;
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_num++;
        
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        
        char *trimmed = trim(line);
        
        /* Skip empty lines and comments */
        if (is_empty_or_comment(trimmed)) continue;
        
        /* Check for section header */
        if (trimmed[0] == '[') {
            current_section = parse_section(trimmed);
            
            if (current_section == SECTION_USER) {
                const char *username = get_section_param(trimmed);
                if (username != NULL) {
                    /* Create new user entry */
                    current_user = calloc(1, sizeof(config_user_t));
                    if (current_user != NULL) {
                        strncpy(current_user->username, username, 
                                sizeof(current_user->username) - 1);
                        current_user->enabled = true;
                        current_user->next = config->users;
                        config->users = current_user;
                    }
                }
                current_route = NULL;
                current_policy = NULL;
            } else if (current_section == SECTION_ROUTE) {
                const char *proxy_user = get_section_param(trimmed);
                if (proxy_user != NULL) {
                    /* Create new route entry */
                    current_route = calloc(1, sizeof(config_route_t));
                    if (current_route != NULL) {
                        strncpy(current_route->proxy_user, proxy_user, sizeof(current_route->proxy_user) - 1);
                        current_route->upstream_port = 22;  /* Default */
                        current_route->enabled = true;
                        current_route->next = config->routes;
                        config->routes = current_route;
                    }
                }
                current_user = NULL;
                current_policy = NULL;
            } else if (current_section == SECTION_POLICY) {
                const char *pattern = get_section_param(trimmed);
                if (pattern != NULL) {
                    /* Create new policy entry */
                    /* Format: [policy:user] or [policy:user@upstream] */
                    current_policy = calloc(1, sizeof(config_policy_t));
                    if (current_policy != NULL) {
                        /* Check for user@upstream format */
                        const char *at = strchr(pattern, '@');
                        if (at != NULL) {
                            /* user@upstream format */
                            size_t user_len = at - pattern;
                            if (user_len >= sizeof(current_policy->username_pattern)) {
                                user_len = sizeof(current_policy->username_pattern) - 1;
                            }
                            strncpy(current_policy->username_pattern, pattern, user_len);
                            current_policy->username_pattern[user_len] = '\0';
                            strncpy(current_policy->upstream_pattern, at + 1,
                                    sizeof(current_policy->upstream_pattern) - 1);
                        } else {
                            /* user only format */
                            strncpy(current_policy->username_pattern, pattern, 
                                    sizeof(current_policy->username_pattern) - 1);
                        }
                        current_policy->allowed_features = 0x7FFFFFFF;  /* All allowed by default */
                        current_policy->denied_features = 0;
                        current_policy->next = config->policies;
                        config->policies = current_policy;
                    }
                }
                current_user = NULL;
                current_route = NULL;
            } else {
                current_user = NULL;
                current_route = NULL;
                current_policy = NULL;
            }
            continue;
        }
        
        /* Parse key = value */
        char key[128], value[CONFIG_MAX_LINE];
        if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) != 0) {
            LOG_WARN("Config line %d: invalid format", line_num);
            continue;
        }
        
        /* Apply value based on current section */
        switch (current_section) {
        case SECTION_SERVER:
            if (strcmp(key, "bind_addr") == 0) {
                strncpy(config->bind_addr, value, sizeof(config->bind_addr) - 1);
            } else if (strcmp(key, "port") == 0) {
                config->port = (uint16_t)atoi(value);
            } else if (strcmp(key, "host_key") == 0) {
                strncpy(config->host_key_path, value, sizeof(config->host_key_path) - 1);
            } else if (strcmp(key, "banner") == 0) {
                strncpy(config->banner_path, value, sizeof(config->banner_path) - 1);
            } else if (strcmp(key, "motd") == 0) {
                strncpy(config->motd, value, sizeof(config->motd) - 1);
            }
            break;
            
        case SECTION_LOGGING:
            if (strcmp(key, "level") == 0) {
                if (strcmp(value, "debug") == 0) config->log_level = 0;
                else if (strcmp(value, "info") == 0) config->log_level = 1;
                else if (strcmp(value, "warn") == 0) config->log_level = 2;
                else if (strcmp(value, "error") == 0) config->log_level = 3;
            } else if (strcmp(key, "audit_dir") == 0) {
                strncpy(config->audit_log_dir, value, sizeof(config->audit_log_dir) - 1);
            }
            break;
            
        case SECTION_LIMITS:
            if (strcmp(key, "max_sessions") == 0) {
                config->max_sessions = (size_t)atol(value);
            } else if (strcmp(key, "session_timeout") == 0) {
                config->session_timeout = (uint32_t)atoi(value);
            } else if (strcmp(key, "auth_timeout") == 0) {
                config->auth_timeout = (uint32_t)atoi(value);
            }
            break;
            
        case SECTION_USER:
            if (current_user != NULL) {
                if (strcmp(key, "password_hash") == 0) {
                    strncpy(current_user->password_hash, value,
                            sizeof(current_user->password_hash) - 1);
                } else if (strcmp(key, "pubkey") == 0) {
                    /* Append to pubkeys (supports multiple keys) */
                    if (current_user->pubkeys == NULL) {
                        current_user->pubkeys = strdup(value);
                    } else {
                        size_t old_len = strlen(current_user->pubkeys);
                        size_t new_len = old_len + strlen(value) + 2;
                        char *new_keys = realloc(current_user->pubkeys, new_len);
                        if (new_keys != NULL) {
                            current_user->pubkeys = new_keys;
                            strcat(current_user->pubkeys, "\n");
                            strcat(current_user->pubkeys, value);
                        }
                    }
                } else if (strcmp(key, "pubkey_file") == 0) {
                    /* Load pubkey from file */
                    FILE *kf = fopen(value, "r");
                    if (kf != NULL) {
                        fseek(kf, 0, SEEK_END);
                        long size = ftell(kf);
                        fseek(kf, 0, SEEK_SET);
                        if (size > 0 && size < CONFIG_MAX_PUBKEY) {
                            char *buf = malloc(size + 1);
                            if (buf != NULL) {
                                if (fread(buf, 1, size, kf) == (size_t)size) {
                                    buf[size] = '\0';
                                    /* Trim trailing whitespace */
                                    while (size > 0 && isspace((unsigned char)buf[size-1])) {
                                        buf[--size] = '\0';
                                    }
                                    if (current_user->pubkeys == NULL) {
                                        current_user->pubkeys = buf;
                                    } else {
                                        size_t old_len = strlen(current_user->pubkeys);
                                        size_t new_len = old_len + strlen(buf) + 2;
                                        char *new_keys = realloc(current_user->pubkeys, new_len);
                                        if (new_keys != NULL) {
                                            current_user->pubkeys = new_keys;
                                            strcat(current_user->pubkeys, "\n");
                                            strcat(current_user->pubkeys, buf);
                                        }
                                        free(buf);
                                    }
                                } else {
                                    free(buf);
                                }
                            }
                        }
                        fclose(kf);
                    } else {
                        LOG_WARN("Config line %d: cannot open pubkey_file: %s", 
                                 line_num, value);
                    }
                } else if (strcmp(key, "enabled") == 0) {
                    current_user->enabled = (strcmp(value, "true") == 0 ||
                                             strcmp(value, "1") == 0 ||
                                             strcmp(value, "yes") == 0);
                }
            }
            break;
            
        case SECTION_ROUTE:
            if (current_route != NULL) {
                if (strcmp(key, "upstream") == 0 || strcmp(key, "upstream_host") == 0 ||
                    strcmp(key, "host") == 0) {
                    strncpy(current_route->upstream_host, value,
                            sizeof(current_route->upstream_host) - 1);
                } else if (strcmp(key, "port") == 0 || strcmp(key, "upstream_port") == 0) {
                    current_route->upstream_port = (uint16_t)atoi(value);
                } else if (strcmp(key, "user") == 0 || strcmp(key, "upstream_user") == 0) {
                    strncpy(current_route->upstream_user, value,
                            sizeof(current_route->upstream_user) - 1);
                } else if (strcmp(key, "privkey") == 0 || strcmp(key, "private_key") == 0) {
                    strncpy(current_route->privkey_path, value,
                            sizeof(current_route->privkey_path) - 1);
                } else if (strcmp(key, "enabled") == 0) {
                    current_route->enabled = (strcmp(value, "true") == 0 ||
                                              strcmp(value, "1") == 0 ||
                                              strcmp(value, "yes") == 0);
                }
            }
            break;
            
        case SECTION_POLICY:
            if (current_policy != NULL) {
                if (strcmp(key, "allow") == 0 || strcmp(key, "allowed") == 0) {
                    current_policy->allowed_features = parse_policy_features(value);
                } else if (strcmp(key, "deny") == 0 || strcmp(key, "denied") == 0) {
                    current_policy->denied_features = parse_policy_features(value);
                }
            }
            break;
            
        default:
            /* Global section or unknown */
            break;
        }
    }
    
    fclose(fp);
    
    LOG_INFO("Configuration loaded from %s", path);
    
    /* Log summary */
    size_t user_count = 0;
    for (config_user_t *u = config->users; u != NULL; u = u->next) user_count++;
    
    size_t route_count = 0;
    for (config_route_t *r = config->routes; r != NULL; r = r->next) route_count++;
    
    size_t policy_count = 0;
    for (config_policy_t *p = config->policies; p != NULL; p = p->next) policy_count++;
    
    LOG_DEBUG("Config: %zu users, %zu routes, %zu policies", user_count, route_count, policy_count);
    
    /* Validate loaded configuration */
    int warnings = 0;

    if (config->port == 0) {
        LOG_WARN("Config validation: port is 0, using default 2222");
        config->port = 2222;
        warnings++;
    }

    if (config->max_sessions == 0) {
        LOG_WARN("Config validation: max_sessions is 0, using default 1000");
        config->max_sessions = 1000;
        warnings++;
    }

    if (config->session_timeout == 0) {
        LOG_WARN("Config validation: session_timeout is 0, using default 3600");
        config->session_timeout = 3600;
        warnings++;
    }

    if (config->auth_timeout == 0) {
        LOG_WARN("Config validation: auth_timeout is 0, using default 60");
        config->auth_timeout = 60;
        warnings++;
    }

    if (config->host_key_path[0] != '\0') {
        if (access(config->host_key_path, R_OK) != 0) {
            LOG_WARN("Config validation: host key '%s' not readable: %s",
                     config->host_key_path, strerror(errno));
            warnings++;
        }
    }

    /* Validate routes have required upstream_host */
    for (config_route_t *r = config->routes; r != NULL; r = r->next) {
        if (r->upstream_host[0] == '\0') {
            LOG_WARN("Config validation: route '%s' has no upstream host",
                     r->proxy_user);
            warnings++;
        }
        if (r->upstream_port == 0) {
            LOG_WARN("Config validation: route '%s' has invalid port, "
                     "using default 22",
                     r->proxy_user);
            r->upstream_port = 22;
            warnings++;
        }
    }

    /* Validate users have at least one auth method */
    for (config_user_t *u = config->users; u != NULL; u = u->next) {
        if (u->password_hash[0] == '\0' &&
            (u->pubkeys == NULL || u->pubkeys[0] == '\0')) {
            LOG_WARN("Config validation: user '%s' has no password_hash "
                     "and no pubkey configured",
                     u->username);
            warnings++;
        }
    }

    if (warnings > 0) {
        LOG_WARN("Config validation: %d warning(s)", warnings);
    }
    
    return config;
}

int config_reload(proxy_config_t *config, const char *path)
{
    if (config == NULL || path == NULL) return -1;
    
    /* Load new config */
    proxy_config_t *new_config = config_load(path);
    if (new_config == NULL) return -1;
    
    /* Free old user list */
    config_user_t *user = config->users;
    while (user != NULL) {
        config_user_t *next = user->next;
        free(user->pubkeys);
        free(user);
        user = next;
    }
    
    /* Free old routes */
    config_route_t *route = config->routes;
    while (route != NULL) {
        config_route_t *next = route->next;
        free(route);
        route = next;
    }
    
    /* Free old policies */
    config_policy_t *policy = config->policies;
    while (policy != NULL) {
        config_policy_t *next = policy->next;
        free(policy);
        policy = next;
    }
    
    /* Copy new values */
    memcpy(config->bind_addr, new_config->bind_addr, sizeof(config->bind_addr));
    config->port = new_config->port;
    memcpy(config->host_key_path, new_config->host_key_path, sizeof(config->host_key_path));
    config->log_level = new_config->log_level;
    memcpy(config->audit_log_dir, new_config->audit_log_dir, sizeof(config->audit_log_dir));
    config->max_sessions = new_config->max_sessions;
    config->session_timeout = new_config->session_timeout;
    config->auth_timeout = new_config->auth_timeout;
    config->users = new_config->users;
    config->routes = new_config->routes;
    config->policies = new_config->policies;
    config->default_policy = new_config->default_policy;
    config->log_transfers = new_config->log_transfers;
    config->log_port_forwards = new_config->log_port_forwards;
    memcpy(config->banner_path, new_config->banner_path, sizeof(config->banner_path));
    memcpy(config->motd, new_config->motd, sizeof(config->motd));
    
    /* Free shell only, not contents (transferred to config) */
    new_config->users = NULL;
    new_config->routes = NULL;
    new_config->policies = NULL;
    config_destroy(new_config);
    
    LOG_INFO("Configuration reloaded");
    return 0;
}

/* Helper to append a validation result to the list */
static config_valid_result_t *add_result(config_valid_result_t **list,
                                          config_valid_level_t level,
                                          const char *fmt, ...)
{
    config_valid_result_t *r = calloc(1, sizeof(config_valid_result_t));
    if (r == NULL) return NULL;
    r->level = level;
    va_list args;
    va_start(args, fmt);
    vsnprintf(r->message, sizeof(r->message), fmt, args);
    va_end(args);
    r->next = NULL;

    if (*list == NULL) {
        *list = r;
    } else {
        config_valid_result_t *tail = *list;
        while (tail->next != NULL) tail = tail->next;
        tail->next = r;
    }
    return r;
}

config_valid_result_t *config_validate(const proxy_config_t *config,
                                       const char *config_path)
{
    config_valid_result_t *results = NULL;

    if (config == NULL) {
        add_result(&results, CONFIG_VALID_ERROR, "Configuration is NULL");
        return results;
    }

    /* Server settings */
    if (config->port == 0) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "Port %u is out of valid range (1-65535)",
                   (unsigned)config->port);
    }

    if (config->bind_addr[0] == '\0') {
        add_result(&results, CONFIG_VALID_ERROR, "Bind address is empty");
    }

    /* Host key */
    if (config->host_key_path[0] != '\0') {
        if (access(config->host_key_path, R_OK) != 0) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Host key '%s' does not exist or is not readable",
                       config->host_key_path);
        } else {
            struct stat st;
            if (stat(config->host_key_path, &st) == 0 && (st.st_mode & S_IROTH)) {
                add_result(&results, CONFIG_VALID_WARN,
                           "Host key '%s' is world-readable (mode %04o)",
                           config->host_key_path, (unsigned)(st.st_mode & 0777));
            }
        }
    }

    /* Users */
    int user_count = 0;
    const config_user_t *user = config->users;
    while (user != NULL) {
        user_count++;
        if (user->username[0] == '\0') {
            add_result(&results, CONFIG_VALID_ERROR,
                       "User #%d has empty username", user_count);
        }
        if (user->password_hash[0] == '\0' &&
            (user->pubkeys == NULL || user->pubkeys[0] == '\0')) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "User '%s' has no password hash or public keys configured",
                       user->username);
        }
        user = user->next;
    }
    if (user_count == 0) {
        add_result(&results, CONFIG_VALID_WARN, "No users configured");
    }

    /* Routes */
    int route_count = 0;
    const config_route_t *route = config->routes;
    while (route != NULL) {
        route_count++;
        if (route->upstream_host[0] == '\0') {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Route #%d has empty upstream host", route_count);
        }
        if (route->upstream_port == 0) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Route #%d upstream port %u is out of valid range (1-65535)",
                       route_count, (unsigned)route->upstream_port);
        }
        if (route->privkey_path[0] != '\0') {
            if (access(route->privkey_path, R_OK) != 0) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Route #%d private key '%s' does not exist or is not readable",
                           route_count, route->privkey_path);
            }
        }
        /* Warn if route pattern doesn't match any configured user */
        if (route->proxy_user[0] != '\0' && user_count > 0) {
            bool matched = false;
            const config_user_t *u = config->users;
            while (u != NULL) {
                if (strcmp(route->proxy_user, "*") == 0 ||
                    strcmp(route->proxy_user, u->username) == 0 ||
                    strchr(route->proxy_user, '*') != NULL ||
                    strchr(route->proxy_user, '?') != NULL) {
                    matched = true;
                    break;
                }
                u = u->next;
            }
            if (!matched) {
                add_result(&results, CONFIG_VALID_WARN,
                           "Route #%d pattern '%s' does not match any configured user",
                           route_count, route->proxy_user);
            }
        }
        route = route->next;
    }
    if (route_count == 0) {
        add_result(&results, CONFIG_VALID_WARN, "No routes configured");
    }

    /* Policies */
    int policy_count = 0;
    const config_policy_t *policy = config->policies;
    while (policy != NULL) {
        policy_count++;
        policy = policy->next;
    }

    /* Summary info */
    add_result(&results, CONFIG_VALID_INFO,
               "Loaded %d user(s), %d route(s), %d policy/policies",
               user_count, route_count, policy_count);

    (void)config_path;  /* reserved for future file-level checks */

    return results;
}

void config_valid_free(config_valid_result_t *results)
{
    while (results != NULL) {
        config_valid_result_t *next = results->next;
        free(results);
        results = next;
    }
}
