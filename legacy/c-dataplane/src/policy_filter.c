/**
 * @file policy_filter.c
 * @brief SSH Proxy Core - Policy Filter Implementation
 *
 * Controls SSH feature access and logs file transfers.
 */

#include "policy_filter.h"
#include "logger.h"
#include "router.h"
#include "json.gen.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

/* Forward declarations */
static filter_status_t policy_on_channel_request(filter_t *filter, filter_context_t *ctx);
static filter_status_t policy_on_data_upstream(filter_t *filter, filter_context_t *ctx,
                                               const uint8_t *data, size_t len);
static void policy_on_close(filter_t *filter, filter_context_t *ctx);
static void policy_destroy(filter_t *filter);

static int init_transfer_log_strings(struct transfer_log *entry)
{
    if (entry == NULL) {
        return -1;
    }

    entry->username = sstr_new();
    entry->event = sstr_new();
    entry->direction = sstr_new();
    entry->protocol = sstr_new();
    entry->path = sstr_new();
    entry->checksum = sstr_new();
    if (entry->username == NULL || entry->event == NULL || entry->direction == NULL ||
        entry->protocol == NULL || entry->path == NULL || entry->checksum == NULL) {
        transfer_log_clear(entry);
        return -1;
    }
    return 0;
}

static int init_port_forward_log_strings(struct port_forward_log *entry)
{
    if (entry == NULL) {
        return -1;
    }

    entry->username = sstr_new();
    entry->type = sstr_new();
    entry->bind_host = sstr_new();
    entry->target_host = sstr_new();
    if (entry->username == NULL || entry->type == NULL || entry->bind_host == NULL ||
        entry->target_host == NULL) {
        port_forward_log_clear(entry);
        return -1;
    }
    return 0;
}

/* Filter callbacks */
static const filter_callbacks_t policy_callbacks = {
    .on_connect = NULL,
    .on_auth = NULL,
    .on_authenticated = NULL,
    .on_route = policy_on_channel_request,  /* Reuse on_route hook for request check */
    .on_data_upstream = policy_on_data_upstream,
    .on_data_downstream = NULL,
    .on_close = policy_on_close,
    .destroy = policy_destroy
};

/* Find matching user rule with optional upstream */
static policy_user_rule_t *find_user_rule(const policy_filter_config_t *config,
                                          const char *username,
                                          const char *upstream)
{
    if (config == NULL || username == NULL) {
        return NULL;
    }
    
    policy_user_rule_t *user_only_match = NULL;
    policy_user_rule_t *wildcard_match = NULL;
    
    policy_user_rule_t *rule = config->user_rules;
    while (rule != NULL) {
        /* Check if username matches */
        if (!router_glob_match(rule->username_pattern, username)) {
            rule = rule->next;
            continue;
        }
        
        /* Username matches, check upstream */
        bool has_upstream_pattern = (rule->upstream_pattern[0] != '\0');
        
        if (!has_upstream_pattern) {
            /* Rule applies to any upstream */
            if (user_only_match == NULL) {
                user_only_match = rule;
            }
        } else if (upstream != NULL) {
            /* Rule has upstream pattern */
            if (router_glob_match(rule->upstream_pattern, upstream)) {
                /* Both match - return immediately for exact match */
                bool user_exact = (strchr(rule->username_pattern, '*') == NULL &&
                                   strchr(rule->username_pattern, '?') == NULL);
                bool upstream_exact = (strchr(rule->upstream_pattern, '*') == NULL &&
                                       strchr(rule->upstream_pattern, '?') == NULL);
                if (user_exact && upstream_exact) {
                    return rule;
                }
                if (wildcard_match == NULL) {
                    wildcard_match = rule;
                }
            }
        }
        
        rule = rule->next;
    }
    
    /* Return best match: upstream-specific > user-only */
    return wildcard_match ? wildcard_match : user_only_match;
}

/* Write transfer log to file */
static void write_transfer_log(const policy_filter_config_t *config,
                               const transfer_record_t *record)
{
    if (config->transfer_log_dir == NULL || record == NULL) {
        return;
    }
    
    /* Ensure directory exists */
    mkdir(config->transfer_log_dir, 0755);
    
    /* Build filename: transfers_YYYYMMDD.log */
    struct tm *tm = localtime(&record->timestamp);
    char path[512];
    snprintf(path, sizeof(path), "%s/transfers_%04d%02d%02d.log",
             config->transfer_log_dir,
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    
    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        LOG_ERROR("Failed to open transfer log: %s: %s", path, strerror(errno));
        return;
    }
    
    /* Use json-gen-c for JSON serialization */
    struct transfer_log log_entry;
    transfer_log_init(&log_entry);
    if (init_transfer_log_strings(&log_entry) != 0) {
        LOG_ERROR("Failed to allocate transfer log serialization buffers");
        fclose(fp);
        return;
    }
    
    log_entry.timestamp = (long)record->timestamp;
    log_entry.session_id = (long)record->session_id;
    sstr_append_cstr(log_entry.username, record->username);
    
    const char *event_str = record->event == TRANSFER_EVENT_START ? "start" :
                            record->event == TRANSFER_EVENT_COMPLETE ? "complete" :
                            record->event == TRANSFER_EVENT_FAILED ? "failed" :
                            record->event == TRANSFER_EVENT_DENIED ? "denied" : "progress";
    sstr_append_cstr(log_entry.event, event_str);
    sstr_append_cstr(log_entry.direction, policy_transfer_dir_name(record->direction));
    sstr_append_cstr(log_entry.protocol, policy_transfer_proto_name(record->protocol));
    sstr_append_cstr(log_entry.path, record->remote_path);
    log_entry.file_size = (long)record->file_size;
    log_entry.bytes_transferred = (long)record->bytes_transferred;
    
    if (record->checksum[0] != '\0') {
        sstr_append_cstr(log_entry.checksum, record->checksum);
    }
    
    sstr_t json_str = sstr_new();
    json_marshal_transfer_log(&log_entry, json_str);
    fprintf(fp, "%s\n", sstr_cstr(json_str));
    
    sstr_free(json_str);
    transfer_log_clear(&log_entry);
    fclose(fp);
}

/* Write port forward log to file */
static void write_port_forward_log(const policy_filter_config_t *config,
                                   const port_forward_record_t *record)
{
    if (config->transfer_log_dir == NULL || record == NULL) {
        return;
    }
    
    /* Ensure directory exists */
    mkdir(config->transfer_log_dir, 0755);
    
    /* Build filename: port_forwards_YYYYMMDD.log */
    struct tm *tm = localtime(&record->timestamp);
    char path[512];
    snprintf(path, sizeof(path), "%s/port_forwards_%04d%02d%02d.log",
             config->transfer_log_dir,
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    
    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        LOG_ERROR("Failed to open port forward log: %s: %s", path, strerror(errno));
        return;
    }
    
    /* Use json-gen-c for JSON serialization */
    struct port_forward_log log_entry;
    port_forward_log_init(&log_entry);
    if (init_port_forward_log_strings(&log_entry) != 0) {
        LOG_ERROR("Failed to allocate port forward log serialization buffers");
        fclose(fp);
        return;
    }
    
    log_entry.timestamp = (long)record->timestamp;
    log_entry.session_id = (long)record->session_id;
    sstr_append_cstr(log_entry.username, record->username);
    sstr_append_cstr(log_entry.type, record->is_local ? "local" : "remote");
    sstr_append_cstr(log_entry.bind_host, record->bind_host);
    log_entry.bind_port = (int)record->bind_port;
    sstr_append_cstr(log_entry.target_host, record->target_host);
    log_entry.target_port = (int)record->target_port;
    log_entry.allowed = record->allowed;
    
    sstr_t json_str = sstr_new();
    json_marshal_port_forward_log(&log_entry, json_str);
    fprintf(fp, "%s\n", sstr_cstr(json_str));
    
    sstr_free(json_str);
    port_forward_log_clear(&log_entry);
    fclose(fp);
}

/* Filter callbacks */
static filter_status_t policy_on_channel_request(filter_t *filter, filter_context_t *ctx)
{
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }
    
    /* Currently, detailed request checking happens in on_data_upstream */
    /* This hook can be extended for pre-channel checks if needed */
    
    return FILTER_CONTINUE;
}

static filter_status_t policy_on_data_upstream(filter_t *filter, filter_context_t *ctx,
                                               const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
    
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }
    
    /* Data inspection for transfer detection is done at a higher level */
    /* The filter primarily enforces policy on exec/subsystem requests */
    
    return FILTER_CONTINUE;
}

static void policy_on_close(filter_t *filter, filter_context_t *ctx)
{
    (void)filter;
    (void)ctx;
    /* Cleanup any session-specific state if needed */
}

static void policy_destroy(filter_t *filter)
{
    if (filter == NULL) {
        return;
    }
    
    policy_filter_config_t *config = (policy_filter_config_t *)filter->config;
    if (config != NULL) {
        /* Free user rules */
        policy_user_rule_t *rule = config->user_rules;
        while (rule != NULL) {
            policy_user_rule_t *next = rule->next;
            free(rule);
            rule = next;
        }
        free(config);
    }
    
    LOG_DEBUG("Policy filter destroyed");
}

/* Public API */
filter_t *policy_filter_create(const policy_filter_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }
    
    /* Deep copy configuration */
    policy_filter_config_t *cfg_copy = calloc(1, sizeof(policy_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }
    
    cfg_copy->default_allowed = config->default_allowed;
    cfg_copy->log_transfers = config->log_transfers;
    cfg_copy->log_port_forwards = config->log_port_forwards;
    cfg_copy->log_denied = config->log_denied;
    cfg_copy->transfer_log_dir = config->transfer_log_dir;
    cfg_copy->transfer_cb = config->transfer_cb;
    cfg_copy->port_forward_cb = config->port_forward_cb;
    cfg_copy->cb_user_data = config->cb_user_data;
    cfg_copy->user_rules = NULL;
    
    /* Copy user rules */
    policy_user_rule_t *src = config->user_rules;
    policy_user_rule_t **dst = &cfg_copy->user_rules;
    while (src != NULL) {
        *dst = calloc(1, sizeof(policy_user_rule_t));
        if (*dst == NULL) {
            goto error;
        }
        memcpy(*dst, src, sizeof(policy_user_rule_t));
        (*dst)->next = NULL;
        dst = &(*dst)->next;
        src = src->next;
    }
    
    filter_t *filter = filter_create("policy", FILTER_TYPE_CUSTOM,
                                     &policy_callbacks, cfg_copy);
    if (filter == NULL) {
        goto error;
    }
    
    LOG_DEBUG("Policy filter created");
    return filter;
    
error:
    {
        policy_user_rule_t *r = cfg_copy->user_rules;
        while (r != NULL) {
            policy_user_rule_t *next = r->next;
            free(r);
            r = next;
        }
        free(cfg_copy);
    }
    return NULL;
}

int policy_add_user_rule(policy_filter_config_t *config,
                         const char *username_pattern,
                         const char *upstream_pattern,
                         uint32_t allowed_features,
                         uint32_t denied_features)
{
    if (config == NULL || username_pattern == NULL) {
        return -1;
    }
    
    policy_user_rule_t *rule = calloc(1, sizeof(policy_user_rule_t));
    if (rule == NULL) {
        return -1;
    }
    
    strncpy(rule->username_pattern, username_pattern, POLICY_MAX_PATTERN - 1);
    if (upstream_pattern != NULL) {
        strncpy(rule->upstream_pattern, upstream_pattern, POLICY_MAX_PATTERN - 1);
    }
    rule->allowed_features = allowed_features;
    rule->denied_features = denied_features;
    rule->next = config->user_rules;
    config->user_rules = rule;
    
    LOG_DEBUG("Policy: Added rule for '%s'%s%s: allow=0x%x, deny=0x%x",
              username_pattern,
              upstream_pattern ? "@" : "",
              upstream_pattern ? upstream_pattern : "",
              allowed_features, denied_features);
    
    return 0;
}

bool policy_check_feature(const policy_filter_config_t *config,
                          const char *username,
                          const char *upstream,
                          policy_feature_t feature)
{
    if (config == NULL) {
        return false;
    }
    
    policy_user_rule_t *rule = find_user_rule(config, username, upstream);
    
    if (rule != NULL) {
        /* Deny takes priority over allow */
        if (rule->denied_features & feature) {
            return false;
        }
        if (rule->allowed_features & feature) {
            return true;
        }
    }
    
    /* Fall back to default */
    return (config->default_allowed & feature) != 0;
}

uint32_t policy_get_allowed_features(const policy_filter_config_t *config,
                                     const char *username,
                                     const char *upstream)
{
    if (config == NULL) {
        return 0;
    }
    
    uint32_t allowed = config->default_allowed;
    
    policy_user_rule_t *rule = find_user_rule(config, username, upstream);
    if (rule != NULL) {
        allowed |= rule->allowed_features;
        allowed &= ~rule->denied_features;
    }
    
    return allowed;
}

void policy_log_transfer(filter_t *filter, const transfer_record_t *record)
{
    if (filter == NULL || record == NULL) {
        return;
    }
    
    policy_filter_config_t *config = (policy_filter_config_t *)filter->config;
    if (config == NULL) {
        return;
    }
    
    /* Log to file if enabled */
    if (config->log_transfers) {
        write_transfer_log(config, record);
    }
    
    /* Call callback if set */
    if (config->transfer_cb != NULL) {
        config->transfer_cb(record, config->cb_user_data);
    }
    
    /* Log to standard log */
    LOG_INFO("Transfer: user=%s dir=%s proto=%s path=%s size=%lu event=%s",
             record->username,
             policy_transfer_dir_name(record->direction),
             policy_transfer_proto_name(record->protocol),
             record->remote_path,
             record->file_size,
             record->event == TRANSFER_EVENT_START ? "start" :
             record->event == TRANSFER_EVENT_COMPLETE ? "complete" :
             record->event == TRANSFER_EVENT_DENIED ? "denied" : "other");
}

void policy_log_port_forward(filter_t *filter, const port_forward_record_t *record)
{
    if (filter == NULL || record == NULL) {
        return;
    }
    
    policy_filter_config_t *config = (policy_filter_config_t *)filter->config;
    if (config == NULL) {
        return;
    }
    
    /* Log to file if enabled */
    if (config->log_port_forwards) {
        write_port_forward_log(config, record);
    }
    
    /* Call callback if set */
    if (config->port_forward_cb != NULL) {
        config->port_forward_cb(record, config->cb_user_data);
    }
    
    /* Log to standard log */
    LOG_INFO("PortForward: user=%s type=%s %s:%u -> %s:%u allowed=%s",
             record->username,
             record->is_local ? "local" : "remote",
             record->bind_host, record->bind_port,
             record->target_host, record->target_port,
             record->allowed ? "yes" : "no");
}

policy_feature_t policy_detect_command(const char *command)
{
    if (command == NULL || command[0] == '\0') {
        return 0;
    }
    
    /* SCP detection */
    if (strncmp(command, "scp ", 4) == 0 || strstr(command, "/scp ") != NULL) {
        if (strstr(command, " -t ") != NULL) {
            return POLICY_FEAT_SCP_UPLOAD;   /* scp -t = sink mode (upload) */
        }
        if (strstr(command, " -f ") != NULL) {
            return POLICY_FEAT_SCP_DOWNLOAD; /* scp -f = source mode (download) */
        }
        return POLICY_FEAT_SCP_UPLOAD | POLICY_FEAT_SCP_DOWNLOAD;
    }
    
    /* SFTP subsystem */
    if (strcmp(command, "sftp") == 0 || strstr(command, "sftp-server") != NULL ||
        strcmp(command, "/usr/lib/openssh/sftp-server") == 0 ||
        strcmp(command, "/usr/libexec/sftp-server") == 0) {
        return POLICY_FEAT_SFTP_UPLOAD | POLICY_FEAT_SFTP_DOWNLOAD | 
               POLICY_FEAT_SFTP_LIST | POLICY_FEAT_SFTP_DELETE;
    }
    
    /* rsync detection */
    if (strncmp(command, "rsync ", 6) == 0 || strstr(command, "/rsync ") != NULL) {
        if (strstr(command, "--sender") != NULL) {
            return POLICY_FEAT_RSYNC_DOWNLOAD;
        }
        return POLICY_FEAT_RSYNC_UPLOAD;
    }
    
    /* Git operations */
    if (strncmp(command, "git-receive-pack ", 17) == 0 || 
        strstr(command, "git receive-pack") != NULL) {
        return POLICY_FEAT_GIT_PUSH;
    }
    if (strncmp(command, "git-upload-pack ", 16) == 0 || 
        strstr(command, "git upload-pack") != NULL) {
        return POLICY_FEAT_GIT_PULL;
    }
    if (strncmp(command, "git-upload-archive ", 19) == 0 ||
        strstr(command, "git upload-archive") != NULL) {
        return POLICY_FEAT_GIT_ARCHIVE;
    }
    
    /* General exec */
    return POLICY_FEAT_EXEC;
}

const char *policy_feature_name(policy_feature_t feature)
{
    switch (feature) {
        case POLICY_FEAT_SHELL:              return "shell";
        case POLICY_FEAT_EXEC:               return "exec";
        case POLICY_FEAT_SCP_UPLOAD:         return "scp_upload";
        case POLICY_FEAT_SCP_DOWNLOAD:       return "scp_download";
        case POLICY_FEAT_SFTP_UPLOAD:        return "sftp_upload";
        case POLICY_FEAT_SFTP_DOWNLOAD:      return "sftp_download";
        case POLICY_FEAT_SFTP_LIST:          return "sftp_list";
        case POLICY_FEAT_SFTP_DELETE:        return "sftp_delete";
        case POLICY_FEAT_RSYNC_UPLOAD:       return "rsync_upload";
        case POLICY_FEAT_RSYNC_DOWNLOAD:     return "rsync_download";
        case POLICY_FEAT_PORT_FORWARD_LOCAL: return "port_forward_local";
        case POLICY_FEAT_PORT_FORWARD_REMOTE: return "port_forward_remote";
        case POLICY_FEAT_PORT_FORWARD_DYNAMIC: return "port_forward_dynamic";
        case POLICY_FEAT_X11_FORWARD:        return "x11_forward";
        case POLICY_FEAT_AGENT_FORWARD:      return "agent_forward";
        case POLICY_FEAT_GIT_PUSH:           return "git_push";
        case POLICY_FEAT_GIT_PULL:           return "git_pull";
        case POLICY_FEAT_GIT_ARCHIVE:        return "git_archive";
        default:                             return "unknown";
    }
}

const char *policy_transfer_dir_name(transfer_direction_t dir)
{
    switch (dir) {
        case TRANSFER_DIR_UPLOAD:   return "upload";
        case TRANSFER_DIR_DOWNLOAD: return "download";
        default:                    return "unknown";
    }
}

const char *policy_transfer_proto_name(transfer_protocol_t proto)
{
    switch (proto) {
        case TRANSFER_PROTO_SCP:    return "scp";
        case TRANSFER_PROTO_SFTP:   return "sftp";
        case TRANSFER_PROTO_RSYNC:  return "rsync";
        case TRANSFER_PROTO_GIT:    return "git";
        default:                    return "unknown";
    }
}
