/**
 * @file ip_acl_filter.c
 * @brief SSH Proxy Core - IP Access Control List Filter Implementation
 */

#include "ip_acl_filter.h"
#include "logger.h"
#include "metrics.h"
#include "session.h"

#include <stdlib.h>
#include <string.h>

/* Forward declarations */
static filter_status_t ip_acl_on_connect(filter_t *filter, filter_context_t *ctx);
static void ip_acl_destroy(filter_t *filter);

/* Filter callbacks */
static const filter_callbacks_t ip_acl_callbacks = {.on_connect = ip_acl_on_connect,
                                                    .on_auth = NULL,
                                                    .on_authenticated = NULL,
                                                    .on_route = NULL,
                                                    .on_data_upstream = NULL,
                                                    .on_data_downstream = NULL,
                                                    .on_close = NULL,
                                                    .destroy = ip_acl_destroy};

/* Parse an IPv4 address string to a uint32_t in host byte order */
static int ip_acl_parse_ip(const char *ip_str, uint32_t *out) {
    if (ip_str == NULL || out == NULL) {
        return -1;
    }

    unsigned int a, b, c, d;
    char trailing;
    int n = sscanf(ip_str, "%u.%u.%u.%u%c", &a, &b, &c, &d, &trailing);
    if (n != 4) {
        return -1;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return -1;
    }

    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

/* Parse CIDR notation into network address and mask (host byte order) */
static int ip_acl_parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask) {
    if (cidr == NULL || network == NULL || mask == NULL) {
        return -1;
    }

    /* Copy the string so we can split on '/' */
    char buf[64];
    size_t len = strlen(cidr);
    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, cidr, len + 1);

    char *slash = strchr(buf, '/');
    int prefix_len = 32;

    if (slash != NULL) {
        *slash = '\0';
        char *endptr = NULL;
        long val = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0' || val < 0 || val > 32) {
            return -1;
        }
        prefix_len = (int)val;
    }

    uint32_t ip;
    if (ip_acl_parse_ip(buf, &ip) != 0) {
        return -1;
    }

    /* Build mask from prefix length */
    if (prefix_len == 0) {
        *mask = 0;
    } else {
        *mask = ~((UINT32_C(1) << (32 - prefix_len)) - 1);
    }

    *network = ip & *mask;
    return 0;
}

/* Check whether a single IP matches an ACL entry */
static bool ip_matches_entry(const ip_acl_entry_t *entry, uint32_t ip) {
    return (ip & entry->mask) == entry->network;
}

/* on_connect callback: extract client IP from session and check ACL */
static filter_status_t ip_acl_on_connect(filter_t *filter, filter_context_t *ctx) {
    if (filter == NULL || ctx == NULL) {
        return FILTER_CONTINUE;
    }

    ip_acl_filter_config_t *config = (ip_acl_filter_config_t *)filter->config;
    if (config == NULL) {
        return FILTER_CONTINUE;
    }

    session_metadata_t *meta = NULL;
    if (ctx->session != NULL) {
        meta = session_get_metadata(ctx->session);
    }

    const char *client_addr = meta ? meta->client_addr : NULL;

    bool allowed = ip_acl_check(filter, client_addr);

    if (!allowed) {
        if (config->log_rejections) {
            LOG_WARN("IP ACL: Connection denied for %s (mode=%s)",
                     client_addr ? client_addr : "(unknown)",
                     config->mode == IP_ACL_WHITELIST ? "whitelist" : "blacklist");
        }
        METRICS_INC(sessions_rejected);
        return FILTER_REJECT;
    }

    if (config->log_accepts) {
        LOG_INFO("IP ACL: Connection allowed for %s",
                 client_addr ? client_addr : "(unknown)");
    }

    return FILTER_CONTINUE;
}

static void ip_acl_destroy(filter_t *filter) {
    if (filter == NULL) {
        return;
    }

    ip_acl_filter_config_t *config = (ip_acl_filter_config_t *)filter->config;
    if (config != NULL) {
        ip_acl_entry_t *entry = config->entries;
        while (entry != NULL) {
            ip_acl_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    LOG_DEBUG("IP ACL filter destroyed");
}

filter_t *ip_acl_filter_create(const ip_acl_filter_config_t *config) {
    if (config == NULL) {
        return NULL;
    }

    /* Deep-copy configuration */
    ip_acl_filter_config_t *cfg_copy = calloc(1, sizeof(ip_acl_filter_config_t));
    if (cfg_copy == NULL) {
        return NULL;
    }
    *cfg_copy = *config;
    cfg_copy->entries = NULL;

    /* Deep-copy entries linked list */
    ip_acl_entry_t *src = config->entries;
    ip_acl_entry_t **dst = &cfg_copy->entries;
    while (src != NULL) {
        *dst = calloc(1, sizeof(ip_acl_entry_t));
        if (*dst == NULL) {
            /* Cleanup on allocation failure */
            ip_acl_entry_t *e = cfg_copy->entries;
            while (e != NULL) {
                ip_acl_entry_t *next = e->next;
                free(e);
                e = next;
            }
            free(cfg_copy);
            return NULL;
        }
        **dst = *src;
        (*dst)->next = NULL;
        dst = &(*dst)->next;
        src = src->next;
    }

    filter_t *filter =
        filter_create("ip_acl", FILTER_TYPE_CUSTOM, &ip_acl_callbacks, cfg_copy);
    if (filter == NULL) {
        ip_acl_entry_t *e = cfg_copy->entries;
        while (e != NULL) {
            ip_acl_entry_t *next = e->next;
            free(e);
            e = next;
        }
        free(cfg_copy);
        return NULL;
    }

    LOG_DEBUG("IP ACL filter created, mode=%s, log_rejections=%d",
              config->mode == IP_ACL_WHITELIST ? "whitelist" : "blacklist",
              config->log_rejections);

    return filter;
}

int ip_acl_add_entry(ip_acl_filter_config_t *config, const char *cidr,
                     ip_acl_action_t action) {
    if (config == NULL || cidr == NULL) {
        return -1;
    }

    uint32_t network, mask;
    if (ip_acl_parse_cidr(cidr, &network, &mask) != 0) {
        LOG_ERROR("IP ACL: Invalid CIDR notation: %s", cidr);
        return -1;
    }

    ip_acl_entry_t *entry = calloc(1, sizeof(ip_acl_entry_t));
    if (entry == NULL) {
        return -1;
    }

    entry->network = network;
    entry->mask = mask;
    entry->action = action;
    strncpy(entry->cidr_str, cidr, sizeof(entry->cidr_str) - 1);
    entry->cidr_str[sizeof(entry->cidr_str) - 1] = '\0';
    entry->next = NULL;

    /* Append to end of list to preserve insertion order (first-match-wins) */
    if (config->entries == NULL) {
        config->entries = entry;
    } else {
        ip_acl_entry_t *tail = config->entries;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = entry;
    }

    LOG_DEBUG("IP ACL entry added: %s -> %s", cidr,
              action == IP_ACL_ALLOW ? "ALLOW" : "DENY");

    return 0;
}

bool ip_acl_check(filter_t *filter, const char *ip_addr) {
    if (filter == NULL) {
        return true;
    }

    ip_acl_filter_config_t *config = (ip_acl_filter_config_t *)filter->config;
    if (config == NULL) {
        return true;
    }

    /* NULL/empty IP: deny in whitelist mode, allow in blacklist mode */
    if (ip_addr == NULL || *ip_addr == '\0') {
        return config->mode == IP_ACL_BLACKLIST;
    }

    uint32_t ip;
    if (ip_acl_parse_ip(ip_addr, &ip) != 0) {
        /* Unparseable IP: deny in whitelist mode, allow in blacklist mode */
        return config->mode == IP_ACL_BLACKLIST;
    }

    /* Walk the rules in order - first match wins */
    ip_acl_entry_t *entry = config->entries;
    while (entry != NULL) {
        if (ip_matches_entry(entry, ip)) {
            return entry->action == IP_ACL_ALLOW;
        }
        entry = entry->next;
    }

    /* No match: whitelist mode denies by default, blacklist mode allows */
    return config->mode == IP_ACL_BLACKLIST;
}

void ip_acl_clear_entries(ip_acl_filter_config_t *config) {
    if (config == NULL) {
        return;
    }

    ip_acl_entry_t *entry = config->entries;
    while (entry != NULL) {
        ip_acl_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
    config->entries = NULL;
}
