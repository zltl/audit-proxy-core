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
#include "audit_sign.h"
#include "ip_cidr.h"
#include "logger.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Configuration sections */
typedef enum {
    SECTION_NONE = 0,
    SECTION_SERVER,
    SECTION_LOGGING,
    SECTION_LIMITS,
    SECTION_ROUTER,
    SECTION_USER,
    SECTION_ROUTE,
    SECTION_POLICY,
    SECTION_NETWORK_SOURCES,
    SECTION_SESSION_STORE,
    SECTION_SECURITY,
    SECTION_ADMIN,
    SECTION_WEBHOOK
} config_section_t;

#define CONFIG_ROUTER_DEFAULT_RETRY_MAX                      3
#define CONFIG_ROUTER_DEFAULT_RETRY_INITIAL_DELAY_MS       100u
#define CONFIG_ROUTER_DEFAULT_RETRY_MAX_DELAY_MS          5000u
#define CONFIG_ROUTER_DEFAULT_RETRY_BACKOFF_FACTOR         2.0f
#define CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE                 10u
#define CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE_TIME_SEC       300u
#define CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_ENABLED      true
#define CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_THRESHOLD     3u
#define CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_OPEN_SECONDS 30u

static config_section_t parse_section(const char *line);
static int parse_key_value(const char *line, char *key, size_t key_len, char *value,
                           size_t value_len);
static void config_policy_init_defaults(config_policy_t *policy);
static bool glob_match(const char *pattern, const char *str);
static void config_route_init_runtime_state(config_route_t *route);

typedef struct config_geo_location {
    char country_code[CONFIG_MAX_COUNTRY_CODE];
    char country[CONFIG_MAX_GEO_TEXT];
    char region[CONFIG_MAX_GEO_TEXT];
    char city[CONFIG_MAX_GEO_TEXT];
    double latitude;
    double longitude;
    bool has_coordinates;
} config_geo_location_t;

typedef struct config_geo_record {
    char cidr[64];
    int prefix_len;
    config_geo_location_t location;
    struct config_geo_record *next;
} config_geo_record_t;

struct config_geo_db {
    config_geo_record_t *records;
};

static void config_free_geoip_db(config_geo_db_t *db);
static int config_load_geoip_db(proxy_config_t *config);
static bool config_geo_lookup(const proxy_config_t *config, const char *ip_addr,
                              config_geo_location_t *location);
static unsigned int config_route_circuit_threshold(const proxy_config_t *config);
static unsigned int config_route_circuit_open_seconds(const proxy_config_t *config);
static bool config_route_circuit_selectable(const proxy_config_t *config, config_route_t *route,
                                            time_t now);
static int route_geo_match_score(const config_route_t *route,
                                 const config_geo_location_t *client_geo);
static double route_geo_distance_sq(const config_route_t *route,
                                    const config_geo_location_t *client_geo);
static uint32_t affinity_hash_key(const char *key);
static int compare_affinity_routes(const void *left, const void *right);
static bool append_route_candidate(config_route_t ***routes, size_t *count, size_t *capacity,
                                   config_route_t *route);
static bool build_affinity_route_order(config_route_t **routes, size_t count,
                                       const char *proxy_user, config_route_t ***out_routes);
static config_route_t *select_available_route_candidate(const proxy_config_t *config,
                                                        config_route_t **routes, size_t count,
                                                        time_t now);
static bool route_pattern_matches(const config_route_t *route, const char *proxy_user,
                                  bool exact_only);
static bool string_equal_fold(const char *lhs, const char *rhs);
static const char *json_skip_ws(const char *cursor, const char *end);
static const char *json_find_matching_delim(const char *start, const char *end, char open_ch,
                                            char close_ch);
static bool json_find_object_field(const char *obj_start, const char *obj_end, const char *key,
                                   const char **value_start, const char **value_end,
                                   bool *string_value);
static bool json_extract_entries_array(const char *json, size_t json_len,
                                       const char **array_start, const char **array_end);
static bool json_copy_string_value(const char *start, const char *end, char *output,
                                   size_t output_len);
static bool json_parse_double_value(const char *start, const char *end, double *value);
static int parse_cidr_prefix_len(const char *cidr);
static config_geo_record_t *config_parse_geo_record(const char *obj_start, const char *obj_end,
                                                    int entry_index);

/* Helper: trim whitespace */
static char *trim(char *str) {
    if (str == NULL)
        return NULL;

    /* Trim leading */
    while (isspace((unsigned char)*str))
        str++;

    if (*str == '\0')
        return str;

    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';

    return str;
}

/* Helper: check if line is empty or comment */
static bool is_empty_or_comment(const char *line) {
    while (isspace((unsigned char)*line))
        line++;
    return (*line == '\0' || *line == '#' || *line == ';');
}

static bool parse_bool_value(const char *value) {
    return value != NULL &&
           (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 || strcmp(value, "yes") == 0);
}

static bool string_equal_fold(const char *lhs, const char *rhs) {
    if (lhs == NULL || rhs == NULL || lhs[0] == '\0' || rhs[0] == '\0') {
        return false;
    }
    return strcasecmp(lhs, rhs) == 0;
}

static void config_route_init_runtime_state(config_route_t *route) {
    if (route == NULL) {
        return;
    }
    atomic_init(&route->circuit_consecutive_failures, 0u);
    atomic_init(&route->circuit_open_until_epoch, 0);
    atomic_init(&route->circuit_probe_inflight, false);
}

static unsigned int config_route_circuit_threshold(const proxy_config_t *config) {
    if (config == NULL || config->router_circuit_breaker_failure_threshold == 0) {
        return CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_THRESHOLD;
    }
    return config->router_circuit_breaker_failure_threshold;
}

static unsigned int config_route_circuit_open_seconds(const proxy_config_t *config) {
    if (config == NULL || config->router_circuit_breaker_open_seconds == 0) {
        return CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_OPEN_SECONDS;
    }
    return config->router_circuit_breaker_open_seconds;
}

config_route_circuit_state_t config_route_circuit_state(const proxy_config_t *config,
                                                        config_route_t *route, time_t now) {
    unsigned int failures;
    time_t open_until;

    if (route == NULL || config == NULL || !config->router_circuit_breaker_enabled) {
        return CONFIG_ROUTE_CIRCUIT_CLOSED;
    }
    failures = atomic_load(&route->circuit_consecutive_failures);
    if (failures < config_route_circuit_threshold(config)) {
        return CONFIG_ROUTE_CIRCUIT_CLOSED;
    }
    if (atomic_load(&route->circuit_probe_inflight)) {
        return CONFIG_ROUTE_CIRCUIT_HALF_OPEN;
    }
    open_until = (time_t)atomic_load(&route->circuit_open_until_epoch);
    (void)open_until;
    (void)now;
    return CONFIG_ROUTE_CIRCUIT_OPEN;
}

static bool config_route_circuit_selectable(const proxy_config_t *config, config_route_t *route,
                                            time_t now) {
    unsigned int failures;
    time_t open_until;

    if (route == NULL || config == NULL || !config->router_circuit_breaker_enabled) {
        return true;
    }
    failures = atomic_load(&route->circuit_consecutive_failures);
    if (failures < config_route_circuit_threshold(config)) {
        return true;
    }
    if (atomic_load(&route->circuit_probe_inflight)) {
        return false;
    }
    open_until = (time_t)atomic_load(&route->circuit_open_until_epoch);
    return now >= open_until;
}

bool config_route_circuit_try_acquire(const proxy_config_t *config, config_route_t *route,
                                      time_t now, bool *half_open_probe) {
    unsigned int failures;
    time_t open_until;
    bool expected_probe = false;

    if (half_open_probe != NULL) {
        *half_open_probe = false;
    }
    if (route == NULL || config == NULL || !config->router_circuit_breaker_enabled) {
        return route != NULL;
    }

    failures = atomic_load(&route->circuit_consecutive_failures);
    if (failures < config_route_circuit_threshold(config)) {
        return true;
    }
    open_until = (time_t)atomic_load(&route->circuit_open_until_epoch);
    if (now < open_until) {
        return false;
    }
    if (!atomic_compare_exchange_strong(&route->circuit_probe_inflight, &expected_probe, true)) {
        return false;
    }
    if (half_open_probe != NULL) {
        *half_open_probe = true;
    }
    LOG_INFO("Circuit breaker half-open probe for route '%s' -> %s:%u", route->proxy_user,
             route->upstream_host, route->upstream_port);
    return true;
}

void config_route_circuit_release_probe(config_route_t *route) {
    if (route == NULL) {
        return;
    }
    atomic_store(&route->circuit_probe_inflight, false);
}

bool config_route_circuit_record_failure(const proxy_config_t *config, config_route_t *route,
                                         time_t now) {
    unsigned int threshold;
    unsigned int open_seconds;
    unsigned int new_failures;
    bool was_probe;

    if (route == NULL || config == NULL || !config->router_circuit_breaker_enabled) {
        config_route_circuit_release_probe(route);
        return false;
    }

    threshold = config_route_circuit_threshold(config);
    open_seconds = config_route_circuit_open_seconds(config);
    was_probe = atomic_exchange(&route->circuit_probe_inflight, false);
    new_failures = atomic_fetch_add(&route->circuit_consecutive_failures, 1u) + 1u;
    if (!was_probe && new_failures < threshold) {
        return false;
    }

    atomic_store(&route->circuit_consecutive_failures, threshold);
    atomic_store(&route->circuit_open_until_epoch, (long long)(now + (time_t)open_seconds));
    LOG_WARN("Circuit breaker opened for route '%s' -> %s:%u after %u failure(s); cooling down for %u second(s)",
             route->proxy_user, route->upstream_host, route->upstream_port,
             was_probe ? threshold : new_failures, open_seconds);
    return true;
}

void config_route_circuit_record_success(config_route_t *route) {
    unsigned int previous_failures;
    long long previous_open_until;
    bool had_probe;

    if (route == NULL) {
        return;
    }

    previous_failures = atomic_exchange(&route->circuit_consecutive_failures, 0u);
    previous_open_until = atomic_exchange(&route->circuit_open_until_epoch, 0);
    had_probe = atomic_exchange(&route->circuit_probe_inflight, false);
    if (had_probe || previous_open_until > 0) {
        LOG_INFO("Circuit breaker closed for route '%s' -> %s:%u after successful recovery probe",
                 route->proxy_user, route->upstream_host, route->upstream_port);
    } else {
        (void)previous_failures;
    }
}

static int route_geo_match_score(const config_route_t *route,
                                 const config_geo_location_t *client_geo) {
    int score = 0;

    if (route == NULL || client_geo == NULL) {
        return 0;
    }
    if (string_equal_fold(route->geo_country_code, client_geo->country_code)) {
        score += 100;
    } else if (string_equal_fold(route->geo_country, client_geo->country)) {
        score += 100;
    }
    if (string_equal_fold(route->geo_region, client_geo->region)) {
        score += 200;
    }
    if (string_equal_fold(route->geo_city, client_geo->city)) {
        score += 400;
    }
    return score;
}

static double route_geo_distance_sq(const config_route_t *route,
                                    const config_geo_location_t *client_geo) {
    double d_lat;
    double d_lon;
    bool has_coordinates;

    has_coordinates =
        route != NULL && (route->geo_has_coordinates ||
                          (route->geo_latitude_set && route->geo_longitude_set));
    if (route == NULL || client_geo == NULL || !has_coordinates ||
        !client_geo->has_coordinates) {
        return DBL_MAX;
    }
    d_lat = route->geo_latitude - client_geo->latitude;
    d_lon = route->geo_longitude - client_geo->longitude;
    return d_lat * d_lat + d_lon * d_lon;
}

static uint32_t affinity_hash_key(const char *key) {
    uint32_t hash = 2166136261u;

    if (key == NULL || *key == '\0') {
        return hash;
    }
    for (const unsigned char *p = (const unsigned char *)key; *p != '\0'; p++) {
        hash ^= (uint32_t)(*p);
        hash *= 16777619u;
    }
    return hash;
}

static int compare_affinity_routes(const void *left, const void *right) {
    const config_route_t *lhs = *(config_route_t *const *)left;
    const config_route_t *rhs = *(config_route_t *const *)right;
    int cmp;

    if (lhs == NULL || rhs == NULL) {
        return lhs == rhs ? 0 : (lhs == NULL ? -1 : 1);
    }
    cmp = strcmp(lhs->upstream_host, rhs->upstream_host);
    if (cmp != 0) {
        return cmp;
    }
    if (lhs->upstream_port != rhs->upstream_port) {
        return lhs->upstream_port < rhs->upstream_port ? -1 : 1;
    }
    cmp = strcmp(lhs->upstream_user, rhs->upstream_user);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->privkey_path, rhs->privkey_path);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->proxy_user, rhs->proxy_user);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->geo_country_code, rhs->geo_country_code);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->geo_country, rhs->geo_country);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->geo_region, rhs->geo_region);
    if (cmp != 0) {
        return cmp;
    }
    cmp = strcmp(lhs->geo_city, rhs->geo_city);
    if (cmp != 0) {
        return cmp;
    }
    if (lhs->geo_latitude != rhs->geo_latitude) {
        return lhs->geo_latitude < rhs->geo_latitude ? -1 : 1;
    }
    if (lhs->geo_longitude != rhs->geo_longitude) {
        return lhs->geo_longitude < rhs->geo_longitude ? -1 : 1;
    }
    if ((uintptr_t)lhs < (uintptr_t)rhs) {
        return -1;
    }
    if ((uintptr_t)lhs > (uintptr_t)rhs) {
        return 1;
    }
    return 0;
}

static bool append_route_candidate(config_route_t ***routes, size_t *count, size_t *capacity,
                                   config_route_t *route) {
    config_route_t **next_routes;
    size_t next_capacity;

    if (routes == NULL || count == NULL || capacity == NULL || route == NULL) {
        return false;
    }
    if (*count == *capacity) {
        next_capacity = *capacity == 0 ? 4 : (*capacity * 2);
        next_routes = realloc(*routes, next_capacity * sizeof((*routes)[0]));
        if (next_routes == NULL) {
            return false;
        }
        *routes = next_routes;
        *capacity = next_capacity;
    }
    (*routes)[(*count)++] = route;
    return true;
}

static bool build_affinity_route_order(config_route_t **routes, size_t count,
                                       const char *proxy_user, config_route_t ***out_routes) {
    config_route_t **ordered;
    size_t start = 0;

    if (out_routes == NULL) {
        return false;
    }
    *out_routes = NULL;
    if (routes == NULL || count == 0) {
        return true;
    }

    qsort(routes, count, sizeof(routes[0]), compare_affinity_routes);
    ordered = calloc(count, sizeof(ordered[0]));
    if (ordered == NULL) {
        return false;
    }
    if (count > 1) {
        start = affinity_hash_key(proxy_user) % count;
    }
    for (size_t i = 0; i < count; i++) {
        ordered[i] = routes[(start + i) % count];
    }
    *out_routes = ordered;
    return true;
}

static config_route_t *select_available_route_candidate(const proxy_config_t *config,
                                                        config_route_t **routes, size_t count,
                                                        time_t now) {
    if (routes == NULL || count == 0) {
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        if (config_route_circuit_selectable(config, routes[i], now)) {
            return routes[i];
        }
    }
    return routes[0];
}

static bool route_pattern_matches(const config_route_t *route, const char *proxy_user,
                                  bool exact_only) {
    bool has_wildcard;

    if (route == NULL || proxy_user == NULL || !route->enabled) {
        return false;
    }
    has_wildcard =
        (strchr(route->proxy_user, '*') != NULL || strchr(route->proxy_user, '?') != NULL);
    if (exact_only) {
        return !has_wildcard && strcmp(route->proxy_user, proxy_user) == 0;
    }
    return has_wildcard && glob_match(route->proxy_user, proxy_user);
}

static const char *json_skip_ws(const char *cursor, const char *end) {
    while (cursor != NULL && cursor < end && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    return cursor;
}

static const char *json_find_matching_delim(const char *start, const char *end, char open_ch,
                                            char close_ch) {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;

    if (start == NULL || end == NULL || start >= end || *start != open_ch) {
        return NULL;
    }

    for (const char *cursor = start; cursor < end; cursor++) {
        char ch = *cursor;
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (ch == open_ch) {
            depth++;
        } else if (ch == close_ch) {
            depth--;
            if (depth == 0) {
                return cursor;
            }
        }
    }

    return NULL;
}

static bool json_find_object_field(const char *obj_start, const char *obj_end, const char *key,
                                   const char **value_start, const char **value_end,
                                   bool *string_value) {
    const char *cursor;

    if (obj_start == NULL || obj_end == NULL || key == NULL || obj_start >= obj_end ||
        *obj_start != '{' || *obj_end != '}') {
        return false;
    }

    cursor = obj_start + 1;
    while (cursor < obj_end) {
        char field_name[64];
        size_t field_len = 0;
        bool escaped = false;
        bool is_string = false;
        const char *field_end;
        const char *field_value_start;
        const char *field_value_end;

        cursor = json_skip_ws(cursor, obj_end);
        if (cursor >= obj_end) {
            break;
        }
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor != '"') {
            cursor++;
            continue;
        }

        field_end = cursor + 1;
        while (field_end < obj_end) {
            if (escaped) {
                escaped = false;
            } else if (*field_end == '\\') {
                escaped = true;
            } else if (*field_end == '"') {
                break;
            }
            if (field_len + 1 < sizeof(field_name) && !escaped && *field_end != '"') {
                field_name[field_len++] = *field_end;
            }
            field_end++;
        }
        if (field_end >= obj_end || *field_end != '"') {
            return false;
        }
        field_name[field_len] = '\0';

        cursor = json_skip_ws(field_end + 1, obj_end);
        if (cursor >= obj_end || *cursor != ':') {
            return false;
        }
        field_value_start = json_skip_ws(cursor + 1, obj_end);
        if (field_value_start >= obj_end) {
            return false;
        }

        if (*field_value_start == '"') {
            const char *str_end = field_value_start + 1;
            escaped = false;
            while (str_end < obj_end) {
                if (escaped) {
                    escaped = false;
                } else if (*str_end == '\\') {
                    escaped = true;
                } else if (*str_end == '"') {
                    break;
                }
                str_end++;
            }
            if (str_end >= obj_end || *str_end != '"') {
                return false;
            }
            field_value_end = str_end;
            is_string = true;
            cursor = str_end + 1;
        } else if (*field_value_start == '{') {
            const char *match = json_find_matching_delim(field_value_start, obj_end + 1, '{', '}');
            if (match == NULL) {
                return false;
            }
            field_value_end = match + 1;
            cursor = match + 1;
        } else if (*field_value_start == '[') {
            const char *match = json_find_matching_delim(field_value_start, obj_end + 1, '[', ']');
            if (match == NULL) {
                return false;
            }
            field_value_end = match + 1;
            cursor = match + 1;
        } else {
            field_value_end = field_value_start;
            while (field_value_end < obj_end && *field_value_end != ',' && *field_value_end != '}') {
                field_value_end++;
            }
            while (field_value_end > field_value_start &&
                   isspace((unsigned char)field_value_end[-1])) {
                field_value_end--;
            }
            cursor = field_value_end;
        }

        if (strcmp(field_name, key) == 0) {
            if (value_start != NULL) {
                *value_start = is_string ? field_value_start + 1 : field_value_start;
            }
            if (value_end != NULL) {
                *value_end = is_string ? field_value_end : field_value_end;
            }
            if (string_value != NULL) {
                *string_value = is_string;
            }
            return true;
        }
    }

    return false;
}

static bool json_extract_entries_array(const char *json, size_t json_len,
                                       const char **array_start, const char **array_end) {
    const char *start = json_skip_ws(json, json + json_len);
    const char *end = json + json_len;
    const char *match;
    const char *value_start;
    const char *value_end;
    bool string_value = false;

    if (start == NULL || start >= end) {
        return false;
    }
    if (*start == '[') {
        match = json_find_matching_delim(start, end, '[', ']');
        if (match == NULL) {
            return false;
        }
        if (array_start != NULL) {
            *array_start = start + 1;
        }
        if (array_end != NULL) {
            *array_end = match;
        }
        return true;
    }
    if (*start != '{') {
        return false;
    }
    match = json_find_matching_delim(start, end, '{', '}');
    if (match == NULL) {
        return false;
    }
    if (!json_find_object_field(start, match, "entries", &value_start, &value_end, &string_value) ||
        string_value || value_start == NULL || value_start >= value_end || *value_start != '[') {
        return false;
    }
    if (array_start != NULL) {
        *array_start = value_start + 1;
    }
    if (array_end != NULL) {
        *array_end = value_end - 1;
    }
    return true;
}

static bool json_copy_string_value(const char *start, const char *end, char *output,
                                   size_t output_len) {
    size_t out_pos = 0;
    bool escaped = false;

    if (start == NULL || end == NULL || output == NULL || output_len == 0 || start > end) {
        return false;
    }

    while (start < end && out_pos + 1 < output_len) {
        char ch = *start++;
        if (escaped) {
            switch (ch) {
            case '"':
            case '\\':
            case '/':
                output[out_pos++] = ch;
                break;
            case 'b':
                output[out_pos++] = '\b';
                break;
            case 'f':
                output[out_pos++] = '\f';
                break;
            case 'n':
                output[out_pos++] = '\n';
                break;
            case 'r':
                output[out_pos++] = '\r';
                break;
            case 't':
                output[out_pos++] = '\t';
                break;
            default:
                output[out_pos++] = ch;
                break;
            }
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        output[out_pos++] = ch;
    }
    output[out_pos] = '\0';
    return !escaped;
}

static bool json_parse_double_value(const char *start, const char *end, double *value) {
    char buf[64];
    size_t len;
    char *parsed_end = NULL;

    if (start == NULL || end == NULL || value == NULL || start >= end) {
        return false;
    }
    while (start < end && isspace((unsigned char)*start)) {
        start++;
    }
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    if (start >= end) {
        return false;
    }
    len = (size_t)(end - start);
    if (len >= sizeof(buf)) {
        return false;
    }
    memcpy(buf, start, len);
    buf[len] = '\0';
    errno = 0;
    *value = strtod(buf, &parsed_end);
    return errno == 0 && parsed_end != NULL && *parsed_end == '\0';
}

static int parse_cidr_prefix_len(const char *cidr) {
    const char *slash;
    const char *addr = cidr;
    int family_default = 32;

    if (cidr == NULL || cidr[0] == '\0') {
        return -1;
    }
    while (isspace((unsigned char)*addr)) {
        addr++;
    }
    slash = strchr(addr, '/');
    if (strchr(addr, ':') != NULL) {
        family_default = 128;
    }
    if (slash == NULL) {
        return family_default;
    }
    return atoi(slash + 1);
}

static config_geo_record_t *config_parse_geo_record(const char *obj_start, const char *obj_end,
                                                    int entry_index) {
    config_geo_record_t *record = NULL;
    const char *value_start = NULL;
    const char *value_end = NULL;
    bool string_value = false;
    bool have_lat = false;
    bool have_lon = false;
    double latitude = 0.0;
    double longitude = 0.0;

    if (obj_start == NULL || obj_end == NULL) {
        return NULL;
    }

    record = calloc(1, sizeof(*record));
    if (record == NULL) {
        return NULL;
    }

    if (!json_find_object_field(obj_start, obj_end, "cidr", &value_start, &value_end, &string_value) ||
        !string_value || !json_copy_string_value(value_start, value_end, record->cidr,
                                                 sizeof(record->cidr)) ||
        !ip_cidr_list_is_valid(record->cidr)) {
        LOG_ERROR("Config validation: geoip entry %d has invalid or missing cidr", entry_index);
        free(record);
        return NULL;
    }
    record->prefix_len = parse_cidr_prefix_len(record->cidr);

    if (json_find_object_field(obj_start, obj_end, "country_code", &value_start, &value_end,
                               &string_value) &&
        string_value) {
        json_copy_string_value(value_start, value_end, record->location.country_code,
                               sizeof(record->location.country_code));
    }
    if (json_find_object_field(obj_start, obj_end, "country", &value_start, &value_end,
                               &string_value) &&
        string_value) {
        json_copy_string_value(value_start, value_end, record->location.country,
                               sizeof(record->location.country));
    }
    if (json_find_object_field(obj_start, obj_end, "region", &value_start, &value_end,
                               &string_value) &&
        string_value) {
        json_copy_string_value(value_start, value_end, record->location.region,
                               sizeof(record->location.region));
    }
    if (json_find_object_field(obj_start, obj_end, "city", &value_start, &value_end,
                               &string_value) &&
        string_value) {
        json_copy_string_value(value_start, value_end, record->location.city,
                               sizeof(record->location.city));
    }
    if (json_find_object_field(obj_start, obj_end, "latitude", &value_start, &value_end,
                               &string_value)) {
        if (string_value || !json_parse_double_value(value_start, value_end, &latitude)) {
            LOG_ERROR("Config validation: geoip entry %d has invalid latitude", entry_index);
            free(record);
            return NULL;
        }
        have_lat = true;
    }
    if (json_find_object_field(obj_start, obj_end, "longitude", &value_start, &value_end,
                               &string_value)) {
        if (string_value || !json_parse_double_value(value_start, value_end, &longitude)) {
            LOG_ERROR("Config validation: geoip entry %d has invalid longitude", entry_index);
            free(record);
            return NULL;
        }
        have_lon = true;
    }
    if (have_lat != have_lon) {
        LOG_ERROR("Config validation: geoip entry %d must set both latitude and longitude",
                  entry_index);
        free(record);
        return NULL;
    }
    if (have_lat) {
        if (latitude < -90.0 || latitude > 90.0 || longitude < -180.0 || longitude > 180.0) {
            LOG_ERROR("Config validation: geoip entry %d has out-of-range coordinates",
                      entry_index);
            free(record);
            return NULL;
        }
        record->location.latitude = latitude;
        record->location.longitude = longitude;
        record->location.has_coordinates = true;
    }

    return record;
}

static void config_free_geoip_db(config_geo_db_t *db) {
    if (db == NULL) {
        return;
    }
    config_geo_record_t *record = db->records;
    while (record != NULL) {
        config_geo_record_t *next = record->next;
        free(record);
        record = next;
    }
    free(db);
}

static int config_load_geoip_db(proxy_config_t *config) {
    FILE *fp = NULL;
    char *content = NULL;
    long file_size = 0;
    size_t read_len = 0;
    const char *array_start = NULL;
    const char *array_end = NULL;
    config_geo_db_t *db = NULL;
    int entry_index = 0;

    if (config == NULL || config->geoip_data_file[0] == '\0') {
        return 0;
    }

    fp = fopen(config->geoip_data_file, "rb");
    if (fp == NULL) {
        LOG_ERROR("Config validation: cannot open geoip_data_file '%s': %s",
                  config->geoip_data_file, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    file_size = ftell(fp);
    if (file_size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    content = calloc((size_t)file_size + 1, 1);
    if (content == NULL) {
        fclose(fp);
        return -1;
    }
    read_len = fread(content, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_len != (size_t)file_size) {
        free(content);
        return -1;
    }

    if (!json_extract_entries_array(content, read_len, &array_start, &array_end)) {
        LOG_ERROR("Config validation: geoip_data_file '%s' must contain a JSON array or {\"entries\": [...] }",
                  config->geoip_data_file);
        free(content);
        return -1;
    }

    db = calloc(1, sizeof(*db));
    if (db == NULL) {
        free(content);
        return -1;
    }

    for (const char *cursor = array_start; cursor < array_end; cursor++) {
        if (*cursor == '{') {
            const char *obj_end = json_find_matching_delim(cursor, array_end + 1, '{', '}');
            config_geo_record_t *record;
            if (obj_end == NULL || obj_end > array_end) {
                LOG_ERROR("Config validation: malformed geoip_data_file '%s'",
                          config->geoip_data_file);
                config_free_geoip_db(db);
                free(content);
                return -1;
            }
            entry_index++;
            record = config_parse_geo_record(cursor, obj_end, entry_index);
            if (record == NULL) {
                config_free_geoip_db(db);
                free(content);
                return -1;
            }
            record->next = db->records;
            db->records = record;
            cursor = obj_end;
        }
    }

    free(content);
    config->geoip_db = db;
    return 0;
}

static bool config_geo_lookup(const proxy_config_t *config, const char *ip_addr,
                              config_geo_location_t *location) {
    const config_geo_record_t *best = NULL;

    if (config == NULL || config->geoip_db == NULL || ip_addr == NULL || ip_addr[0] == '\0') {
        return false;
    }

    for (const config_geo_record_t *record = config->geoip_db->records; record != NULL;
         record = record->next) {
        if (!ip_cidr_match(ip_addr, record->cidr)) {
            continue;
        }
        if (best == NULL || record->prefix_len > best->prefix_len) {
            best = record;
        }
    }

    if (best == NULL) {
        return false;
    }
    if (location != NULL) {
        *location = best->location;
    }
    return true;
}

static int parse_epoch_seconds(const char *value, time_t *out) {
    if (value == NULL || out == NULL || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    char *end = NULL;
    long long raw = strtoll(value, &end, 10);
    if (errno != 0 || end == value || raw < 0) {
        return -1;
    }
    while (*end != '\0' && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0') {
        return -1;
    }

    *out = (time_t)raw;
    if ((long long)*out != raw) {
        return -1;
    }
    return 0;
}

static void config_policy_init_defaults(config_policy_t *policy) {
    if (policy == NULL) {
        return;
    }

    policy->allowed_features = 0x7FFFFFFF; /* All allowed by default */
    policy->denied_features = 0;
    policy->login_window_enabled = false;
    policy->login_days_mask = CONFIG_POLICY_DAY_ALL;
    policy->login_window_start_minute = 0;
    policy->login_window_end_minute = 0;
    policy->login_timezone_offset_minutes = 0;
    policy->allowed_source_types = CONFIG_POLICY_SOURCE_ALL;
    policy->denied_source_types = 0;
}

static int parse_clock_minutes(const char *value, uint16_t *out) {
    int hour = 0;
    int minute = 0;
    char tail = '\0';

    if (value == NULL || out == NULL) {
        return -1;
    }
    if (sscanf(value, "%d:%d%c", &hour, &minute, &tail) != 2) {
        return -1;
    }
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
        return -1;
    }

    *out = (uint16_t)(hour * 60 + minute);
    return 0;
}

static int parse_policy_login_window(const char *value, uint16_t *start, uint16_t *end) {
    char buf[64];
    char *sep = NULL;
    char *start_value = NULL;
    char *end_value = NULL;

    if (value == NULL || start == NULL || end == NULL) {
        return -1;
    }

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    sep = strchr(buf, '-');
    if (sep == NULL) {
        return -1;
    }
    *sep = '\0';
    start_value = trim(buf);
    end_value = trim(sep + 1);
    if (start_value == NULL || end_value == NULL || start_value[0] == '\0' ||
        end_value[0] == '\0') {
        return -1;
    }
    if (parse_clock_minutes(start_value, start) != 0 ||
        parse_clock_minutes(end_value, end) != 0) {
        return -1;
    }
    if (*start == *end) {
        return -1;
    }
    return 0;
}

static int parse_policy_day_index(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return -1;
    }

    if (strcmp(value, "mon") == 0 || strcmp(value, "monday") == 0) {
        return 0;
    }
    if (strcmp(value, "tue") == 0 || strcmp(value, "tues") == 0 ||
        strcmp(value, "tuesday") == 0) {
        return 1;
    }
    if (strcmp(value, "wed") == 0 || strcmp(value, "wednesday") == 0) {
        return 2;
    }
    if (strcmp(value, "thu") == 0 || strcmp(value, "thur") == 0 ||
        strcmp(value, "thurs") == 0 || strcmp(value, "thursday") == 0) {
        return 3;
    }
    if (strcmp(value, "fri") == 0 || strcmp(value, "friday") == 0) {
        return 4;
    }
    if (strcmp(value, "sat") == 0 || strcmp(value, "saturday") == 0) {
        return 5;
    }
    if (strcmp(value, "sun") == 0 || strcmp(value, "sunday") == 0) {
        return 6;
    }
    return -1;
}

static uint8_t policy_day_range_mask(int start_day, int end_day) {
    uint8_t mask = 0;
    int day = start_day;

    while (day >= 0 && day < 7) {
        mask |= (uint8_t)(1u << day);
        if (day == end_day) {
            break;
        }
        day = (day + 1) % 7;
    }
    return mask;
}

static int parse_policy_login_days(const char *value, uint8_t *out) {
    char buf[128];
    char *saveptr = NULL;
    char *token = NULL;
    uint8_t mask = 0;

    if (value == NULL || out == NULL) {
        return -1;
    }

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (token = strtok_r(buf, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
        char *part = trim(token);
        char *dash = NULL;
        int start_day = -1;
        int end_day = -1;

        if (part == NULL || part[0] == '\0') {
            continue;
        }

        if (strcmp(part, "all") == 0 || strcmp(part, "any") == 0) {
            mask |= CONFIG_POLICY_DAY_ALL;
            continue;
        }
        if (strcmp(part, "weekdays") == 0 || strcmp(part, "weekday") == 0) {
            mask |= policy_day_range_mask(0, 4);
            continue;
        }
        if (strcmp(part, "weekends") == 0 || strcmp(part, "weekend") == 0) {
            mask |= CONFIG_POLICY_DAY_SAT | CONFIG_POLICY_DAY_SUN;
            continue;
        }

        dash = strchr(part, '-');
        if (dash != NULL) {
            *dash = '\0';
            start_day = parse_policy_day_index(trim(part));
            end_day = parse_policy_day_index(trim(dash + 1));
            if (start_day < 0 || end_day < 0) {
                return -1;
            }
            mask |= policy_day_range_mask(start_day, end_day);
            continue;
        }

        start_day = parse_policy_day_index(part);
        if (start_day < 0) {
            return -1;
        }
        mask |= (uint8_t)(1u << start_day);
    }

    if (mask == 0) {
        return -1;
    }

    *out = mask;
    return 0;
}

static int parse_policy_timezone_offset(const char *value, int16_t *out) {
    char buf[32];
    char *trimmed = NULL;
    int sign = 1;
    int hour = 0;
    int minute = 0;
    char tail = '\0';

    if (value == NULL || out == NULL) {
        return -1;
    }

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trimmed = trim(buf);
    if (trimmed != buf) {
        memmove(buf, trimmed, strlen(trimmed) + 1);
    }

    if (strcmp(buf, "UTC") == 0 || strcmp(buf, "utc") == 0 || strcmp(buf, "Z") == 0 ||
        strcmp(buf, "z") == 0) {
        *out = 0;
        return 0;
    }

    if (buf[0] != '+' && buf[0] != '-') {
        return -1;
    }
    sign = (buf[0] == '-') ? -1 : 1;
    if (sscanf(buf + 1, "%d:%d%c", &hour, &minute, &tail) != 2) {
        return -1;
    }
    if (hour < 0 || hour > 14 || minute < 0 || minute > 59) {
        return -1;
    }
    if (hour == 14 && minute != 0) {
        return -1;
    }

    *out = (int16_t)(sign * (hour * 60 + minute));
    return 0;
}

static int policy_weekday_index(const struct tm *tm_value) {
    if (tm_value == NULL) {
        return -1;
    }
    return (tm_value->tm_wday + 6) % 7;
}

static bool policy_time_window_matches(const config_policy_t *policy, const struct tm *tm_value) {
    int weekday = 0;
    uint16_t minute = 0;
    uint8_t current_day_bit = 0;

    if (policy == NULL || tm_value == NULL) {
        return false;
    }

    weekday = policy_weekday_index(tm_value);
    if (weekday < 0) {
        return false;
    }
    minute = (uint16_t)(tm_value->tm_hour * 60 + tm_value->tm_min);
    current_day_bit = (uint8_t)(1u << weekday);

    if (policy->login_window_start_minute < policy->login_window_end_minute) {
        return (policy->login_days_mask & current_day_bit) != 0 &&
               minute >= policy->login_window_start_minute &&
               minute < policy->login_window_end_minute;
    }

    if ((policy->login_days_mask & current_day_bit) != 0 &&
        minute >= policy->login_window_start_minute) {
        return true;
    }

    int previous_day = (weekday + 6) % 7;
    uint8_t previous_day_bit = (uint8_t)(1u << previous_day);
    return (policy->login_days_mask & previous_day_bit) != 0 &&
           minute < policy->login_window_end_minute;
}

static void format_policy_minutes(uint16_t minute, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    snprintf(out, out_len, "%02u:%02u", (unsigned)(minute / 60), (unsigned)(minute % 60));
}

static void format_policy_day_mask(uint8_t mask, char *out, size_t out_len) {
    static const char *kDayNames[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
    size_t used = 0;

    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';

    for (size_t i = 0; i < sizeof(kDayNames) / sizeof(kDayNames[0]); i++) {
        if ((mask & (1u << i)) == 0) {
            continue;
        }
        if (used > 0 && used + 1 < out_len) {
            out[used++] = ',';
            out[used] = '\0';
        }
        snprintf(out + used, out_len - used, "%s", kDayNames[i]);
        used = strlen(out);
    }
}

static void format_policy_timezone(int16_t offset_minutes, char *out, size_t out_len) {
    int total_minutes = 0;
    int hours = 0;
    int minutes = 0;
    char sign = '+';

    if (out == NULL || out_len == 0) {
        return;
    }

    if (offset_minutes == 0) {
        snprintf(out, out_len, "UTC");
        return;
    }

    total_minutes = abs(offset_minutes);
    hours = total_minutes / 60;
    minutes = total_minutes % 60;
    if (offset_minutes < 0) {
        sign = '-';
    }
    snprintf(out, out_len, "UTC%c%02d:%02d", sign, hours, minutes);
}

static uint8_t source_type_bit_from_name(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (strcmp(value, "office") == 0 || strcmp(value, "corp") == 0 ||
        strcmp(value, "corporate") == 0) {
        return CONFIG_POLICY_SOURCE_OFFICE;
    }
    if (strcmp(value, "vpn") == 0) {
        return CONFIG_POLICY_SOURCE_VPN;
    }
    if (strcmp(value, "public") == 0 || strcmp(value, "internet") == 0) {
        return CONFIG_POLICY_SOURCE_PUBLIC;
    }
    return 0;
}

static int parse_policy_source_types(const char *value, uint8_t *out) {
    char buf[128];
    char *saveptr = NULL;
    char *token = NULL;
    uint8_t mask = 0;

    if (value == NULL || out == NULL) {
        return -1;
    }

    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (token = strtok_r(buf, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
        char *part = trim(token);
        uint8_t bit = 0;

        if (part == NULL || part[0] == '\0') {
            continue;
        }
        if (strcmp(part, "all") == 0 || strcmp(part, "any") == 0) {
            mask |= CONFIG_POLICY_SOURCE_ALL;
            continue;
        }

        bit = source_type_bit_from_name(part);
        if (bit == 0) {
            return -1;
        }
        mask |= bit;
    }

    if (mask == 0) {
        return -1;
    }
    *out = mask;
    return 0;
}

static void format_policy_source_types(uint8_t mask, char *out, size_t out_len) {
    static const struct {
        uint8_t bit;
        const char *name;
    } kTypes[] = {
        {CONFIG_POLICY_SOURCE_OFFICE, "office"},
        {CONFIG_POLICY_SOURCE_VPN, "vpn"},
        {CONFIG_POLICY_SOURCE_PUBLIC, "public"},
    };
    size_t used = 0;

    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';

    for (size_t i = 0; i < sizeof(kTypes) / sizeof(kTypes[0]); i++) {
        if ((mask & kTypes[i].bit) == 0) {
            continue;
        }
        if (used > 0 && used + 1 < out_len) {
            out[used++] = ',';
            out[used] = '\0';
        }
        snprintf(out + used, out_len - used, "%s", kTypes[i].name);
        used = strlen(out);
    }
}

static uint8_t classify_connection_source_type(const proxy_config_t *config, const char *client_addr) {
    if (client_addr == NULL || *client_addr == '\0' || config == NULL) {
        return CONFIG_POLICY_SOURCE_PUBLIC;
    }
    if (config->vpn_source_cidrs != NULL &&
        ip_cidr_list_match(client_addr, config->vpn_source_cidrs)) {
        return CONFIG_POLICY_SOURCE_VPN;
    }
    if (config->office_source_cidrs != NULL &&
        ip_cidr_list_match(client_addr, config->office_source_cidrs)) {
        return CONFIG_POLICY_SOURCE_OFFICE;
    }
    return CONFIG_POLICY_SOURCE_PUBLIC;
}

static const char *source_type_name(uint8_t source_type) {
    switch (source_type) {
        case CONFIG_POLICY_SOURCE_OFFICE:
            return "office";
        case CONFIG_POLICY_SOURCE_VPN:
            return "vpn";
        case CONFIG_POLICY_SOURCE_PUBLIC:
        default:
            return "public";
    }
}

static int append_multiline_value(char **dst, const char *value) {
    char *copy = NULL;

    if (dst == NULL || value == NULL || value[0] == '\0') {
        return -1;
    }

    if (*dst == NULL) {
        copy = strdup(value);
        if (copy == NULL) {
            return -1;
        }
        *dst = copy;
        return 0;
    }

    size_t old_len = strlen(*dst);
    size_t new_len = old_len + strlen(value) + 2;
    copy = realloc(*dst, new_len);
    if (copy == NULL) {
        return -1;
    }

    *dst = copy;
    strcat(*dst, "\n");
    strcat(*dst, value);
    return 0;
}

static int append_file_value(char **dst, const char *path, size_t max_size, int line_num,
                             const char *key_name) {
    FILE *fp = NULL;
    char *buf = NULL;
    long size = 0;

    if (dst == NULL || path == NULL || path[0] == '\0') {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        LOG_WARN("Config line %d: cannot open %s: %s", line_num, key_name, path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0 || (size_t)size >= max_size) {
        fclose(fp);
        return -1;
    }

    buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    buf[size] = '\0';

    while (size > 0 && isspace((unsigned char)buf[size - 1])) {
        buf[--size] = '\0';
    }

    int rc = append_multiline_value(dst, buf);
    free(buf);
    return rc;
}

static bool config_has_trusted_user_ca_keys(const proxy_config_t *config) {
    return config != NULL && config->trusted_user_ca_keys != NULL &&
           config->trusted_user_ca_keys[0] != '\0';
}

static bool valid_hex_string(const char *value, size_t expected_len) {
    if (value == NULL || value[0] == '\0' || strlen(value) != expected_len) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isxdigit(*p)) {
            return false;
        }
    }
    return true;
}

#define CONFIG_MASTER_KEY_HEX_LEN 64
#define CONFIG_SECRET_PREFIX "enc:v1:"
#define CONFIG_SECRET_NONCE_SIZE 12
#define CONFIG_SECRET_TAG_SIZE 16

static bool is_encrypted_secret_value(const char *value) {
    return value != NULL && strncmp(value, CONFIG_SECRET_PREFIX, strlen(CONFIG_SECRET_PREFIX)) == 0;
}

static char *dup_trimmed_string(const char *value) {
    char *copy = NULL;
    char *trimmed = NULL;

    if (value == NULL) {
        return NULL;
    }
    copy = strdup(value);
    if (copy == NULL) {
        return NULL;
    }
    trimmed = trim(copy);
    if (trimmed != copy) {
        memmove(copy, trimmed, strlen(trimmed) + 1);
    }
    return copy;
}

static int read_secret_file_value(const char *path, char **out) {
    FILE *fp = NULL;
    char *buf = NULL;
    long size = 0;
    char *trimmed = NULL;

    if (path == NULL || out == NULL) {
        return -1;
    }
    *out = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    size = ftell(fp);
    if (size <= 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buf = calloc((size_t)size + 1, 1);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        explicit_bzero(buf, (size_t)size + 1);
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    trimmed = trim(buf);
    if (trimmed != buf) {
        memmove(buf, trimmed, strlen(trimmed) + 1);
    }
    *out = buf;
    return 0;
}

static int assign_master_key(char **dst, const char *value, int line_num, const char *key_name) {
    char *copy = NULL;

    if (dst == NULL || value == NULL || value[0] == '\0') {
        return -1;
    }
    if (*dst != NULL) {
        LOG_ERROR("Config line %d: duplicate %s is not allowed", line_num, key_name);
        return -1;
    }
    copy = dup_trimmed_string(value);
    if (copy == NULL) {
        return -1;
    }
    *dst = copy;
    return 0;
}

static int prescan_master_key(const char *path, char **out_master_key) {
    FILE *fp = NULL;
    char line[CONFIG_MAX_LINE];
    config_section_t current_section = SECTION_NONE;
    int line_num = 0;
    char *master_key = NULL;

    if (path == NULL || out_master_key == NULL) {
        return -1;
    }
    *out_master_key = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char key[128];
        char value[CONFIG_MAX_LINE];
        char *trimmed = NULL;
        line_num++;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        trimmed = trim(line);
        if (is_empty_or_comment(trimmed)) {
            continue;
        }
        if (trimmed[0] == '[') {
            current_section = parse_section(trimmed);
            continue;
        }
        if (current_section != SECTION_SECURITY) {
            continue;
        }
        if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) != 0) {
            continue;
        }
        if (strcmp(key, "master_key") == 0) {
            if (assign_master_key(&master_key, value, line_num, "master_key") != 0) {
                goto fail;
            }
        } else if (strcmp(key, "master_key_file") == 0) {
            char *file_value = NULL;
            if (master_key != NULL) {
                LOG_ERROR("Config line %d: master_key and master_key_file are mutually exclusive",
                          line_num);
                goto fail;
            }
            if (read_secret_file_value(value, &file_value) != 0) {
                LOG_ERROR("Config line %d: failed to read master_key_file '%s'", line_num, value);
                goto fail;
            }
            master_key = file_value;
        }
    }

    fclose(fp);
    if (master_key != NULL && !valid_hex_string(master_key, CONFIG_MASTER_KEY_HEX_LEN)) {
        LOG_ERROR("Config: master_key must be a 64-character hex AES-256 key");
        goto fail_after_close;
    }
    *out_master_key = master_key;
    return 0;

fail:
    fclose(fp);
fail_after_close:
    if (master_key != NULL) {
        explicit_bzero(master_key, strlen(master_key));
        free(master_key);
    }
    return -1;
}

static int decrypt_secret_value(const char *value, const char *master_key, char *out, size_t out_len) {
    char *copy = NULL;
    char *saveptr = NULL;
    char *nonce_hex = NULL;
    char *ciphertext_hex = NULL;
    char *tag_hex = NULL;
    uint8_t key[32];
    uint8_t nonce[CONFIG_SECRET_NONCE_SIZE];
    uint8_t tag[CONFIG_SECRET_TAG_SIZE];
    uint8_t *ciphertext = NULL;
    uint8_t *plaintext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int key_len = 0;
    int ciphertext_len = 0;
    int plain_len = 0;
    int final_len = 0;
    int rc = -1;

    if (value == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    if (!is_encrypted_secret_value(value)) {
        if (strlen(value) >= out_len) {
            return -1;
        }
        memcpy(out, value, strlen(value) + 1);
        return 0;
    }

    if (master_key == NULL || !valid_hex_string(master_key, CONFIG_MASTER_KEY_HEX_LEN)) {
        return -1;
    }

    copy = strdup(value + strlen(CONFIG_SECRET_PREFIX));
    if (copy == NULL) {
        return -1;
    }

    nonce_hex = strtok_r(copy, ":", &saveptr);
    ciphertext_hex = strtok_r(NULL, ":", &saveptr);
    tag_hex = strtok_r(NULL, ":", &saveptr);
    if (nonce_hex == NULL || ciphertext_hex == NULL || tag_hex == NULL ||
        strtok_r(NULL, ":", &saveptr) != NULL) {
        goto cleanup;
    }
    if (!valid_hex_string(nonce_hex, CONFIG_SECRET_NONCE_SIZE * 2U) ||
        !valid_hex_string(tag_hex, CONFIG_SECRET_TAG_SIZE * 2U) ||
        (strlen(ciphertext_hex) % 2U) != 0) {
        goto cleanup;
    }

    key_len = hex_decode(master_key, key, sizeof(key));
    if (key_len != 32 ||
        hex_decode(nonce_hex, nonce, sizeof(nonce)) != CONFIG_SECRET_NONCE_SIZE ||
        hex_decode(tag_hex, tag, sizeof(tag)) != CONFIG_SECRET_TAG_SIZE) {
        goto cleanup;
    }

    ciphertext = calloc(strlen(ciphertext_hex) / 2U + 1U, 1);
    if (ciphertext == NULL) {
        goto cleanup;
    }
    ciphertext_len = hex_decode(ciphertext_hex, ciphertext, strlen(ciphertext_hex) / 2U + 1U);
    if (ciphertext_len < 0) {
        goto cleanup;
    }

    plaintext = calloc((size_t)ciphertext_len + 1U, 1);
    if (plaintext == NULL) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        (ciphertext_len > 0 && EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, ciphertext_len) != 1) ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &final_len) != 1) {
        goto cleanup;
    }

    if ((size_t)(plain_len + final_len) >= out_len) {
        goto cleanup;
    }
    memcpy(out, plaintext, (size_t)(plain_len + final_len));
    out[plain_len + final_len] = '\0';
    rc = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(key, sizeof(key));
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(tag, sizeof(tag));
    if (plaintext != NULL) {
        explicit_bzero(plaintext, (size_t)ciphertext_len + 1U);
        free(plaintext);
    }
    if (ciphertext != NULL) {
        explicit_bzero(ciphertext, strlen(ciphertext_hex != NULL ? ciphertext_hex : "") / 2U + 1U);
        free(ciphertext);
    }
    if (copy != NULL) {
        explicit_bzero(copy, strlen(copy));
        free(copy);
    }
    return rc;
}

/* Helper: parse section header [section] */
static config_section_t parse_section(const char *line) {
    if (line[0] != '[')
        return SECTION_NONE;

    char section[64] = {0};
    const char *start = line + 1;
    const char *end = strchr(start, ']');
    if (end == NULL)
        return SECTION_NONE;

    size_t len = end - start;
    if (len >= sizeof(section))
        len = sizeof(section) - 1;
    strncpy(section, start, len);

    if (strcmp(section, "server") == 0)
        return SECTION_SERVER;
    if (strcmp(section, "logging") == 0)
        return SECTION_LOGGING;
    if (strcmp(section, "limits") == 0)
        return SECTION_LIMITS;
    if (strcmp(section, "router") == 0)
        return SECTION_ROUTER;
    if (strcmp(section, "security") == 0)
        return SECTION_SECURITY;
    if (strcmp(section, "admin") == 0)
        return SECTION_ADMIN;
    if (strcmp(section, "webhook") == 0)
        return SECTION_WEBHOOK;
    if (strcmp(section, "network_sources") == 0 || strcmp(section, "source_networks") == 0)
        return SECTION_NETWORK_SOURCES;
    if (strcmp(section, "session_store") == 0)
        return SECTION_SESSION_STORE;
    if (strncmp(section, "user:", 5) == 0)
        return SECTION_USER;
    if (strncmp(section, "route:", 6) == 0)
        return SECTION_ROUTE;
    if (strncmp(section, "policy:", 7) == 0)
        return SECTION_POLICY;

    return SECTION_NONE;
}

/* Helper: extract section parameter (e.g., "user:testuser" -> "testuser") */
static const char *get_section_param(const char *line) {
    const char *colon = strchr(line + 1, ':');
    if (colon == NULL)
        return NULL;

    static char param[256];
    const char *start = colon + 1;
    const char *end = strchr(start, ']');
    if (end == NULL)
        return NULL;

    size_t len = end - start;
    if (len >= sizeof(param))
        len = sizeof(param) - 1;
    strncpy(param, start, len);
    param[len] = '\0';

    return trim(param);
}

/* Helper: parse key = value */
static int parse_key_value(const char *line, char *key, size_t key_len, char *value,
                           size_t value_len) {
    const char *eq = strchr(line, '=');
    if (eq == NULL)
        return -1;

    /* Extract key */
    size_t klen = eq - line;
    if (klen >= key_len)
        klen = key_len - 1;
    strncpy(key, line, klen);
    key[klen] = '\0';

    /* Trim key */
    char *k = trim(key);
    if (k != key)
        memmove(key, k, strlen(k) + 1);

    /* Extract value */
    const char *v = eq + 1;
    while (isspace((unsigned char)*v))
        v++;

    strncpy(value, v, value_len - 1);
    value[value_len - 1] = '\0';

    /* Trim value */
    char *val = trim(value);
    if (val != value)
        memmove(value, val, strlen(val) + 1);

    /* Remove quotes if present */
    size_t vlen = strlen(value);
    if (vlen >= 2 && ((value[0] == '"' && value[vlen - 1] == '"') ||
                      (value[0] == '\'' && value[vlen - 1] == '\''))) {
        memmove(value, value + 1, vlen - 2);
        value[vlen - 2] = '\0';
    }

    /* Expand ${env:...} and ${file:...} references */
    char expanded[CONFIG_MAX_LINE];
    if (config_expand_env(value, expanded, sizeof(expanded)) == 0) {
        strncpy(value, expanded, value_len - 1);
        value[value_len - 1] = '\0';
    }

    return 0;
}

static bool line_uses_secret_reference(const char *line) {
    const char *eq = NULL;
    const char *value = NULL;
    char buf[CONFIG_MAX_LINE];
    char *trimmed = NULL;
    size_t len = 0;

    if (line == NULL) {
        return false;
    }
    eq = strchr(line, '=');
    if (eq == NULL) {
        return false;
    }

    value = eq + 1;
    while (isspace((unsigned char)*value)) {
        value++;
    }

    len = strlen(value);
    if (len >= sizeof(buf)) {
        len = sizeof(buf) - 1;
    }
    memcpy(buf, value, len);
    buf[len] = '\0';
    trimmed = trim(buf);
    if (trimmed != buf) {
        memmove(buf, trimmed, strlen(trimmed) + 1);
    }

    len = strlen(buf);
    if (len >= 2 && ((buf[0] == '"' && buf[len - 1] == '"') || (buf[0] == '\'' && buf[len - 1] == '\''))) {
        memmove(buf, buf + 1, len - 2);
        buf[len - 2] = '\0';
    }

    return strstr(buf, "${env:") != NULL || strstr(buf, "${file:") != NULL ||
           is_encrypted_secret_value(buf);
}

static uint32_t parse_webhook_event_mask(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return (uint32_t)WEBHOOK_EVENT_ALL;
    }

    char buf[CONFIG_MAX_LINE];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    uint32_t mask = 0;
    char *saveptr = NULL;
    for (char *token = strtok_r(buf, ",", &saveptr); token != NULL;
         token = strtok_r(NULL, ",", &saveptr)) {
        char *name = trim(token);
        if (strcmp(name, "all") == 0) {
            return (uint32_t)WEBHOOK_EVENT_ALL;
        } else if (strcmp(name, "auth.success") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_AUTH_SUCCESS;
        } else if (strcmp(name, "auth.failure") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_AUTH_FAILURE;
        } else if (strcmp(name, "session.start") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_SESSION_START;
        } else if (strcmp(name, "session.end") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_SESSION_END;
        } else if (strcmp(name, "rate_limit.triggered") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_RATE_LIMIT;
        } else if (strcmp(name, "ip_acl.denied") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_IP_ACL_DENIED;
        } else if (strcmp(name, "upstream.unhealthy") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_UPSTREAM_UNHEALTHY;
        } else if (strcmp(name, "upstream.healthy") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_UPSTREAM_HEALTHY;
        } else if (strcmp(name, "config.reloaded") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_CONFIG_RELOADED;
        } else if (strcmp(name, "user.created") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_USER_CREATED;
        } else if (strcmp(name, "user.updated") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_USER_UPDATED;
        } else if (strcmp(name, "user.deleted") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_USER_DELETED;
        } else if (strcmp(name, "policy.updated") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_POLICY_UPDATED;
        } else if (strcmp(name, "certificate.issued") == 0) {
            mask |= (uint32_t)WEBHOOK_EVENT_CERT_ISSUED;
        } else {
            LOG_WARN("config: unknown webhook event '%s'", name);
        }
    }

    return mask;
}

int config_expand_env(const char *value, char *out, size_t out_len) {
    if (value == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    const char *src = value;
    size_t pos = 0;

    while (*src != '\0' && pos < out_len - 1) {
        /* Look for ${env:...} or ${file:...} */
        if (src[0] == '$' && src[1] == '{') {
            const char *close = strchr(src + 2, '}');
            if (close == NULL) {
                /* No closing brace — copy literally */
                out[pos++] = *src++;
                continue;
            }

            /* Extract the prefix:body between ${ and } */
            size_t inner_len = close - (src + 2);
            char inner[CONFIG_MAX_LINE];
            if (inner_len >= sizeof(inner)) {
                inner_len = sizeof(inner) - 1;
            }
            memcpy(inner, src + 2, inner_len);
            inner[inner_len] = '\0';

            const char *replacement = NULL;
            char file_buf[CONFIG_MAX_LINE];

            if (strncmp(inner, "env:", 4) == 0) {
                const char *varname = inner + 4;
                replacement = getenv(varname);
                if (replacement == NULL) {
                    LOG_WARN("config: environment variable '%s' not set", varname);
                    /* Leave empty */
                    replacement = "";
                }
            } else if (strncmp(inner, "file:", 5) == 0) {
                const char *filepath = inner + 5;
                FILE *fp = fopen(filepath, "r");
                if (fp == NULL) {
                    LOG_WARN("config: cannot open file '%s' for expansion", filepath);
                    replacement = "";
                } else {
                    if (fgets(file_buf, sizeof(file_buf), fp) != NULL) {
                        /* Strip trailing newline */
                        size_t flen = strlen(file_buf);
                        while (flen > 0 &&
                               (file_buf[flen - 1] == '\n' || file_buf[flen - 1] == '\r')) {
                            file_buf[--flen] = '\0';
                        }
                        replacement = file_buf;
                    } else {
                        replacement = "";
                    }
                    fclose(fp);
                }
            } else {
                /* Unknown prefix — copy literally */
                out[pos++] = *src++;
                continue;
            }

            /* Copy replacement into output */
            size_t rlen = strlen(replacement);
            if (pos + rlen >= out_len) {
                rlen = out_len - pos - 1;
            }
            memcpy(out + pos, replacement, rlen);
            pos += rlen;

            /* Advance past ${...} */
            src = close + 1;
        } else {
            out[pos++] = *src++;
        }
    }

    out[pos] = '\0';
    return 0;
}

proxy_config_t *config_create(void) {
    proxy_config_t *config = calloc(1, sizeof(proxy_config_t));
    if (config == NULL)
        return NULL;

    /* Set defaults */
    strncpy(config->bind_addr, "0.0.0.0", sizeof(config->bind_addr) - 1);
    config->port = 2222;
    strncpy(config->host_key_path, "/tmp/ssh_proxy_host_key", sizeof(config->host_key_path) - 1);

    config->log_level = 1; /* INFO */
    strncpy(config->audit_log_dir, "/tmp/ssh_proxy_audit", sizeof(config->audit_log_dir) - 1);
    config->audit_max_archived_files = 0;
    config->audit_retention_days = 0;

    config->max_sessions = 1000;
    config->session_timeout = 3600;
    config->auth_timeout = 60;
    strncpy(config->session_store_type, "local", sizeof(config->session_store_type) - 1);
    config->session_store_sync_interval = 5;

    config->users = NULL;
    config->routes = NULL;
    config->policies = NULL;
    config->default_policy = 0xFFFFFFFF; /* All features allowed by default */
    config->log_transfers = true;
    config->log_port_forwards = true;
    config->show_progress = true; /* Enable by default */
    config->router_retry_max = CONFIG_ROUTER_DEFAULT_RETRY_MAX;
    config->router_retry_initial_delay_ms = CONFIG_ROUTER_DEFAULT_RETRY_INITIAL_DELAY_MS;
    config->router_retry_max_delay_ms = CONFIG_ROUTER_DEFAULT_RETRY_MAX_DELAY_MS;
    config->router_retry_backoff_factor = CONFIG_ROUTER_DEFAULT_RETRY_BACKOFF_FACTOR;
    config->router_pool_enabled = false;
    config->router_pool_max_idle = CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE;
    config->router_pool_max_idle_time_sec = CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE_TIME_SEC;
    config->router_circuit_breaker_enabled = CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_ENABLED;
    config->router_circuit_breaker_failure_threshold =
        CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_THRESHOLD;
    config->router_circuit_breaker_open_seconds =
        CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_OPEN_SECONDS;

    /* Security defaults */
    config->lockout.lockout_enabled = false;
    config->lockout.lockout_threshold = 5;
    config->lockout.lockout_duration_sec = 300;
    config->lockout.ip_ban_enabled = false;
    config->lockout.ip_ban_threshold = 10;
    config->lockout.ip_ban_duration_sec = 900;
    config->password_policy = password_policy_defaults();

    config->webhook.enabled = false;
    config->webhook.event_mask = (uint32_t)WEBHOOK_EVENT_ALL;
    config->webhook.retry_max = 3;
    config->webhook.retry_delay_ms = 1000;
    config->webhook.timeout_ms = 5000;
    config->webhook.queue_size = 1024;
    snprintf(config->webhook.dead_letter_path, sizeof(config->webhook.dead_letter_path),
             "%s/webhook-dlq.jsonl", config->audit_log_dir);

    return config;
}

void config_destroy(proxy_config_t *config) {
    if (config == NULL)
        return;

    /* Clear sensitive data before freeing */
    config_clear_sensitive(config);

    /* Free users */
    config_user_t *user = config->users;
    while (user != NULL) {
        config_user_t *next = user->next;
        explicit_bzero(user->password_hash, sizeof(user->password_hash));
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

    if (config->audit_encryption_key != NULL) {
        explicit_bzero(config->audit_encryption_key, strlen(config->audit_encryption_key));
        free(config->audit_encryption_key);
    }
    free(config->office_source_cidrs);
    free(config->vpn_source_cidrs);
    config_free_geoip_db(config->geoip_db);
    free(config->trusted_user_ca_keys);
    free(config->revoked_user_cert_serials);
    free(config);
}

void config_clear_sensitive(proxy_config_t *config) {
    if (config == NULL)
        return;

    config_user_t *user = config->users;
    while (user != NULL) {
        explicit_bzero(user->password_hash, sizeof(user->password_hash));
        user = user->next;
    }

    explicit_bzero(config->admin_auth_token, sizeof(config->admin_auth_token));
    explicit_bzero(config->webhook.hmac_secret, sizeof(config->webhook.hmac_secret));
    if (config->audit_encryption_key != NULL) {
        explicit_bzero(config->audit_encryption_key, strlen(config->audit_encryption_key));
    }
}

int config_add_user(proxy_config_t *config, const char *username, const char *password_hash,
                    const char *pubkeys) {
    if (config == NULL || username == NULL)
        return -1;

    config_user_t *user = calloc(1, sizeof(config_user_t));
    if (user == NULL)
        return -1;

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

config_user_t *config_find_user(const proxy_config_t *config, const char *username) {
    if (config == NULL || username == NULL)
        return NULL;

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
static bool glob_match(const char *pattern, const char *str) {
    if (pattern == NULL || str == NULL)
        return false;

    while (*pattern && *str) {
        if (*pattern == '*') {
            while (*pattern == '*')
                pattern++;
            if (*pattern == '\0')
                return true;
            while (*str) {
                if (glob_match(pattern, str))
                    return true;
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

    while (*pattern == '*')
        pattern++;
    return (*pattern == '\0' && *str == '\0');
}

/* Parse policy feature flags from comma-separated string */
static uint32_t parse_policy_features(const char *value) {
    if (value == NULL || value[0] == '\0')
        return 0;

    uint32_t features = 0;
    char buf[1024];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(buf, ",|+& \t", &saveptr);
    while (token != NULL) {
        /* Trim token */
        while (*token && isspace((unsigned char)*token))
            token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end))
            *end-- = '\0';

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
        } else if (strcmp(token, "port_forward_local") == 0 ||
                   strcmp(token, "local-forward") == 0) {
            features |= (1 << 10);
        } else if (strcmp(token, "port_forward_remote") == 0 ||
                   strcmp(token, "remote-forward") == 0) {
            features |= (1 << 11);
        } else if (strcmp(token, "port_forward_dynamic") == 0 ||
                   strcmp(token, "dynamic-forward") == 0) {
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
            features |= (1 << 2) | (1 << 4) | (1 << 8); /* scp_upload, sftp_upload, rsync_upload */
        } else if (strcmp(token, "download") == 0) {
            features |=
                (1 << 3) | (1 << 5) | (1 << 9); /* scp_download, sftp_download, rsync_download */
        }

        token = strtok_r(NULL, ",|+& \t", &saveptr);
    }

    return features;
}

int config_add_route(proxy_config_t *config, const char *proxy_user, const char *upstream_host,
                     uint16_t upstream_port, const char *upstream_user, const char *privkey_path) {
    if (config == NULL || proxy_user == NULL || upstream_host == NULL)
        return -1;

    config_route_t *route = calloc(1, sizeof(config_route_t));
    if (route == NULL)
        return -1;

    strncpy(route->proxy_user, proxy_user, sizeof(route->proxy_user) - 1);
    strncpy(route->upstream_host, upstream_host, sizeof(route->upstream_host) - 1);
    route->upstream_port = upstream_port > 0 ? upstream_port : 22;
    config_route_init_runtime_state(route);
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

size_t config_get_route_candidates_for_client(const proxy_config_t *config, const char *proxy_user,
                                              const char *client_addr,
                                              config_route_t ***out_routes) {
    config_route_t **exact_routes = NULL;
    config_route_t **wildcard_routes = NULL;
    config_route_t **best_geo_routes = NULL;
    config_route_t **candidate_routes = NULL;
    config_geo_location_t client_geo;
    size_t exact_count = 0;
    size_t wildcard_count = 0;
    size_t exact_capacity = 0;
    size_t wildcard_capacity = 0;
    size_t best_geo_count = 0;
    size_t best_geo_capacity = 0;
    size_t candidate_count = 0;
    size_t result_count = 0;
    bool have_client_geo;
    int best_score = -1;
    double best_distance = DBL_MAX;

    if (out_routes != NULL) {
        *out_routes = NULL;
    }
    if (config == NULL || proxy_user == NULL || out_routes == NULL) {
        return 0;
    }

    have_client_geo = config_geo_lookup(config, client_addr, &client_geo);

    for (config_route_t *route = config->routes; route != NULL; route = route->next) {
        if (route_pattern_matches(route, proxy_user, true)) {
            if (!append_route_candidate(&exact_routes, &exact_count, &exact_capacity, route)) {
                goto done;
            }
        } else if (route_pattern_matches(route, proxy_user, false)) {
            if (!append_route_candidate(&wildcard_routes, &wildcard_count, &wildcard_capacity,
                                        route)) {
                goto done;
            }
        }
    }

    candidate_routes = exact_count > 0 ? exact_routes : wildcard_routes;
    candidate_count = exact_count > 0 ? exact_count : wildcard_count;
    if (candidate_count == 0) {
        goto done;
    }

    if (have_client_geo) {
        for (size_t i = 0; i < candidate_count; i++) {
            config_route_t *route = candidate_routes[i];
            int score = route_geo_match_score(route, &client_geo);
            double distance = route_geo_distance_sq(route, &client_geo);

            if (score <= 0 && distance == DBL_MAX) {
                continue;
            }
            if (best_geo_count == 0 || score > best_score ||
                (score == best_score && distance < best_distance)) {
                best_geo_count = 0;
                best_score = score;
                best_distance = distance;
            }
            if (score == best_score && distance == best_distance) {
                if (!append_route_candidate(&best_geo_routes, &best_geo_count, &best_geo_capacity,
                                            route)) {
                    goto done;
                }
            }
        }
        if (best_geo_count > 0) {
            if (!build_affinity_route_order(best_geo_routes, best_geo_count, proxy_user,
                                            out_routes)) {
                goto done;
            }
            result_count = best_geo_count;
            goto done;
        }
    }

    if (!build_affinity_route_order(candidate_routes, candidate_count, proxy_user, out_routes)) {
        goto done;
    }
    result_count = candidate_count;

done:
    free(best_geo_routes);
    free(exact_routes);
    free(wildcard_routes);
    return result_count;
}

config_route_t *config_find_route_for_client(const proxy_config_t *config, const char *proxy_user,
                                             const char *client_addr) {
    config_route_t **routes = NULL;
    config_route_t *selected = NULL;
    size_t route_count;

    route_count = config_get_route_candidates_for_client(config, proxy_user, client_addr, &routes);
    if (route_count == 0) {
        return NULL;
    }
    selected = select_available_route_candidate(config, routes, route_count, time(NULL));
    free(routes);
    return selected;
}

config_route_t *config_find_route(const proxy_config_t *config, const char *proxy_user) {
    return config_find_route_for_client(config, proxy_user, NULL);
}

int config_add_policy(proxy_config_t *config, const char *username_pattern,
                      const char *upstream_pattern, uint32_t allowed_features,
                      uint32_t denied_features) {
    if (config == NULL || username_pattern == NULL)
        return -1;

    config_policy_t *policy = calloc(1, sizeof(config_policy_t));
    if (policy == NULL)
        return -1;

    config_policy_init_defaults(policy);
    strncpy(policy->username_pattern, username_pattern, sizeof(policy->username_pattern) - 1);
    if (upstream_pattern != NULL) {
        strncpy(policy->upstream_pattern, upstream_pattern, sizeof(policy->upstream_pattern) - 1);
    }
    policy->allowed_features = allowed_features;
    policy->denied_features = denied_features;

    /* Add to head of list */
    policy->next = config->policies;
    config->policies = policy;

    return 0;
}

config_policy_t *config_find_policy(const proxy_config_t *config, const char *username,
                                    const char *upstream) {
    if (config == NULL || username == NULL)
        return NULL;

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
        bool user_matches = user_has_wildcard ? glob_match(policy->username_pattern, username)
                                              : (strcmp(policy->username_pattern, username) == 0);

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
            bool upstream_matches = upstream_has_wildcard
                                        ? glob_match(policy->upstream_pattern, upstream)
                                        : (strcmp(policy->upstream_pattern, upstream) == 0);

            if (upstream_matches) {
                /* Both user and upstream match */
                if (!user_has_wildcard && !upstream_has_wildcard) {
                    return policy; /* Best match: exact user + exact upstream */
                }
                if (!user_has_wildcard) {
                    /* Exact user + wildcard/exact upstream */
                    if (user_only_match == NULL || policy->upstream_pattern[0] != '\0') {
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

bool config_policy_allows_connection(const proxy_config_t *config, const char *username,
                                     const char *upstream, const char *client_addr, time_t now,
                                     char *reason, size_t reason_len) {
    config_policy_t *policy = NULL;
    uint8_t source_type = 0;
    time_t shifted_now = 0;
    struct tm tm_value;
    char start_buf[8];
    char end_buf[8];
    char day_buf[32];
    char tz_buf[16];
    char current_buf[48];
    char allowed_sources[32];

    (void)client_addr;

    if (reason != NULL && reason_len > 0) {
        reason[0] = '\0';
    }
    if (config == NULL || username == NULL) {
        if (reason != NULL && reason_len > 0) {
            snprintf(reason, reason_len, "invalid policy context");
        }
        return false;
    }

    policy = config_find_policy(config, username, upstream);
    if (policy == NULL ||
        (!policy->login_window_enabled &&
         policy->allowed_source_types == CONFIG_POLICY_SOURCE_ALL &&
         policy->denied_source_types == 0)) {
        return true;
    }
    source_type = classify_connection_source_type(config, client_addr);
    if ((policy->denied_source_types & source_type) != 0 ||
        (policy->allowed_source_types & source_type) == 0) {
        if (reason != NULL && reason_len > 0) {
            if ((policy->denied_source_types & source_type) != 0) {
                snprintf(reason, reason_len, "source type %s is explicitly denied",
                         source_type_name(source_type));
            } else {
                format_policy_source_types(policy->allowed_source_types, allowed_sources,
                                           sizeof(allowed_sources));
                snprintf(reason, reason_len, "source type %s is not allowed (allowed: %s)",
                         source_type_name(source_type),
                         allowed_sources[0] != '\0' ? allowed_sources : "none");
            }
        }
        return false;
    }

    if (!policy->login_window_enabled) {
        return true;
    }
    if (policy->login_days_mask == 0 || policy->login_window_start_minute >= 1440 ||
        policy->login_window_end_minute >= 1440 ||
        policy->login_window_start_minute == policy->login_window_end_minute ||
        policy->login_timezone_offset_minutes < -14 * 60 ||
        policy->login_timezone_offset_minutes > 14 * 60) {
        if (reason != NULL && reason_len > 0) {
            snprintf(reason, reason_len, "invalid login window configuration");
        }
        return false;
    }

    shifted_now = now + ((time_t)policy->login_timezone_offset_minutes * 60);
    if (gmtime_r(&shifted_now, &tm_value) == NULL) {
        if (reason != NULL && reason_len > 0) {
            snprintf(reason, reason_len, "failed to evaluate login window");
        }
        return false;
    }
    if (policy_time_window_matches(policy, &tm_value)) {
        return true;
    }

    if (reason != NULL && reason_len > 0) {
        static const char *kDayNames[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
        int weekday = policy_weekday_index(&tm_value);
        format_policy_minutes(policy->login_window_start_minute, start_buf, sizeof(start_buf));
        format_policy_minutes(policy->login_window_end_minute, end_buf, sizeof(end_buf));
        format_policy_day_mask(policy->login_days_mask, day_buf, sizeof(day_buf));
        format_policy_timezone(policy->login_timezone_offset_minutes, tz_buf, sizeof(tz_buf));
        snprintf(current_buf, sizeof(current_buf), "%s %02d:%02d %s",
                 (weekday >= 0 && weekday < 7) ? kDayNames[weekday] : "unknown",
                 tm_value.tm_hour, tm_value.tm_min, tz_buf);
        snprintf(reason, reason_len,
                 "outside login window %s %s-%s (%s now)",
                 day_buf[0] != '\0' ? day_buf : "all",
                 start_buf, end_buf, current_buf);
    }

    return false;
}

proxy_config_t *config_load(const char *path) {
    char *master_key = NULL;

    if (path == NULL)
        return NULL;

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
    if (prescan_master_key(path, &master_key) != 0) {
        fclose(fp);
        config_destroy(config);
        return NULL;
    }

    char line[CONFIG_MAX_LINE];
    config_section_t current_section = SECTION_NONE;
    config_user_t *current_user = NULL;
    config_route_t *current_route = NULL;
    config_policy_t *current_policy = NULL;
    bool webhook_dead_letter_explicit = false;
    int line_num = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_num++;

        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (is_empty_or_comment(trimmed))
            continue;

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
                        strncpy(current_route->proxy_user, proxy_user,
                                sizeof(current_route->proxy_user) - 1);
                        config_route_init_runtime_state(current_route);
                        current_route->upstream_port = 22; /* Default */
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
                        config_policy_init_defaults(current_policy);
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
        bool value_indirect = line_uses_secret_reference(trimmed);
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
            } else if (strcmp(key, "show_progress") == 0) {
                config->show_progress = parse_bool_value(value);
            }
            break;

        case SECTION_LOGGING:
            if (strcmp(key, "level") == 0) {
                if (strcmp(value, "debug") == 0)
                    config->log_level = 0;
                else if (strcmp(value, "info") == 0)
                    config->log_level = 1;
                else if (strcmp(value, "warn") == 0)
                    config->log_level = 2;
                else if (strcmp(value, "error") == 0)
                    config->log_level = 3;
            } else if (strcmp(key, "audit_dir") == 0) {
                strncpy(config->audit_log_dir, value, sizeof(config->audit_log_dir) - 1);
                if (!webhook_dead_letter_explicit) {
                    snprintf(config->webhook.dead_letter_path,
                             sizeof(config->webhook.dead_letter_path),
                             "%s/webhook-dlq.jsonl", config->audit_log_dir);
                }
            } else if (strcmp(key, "audit_max_file_size") == 0) {
                config->audit_max_file_size = (size_t)strtoull(value, NULL, 10);
            } else if (strcmp(key, "audit_max_archived_files") == 0) {
                config->audit_max_archived_files = (size_t)strtoull(value, NULL, 10);
            } else if (strcmp(key, "audit_retention_days") == 0) {
                config->audit_retention_days = (uint32_t)strtoul(value, NULL, 10);
            } else if (strcmp(key, "audit_encryption_key") == 0) {
                char secret[CONFIG_MAX_LINE];
                if (decrypt_secret_value(value, master_key, secret, sizeof(secret)) != 0 ||
                    append_multiline_value(&config->audit_encryption_key, secret) != 0) {
                    explicit_bzero(secret, sizeof(secret));
                    LOG_ERROR("Config line %d: invalid audit_encryption_key", line_num);
                    goto load_fail;
                }
                config->audit_encryption_key_is_indirect = value_indirect;
                explicit_bzero(secret, sizeof(secret));
            } else if (strcmp(key, "audit_encryption_key_file") == 0) {
                append_file_value(&config->audit_encryption_key, value, 128, line_num,
                                  "audit_encryption_key_file");
                config->audit_encryption_key_is_indirect = true;
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

        case SECTION_ROUTER: {
            char *parse_end = NULL;
            unsigned long parsed = 0;

            if (strcmp(key, "retry_max") == 0) {
                errno = 0;
                long retry_max = strtol(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router retry_max: %s", line_num, value);
                    goto load_fail;
                }
                config->router_retry_max = (int)retry_max;
            } else if (strcmp(key, "retry_initial_delay_ms") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router retry_initial_delay_ms: %s", line_num,
                              value);
                    goto load_fail;
                }
                config->router_retry_initial_delay_ms = (uint32_t)parsed;
            } else if (strcmp(key, "retry_max_delay_ms") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router retry_max_delay_ms: %s", line_num,
                              value);
                    goto load_fail;
                }
                config->router_retry_max_delay_ms = (uint32_t)parsed;
            } else if (strcmp(key, "retry_backoff_factor") == 0) {
                errno = 0;
                config->router_retry_backoff_factor = strtof(value, &parse_end);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router retry_backoff_factor: %s", line_num,
                              value);
                    goto load_fail;
                }
            } else if (strcmp(key, "pool_enabled") == 0) {
                config->router_pool_enabled = parse_bool_value(value);
            } else if (strcmp(key, "pool_max_idle") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router pool_max_idle: %s", line_num, value);
                    goto load_fail;
                }
                config->router_pool_max_idle = (size_t)parsed;
            } else if (strcmp(key, "pool_max_idle_time") == 0 ||
                       strcmp(key, "pool_max_idle_time_sec") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router pool_max_idle_time: %s", line_num,
                              value);
                    goto load_fail;
                }
                config->router_pool_max_idle_time_sec = (uint32_t)parsed;
            } else if (strcmp(key, "circuit_breaker_enabled") == 0) {
                config->router_circuit_breaker_enabled = parse_bool_value(value);
            } else if (strcmp(key, "circuit_breaker_failure_threshold") == 0 ||
                       strcmp(key, "failure_threshold") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router circuit_breaker_failure_threshold: %s",
                              line_num, value);
                    goto load_fail;
                }
                config->router_circuit_breaker_failure_threshold = (uint32_t)parsed;
            } else if (strcmp(key, "circuit_breaker_open_seconds") == 0 ||
                       strcmp(key, "open_seconds") == 0) {
                errno = 0;
                parsed = strtoul(value, &parse_end, 10);
                if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                    LOG_ERROR("Config line %d: invalid router circuit_breaker_open_seconds: %s",
                              line_num, value);
                    goto load_fail;
                }
                config->router_circuit_breaker_open_seconds = (uint32_t)parsed;
            }
            break;
        }

        case SECTION_SESSION_STORE:
            if (strcmp(key, "type") == 0) {
                strncpy(config->session_store_type, value,
                        sizeof(config->session_store_type) - 1);
            } else if (strcmp(key, "path") == 0) {
                strncpy(config->session_store_path, value,
                        sizeof(config->session_store_path) - 1);
            } else if (strcmp(key, "sync_interval") == 0) {
                config->session_store_sync_interval = atoi(value);
            } else if (strcmp(key, "instance_id") == 0) {
                strncpy(config->session_store_instance_id, value,
                        sizeof(config->session_store_instance_id) - 1);
            }
            break;

        case SECTION_USER:
            if (current_user != NULL) {
                if (strcmp(key, "password_hash") == 0) {
                    if (decrypt_secret_value(value, master_key, current_user->password_hash,
                                             sizeof(current_user->password_hash)) != 0) {
                        LOG_ERROR("Config line %d: invalid password_hash for user '%s'", line_num,
                                  current_user->username);
                        goto load_fail;
                    }
                    current_user->password_hash_is_indirect = value_indirect;
                } else if (strcmp(key, "pubkey") == 0) {
                    append_multiline_value(&current_user->pubkeys, value);
                } else if (strcmp(key, "pubkey_file") == 0) {
                    append_file_value(&current_user->pubkeys, value, CONFIG_MAX_PUBKEY, line_num,
                                      "pubkey_file");
                } else if (strcmp(key, "enabled") == 0) {
                    current_user->enabled = parse_bool_value(value);
                } else if (strcmp(key, "password_changed_at") == 0) {
                    time_t changed_at = (time_t)0;
                    if (parse_epoch_seconds(value, &changed_at) == 0) {
                        current_user->password_changed_at = changed_at;
                        current_user->password_changed_at_set = true;
                    } else {
                        LOG_WARN("Config line %d: invalid password_changed_at for user '%s': %s",
                                 line_num, current_user->username, value);
                    }
                } else if (strcmp(key, "password_change_required") == 0) {
                    current_user->password_change_required = parse_bool_value(value);
                }
            }
            break;

        case SECTION_ROUTE:
            if (current_route != NULL) {
                char *parse_end = NULL;
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
                } else if (strcmp(key, "country_code") == 0) {
                    strncpy(current_route->geo_country_code, value,
                            sizeof(current_route->geo_country_code) - 1);
                } else if (strcmp(key, "country") == 0) {
                    strncpy(current_route->geo_country, value,
                            sizeof(current_route->geo_country) - 1);
                } else if (strcmp(key, "region") == 0) {
                    strncpy(current_route->geo_region, value,
                            sizeof(current_route->geo_region) - 1);
                } else if (strcmp(key, "city") == 0) {
                    strncpy(current_route->geo_city, value, sizeof(current_route->geo_city) - 1);
                } else if (strcmp(key, "latitude") == 0) {
                    errno = 0;
                    current_route->geo_latitude = strtod(value, &parse_end);
                    if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                        LOG_ERROR("Config line %d: invalid route latitude: %s", line_num, value);
                        goto load_fail;
                    }
                    current_route->geo_latitude_set = true;
                } else if (strcmp(key, "longitude") == 0) {
                    errno = 0;
                    current_route->geo_longitude = strtod(value, &parse_end);
                    if (errno != 0 || parse_end == value || *trim(parse_end) != '\0') {
                        LOG_ERROR("Config line %d: invalid route longitude: %s", line_num, value);
                        goto load_fail;
                    }
                    current_route->geo_longitude_set = true;
                } else if (strcmp(key, "enabled") == 0) {
                    current_route->enabled = parse_bool_value(value);
                }
            }
            break;

        case SECTION_NETWORK_SOURCES:
            if (strcmp(key, "office_cidrs") == 0 || strcmp(key, "office") == 0) {
                char *cidrs = dup_trimmed_string(value);
                if (cidrs == NULL || !ip_cidr_list_is_valid(cidrs)) {
                    free(cidrs);
                    LOG_ERROR("Config line %d: invalid %s CIDR list: %s", line_num, key, value);
                    goto load_fail;
                }
                free(config->office_source_cidrs);
                config->office_source_cidrs = cidrs;
            } else if (strcmp(key, "vpn_cidrs") == 0 || strcmp(key, "vpn") == 0) {
                char *cidrs = dup_trimmed_string(value);
                if (cidrs == NULL || !ip_cidr_list_is_valid(cidrs)) {
                    free(cidrs);
                    LOG_ERROR("Config line %d: invalid %s CIDR list: %s", line_num, key, value);
                    goto load_fail;
                }
                free(config->vpn_source_cidrs);
                config->vpn_source_cidrs = cidrs;
            } else if (strcmp(key, "geoip_data_file") == 0) {
                strncpy(config->geoip_data_file, value, sizeof(config->geoip_data_file) - 1);
            }
            break;

        case SECTION_POLICY:
            if (current_policy != NULL) {
                if (strcmp(key, "allow") == 0 || strcmp(key, "allowed") == 0) {
                    current_policy->allowed_features = parse_policy_features(value);
                } else if (strcmp(key, "deny") == 0 || strcmp(key, "denied") == 0) {
                    current_policy->denied_features = parse_policy_features(value);
                } else if (strcmp(key, "allowed_source_types") == 0 ||
                           strcmp(key, "source_types") == 0) {
                    if (parse_policy_source_types(value, &current_policy->allowed_source_types) != 0) {
                        LOG_ERROR("Config line %d: invalid %s for policy '%s': %s", line_num, key,
                                  current_policy->username_pattern, value);
                        goto load_fail;
                    }
                } else if (strcmp(key, "denied_source_types") == 0) {
                    if (parse_policy_source_types(value, &current_policy->denied_source_types) != 0) {
                        LOG_ERROR("Config line %d: invalid %s for policy '%s': %s", line_num, key,
                                  current_policy->username_pattern, value);
                        goto load_fail;
                    }
                } else if (strcmp(key, "login_window") == 0 ||
                           strcmp(key, "allowed_login_window") == 0 ||
                           strcmp(key, "time_window") == 0) {
                    if (parse_policy_login_window(value, &current_policy->login_window_start_minute,
                                                  &current_policy->login_window_end_minute) != 0) {
                        LOG_ERROR("Config line %d: invalid %s for policy '%s': %s", line_num, key,
                                  current_policy->username_pattern, value);
                        goto load_fail;
                    }
                    current_policy->login_window_enabled = true;
                } else if (strcmp(key, "login_days") == 0 ||
                           strcmp(key, "allowed_login_days") == 0) {
                    if (parse_policy_login_days(value, &current_policy->login_days_mask) != 0) {
                        LOG_ERROR("Config line %d: invalid %s for policy '%s': %s", line_num, key,
                                  current_policy->username_pattern, value);
                        goto load_fail;
                    }
                } else if (strcmp(key, "login_timezone") == 0 ||
                           strcmp(key, "timezone") == 0) {
                    if (parse_policy_timezone_offset(value,
                                                     &current_policy->login_timezone_offset_minutes) != 0) {
                        LOG_ERROR("Config line %d: invalid %s for policy '%s': %s", line_num, key,
                                  current_policy->username_pattern, value);
                        goto load_fail;
                    }
                }
            }
            break;

        case SECTION_SECURITY:
            if (strcmp(key, "lockout_enabled") == 0) {
                config->lockout.lockout_enabled = parse_bool_value(value);
            } else if (strcmp(key, "lockout_threshold") == 0) {
                config->lockout.lockout_threshold = (uint32_t)atoi(value);
            } else if (strcmp(key, "lockout_duration") == 0) {
                config->lockout.lockout_duration_sec = (uint32_t)atoi(value);
            } else if (strcmp(key, "ip_ban_enabled") == 0) {
                config->lockout.ip_ban_enabled = parse_bool_value(value);
            } else if (strcmp(key, "ip_ban_threshold") == 0) {
                config->lockout.ip_ban_threshold = (uint32_t)atoi(value);
            } else if (strcmp(key, "ip_ban_duration") == 0) {
                config->lockout.ip_ban_duration_sec = (uint32_t)atoi(value);
            } else if (strcmp(key, "password_min_length") == 0) {
                config->password_policy.min_length = (uint32_t)atoi(value);
            } else if (strcmp(key, "password_require_uppercase") == 0) {
                config->password_policy.require_uppercase = parse_bool_value(value);
            } else if (strcmp(key, "password_require_lowercase") == 0) {
                config->password_policy.require_lowercase = parse_bool_value(value);
            } else if (strcmp(key, "password_require_digit") == 0) {
                config->password_policy.require_digit = parse_bool_value(value);
            } else if (strcmp(key, "password_require_special") == 0) {
                config->password_policy.require_special = parse_bool_value(value);
            } else if (strcmp(key, "password_max_age_days") == 0) {
                config->password_policy.max_age_days = (uint32_t)atoi(value);
            } else if (strcmp(key, "trusted_user_ca_key") == 0) {
                append_multiline_value(&config->trusted_user_ca_keys, value);
            } else if (strcmp(key, "trusted_user_ca_keys_file") == 0) {
                append_file_value(&config->trusted_user_ca_keys, value, CONFIG_MAX_PUBKEY * 4U,
                                  line_num, "trusted_user_ca_keys_file");
            } else if (strcmp(key, "revoked_user_cert_serial") == 0) {
                append_multiline_value(&config->revoked_user_cert_serials, value);
            } else if (strcmp(key, "revoked_user_cert_serials_file") == 0) {
                append_file_value(&config->revoked_user_cert_serials, value, CONFIG_MAX_PUBKEY,
                                  line_num, "revoked_user_cert_serials_file");
            } else if (strcmp(key, "master_key") == 0 || strcmp(key, "master_key_file") == 0) {
                /* Consumed during pre-scan; ignore in the main pass. */
            }
            break;

        case SECTION_ADMIN:
            if (strcmp(key, "enabled") == 0) {
                config->admin_api_enabled = parse_bool_value(value);
            } else if (strcmp(key, "auth_token") == 0) {
                if (decrypt_secret_value(value, master_key, config->admin_auth_token,
                                         sizeof(config->admin_auth_token)) != 0) {
                    LOG_ERROR("Config line %d: invalid auth_token", line_num);
                    goto load_fail;
                }
                config->admin_auth_token_is_indirect = value_indirect;
            } else if (strcmp(key, "token_expiry") == 0) {
                config->admin_token_expiry_sec = (uint32_t)atoi(value);
            } else if (strcmp(key, "tls_enabled") == 0) {
                config->admin_tls_enabled = parse_bool_value(value);
            } else if (strcmp(key, "tls_cert") == 0) {
                strncpy(config->admin_tls_cert_path, value,
                        sizeof(config->admin_tls_cert_path) - 1);
            } else if (strcmp(key, "tls_key") == 0) {
                strncpy(config->admin_tls_key_path, value, sizeof(config->admin_tls_key_path) - 1);
            }
            break;

        case SECTION_WEBHOOK:
            if (strcmp(key, "enabled") == 0) {
                config->webhook.enabled = parse_bool_value(value);
            } else if (strcmp(key, "url") == 0) {
                strncpy(config->webhook.url, value, sizeof(config->webhook.url) - 1);
            } else if (strcmp(key, "auth_header") == 0) {
                strncpy(config->webhook.auth_header, value,
                        sizeof(config->webhook.auth_header) - 1);
            } else if (strcmp(key, "hmac_secret") == 0) {
                if (decrypt_secret_value(value, master_key, config->webhook.hmac_secret,
                                         sizeof(config->webhook.hmac_secret)) != 0) {
                    LOG_ERROR("Config line %d: invalid hmac_secret", line_num);
                    goto load_fail;
                }
                config->webhook_hmac_secret_is_indirect = value_indirect;
            } else if (strcmp(key, "dead_letter_path") == 0) {
                strncpy(config->webhook.dead_letter_path, value,
                        sizeof(config->webhook.dead_letter_path) - 1);
                webhook_dead_letter_explicit = true;
            } else if (strcmp(key, "events") == 0) {
                config->webhook.event_mask = parse_webhook_event_mask(value);
            } else if (strcmp(key, "retry_max") == 0) {
                config->webhook.retry_max = atoi(value);
            } else if (strcmp(key, "retry_delay_ms") == 0) {
                config->webhook.retry_delay_ms = atoi(value);
            } else if (strcmp(key, "timeout_ms") == 0) {
                config->webhook.timeout_ms = atoi(value);
            } else if (strcmp(key, "queue_size") == 0) {
                config->webhook.queue_size = atoi(value);
            }
            break;

        default:
            /* Global section or unknown */
            break;
        }
    }

    fclose(fp);
    if (master_key != NULL) {
        explicit_bzero(master_key, strlen(master_key));
        free(master_key);
    }

    LOG_INFO("Configuration loaded from %s", path);

    /* Log summary */
    size_t user_count = 0;
    for (config_user_t *u = config->users; u != NULL; u = u->next)
        user_count++;

    size_t route_count = 0;
    for (config_route_t *r = config->routes; r != NULL; r = r->next)
        route_count++;

    size_t policy_count = 0;
    for (config_policy_t *p = config->policies; p != NULL; p = p->next)
        policy_count++;

    LOG_DEBUG("Config: %zu users, %zu routes, %zu policies", user_count, route_count, policy_count);

    if (config->webhook.enabled && config->webhook.url[0] == '\0') {
        LOG_ERROR("Config validation: [webhook] enabled=true but url is empty");
        config_destroy(config);
        return NULL;
    }

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

    if (config->session_store_type[0] == '\0') {
        strncpy(config->session_store_type, "local", sizeof(config->session_store_type) - 1);
    }
    if (strcmp(config->session_store_type, "local") != 0 &&
        strcmp(config->session_store_type, "file") != 0) {
        LOG_ERROR("Config validation: session_store.type must be 'local' or 'file'");
        config_destroy(config);
        return NULL;
    }
    if (strcmp(config->session_store_type, "file") == 0 &&
        config->session_store_path[0] == '\0') {
        LOG_ERROR("Config validation: session_store.path is required when type=file");
        config_destroy(config);
        return NULL;
    }
    if (config->session_store_sync_interval <= 0) {
        LOG_WARN("Config validation: session_store.sync_interval is 0, using default 5");
        config->session_store_sync_interval = 5;
        warnings++;
    }
    if (config->router_retry_max < 0) {
        LOG_WARN("Config validation: router.retry_max is negative, using default %d",
                 CONFIG_ROUTER_DEFAULT_RETRY_MAX);
        config->router_retry_max = CONFIG_ROUTER_DEFAULT_RETRY_MAX;
        warnings++;
    }
    if (config->router_retry_initial_delay_ms == 0) {
        LOG_WARN("Config validation: router.retry_initial_delay_ms is 0, using default %u",
                 CONFIG_ROUTER_DEFAULT_RETRY_INITIAL_DELAY_MS);
        config->router_retry_initial_delay_ms = CONFIG_ROUTER_DEFAULT_RETRY_INITIAL_DELAY_MS;
        warnings++;
    }
    if (config->router_retry_max_delay_ms < config->router_retry_initial_delay_ms) {
        LOG_WARN("Config validation: router.retry_max_delay_ms is smaller than retry_initial_delay_ms; using %u",
                 config->router_retry_initial_delay_ms);
        config->router_retry_max_delay_ms = config->router_retry_initial_delay_ms;
        warnings++;
    }
    if (config->router_retry_backoff_factor < 1.0f) {
        LOG_WARN("Config validation: router.retry_backoff_factor must be >= 1.0, using default %.1f",
                 CONFIG_ROUTER_DEFAULT_RETRY_BACKOFF_FACTOR);
        config->router_retry_backoff_factor = CONFIG_ROUTER_DEFAULT_RETRY_BACKOFF_FACTOR;
        warnings++;
    }
    if (config->router_pool_enabled && config->router_pool_max_idle == 0) {
        LOG_WARN("Config validation: router.pool_max_idle is 0 while pool_enabled=true; using default %u",
                 CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE);
        config->router_pool_max_idle = CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE;
        warnings++;
    }
    if (config->router_pool_max_idle_time_sec == 0) {
        LOG_WARN("Config validation: router.pool_max_idle_time is 0, using default %u",
                 CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE_TIME_SEC);
        config->router_pool_max_idle_time_sec = CONFIG_ROUTER_DEFAULT_POOL_MAX_IDLE_TIME_SEC;
        warnings++;
    }
    if (config->router_circuit_breaker_failure_threshold == 0) {
        LOG_WARN("Config validation: router.circuit_breaker_failure_threshold is 0, using default %u",
                 CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        config->router_circuit_breaker_failure_threshold =
            CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_THRESHOLD;
        warnings++;
    }
    if (config->router_circuit_breaker_open_seconds == 0) {
        LOG_WARN("Config validation: router.circuit_breaker_open_seconds is 0, using default %u",
                 CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_OPEN_SECONDS);
        config->router_circuit_breaker_open_seconds =
            CONFIG_ROUTER_DEFAULT_CIRCUIT_BREAKER_OPEN_SECONDS;
        warnings++;
    }

    if (config->host_key_path[0] != '\0') {
        if (access(config->host_key_path, R_OK) != 0) {
            LOG_WARN("Config validation: host key '%s' not readable: %s", config->host_key_path,
                     strerror(errno));
            warnings++;
        }
    }

    /* Validate routes have required upstream_host */
    for (config_route_t *r = config->routes; r != NULL; r = r->next) {
        if (r->upstream_host[0] == '\0') {
            LOG_WARN("Config validation: route '%s' has no upstream host", r->proxy_user);
            warnings++;
        }
        if (r->upstream_port == 0) {
            LOG_WARN("Config validation: route '%s' has invalid port, "
                     "using default 22",
                     r->proxy_user);
            r->upstream_port = 22;
            warnings++;
        }
        if (r->geo_latitude_set != r->geo_longitude_set) {
            LOG_ERROR("Config validation: route '%s' must set both latitude and longitude",
                      r->proxy_user);
            config_destroy(config);
            return NULL;
        }
        if (r->geo_latitude_set) {
            if (r->geo_latitude < -90.0 || r->geo_latitude > 90.0 || r->geo_longitude < -180.0 ||
                r->geo_longitude > 180.0) {
                LOG_ERROR("Config validation: route '%s' has out-of-range coordinates",
                          r->proxy_user);
                config_destroy(config);
                return NULL;
            }
            r->geo_has_coordinates = true;
        }
        if ((r->geo_country_code[0] != '\0' || r->geo_country[0] != '\0' || r->geo_region[0] != '\0' ||
             r->geo_city[0] != '\0' || r->geo_has_coordinates) &&
            config->geoip_data_file[0] == '\0') {
            LOG_WARN("Config validation: route '%s' defines geo metadata but network_sources.geoip_data_file is empty",
                     r->proxy_user);
            warnings++;
        }
    }

    if (config->geoip_data_file[0] != '\0' && config_load_geoip_db(config) != 0) {
        config_destroy(config);
        return NULL;
    }

    /* Validate users have at least one auth method */
    for (config_user_t *u = config->users; u != NULL; u = u->next) {
        if (u->password_hash[0] == '\0' && (u->pubkeys == NULL || u->pubkeys[0] == '\0') &&
            !config_has_trusted_user_ca_keys(config)) {
            LOG_WARN("Config validation: user '%s' has no password_hash "
                     "and no pubkey or trusted_user_ca_key configured",
                     u->username);
            warnings++;
        }
        /* Warn about plaintext sensitive fields */
        if (u->password_hash[0] != '\0' && !u->password_hash_is_indirect) {
            LOG_WARN("Config validation: user '%s' password_hash appears to "
                     "be plaintext (consider using ${env:} or ${file:})",
                     u->username);
            warnings++;
        }
        if (config->password_policy.max_age_days > 0 && u->password_hash[0] != '\0' &&
            !u->password_changed_at_set) {
            LOG_WARN("Config validation: user '%s' has password_max_age_days enabled "
                     "but no password_changed_at metadata; expiry will not apply",
                     u->username);
            warnings++;
        }
        if (u->password_change_required && u->password_hash[0] == '\0') {
            LOG_WARN("Config validation: user '%s' requires password rotation "
                     "but has no password_hash configured",
                     u->username);
            warnings++;
        }
    }

    if (config->admin_api_enabled && !config->admin_tls_enabled) {
        LOG_WARN("Config validation: admin API is enabled without TLS; HTTPS enforcement will "
                 "disable it");
        warnings++;
    }
    if (config->admin_auth_token[0] != '\0' && !config->admin_auth_token_is_indirect) {
        LOG_WARN("Config validation: admin auth_token appears to be plaintext "
                 "(consider using ${env:}, ${file:}, or enc:v1:...)");
        warnings++;
    }
    if (config->admin_api_enabled && config->admin_tls_enabled &&
        (config->admin_tls_cert_path[0] == '\0' || config->admin_tls_key_path[0] == '\0')) {
        LOG_WARN("Config validation: admin API TLS is enabled but tls_cert/tls_key is incomplete");
        warnings++;
    }
    if (config->webhook.hmac_secret[0] != '\0' && !config->webhook_hmac_secret_is_indirect) {
        LOG_WARN("Config validation: webhook hmac_secret appears to be plaintext "
                 "(consider using ${env:}, ${file:}, or enc:v1:...)");
        warnings++;
    }
    if (config->audit_encryption_key != NULL && config->audit_encryption_key[0] != '\0' &&
        !config->audit_encryption_key_is_indirect) {
        LOG_WARN("Config validation: logging.audit_encryption_key appears to be plaintext "
                 "(consider using ${env:}, ${file:}, or enc:v1:...)");
        warnings++;
    }

    if (warnings > 0) {
        LOG_WARN("Config validation: %d warning(s)", warnings);
    }

    return config;

load_fail:
    fclose(fp);
    if (master_key != NULL) {
        explicit_bzero(master_key, strlen(master_key));
        free(master_key);
    }
    config_destroy(config);
    return NULL;
}

int config_apply_loaded(proxy_config_t *config, proxy_config_t *new_config) {
    if (config == NULL || new_config == NULL)
        return -1;

    /* Free old user list */
    config_user_t *user = config->users;
    while (user != NULL) {
        config_user_t *next = user->next;
        explicit_bzero(user->password_hash, sizeof(user->password_hash));
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

    if (config->audit_encryption_key != NULL) {
        explicit_bzero(config->audit_encryption_key, strlen(config->audit_encryption_key));
        free(config->audit_encryption_key);
    }
    free(config->office_source_cidrs);
    free(config->vpn_source_cidrs);
    config_free_geoip_db(config->geoip_db);
    free(config->trusted_user_ca_keys);
    free(config->revoked_user_cert_serials);

    /* Copy new values */
    memcpy(config->bind_addr, new_config->bind_addr, sizeof(config->bind_addr));
    config->port = new_config->port;
    memcpy(config->host_key_path, new_config->host_key_path, sizeof(config->host_key_path));
    config->log_level = new_config->log_level;
    memcpy(config->audit_log_dir, new_config->audit_log_dir, sizeof(config->audit_log_dir));
    config->audit_max_file_size = new_config->audit_max_file_size;
    config->audit_max_archived_files = new_config->audit_max_archived_files;
    config->audit_retention_days = new_config->audit_retention_days;
    config->max_sessions = new_config->max_sessions;
    config->session_timeout = new_config->session_timeout;
    config->auth_timeout = new_config->auth_timeout;
    memcpy(config->session_store_type, new_config->session_store_type,
           sizeof(config->session_store_type));
    memcpy(config->session_store_path, new_config->session_store_path,
           sizeof(config->session_store_path));
    config->session_store_sync_interval = new_config->session_store_sync_interval;
    memcpy(config->session_store_instance_id, new_config->session_store_instance_id,
           sizeof(config->session_store_instance_id));
    config->router_retry_max = new_config->router_retry_max;
    config->router_retry_initial_delay_ms = new_config->router_retry_initial_delay_ms;
    config->router_retry_max_delay_ms = new_config->router_retry_max_delay_ms;
    config->router_retry_backoff_factor = new_config->router_retry_backoff_factor;
    config->router_pool_enabled = new_config->router_pool_enabled;
    config->router_pool_max_idle = new_config->router_pool_max_idle;
    config->router_pool_max_idle_time_sec = new_config->router_pool_max_idle_time_sec;
    config->router_circuit_breaker_enabled = new_config->router_circuit_breaker_enabled;
    config->router_circuit_breaker_failure_threshold =
        new_config->router_circuit_breaker_failure_threshold;
    config->router_circuit_breaker_open_seconds =
        new_config->router_circuit_breaker_open_seconds;
    config->users = new_config->users;
    config->routes = new_config->routes;
    config->policies = new_config->policies;
    config->default_policy = new_config->default_policy;
    config->office_source_cidrs = new_config->office_source_cidrs;
    config->vpn_source_cidrs = new_config->vpn_source_cidrs;
    memcpy(config->geoip_data_file, new_config->geoip_data_file, sizeof(config->geoip_data_file));
    config->geoip_db = new_config->geoip_db;
    config->audit_encryption_key_is_indirect = new_config->audit_encryption_key_is_indirect;
    config->log_transfers = new_config->log_transfers;
    config->log_port_forwards = new_config->log_port_forwards;
    memcpy(config->banner_path, new_config->banner_path, sizeof(config->banner_path));
    memcpy(config->motd, new_config->motd, sizeof(config->motd));
    config->show_progress = new_config->show_progress;
    config->lockout = new_config->lockout;
    config->password_policy = new_config->password_policy;
    config->admin_api_enabled = new_config->admin_api_enabled;
    explicit_bzero(config->admin_auth_token, sizeof(config->admin_auth_token));
    memcpy(config->admin_auth_token, new_config->admin_auth_token, sizeof(config->admin_auth_token));
    config->admin_token_expiry_sec = new_config->admin_token_expiry_sec;
    config->admin_tls_enabled = new_config->admin_tls_enabled;
    memcpy(config->admin_tls_cert_path, new_config->admin_tls_cert_path,
           sizeof(config->admin_tls_cert_path));
    memcpy(config->admin_tls_key_path, new_config->admin_tls_key_path,
           sizeof(config->admin_tls_key_path));
    config->audit_encryption_key = new_config->audit_encryption_key;
    config->trusted_user_ca_keys = new_config->trusted_user_ca_keys;
    config->revoked_user_cert_serials = new_config->revoked_user_cert_serials;
    config->admin_auth_token_is_indirect = new_config->admin_auth_token_is_indirect;
    explicit_bzero(config->webhook.hmac_secret, sizeof(config->webhook.hmac_secret));
    config->webhook = new_config->webhook;
    config->webhook_hmac_secret_is_indirect = new_config->webhook_hmac_secret_is_indirect;

    /* Free shell only, not contents (transferred to config) */
    new_config->users = NULL;
    new_config->routes = NULL;
    new_config->policies = NULL;
    new_config->office_source_cidrs = NULL;
    new_config->vpn_source_cidrs = NULL;
    new_config->geoip_db = NULL;
    new_config->audit_encryption_key = NULL;
    new_config->trusted_user_ca_keys = NULL;
    new_config->revoked_user_cert_serials = NULL;
    config_destroy(new_config);

    return 0;
}

int config_reload(proxy_config_t *config, const char *path) {
    if (config == NULL || path == NULL)
        return -1;

    proxy_config_t *new_config = config_load(path);
    if (new_config == NULL)
        return -1;

    if (config_apply_loaded(config, new_config) != 0) {
        config_destroy(new_config);
        return -1;
    }

    LOG_INFO("Configuration reloaded");
    return 0;
}

/* Helper to append a validation result to the list */
static config_valid_result_t *add_result(config_valid_result_t **list, config_valid_level_t level,
                                         const char *fmt, ...) {
    config_valid_result_t *r = calloc(1, sizeof(config_valid_result_t));
    if (r == NULL)
        return NULL;
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
        while (tail->next != NULL)
            tail = tail->next;
        tail->next = r;
    }
    return r;
}

config_valid_result_t *config_validate(const proxy_config_t *config, const char *config_path) {
    config_valid_result_t *results = NULL;

    if (config == NULL) {
        add_result(&results, CONFIG_VALID_ERROR, "Configuration is NULL");
        return results;
    }

    /* Server settings */
    if (config->port == 0) {
        add_result(&results, CONFIG_VALID_ERROR, "Port %u is out of valid range (1-65535)",
                   (unsigned)config->port);
    }

    if (config->bind_addr[0] == '\0') {
        add_result(&results, CONFIG_VALID_ERROR, "Bind address is empty");
    }

    if (config->session_store_type[0] != '\0' &&
        strcmp(config->session_store_type, "local") != 0 &&
        strcmp(config->session_store_type, "file") != 0) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "session_store.type must be 'local' or 'file'");
    }
    if (strcmp(config->session_store_type, "file") == 0 &&
        config->session_store_path[0] == '\0') {
        add_result(&results, CONFIG_VALID_ERROR,
                   "session_store.path is required when session_store.type=file");
    }
    if (config->session_store_sync_interval <= 0) {
        add_result(&results, CONFIG_VALID_WARN,
                   "session_store.sync_interval should be greater than zero");
    }
    if (config->router_retry_max < 0) {
        add_result(&results, CONFIG_VALID_ERROR, "router.retry_max must be >= 0");
    }
    if (config->router_retry_initial_delay_ms == 0) {
        add_result(&results, CONFIG_VALID_WARN,
                   "router.retry_initial_delay_ms should be greater than zero");
    }
    if (config->router_retry_max_delay_ms < config->router_retry_initial_delay_ms) {
        add_result(&results, CONFIG_VALID_WARN,
                   "router.retry_max_delay_ms should be >= router.retry_initial_delay_ms");
    }
    if (config->router_retry_backoff_factor < 1.0f) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "router.retry_backoff_factor must be >= 1.0");
    }
    if (config->router_pool_enabled && config->router_pool_max_idle == 0) {
        add_result(&results, CONFIG_VALID_WARN,
                   "router.pool_enabled=true but router.pool_max_idle is 0");
    }
    if (config->router_pool_max_idle_time_sec == 0) {
        add_result(&results, CONFIG_VALID_WARN,
                   "router.pool_max_idle_time should be greater than zero");
    }
    if (config->router_circuit_breaker_failure_threshold == 0) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "router.circuit_breaker_failure_threshold must be greater than zero");
    }
    if (config->router_circuit_breaker_open_seconds == 0) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "router.circuit_breaker_open_seconds must be greater than zero");
    }

    /* Host key */
    if (config->host_key_path[0] != '\0') {
        if (access(config->host_key_path, R_OK) != 0) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Host key '%s' does not exist or is not readable", config->host_key_path);
        } else {
            struct stat st;
            if (stat(config->host_key_path, &st) == 0 && (st.st_mode & S_IROTH)) {
                add_result(&results, CONFIG_VALID_WARN,
                           "Host key '%s' is world-readable (mode %04o)", config->host_key_path,
                           (unsigned)(st.st_mode & 0777));
            }
        }
    }

    /* Users */
    int user_count = 0;
    const config_user_t *user = config->users;
    while (user != NULL) {
        user_count++;
        if (user->username[0] == '\0') {
            add_result(&results, CONFIG_VALID_ERROR, "User #%d has empty username", user_count);
        }
        if (user->password_hash[0] == '\0' && (user->pubkeys == NULL || user->pubkeys[0] == '\0') &&
            !config_has_trusted_user_ca_keys(config)) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "User '%s' has no password hash, public keys, or trusted SSH CA configured",
                       user->username);
        }
        if (config->password_policy.max_age_days > 0 && user->password_hash[0] != '\0' &&
            !user->password_changed_at_set) {
            add_result(&results, CONFIG_VALID_WARN,
                       "User '%s' is subject to password_max_age_days but has no "
                       "password_changed_at metadata",
                       user->username);
        }
        if (user->password_change_required && user->password_hash[0] == '\0') {
            add_result(&results, CONFIG_VALID_WARN,
                       "User '%s' has password_change_required enabled without a password hash",
                       user->username);
        }
        if (user->password_hash[0] != '\0' && !user->password_hash_is_indirect) {
            add_result(&results, CONFIG_VALID_WARN,
                       "User '%s' password_hash appears to be plaintext (consider using ${env:}, ${file:}, or enc:v1:...)",
                       user->username);
        }
        user = user->next;
    }
    if (user_count == 0) {
        add_result(&results, CONFIG_VALID_WARN, "No users configured");
    }

    if (config->audit_encryption_key != NULL && config->audit_encryption_key[0] != '\0' &&
        !valid_hex_string(config->audit_encryption_key, 64)) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "logging.audit_encryption_key must be a 64-character hex AES-256 key");
    }
    if (config->audit_encryption_key != NULL && config->audit_encryption_key[0] != '\0' &&
        !config->audit_encryption_key_is_indirect) {
        add_result(&results, CONFIG_VALID_WARN,
                   "logging.audit_encryption_key appears to be plaintext (consider using ${env:}, ${file:}, or enc:v1:...)");
    }
    if (config->admin_auth_token[0] != '\0' && !config->admin_auth_token_is_indirect) {
        add_result(&results, CONFIG_VALID_WARN,
                   "admin.auth_token appears to be plaintext (consider using ${env:}, ${file:}, or enc:v1:...)");
    }
    if (config->webhook.hmac_secret[0] != '\0' && !config->webhook_hmac_secret_is_indirect) {
        add_result(&results, CONFIG_VALID_WARN,
                   "webhook.hmac_secret appears to be plaintext (consider using ${env:}, ${file:}, or enc:v1:...)");
    }
    if (config->office_source_cidrs != NULL &&
        !ip_cidr_list_is_valid(config->office_source_cidrs)) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "network_sources.office_cidrs contains an invalid CIDR list");
    }
    if (config->vpn_source_cidrs != NULL && !ip_cidr_list_is_valid(config->vpn_source_cidrs)) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "network_sources.vpn_cidrs contains an invalid CIDR list");
    }
    if (config->geoip_data_file[0] != '\0' && access(config->geoip_data_file, R_OK) != 0) {
        add_result(&results, CONFIG_VALID_ERROR,
                   "network_sources.geoip_data_file '%s' does not exist or is not readable",
                   config->geoip_data_file);
    }

    /* Routes */
    int route_count = 0;
    const config_route_t *route = config->routes;
    while (route != NULL) {
        route_count++;
        if (route->upstream_host[0] == '\0') {
            add_result(&results, CONFIG_VALID_ERROR, "Route #%d has empty upstream host",
                       route_count);
        }
        if (route->upstream_port == 0) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Route #%d upstream port %u is out of valid range (1-65535)", route_count,
                       (unsigned)route->upstream_port);
        }
        if (route->privkey_path[0] != '\0') {
            if (access(route->privkey_path, R_OK) != 0) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Route #%d private key '%s' does not exist or is not readable",
                           route_count, route->privkey_path);
            }
        }
        if (route->geo_latitude_set != route->geo_longitude_set) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Route #%d must set both latitude and longitude", route_count);
        }
        if (route->geo_latitude_set &&
            (route->geo_latitude < -90.0 || route->geo_latitude > 90.0 ||
             route->geo_longitude < -180.0 || route->geo_longitude > 180.0)) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Route #%d has out-of-range latitude/longitude", route_count);
        }
        if ((route->geo_country_code[0] != '\0' || route->geo_country[0] != '\0' ||
             route->geo_region[0] != '\0' || route->geo_city[0] != '\0' ||
             route->geo_latitude_set || route->geo_longitude_set) &&
            config->geoip_data_file[0] == '\0') {
            add_result(&results, CONFIG_VALID_WARN,
                       "Route #%d defines geo metadata but network_sources.geoip_data_file is empty",
                       route_count);
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
                           "Route #%d pattern '%s' does not match any configured user", route_count,
                           route->proxy_user);
            }
        }
        route = route->next;
    }
    if (route_count == 0) {
        add_result(&results, CONFIG_VALID_WARN, "No routes configured");
    }

    if (config->admin_api_enabled && !config->admin_tls_enabled) {
        add_result(&results, CONFIG_VALID_WARN,
                   "Admin API is enabled without TLS and will be disabled at runtime");
    }
    if (config->admin_api_enabled && config->admin_tls_enabled &&
        (config->admin_tls_cert_path[0] == '\0' || config->admin_tls_key_path[0] == '\0')) {
        add_result(&results, CONFIG_VALID_WARN,
                   "Admin API TLS is enabled but tls_cert or tls_key is missing");
    }

    /* Policies */
    int policy_count = 0;
    const config_policy_t *policy = config->policies;
    while (policy != NULL) {
        policy_count++;
        if (policy->username_pattern[0] == '\0') {
            add_result(&results, CONFIG_VALID_ERROR, "Policy #%d has empty username pattern",
                       policy_count);
        }
        if ((policy->allowed_source_types & ~CONFIG_POLICY_SOURCE_ALL) != 0 ||
            (policy->denied_source_types & ~CONFIG_POLICY_SOURCE_ALL) != 0 ||
            policy->allowed_source_types == 0) {
            add_result(&results, CONFIG_VALID_ERROR,
                       "Policy #%d has invalid source type configuration", policy_count);
        }
        if ((policy->allowed_source_types != CONFIG_POLICY_SOURCE_ALL ||
             policy->denied_source_types != 0) &&
            (policy->allowed_source_types & CONFIG_POLICY_SOURCE_OFFICE) != 0 &&
            (config->office_source_cidrs == NULL || config->office_source_cidrs[0] == '\0')) {
            add_result(&results, CONFIG_VALID_WARN,
                       "Policy #%d allows office sources but network_sources.office_cidrs is empty",
                       policy_count);
        }
        if ((policy->allowed_source_types != CONFIG_POLICY_SOURCE_ALL ||
             policy->denied_source_types != 0) &&
            (policy->allowed_source_types & CONFIG_POLICY_SOURCE_VPN) != 0 &&
            (config->vpn_source_cidrs == NULL || config->vpn_source_cidrs[0] == '\0')) {
            add_result(&results, CONFIG_VALID_WARN,
                       "Policy #%d allows VPN sources but network_sources.vpn_cidrs is empty",
                       policy_count);
        }
        if (policy->login_window_enabled) {
            if (policy->login_days_mask == 0) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Policy #%d enables login_window but has no allowed days", policy_count);
            }
            if (policy->login_window_start_minute >= 1440 ||
                policy->login_window_end_minute >= 1440) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Policy #%d login_window must stay within 00:00-23:59", policy_count);
            }
            if (policy->login_window_start_minute == policy->login_window_end_minute) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Policy #%d login_window start and end must differ", policy_count);
            }
            if (policy->login_timezone_offset_minutes < -14 * 60 ||
                policy->login_timezone_offset_minutes > 14 * 60) {
                add_result(&results, CONFIG_VALID_ERROR,
                           "Policy #%d login_timezone must stay within UTC-14:00..UTC+14:00",
                           policy_count);
            }
        }
        policy = policy->next;
    }

    /* Summary info */
    add_result(&results, CONFIG_VALID_INFO, "Loaded %d user(s), %d route(s), %d policy/policies",
               user_count, route_count, policy_count);

    (void)config_path; /* reserved for future file-level checks */

    return results;
}

void config_valid_free(config_valid_result_t *results) {
    while (results != NULL) {
        config_valid_result_t *next = results->next;
        free(results);
        results = next;
    }
}
