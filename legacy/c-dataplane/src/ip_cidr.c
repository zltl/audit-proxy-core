/**
 * @file ip_cidr.c
 * @brief Shared IPv4/IPv6 CIDR matching helpers
 */

#include "ip_cidr.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool parse_cidr_token(const char *token, int *family, uint8_t *network_bin, int *prefix) {
    char buf[128];
    char *slash = NULL;
    char *end = NULL;
    int parsed_family = AF_UNSPEC;
    int max_prefix = 0;
    int parsed_prefix = 0;

    if (token == NULL || family == NULL || network_bin == NULL || prefix == NULL) {
        return false;
    }

    while (isspace((unsigned char)*token)) {
        token++;
    }
    if (*token == '\0') {
        return false;
    }

    strncpy(buf, token, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    end = buf + strlen(buf);
    while (end > buf && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }

    slash = strchr(buf, '/');
    parsed_family = strchr(buf, ':') != NULL ? AF_INET6 : AF_INET;
    max_prefix = parsed_family == AF_INET6 ? 128 : 32;
    parsed_prefix = max_prefix;

    if (slash != NULL) {
        char *endptr = NULL;
        long raw = 0;
        *slash = '\0';
        raw = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0') {
            return false;
        }
        parsed_prefix = (int)raw;
    }
    if (parsed_prefix < 0 || parsed_prefix > max_prefix) {
        return false;
    }
    if (inet_pton(parsed_family, buf, network_bin) != 1) {
        return false;
    }

    *family = parsed_family;
    *prefix = parsed_prefix;
    return true;
}

bool ip_cidr_match(const char *ip_addr, const char *cidr) {
    int family = AF_UNSPEC;
    int prefix = 0;
    int full_bytes = 0;
    int partial_bits = 0;
    uint8_t client_bin[16];
    uint8_t network_bin[16];
    uint8_t mask = 0;

    if (ip_addr == NULL || cidr == NULL || *ip_addr == '\0' || *cidr == '\0') {
        return false;
    }
    if (!parse_cidr_token(cidr, &family, network_bin, &prefix)) {
        return false;
    }
    if (inet_pton(family, ip_addr, client_bin) != 1) {
        return false;
    }

    full_bytes = prefix / 8;
    partial_bits = prefix % 8;
    if (full_bytes > 0 && memcmp(client_bin, network_bin, (size_t)full_bytes) != 0) {
        return false;
    }
    if (partial_bits == 0) {
        return true;
    }

    mask = (uint8_t)(0xFFU << (8 - partial_bits));
    return (client_bin[full_bytes] & mask) == (network_bin[full_bytes] & mask);
}

bool ip_cidr_list_match(const char *ip_addr, const char *cidr_list) {
    char *copy = NULL;
    char *saveptr = NULL;
    char *token = NULL;
    bool matched = false;

    if (ip_addr == NULL || cidr_list == NULL || cidr_list[0] == '\0') {
        return false;
    }

    copy = strdup(cidr_list);
    if (copy == NULL) {
        return false;
    }

    for (token = strtok_r(copy, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
        if (ip_cidr_match(ip_addr, token)) {
            matched = true;
            break;
        }
    }

    free(copy);
    return matched;
}

bool ip_cidr_list_is_valid(const char *cidr_list) {
    char *copy = NULL;
    char *saveptr = NULL;
    char *token = NULL;
    bool valid = true;

    if (cidr_list == NULL || cidr_list[0] == '\0') {
        return true;
    }

    copy = strdup(cidr_list);
    if (copy == NULL) {
        return false;
    }

    for (token = strtok_r(copy, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
        int family = AF_UNSPEC;
        int prefix = 0;
        uint8_t network_bin[16];
        if (!parse_cidr_token(token, &family, network_bin, &prefix)) {
            valid = false;
            break;
        }
        (void)family;
        (void)prefix;
    }

    free(copy);
    return valid;
}
