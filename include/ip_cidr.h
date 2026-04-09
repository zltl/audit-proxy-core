/**
 * @file ip_cidr.h
 * @brief Shared IPv4/IPv6 CIDR matching helpers
 */

#ifndef SSH_PROXY_IP_CIDR_H
#define SSH_PROXY_IP_CIDR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether an IP address matches a CIDR token or exact IP
 * @param ip_addr Client IP address
 * @param cidr CIDR token, e.g. "10.0.0.0/8" or "2001:db8::/32"
 * @return true when the address matches, false otherwise
 */
bool ip_cidr_match(const char *ip_addr, const char *cidr);

/**
 * @brief Check whether an IP address matches any token in a comma-separated CIDR list
 * @param ip_addr Client IP address
 * @param cidr_list Comma-separated CIDR tokens
 * @return true when any token matches, false otherwise
 */
bool ip_cidr_list_match(const char *ip_addr, const char *cidr_list);

/**
 * @brief Validate a comma-separated CIDR list
 * @param cidr_list Comma-separated CIDR tokens
 * @return true when every token is a valid exact IP or CIDR, false otherwise
 */
bool ip_cidr_list_is_valid(const char *cidr_list);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_IP_CIDR_H */
