/**
 * @file ssh_cert.h
 * @brief Minimal OpenSSH user-certificate validation helpers.
 */

#ifndef SSH_PROXY_SSH_CERT_H
#define SSH_PROXY_SSH_CERT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SSH_CERT_EVAL_NOT_CERT = 0,
    SSH_CERT_EVAL_SUCCESS,
    SSH_CERT_EVAL_FAILURE,
    SSH_CERT_EVAL_DENIED
} ssh_cert_eval_result_t;

ssh_cert_eval_result_t ssh_cert_evaluate_user(const char *authorized_key_line,
                                              const char *username,
                                              const char *client_addr,
                                              const char *trusted_ca_keys,
                                              const char *revoked_serials);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_SSH_CERT_H */
