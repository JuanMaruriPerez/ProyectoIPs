#ifndef HANDSHAKE_CLIENT_H
#define HANDSHAKE_CLIENT_H

#include <unistd.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "handshake.h"

int connect_to_server(const char *ip, uint16_t port);
int generate_client_keys(EVP_PKEY **kem_key, EVP_PKEY **ecdh_key);
int send_client_hello(int sock, EVP_PKEY *kem_key, EVP_PKEY *ecdh_key, client_hello_t *out_ch);
int receive_server_hello(int sock, server_hello_t *sh);
int receive_server_certificate(int sock, server_certificate_t *cert_msg);

int compute_shared_secrets(const server_hello_t *sh, EVP_PKEY *kem_priv, EVP_PKEY *ecdh_priv,
                           uint8_t *ss_kem, uint8_t *ss_ecdh);
int derive_master_secret(const server_hello_t *sh, const uint8_t *ss_kem, const uint8_t *ss_ecdh, uint8_t *master_secret);

int save_shared_key(const char *path, const uint8_t *key, size_t key_len);
int generate_client_conf(const char *path, const char *remote_ip, const char *key_path);

#endif
