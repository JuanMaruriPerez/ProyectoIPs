#ifndef HANDSHAKE_SERVER_H
#define HANDSHAKE_SERVER_H

#include <unistd.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "handshake.h"


int create_listening_socket(uint16_t port);
int receive_client_hello(int fd, client_hello_t *ch);
int generate_server_keys(const client_hello_t *ch, EVP_PKEY **kem_priv, EVP_PKEY **ecdh_priv);
int derive_secrets_and_ciphertext(const client_hello_t *ch,
                                  EVP_PKEY *server_kem_priv, EVP_PKEY *server_ecdh_priv,
                                  uint8_t *ciphertext,

                                  uint8_t *ss_kem, uint8_t *ss_ecdh);
int send_server_hello(int fd,const client_hello_t *ch,const uint8_t *ciphertext,EVP_PKEY *server_kem_priv,EVP_PKEY *server_ecdh_priv,server_hello_t *sh_out);

int load_certificate_from_file(const char *path, uint8_t *buffer, size_t max_len);
int send_server_certificate(int fd) ;

int derive_master_secret(const client_hello_t *ch, const uint8_t *ss_kem, const uint8_t *ss_ecdh, uint8_t *master_secret);

int save_shared_key(const char *filename, const uint8_t *key, size_t len);
int generate_server_conf(const char *filename, const char *key_file);


#endif
