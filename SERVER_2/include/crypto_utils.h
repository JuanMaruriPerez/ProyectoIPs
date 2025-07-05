#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/evp.h>
#include <stdint.h>

// Tamaños recomendados
#define SHARED_SECRET_MAX 64
#define DERIVED_KEY_LEN 32

// ---------- Inicialización y limpieza ----------
int crypto_init(void);                  // Cargar providers (incluyendo oqs)
void crypto_cleanup();              // Limpiar contexto

// ---------- Generación de claves ----------
EVP_PKEY *generate_ecdh_key(const char *alg);       // ej. "X25519"
EVP_PKEY *generate_kem_key(const char *alg);        // ej. "Kyber768"

// ---------- Operaciones ECDH y KEM ----------
int derive_ecdh_secret(EVP_PKEY *privkey, EVP_PKEY *peerkey, uint8_t *secret, size_t *secret_len);
int kem_encapsulate(EVP_PKEY *kem_pubkey, uint8_t *ciphertext, size_t *ct_len, uint8_t *shared_secret, size_t *ss_len);
int kem_decapsulate(EVP_PKEY *kem_privkey, const uint8_t *ciphertext, size_t ct_len, uint8_t *shared_secret, size_t *ss_len);

// ---------- Derivación de claves ----------
int hkdf_derive(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len, const char *hash_alg);

// ---------- Serialización ----------
int serialize_pubkey(EVP_PKEY *key, uint8_t *out, size_t *out_len);
EVP_PKEY *deserialize_pubkey(const char *alg_name, const uint8_t *in, size_t in_len);

// Utilidades
void print_hex(const char *label, const uint8_t *buf, size_t len);

#endif // CRYPTO_UTILS_H
