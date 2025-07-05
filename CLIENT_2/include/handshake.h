#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>

// Longitud estándar para campos aleatorios
#define RANDOM_SIZE 32
#define MAX_ALGO_NAME_LEN 64
#define MAX_CERT_SIZE 1462

#define MAX_KEY_SIZE 4096

#define CIPHERTEXT_LEN 1088

#define ECDH_PUB_KEY_SIZE 32
#define KEM_PUB_KEY_SIZE 1184

#define SHARED_SECRET_LEN 32

// ------------------------
// Mensaje: ClientHello
// ------------------------
// El cliente propone algoritmos y envía sus claves públicas (ECDH + opcionalmente KEM)
typedef struct {
    char kem_name[MAX_ALGO_NAME_LEN];
    char ecdh_name[MAX_ALGO_NAME_LEN];
    char hash_name[MAX_ALGO_NAME_LEN];
    uint8_t client_random[RANDOM_SIZE];

    uint8_t ecdh_pubkey[ECDH_PUB_KEY_SIZE];

    // En algunos esquemas KEM el cliente puede enviar ya su clave pública
    uint8_t kem_pubkey[KEM_PUB_KEY_SIZE];
} client_hello_t;

// ------------------------
// Mensaje: ServerHello
// ------------------------
// El servidor confirma los algoritmos, envía sus claves públicas y el ciphertext KEM
typedef struct {
    char selected_kem[MAX_ALGO_NAME_LEN];
    char selected_ecdh[MAX_ALGO_NAME_LEN];
    char selected_hash[MAX_ALGO_NAME_LEN];
    uint8_t server_random[RANDOM_SIZE];

    uint8_t ecdh_pubkey[ECDH_PUB_KEY_SIZE];

    // En algunos esquemas KEM el cliente puede enviar ya su clave pública
    uint8_t kem_pubkey[KEM_PUB_KEY_SIZE];

    uint8_t ciphertext[CIPHERTEXT_LEN];
} server_hello_t;

// ------------------------
// Mensaje: ServerCertificate
// ------------------------
// Información adicional firmada por el servidor
typedef struct {
    uint8_t certificate[MAX_CERT_SIZE];  // Certificado X.509 u otro
    uint32_t cert_len;

    uint8_t signature[MAX_KEY_SIZE];     // Firma del servidor sobre el transcript
    uint32_t sig_len;
} server_certificate_t;

// ------------------------
// Mensaje: Finished
// ------------------------
// Ambos lados demuestran conocimiento del secreto compartido
typedef struct {
    uint8_t handshake_hash[32];  // Hash autenticado del handshake completo
} finished_t;

#endif // HANDSHAKE_H
