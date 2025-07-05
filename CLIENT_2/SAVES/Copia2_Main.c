#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

#include "crypto_utils.h"
#include "handshake.h"

#define SERVER_IP "172.233.116.200"
#define SERVER_PORT 1194

int main() {
    // 1. Cargar el provider post-cuántico
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!prov) {
        fprintf(stderr, "❌ Error cargando el provider oqsprovider\n");
        return 1;
    }
    printf("✅ Provider OQS cargado correctamente.\n");

    // 2. Crear socket y conectar al servidor
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = inet_addr(SERVER_IP),
    };
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("❌ Error conectando al servidor");
        return 1;
    }
    printf("✅ Conectado al servidor en %s:%d\n", SERVER_IP, SERVER_PORT);

    // % Generar Material
    // Crear par de claves x25519 y par de claves Kyber768
    EVP_PKEY_CTX *kem_ctx = EVP_PKEY_CTX_new_from_name(NULL, "MLKEM768", NULL);
    EVP_PKEY_CTX *ecdh_ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);

    EVP_PKEY *kem_key = NULL;
    EVP_PKEY *ecdh_key = NULL;

    if (!kem_ctx || EVP_PKEY_keygen_init(kem_ctx) <= 0 || EVP_PKEY_keygen(kem_ctx, &kem_key) <= 0) {
        fprintf(stderr, "❌ Error generando clave KEM cliente\n");
        return 1;
    }

    if (!ecdh_ctx || EVP_PKEY_keygen_init(ecdh_ctx) <= 0 || EVP_PKEY_keygen(ecdh_ctx, &ecdh_key) <= 0) {
        fprintf(stderr, "❌ Error generando clave ECDH cliente\n");
        return 1;
    }

    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_CTX_free(ecdh_ctx);

    // Extraer claves publicas
    uint8_t kem_pub[MAX_KEY_SIZE];
    size_t kem_len = 0;
    EVP_PKEY_get_raw_public_key(kem_key, NULL, &kem_len);
    EVP_PKEY_get_raw_public_key(kem_key, kem_pub, &kem_len);

    uint8_t ecdh_pub[MAX_KEY_SIZE];
    size_t ecdh_len = 0;
    EVP_PKEY_get_raw_public_key(ecdh_key, NULL, &ecdh_len);
    EVP_PKEY_get_raw_public_key(ecdh_key, ecdh_pub, &ecdh_len);

    // 3. Enviar ClientHello
    client_hello_t ch = {0};
    strcpy(ch.kem_name, "MLKEM768");
    strcpy(ch.ecdh_name, "X25519");
    strcpy(ch.hash_name, "SHA256");
    RAND_bytes(ch.client_random, RANDOM_SIZE);
    memcpy(ch.kem_pubkey, kem_pub, KEM_PUB_KEY_SIZE);
    memcpy(ch.ecdh_pubkey, ecdh_pub, ECDH_PUB_KEY_SIZE);

    printf("➡️ Enviando ClientHello (%zu bytes)...\n", sizeof(ch));
    write(sock, &ch, sizeof(ch));


    // 4. Recibir ServerHello
    server_hello_t sh = {0};
    ssize_t rh = read(sock, &sh, sizeof(sh));
    printf("⬅️ Recibido ServerHello\n");
    printf("++++ Kem Name: %s\n", sh.selected_kem);
    printf("++++ ECDH Name: %s\n", sh.selected_ecdh);
    printf("++++ Hash Name: %s\n", sh.selected_hash);
    printf("++++ Client Random: %s\n", sh.server_random);
    printf("++++ Kempub:\n");
    print_hex("%s\n", sh.kem_pubkey, KEM_PUB_KEY_SIZE);
    printf("++++ ECDHpub:\n");
    print_hex("%s\n", sh.ecdh_pubkey, ECDH_PUB_KEY_SIZE);
    printf("++++ Ciphertext:\n");
    print_hex("%s\n", sh.ciphertext, CIPHERTEXT_LEN);




    // Limpieza
    EVP_PKEY_free(kem_key);
    EVP_PKEY_free(ecdh_key);
    close(sock);
    return 0;
}
