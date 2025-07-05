#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

#include "crypto_utils.h"
#include "handshake.h"

#define SERVER_PORT 1194

int main() {
    // 1. Cargar el provider post-cuántico
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!prov) {
        fprintf(stderr, "❌ Error cargando el provider oqsprovider\n");
        return 1;
    }
    printf("✅ Provider OQS cargado correctamente.\n");

    // 2. Crear socket y aceptar conexión
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 1);
    printf("🟢 Esperando conexión en puerto %d...\n", SERVER_PORT);

    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("❌ Error en accept()");
        return 1;
    }
    printf("✅ Cliente conectado\n");

    // 3. Recibir ClientHello
    client_hello_t ch = {0};
    read(client_fd, &ch, sizeof(ch));
    printf("⬅️ Recibido ClientHello: %s\n", ch.kem_name);

    // 4. Enviar ServerHello
    server_hello_t sh = {0};
    strcpy(sh.selected_kem, ch.kem_name);
    strcpy(sh.selected_hash, ch.hash_name);
    RAND_bytes(sh.server_random, RANDOM_SIZE);
    write(client_fd, &sh, sizeof(sh));
    printf("➡️ Enviado ServerHello\n");

    // 5. Generar clave pública y encapsular secreto
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, sh.selected_kem, NULL);
    EVP_PKEY *server_key = NULL;
    uint8_t ciphertext[4096];
    size_t ct_len = sizeof(ciphertext);
    uint8_t shared_secret[64];
    size_t ss_len = sizeof(shared_secret);

    if (!ctx ||
        EVP_PKEY_encapsulate_init(ctx, &server_key) <= 0 ||
        EVP_PKEY_encapsulate(ctx, ciphertext, &ct_len, shared_secret, &ss_len) <= 0) {
        fprintf(stderr, "❌ Error encapsulando secreto\n");
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);
    printf("✅ Secreto encapsulado con éxito\n");

    // 6. Enviar clave pública (raw) del servidor
    uint8_t server_pub[4096];
    size_t server_pub_len = 0;
    EVP_PKEY_get_raw_public_key(server_key, NULL, &server_pub_len);
    EVP_PKEY_get_raw_public_key(server_key, server_pub, &server_pub_len);

    write(client_fd, &server_pub_len, sizeof(uint32_t));
    write(client_fd, server_pub, server_pub_len);
    printf("➡️ Enviada clave pública del servidor (%zu bytes)\n", server_pub_len);
    print_hex("🔑 Clave pública servidor", server_pub, server_pub_len);

    // 7. Enviar ciphertext al cliente
    write(client_fd, &ct_len, sizeof(uint32_t));
    write(client_fd, ciphertext, ct_len);
    printf("➡️ Enviado ciphertext al cliente (%zu bytes)\n", ct_len);
    print_hex("📦 Ciphertext", ciphertext, ct_len);

    // 8. Derivar clave final con HKDF
    uint8_t final_key[32];
    hkdf_derive(shared_secret, ss_len, final_key, sizeof(final_key), "SHA256");
    print_hex("🔐 Clave final derivada (servidor)", final_key, sizeof(final_key));

    // 9. Limpieza
    EVP_PKEY_free(server_key);
    close(client_fd);
    close(listen_fd);
    return 0;
}
