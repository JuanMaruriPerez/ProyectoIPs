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

    // 3. Enviar ClientHello
    client_hello_t ch = {0};
    strcpy(ch.kem_name, "X25519MLKEM768");
    strcpy(ch.hash_name, "SHA256");
    RAND_bytes(ch.client_random, RANDOM_SIZE);
    printf("➡️ Enviando ClientHello (%zu bytes)...\n", sizeof(ch));
    write(sock, &ch, sizeof(ch));

    // 4. Recibir ServerHello
    server_hello_t sh = {0};
    ssize_t rh = read(sock, &sh, sizeof(sh));
    printf("⬅️ Recibido ServerHello (%zd bytes): %s\n", rh, sh.selected_kem);

    // 5. Generar clave híbrida cliente (privada)
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, sh.selected_kem, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "❌ Error creando/inicializando contexto\n");
        return 1;
    }
    EVP_PKEY *client_priv = NULL;
    if (EVP_PKEY_keygen(ctx, &client_priv) <= 0) {
        fprintf(stderr, "❌ Error generando clave híbrida cliente\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);
    printf("✅ Clave híbrida generada (cliente)\n");

    // 6. Recibir clave pública y encapsulado del servidor
    uint32_t server_pub_len = 0;
    if (read(sock, &server_pub_len, sizeof(server_pub_len)) != sizeof(server_pub_len)) {
        fprintf(stderr, "❌ Error leyendo longitud de la clave pública\n");
        return 1;
    }
    if (server_pub_len == 0 || server_pub_len > 4096) {
        fprintf(stderr, "❌ Tamaño inválido de la clave pública: %u\n", server_pub_len);
        return 1;
    }

    uint8_t server_pub[4096];
    if (read(sock, server_pub, server_pub_len) != server_pub_len) {
        fprintf(stderr, "❌ Error leyendo la clave pública del servidor\n");
        return 1;
    }

    uint32_t encapsulated_len = 0;
    if (read(sock, &encapsulated_len, sizeof(encapsulated_len)) != sizeof(encapsulated_len)) {
        fprintf(stderr, "❌ Error leyendo longitud del encapsulado\n");
        return 1;
    }
    if (encapsulated_len == 0 || encapsulated_len > 4096) {
        fprintf(stderr, "❌ Tamaño inválido del encapsulado: %u\n", encapsulated_len);
        return 1;
    }

    uint8_t encapsulated[4096];
    if (read(sock, encapsulated, encapsulated_len) != encapsulated_len) {
        fprintf(stderr, "❌ Error leyendo el encapsulado\n");
        return 1;
    }

    printf("⬅️ Recibida clave pública del servidor (%u bytes)\n", server_pub_len);
    print_hex("🔑 Clave pública servidor", server_pub, server_pub_len);
    printf("⬅️ Recibido encapsulado del servidor (%u bytes)\n", encapsulated_len);
    print_hex("📦 Encapsulado", encapsulated, encapsulated_len);

    // 7. Realizar decapsulación (obtener secreto compartido)
    EVP_PKEY_CTX *decaps_ctx = EVP_PKEY_CTX_new(client_priv, NULL);
    if (!decaps_ctx || EVP_PKEY_decapsulate_init(decaps_ctx,NULL) <= 0) {
        fprintf(stderr, "❌ Error creando contexto de decapsulación\n");
        return 1;
    }

    uint8_t shared_secret[64];
    size_t secret_len = sizeof(shared_secret);

    if (EVP_PKEY_decapsulate(decaps_ctx, shared_secret, &secret_len, encapsulated, encapsulated_len) <= 0) {
        fprintf(stderr, "❌ Error en decapsulación\n");
        EVP_PKEY_CTX_free(decaps_ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(decaps_ctx);
    printf("✅ Secreto compartido decapsulado (%zu bytes)\n", secret_len);

    // 8. Obtener clave pública cliente (enviar al servidor)
    uint8_t client_pub[4096];
    size_t client_pub_len = 0;
    if (!EVP_PKEY_get_raw_public_key(client_priv, NULL, &client_pub_len) ||
        client_pub_len > sizeof(client_pub) ||
        !EVP_PKEY_get_raw_public_key(client_priv, client_pub, &client_pub_len)) {
        fprintf(stderr, "❌ Error extrayendo clave pública del cliente\n");
        return 1;
    }

    write(sock, &client_pub_len, sizeof(client_pub_len));
    write(sock, client_pub, client_pub_len);
    printf("📤 Clave pública cliente enviada (%zu bytes)\n", client_pub_len);
    print_hex("🔑 Clave pública cliente", client_pub, client_pub_len);

    // 9. Derivar clave final con HKDF
    uint8_t final_key[32];
    hkdf_derive(shared_secret, secret_len, final_key, sizeof(final_key), "SHA256");
    print_hex("🔐 Clave final derivada (cliente)", final_key, sizeof(final_key));

    // 10. Limpieza
    EVP_PKEY_free(client_priv);
    close(sock);
    return 0;
}
