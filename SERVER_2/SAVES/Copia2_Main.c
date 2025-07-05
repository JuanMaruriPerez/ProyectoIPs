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
    printf("⬅️ Recibido ClientHello\n");
    printf("++++ Kem Name: %s\n", ch.kem_name);
    printf("++++ ECDH Name: %s\n", ch.ecdh_name);
    printf("++++ Hash Name: %s\n", ch.hash_name);
    printf("++++ Client Random: %s\n", ch.client_random);
    printf("++++ Kempub:\n");
    print_hex("%s\n", ch.kem_pubkey,KEM_PUB_KEY_SIZE);
    printf("++++ ECDHpub:\n");
    print_hex("%s\n", ch.ecdh_pubkey,ECDH_PUB_KEY_SIZE);

    // % Generar Material
    // Crear par de claves del tipo kem_name y ecdh_name
    EVP_PKEY_CTX *kem_ctx = EVP_PKEY_CTX_new_from_name(NULL, ch.kem_name, NULL);
    EVP_PKEY *server_kem_priv = NULL;
    EVP_PKEY_keygen_init(kem_ctx);
    EVP_PKEY_keygen(kem_ctx, &server_kem_priv);
    EVP_PKEY_CTX_free(kem_ctx);

    // Generar clave privada ECDH del servidor
    EVP_PKEY_CTX *ecdh_ctx = EVP_PKEY_CTX_new_from_name(NULL, ch.ecdh_name, NULL);
    EVP_PKEY *server_ecdh_priv = NULL;
    EVP_PKEY_keygen_init(ecdh_ctx);
    EVP_PKEY_keygen(ecdh_ctx, &server_ecdh_priv);
    EVP_PKEY_CTX_free(ecdh_ctx);

    // Importar clave pública KEM del cliente
    EVP_PKEY *client_kem_pub = deserialize_pubkey(ch.kem_name, ch.kem_pubkey, KEM_PUB_KEY_SIZE);

    // Encapsular clave secreta KEM
    uint8_t ciphertext[CIPHERTEXT_LEN];
    size_t ct_len = sizeof(ciphertext);
    uint8_t shared_secret_kem[SHARED_SECRET_LEN];
    size_t ss_kem_len = sizeof(shared_secret_kem);

    EVP_PKEY_CTX *encaps_ctx = EVP_PKEY_CTX_new(client_kem_pub, NULL);
    EVP_PKEY_encapsulate_init(encaps_ctx,NULL);
    EVP_PKEY_encapsulate(encaps_ctx, ciphertext, &ct_len, shared_secret_kem, &ss_kem_len);
    EVP_PKEY_CTX_free(encaps_ctx);
    EVP_PKEY_free(client_kem_pub);

    // Importar clave pública ECDH del cliente
    EVP_PKEY *client_ecdh_pub = deserialize_pubkey(ch.ecdh_name, ch.ecdh_pubkey, ECDH_PUB_KEY_SIZE);

    // Derivar secreto ECDH
    uint8_t shared_secret_ecdh[SHARED_SECRET_LEN];
    size_t ss_ecdh_len = sizeof(shared_secret_ecdh);
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(server_ecdh_priv, NULL);
    EVP_PKEY_derive_init(derive_ctx);
    EVP_PKEY_derive_set_peer(derive_ctx, client_ecdh_pub);
    EVP_PKEY_derive(derive_ctx, shared_secret_ecdh, &ss_ecdh_len);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(client_ecdh_pub);


    // 4. Enviar ServerHello
    server_hello_t sh = {0};
    strcpy(sh.selected_kem, ch.kem_name);
    strcpy(sh.selected_ecdh, ch.ecdh_name);
    strcpy(sh.selected_hash, ch.hash_name);
    RAND_bytes(sh.server_random, RANDOM_SIZE);
    memcpy(sh.kem_pubkey, client_kem_pub, KEM_PUB_KEY_SIZE);
    memcpy(sh.ecdh_pubkey, client_ecdh_pub, ECDH_PUB_KEY_SIZE);
    memcpy(sh.ciphertext, ciphertext, CIPHERTEXT_LEN);

    write(client_fd, &sh, sizeof(sh));
    printf("➡️ Enviado ServerHello\n");


    // Limpieza
    //EVP_PKEY_free(server_key);
    close(client_fd);
    close(listen_fd);
    return 0;
}
