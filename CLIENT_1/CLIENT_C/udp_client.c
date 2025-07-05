#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/provider.h>

#define SERVER_IP "172.233.108.45"
#define PORT 8080
#define BUFSIZE 4096

int main() {
    // 1. Cargar provider post-cuántico
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!prov) {
        fprintf(stderr, "Error cargando el provider oqsprovider\n");
        return 1;
    }
    printf("Provider OQS cargado y contexto creado correctamente.\n");

    // 2. Crear contexto para clave híbrida X25519+MLKEM768
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519MLKEM768", NULL);
    if (!ctx) {
        fprintf(stderr, "Error creando contexto EVP_PKEY_CTX\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Error inicializando generación de clave\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error generando clave\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    // 3. Guardar clave privada
    FILE *priv = fopen("client_key.pem", "w");
    if (priv) {
        PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(priv);
    }

    // 4. Guardar clave pública
    FILE *pub = fopen("client_pub.pem", "w");
    if (pub) {
        PEM_write_PUBKEY(pub, pkey);
        fclose(pub);
    }

    // 5. Extraer clave pública en formato binario y convertir a Base64
    unsigned char *raw_pub = NULL;
    size_t raw_pub_len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &raw_pub_len) <= 0) {
        fprintf(stderr, "Error obteniendo longitud de la clave pública\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    raw_pub = malloc(raw_pub_len);
    if (!raw_pub || EVP_PKEY_get_raw_public_key(pkey, raw_pub, &raw_pub_len) <= 0) {
        fprintf(stderr, "Error obteniendo clave pública en formato raw\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        free(raw_pub);
        return 1;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, raw_pub, raw_pub_len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);

    char *b64_pub = malloc(bptr->length + 1);
    memcpy(b64_pub, bptr->data, bptr->length);
    b64_pub[bptr->length] = '\0';

    printf("Clave pública (Base64):\n%s\n", b64_pub);

    // Limpieza
    free(b64_pub);
    free(raw_pub);
    BIO_free_all(b64);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    // 6. Crear mensaje HELLO_SERVER
    const char *client_id = "client01";
    const char *algorithms = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";

    char message[BUFSIZE];
    snprintf(message, BUFSIZE, "HELLO_SERVER|%s|%s|", client_id, algorithms);
    printf("\nMensaje HELLO_SERVER enviado:\n%s\n", message);

    // 7. Enviar mensaje por UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = inet_addr(SERVER_IP)
    };

    sendto(sockfd, message, strlen(message), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));

    // 8. Recibir respuesta del servidor
    char buffer[BUFSIZE];
    socklen_t addr_len = sizeof(server_addr);
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFSIZE - 1, 0,
                                (struct sockaddr *)&server_addr, &addr_len);
    if (recv_len >= 0) {
        buffer[recv_len] = '\0';
        printf("Respuesta del servidor: %s\n", buffer);
    } else {
        perror("recvfrom");
    }

    close(sockfd);
    return 0;
}
