#include "handshake_client.h"
#include "crypto_utils.h"


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#define CA_CERT_PATH "certs/ca.cert.pem"

// Conecta al servidor con la IP y puerto dados
int connect_to_server(const char *ip, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("❌ Error creando socket");
        return -1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(ip),
    };

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("❌ Error conectando al servidor");
        close(sock);
        return -1;
    }

    printf("✅ Conectado al servidor en %s:%d\n", ip, port);
    return sock;
}

// Genera las claves híbridas del cliente
int generate_client_keys(EVP_PKEY **kem_key, EVP_PKEY **ecdh_key) {
    *kem_key = generate_kem_key("MLKEM768");
    if (!*kem_key) {
        fprintf(stderr, "❌ Error generando clave KEM cliente\n");
        return 0;
    }

    *ecdh_key = generate_ecdh_key("X25519");
    if (!*ecdh_key) {
        fprintf(stderr, "❌ Error generando clave ECDH cliente\n");
        EVP_PKEY_free(*kem_key);
        return 0;
    }

    return 1;
}

// Construye y envía el ClientHello con las claves públicas
int send_client_hello(int sock, EVP_PKEY *kem_key, EVP_PKEY *ecdh_key, client_hello_t *out_ch) {
    client_hello_t ch = {0};
    strcpy(ch.kem_name, "MLKEM768");
    strcpy(ch.ecdh_name, "X25519");
    strcpy(ch.hash_name, "SHA256");
    RAND_bytes(ch.client_random, RANDOM_SIZE);

    size_t kem_len = KEM_PUB_KEY_SIZE;
    size_t ecdh_len = ECDH_PUB_KEY_SIZE;

    if (!serialize_pubkey(kem_key, ch.kem_pubkey, &kem_len) ||
        !serialize_pubkey(ecdh_key, ch.ecdh_pubkey, &ecdh_len)) {
        fprintf(stderr, "❌ Error serializando claves públicas\n");
        return 0;
    }
    memcpy(out_ch, &ch, sizeof(client_hello_t));

    if (write(sock, &ch, sizeof(ch)) != sizeof(ch)) {
        perror("❌ Error enviando ClientHello");
        return 0;
    }

    printf("➡️ Enviado ClientHello\n");
    return 1;
}

// Recibe el ServerHello
int receive_server_hello(int sock, server_hello_t *sh) {
    ssize_t r = read(sock, sh, sizeof(*sh));
    if (r != sizeof(*sh)) {
        perror("❌ Error leyendo ServerHello");
        return 0;
    }

    printf("⬅️ Recibido ServerHello\n");
    printf("++++ Kem Name: %s\n", sh->selected_kem);
    printf("++++ ECDH Name: %s\n", sh->selected_ecdh);
    printf("++++ Hash Name: %s\n", sh->selected_hash);
    print_hex("++++ Server Random", sh->server_random, RANDOM_SIZE);
    print_hex("++++ Kempub", sh->kem_pubkey, KEM_PUB_KEY_SIZE);
    print_hex("++++ ECDHpub", sh->ecdh_pubkey, ECDH_PUB_KEY_SIZE);
    print_hex("++++ Ciphertext", sh->ciphertext, CIPHERTEXT_LEN);

    return 1;
}

int receive_server_certificate(int sock, server_certificate_t *cert_msg) {
    if (read(sock, cert_msg, sizeof(*cert_msg)) != sizeof(*cert_msg)) {
        perror("❌ Error leyendo ServerCertificate");
        return 0;
    }

    printf("⬅️ Recibido ServerCertificate (%d bytes)\n", MAX_CERT_SIZE);
    print_hex("📜 Certificado (DER)", cert_msg->certificate, MAX_CERT_SIZE);

    // Convertir el buffer DER a estructura X509
    const unsigned char *p = cert_msg->certificate;
    X509 *server_cert = d2i_X509(NULL, &p, MAX_CERT_SIZE);
    if (!server_cert) {
        fprintf(stderr, "❌ Error parseando certificado DER\n");
        return 0;
    }

    // Crear store y cargar la CA
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "❌ Error creando X509_STORE\n");
        X509_free(server_cert);
        return 0;
    }

    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || !X509_LOOKUP_load_file(lookup, CA_CERT_PATH, X509_FILETYPE_PEM)) {
        fprintf(stderr, "❌ Error cargando CA desde %s\n", CA_CERT_PATH);
        X509_free(server_cert);
        X509_STORE_free(store);
        return 0;
    }

    // Crear contexto de verificación
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "❌ Error creando contexto de verificación\n");
        X509_free(server_cert);
        X509_STORE_free(store);
        return 0;
    }

    if (!X509_STORE_CTX_init(ctx, store, server_cert, NULL)) {
        fprintf(stderr, "❌ Error inicializando contexto de verificación\n");
        X509_STORE_CTX_free(ctx);
        X509_free(server_cert);
        X509_STORE_free(store);
        return 0;
    }

    // Verificar
    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        printf("✅ Certificado verificado correctamente con la CA\n");
    } else {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "❌ Fallo en la verificación del certificado: %s\n", X509_verify_cert_error_string(err));
    }

    // Limpieza
    X509_STORE_CTX_free(ctx);
    X509_free(server_cert);
    X509_STORE_free(store);
    return ret == 1;
}

int compute_shared_secrets(const server_hello_t *sh, EVP_PKEY *kem_priv, EVP_PKEY *ecdh_priv,
                           uint8_t *ss_kem, uint8_t *ss_ecdh) {
    // Deserializar claves públicas del servidor
    EVP_PKEY *server_kem_pub = deserialize_pubkey(sh->selected_kem, sh->kem_pubkey, KEM_PUB_KEY_SIZE);
    EVP_PKEY *server_ecdh_pub = deserialize_pubkey(sh->selected_ecdh, sh->ecdh_pubkey, ECDH_PUB_KEY_SIZE);

    if (!server_kem_pub || !server_ecdh_pub) {
        fprintf(stderr, "❌ Error deserializando claves públicas del servidor\n");
        EVP_PKEY_free(server_kem_pub);
        EVP_PKEY_free(server_ecdh_pub);
        return 0;
    }

    // Derivación de secretos
    size_t ss_kem_len = SHARED_SECRET_LEN;
    size_t ss_ecdh_len = SHARED_SECRET_LEN;

    if (!kem_decapsulate(kem_priv, sh->ciphertext, CIPHERTEXT_LEN, ss_kem, &ss_kem_len)) {
        fprintf(stderr, "❌ Error en kem_decapsulate\n");
        EVP_PKEY_free(server_kem_pub);
        EVP_PKEY_free(server_ecdh_pub);
        return 0;
    }

    if (!derive_ecdh_secret(ecdh_priv, server_ecdh_pub, ss_ecdh, &ss_ecdh_len)) {
        fprintf(stderr, "❌ Error en derive_ecdh_secret\n");
        EVP_PKEY_free(server_kem_pub);
        EVP_PKEY_free(server_ecdh_pub);
        return 0;
    }

    EVP_PKEY_free(server_kem_pub);
    EVP_PKEY_free(server_ecdh_pub);
    return 1;
}

int derive_master_secret(const server_hello_t *sh, const uint8_t *ss_kem, const uint8_t *ss_ecdh, uint8_t *master_secret) {
    uint8_t combined[SHARED_SECRET_LEN * 2];

    // Concatenación: primero ECDH, luego KEM
    memcpy(combined, ss_ecdh, SHARED_SECRET_LEN);
    memcpy(combined + SHARED_SECRET_LEN, ss_kem, SHARED_SECRET_LEN);

    // Usamos el hash indicado en el ServerHello (normalmente SHA256)
    return hkdf_derive(
        combined,
        sizeof(combined),
        master_secret,
        DERIVED_KEY_LEN,
        sh->selected_hash
    );
}


int save_shared_key(const char *filename, const uint8_t *key, size_t len) {
    FILE *f = fopen(filename, "w");
    if (!f) return 0;

    fprintf(f, "#\n# 2048 bit OpenVPN static key\n#\n");
    fprintf(f, "-----BEGIN OpenVPN Static key V1-----\n");

    // Rellenamos hasta 256 bytes repitiendo la clave original
    for (size_t i = 0; i < 256; ++i) {
        fprintf(f, "%02x", key[i % len]);
        if ((i + 1) % 16 == 0) fprintf(f, "\n");
    }

    fprintf(f, "-----END OpenVPN Static key V1-----\n");

    fclose(f);
    return 1;
}


int generate_client_conf(const char *path, const char *remote_ip, const char *key_path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("❌ No se pudo crear client.conf");
        return 0;
    }

    fprintf(f,
        "dev tun\n"
	"allow-deprecated-insecure-static-crypto\n"
        "proto tcp\n"
        "remote %s 1194\n"
        "secret %s\n"
        "cipher AES-256-CBC\n"
        "ifconfig 10.8.0.2 10.8.0.1\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
	"verb 4\n",
        remote_ip, key_path
    );

    fclose(f);
    return 1;
}

