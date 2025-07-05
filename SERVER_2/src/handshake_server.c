#include "handshake_server.h"
#include "crypto_utils.h"

#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#define CERT_PATH "certs/server.cert.pem.der"

int create_listening_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("❌ Error creando socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("❌ setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("❌ Error en bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        perror("❌ Error en listen");
        close(fd);
        return -1;
    }

    return fd;
}

int receive_client_hello(int fd, client_hello_t *ch) {
    if (read(fd, ch, sizeof(*ch)) != sizeof(*ch)) return 0;
    printf("⬅️ Recibido ClientHello\n");
    printf("++++ Kem Name: %s\n", ch->kem_name);
    printf("++++ ECDH Name: %s\n", ch->ecdh_name);
    printf("++++ Hash Name: %s\n", ch->hash_name);
    print_hex("++++ Client Random", ch->client_random, RANDOM_SIZE);
    print_hex("++++ KEM PubKey", ch->kem_pubkey, KEM_PUB_KEY_SIZE);
    print_hex("++++ ECDH PubKey", ch->ecdh_pubkey, ECDH_PUB_KEY_SIZE);
    return 1;
}

int generate_server_keys(const client_hello_t *ch, EVP_PKEY **kem_priv, EVP_PKEY **ecdh_priv) {
    *kem_priv = generate_kem_key(ch->kem_name);
    *ecdh_priv = generate_ecdh_key(ch->ecdh_name);
    return (*kem_priv && *ecdh_priv);
}

int derive_secrets_and_ciphertext(
    const client_hello_t *ch,
    EVP_PKEY *server_kem_priv, EVP_PKEY *server_ecdh_priv,
    uint8_t *ciphertext, uint8_t *ss_kem, uint8_t *ss_ecdh
) {
    EVP_PKEY *client_kem_pub = deserialize_pubkey(ch->kem_name, ch->kem_pubkey, KEM_PUB_KEY_SIZE);
    EVP_PKEY *client_ecdh_pub = deserialize_pubkey(ch->ecdh_name, ch->ecdh_pubkey, ECDH_PUB_KEY_SIZE);

    if (!client_kem_pub || !client_ecdh_pub) return 0;

    size_t ct_len = CIPHERTEXT_LEN, ss_kem_len = SHARED_SECRET_LEN, ss_ecdh_len = SHARED_SECRET_LEN;
    if (!kem_encapsulate(client_kem_pub, ciphertext, &ct_len, ss_kem, &ss_kem_len)) return 0;
    if (!derive_ecdh_secret(server_ecdh_priv, client_ecdh_pub, ss_ecdh, &ss_ecdh_len)) return 0;

    EVP_PKEY_free(client_kem_pub);
    EVP_PKEY_free(client_ecdh_pub);
    return 1;
}

int send_server_hello(int fd, const client_hello_t *ch, const uint8_t *ciphertext, EVP_PKEY *kem_priv, EVP_PKEY *ecdh_priv, server_hello_t *sh_out) {
    server_hello_t sh = {0};
    strcpy(sh.selected_kem, ch->kem_name);
    strcpy(sh.selected_ecdh, ch->ecdh_name);
    strcpy(sh.selected_hash, ch->hash_name);
    RAND_bytes(sh.server_random, RANDOM_SIZE);
    memcpy(sh.ciphertext, ciphertext, CIPHERTEXT_LEN);

    size_t kem_len = KEM_PUB_KEY_SIZE;
    size_t ecdh_len = ECDH_PUB_KEY_SIZE;
    if (!serialize_pubkey(kem_priv, sh.kem_pubkey, &kem_len) ||
        !serialize_pubkey(ecdh_priv, sh.ecdh_pubkey, &ecdh_len)) {
        fprintf(stderr, "❌ Error serializando claves públicas en ServerHello\n");
        return 0;
    }

    if (write(fd, &sh, sizeof(sh)) != sizeof(sh)) return 0;

    *sh_out = sh;
    printf("➡️ Enviado ServerHello\n");
    return 1;
}

int load_certificate_from_file(const char *path, uint8_t *buffer, size_t max_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("❌ Error abriendo certificado");
        return 0;
    }
    size_t read_len = fread(buffer, 1, max_len, f);
    fclose(f);
    if (read_len != max_len) {
        fprintf(stderr, "❌ Tamaño inesperado del certificado (%zu bytes)", read_len);
        return 0;
    }
    return 1;
}

int send_server_certificate(int fd) {
    server_certificate_t msg = {0};
    if (!load_certificate_from_file(CERT_PATH, msg.certificate, MAX_CERT_SIZE)) return 0;
    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
        perror("❌ Error enviando ServerCertificate");
        return 0;
    }
    printf("➡️ Enviado ServerCertificate (%d bytes)\n", MAX_CERT_SIZE);
    return 1;
}

int derive_master_secret(const client_hello_t *ch, const uint8_t *ss_kem, const uint8_t *ss_ecdh, uint8_t *master_secret) {
    uint8_t hybrid_input[SHARED_SECRET_LEN * 2];
    memcpy(hybrid_input, ss_ecdh, SHARED_SECRET_LEN);
    memcpy(hybrid_input + SHARED_SECRET_LEN, ss_kem, SHARED_SECRET_LEN);

    if (!hkdf_derive(hybrid_input, sizeof(hybrid_input), master_secret, DERIVED_KEY_LEN, ch->hash_name)) {
        fprintf(stderr, "❌ Error en HKDF\n");
        return 0;
    }
    printf("✅ Master secret derivado con éxito\n");
    print_hex("🔑 Master Secret", master_secret, DERIVED_KEY_LEN);
    return 1;
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


int generate_server_conf(const char *filename, const char *key_file) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("❌ Error abriendo server.conf");
        return 0;
    }

    fprintf(f,
        "dev tun\n"
	"allow-deprecated-insecure-static-crypto\n"
        "ifconfig 10.8.0.1 10.8.0.2\n"
        "secret %s\n"
        "port 1194\n"
        "proto tcp-server\n"
        "persist-key\n"
        "persist-tun\n"
	"cipher AES-256-CBC\n"
        "ping 10\n"
        "ping-restart 60\n"
        "verb 4\n",
        key_file
    );

    fclose(f);
    printf("📝 Archivo de configuración generado: %s\n", filename);
    return 1;
}
