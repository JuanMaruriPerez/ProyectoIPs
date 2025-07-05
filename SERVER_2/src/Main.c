#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/provider.h>
#include <sys/wait.h>


#include "handshake.h"
#include "handshake_server.h"
#include "crypto_utils.h"

#define SERVER_PORT 11194

int main() {
    // Inicializar proveedor criptográfico
    if (!crypto_init()) {
        fprintf(stderr, "❌ Fallo al inicializar criptografía\n");
        return 1;
    }
    printf("✅ Provider OQS cargado correctamente.\n");

    int listen_fd = create_listening_socket(SERVER_PORT);
    if (listen_fd < 0) return 1;
    printf("🟢 Escuchando en puerto %d...\n", SERVER_PORT);

    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) return perror("❌ Error en accept()"), 1;
    printf("✅ Cliente conectado\n");


    // HANDSHAKE
    client_hello_t ch;
    EVP_PKEY *kem_priv = NULL, *ecdh_priv = NULL;
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t ss_kem[SHARED_SECRET_LEN], ss_ecdh[SHARED_SECRET_LEN];
    server_hello_t sh;

    if (!receive_client_hello(client_fd, &ch)) goto cleanup;
    if (!generate_server_keys(&ch, &kem_priv, &ecdh_priv)) goto cleanup;
    if (!derive_secrets_and_ciphertext(&ch, kem_priv, ecdh_priv, ciphertext, ss_kem, ss_ecdh)) goto cleanup;
    if (!send_server_hello(client_fd, &ch, ciphertext, kem_priv, ecdh_priv, &sh)) goto cleanup;
    if (!send_server_certificate(client_fd)) goto cleanup;

    uint8_t master_secret[DERIVED_KEY_LEN];
    if (!derive_master_secret(&ch, ss_kem, ss_ecdh, master_secret)) goto cleanup;

    //OPENVPN
    if (!save_shared_key("shared.key", master_secret, DERIVED_KEY_LEN)) goto cleanup;
    if (!generate_server_conf("server.conf", "shared.key")) goto cleanup;

    // Lanzar OpenVPN
    pid_t pid = fork();
    if (pid < 0) {
        perror("❌ fork() falló");
        goto cleanup;
    } else if (pid == 0) {
        execlp("openvpn", "openvpn", "--config", "server.conf","--allow-deprecated-insecure-static-crypto", NULL);
        perror("❌ execlp() falló");
        _exit(1);
    } else {
        printf("🚀 OpenVPN lanzado con PID %d\n", pid);
        int status;
        waitpid(pid, &status, 0);
        printf("🛑 OpenVPN finalizó con código %d\n", WEXITSTATUS(status));
    }


cleanup:
    EVP_PKEY_free(kem_priv);
    EVP_PKEY_free(ecdh_priv);
    close(client_fd);
    close(listen_fd);
    return 0;
}
