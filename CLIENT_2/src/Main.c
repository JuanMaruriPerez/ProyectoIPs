#include <stdio.h>
#include <openssl/provider.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "handshake_client.h"
#include "crypto_utils.h"


#define SERVER_IP "172.233.116.200"
#define SERVER_PORT 11194

int main() {
    if (!crypto_init()) return 1;

    int sock = connect_to_server(SERVER_IP, SERVER_PORT);
    if (sock < 0) return 1;


    //HANDHSAKE
    EVP_PKEY *kem_key = NULL, *ecdh_key = NULL;
    if (!generate_client_keys(&kem_key, &ecdh_key)) goto cleanup;

    client_hello_t ch;  // <- Guardamos la estructura para usarla después
    if (!send_client_hello(sock, kem_key, ecdh_key, &ch)) goto cleanup;

    server_hello_t sh;
    if (!receive_server_hello(sock, &sh)) goto cleanup;

    server_certificate_t cert_msg;
    if (!receive_server_certificate(sock, &cert_msg)) {
        fprintf(stderr, "❌ Error o fallo al verificar certificado\n");
        return 1;
    }

    // Derivación de secretos híbridos
    uint8_t ss_kem[SHARED_SECRET_LEN], ss_ecdh[SHARED_SECRET_LEN];
    if (!compute_shared_secrets(&sh, kem_key, ecdh_key, ss_kem, ss_ecdh)) {
        fprintf(stderr, "❌ Error derivando secretos híbridos\n");
        goto cleanup;
    }

    // Hibridación + HKDF
    uint8_t master_secret[DERIVED_KEY_LEN];
    if (!derive_master_secret(&sh, ss_kem, ss_ecdh, master_secret)) {
        fprintf(stderr, "❌ Error derivando master secret\n");
        goto cleanup;
    }

    print_hex("🔑 Master Secret", master_secret, DERIVED_KEY_LEN);



    //OPENVPN
    // Guardar clave y levantar túnel
    if (!save_shared_key("shared.key", master_secret, DERIVED_KEY_LEN)) goto cleanup;
    if (!generate_client_conf("client.conf", SERVER_IP, "shared.key")) goto cleanup;

    // Lanzar OpenVPN usando fork + execlp
    pid_t pid = fork();
    if (pid < 0) {
        perror("❌ fork() falló");
        goto cleanup;
    } else if (pid == 0) {
        // Proceso hijo: ejecuta OpenVPN
        execlp("openvpn", "openvpn", "--config", "client.conf","--allow-deprecated-insecure-static-crypto", NULL);
        perror("❌ execlp() falló");
        _exit(1);
    } else {
        printf("🚀 Lanzado OpenVPN con PID %d\n", pid);
        // Esperar a que OpenVPN termine (opcional)
        int status;
        waitpid(pid, &status, 0);
        printf("🛑 OpenVPN finalizó con código %d\n", WEXITSTATUS(status));
    }


cleanup:
    EVP_PKEY_free(kem_key);
    EVP_PKEY_free(ecdh_key);
    close(sock);
    return 0;
}
