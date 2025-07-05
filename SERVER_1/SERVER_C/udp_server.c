#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFSIZE 1024

int main() {
    int sockfd;
    char buffer[BUFSIZE];
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len = sizeof(cliaddr);

    // Crear socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Inicializar servidor
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Enlazar socket al puerto
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Servidor UDP escuchando en el puerto %d...\n", PORT);

    // Esperar mensaje
    int n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0,
                     (struct sockaddr *)&cliaddr, &len);
    buffer[n] = '\0';
    printf("Mensaje recibido del cliente: %s\n", buffer);

    // Responder
    const char *reply = "Hola cliente, recibido tu mensaje.";
    sendto(sockfd, reply, strlen(reply), 0, (const struct sockaddr *)&cliaddr, len);

    printf("Respuesta enviada al cliente.\n");

    close(sockfd);
    return 0;
}
