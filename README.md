# Hybrid-Tunnel

**Asignatura:** Ingeniería de Protocolos  
**Autor:** Juan Maruri Pérez  
**Fecha:** 31/06/2025

## Descripción

Este proyecto tiene como objetivo establecer un túnel VPN seguro entre un cliente y un servidor, 
empleando una fase de **handshake** basada en una versión híbrida experimental del protocolo 
**TLS 1.3**, tal como se describe en el borrador del IETF *“Hybrid Key Exchange in TLS 1.3”* 
([draft-ietf-tls-hybrid-design-12](https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-12)).

La versión híbrida de TLS combina dos mecanismos de intercambio de claves:

- **ECDHE** (basado en curvas elípticas, clásico)
- **Kyber** (post-cuántico, resistente a ataques con ordenadores cuánticos)

Esta combinación permite fortalecer la seguridad frente a futuros adversarios cuánticos, asegurando que el secreto compartido se mantenga robusto incluso si uno de los esquemas se viera comprometido.

## Estructura del repositorio

```bash
.
├── BASH_HISTORY/     # Comandos relevantes usados durante la configuración de las máquinas
├── CLIENT_1/         # Cliente contexto real 
├── CLIENT_2/         # Cliente contexto de pruebas
├── SERVER_1/         # Servidor contexto real 
└── SERVER_2/         # Servidor contexto de pruebas

## BASH_HISTORY 

El directorio `BASH_HISTORY/` contiene registros de comandos utilizados durante la configuración 
del entorno experimental. Se incluyen tanto volcados completos de sesiones de terminal como 
versiones depuradas que facilitan la replicación del entorno.

### Archivos incluidos

```bash
BASH_HISTORY/
├── bash_history_remoto_backup
├── bash_history_remoto_backup_OPENVPN
├── bash_history_remoto_clean
└── bash_history_remoto_clean_OPENVPN

### Descripción

- `*_backup`: Volcados completos del historial de terminal (con errores y pruebas). Documentan 
todo el proceso seguido.
- `*_clean`: Scripts depurados que dejan las máquinas listas para ejecutar cliente y servidor. 
Se aplican simétricamente en ambos extremos.

## CLIENT_1 y SERVER_1

Estos directorios contienen el cliente y servidor correspondientes a un entorno funcional basado 
en OpenVPN, configurado para utilizar:

- **OpenSSL 3.5** con soporte híbrido (`oqs-provider`)
- **OpenVPN 2.7_alpha1** (versión con soporte para bibliotecas criptográficas personalizadas)

Ambas máquinas comparten la misma Autoridad Certificadora (CA), y sus certificados han sido 
generados y firmados manualmente.

### CLIENT_1/

Contiene la configuración y binarios necesarios para ejecutar el cliente OpenVPN, así como 
herramientas propias de cliente UDP para pruebas experimentales.

```bash
CLIENT_1/
├── CLIENT_C/                 
│   ├── client_key.pem        # Clave privada del cliente
│   ├── client_pub.pem        # Clave pública
│   ├── udp_client            # Binario cliente 
│   └── udp_client.c          # Código fuente
├── configuracion.txt         # Notas de configuración
├── openvpn-ca/               # Archivos de certificados
│   ├── ca.cert.pem           # Certificado de la CA
│   ├── client.cert.pem       # Certificado firmado del cliente
│   ├── client.key.pem        # Clave privada
│   ├── client.ovpn           # Configuración de cliente OpenVPN
│   ├── openvpn.log           # Log de ejecución
│   └── start_client.sh       # Script de arranque y captura de tráfico
├── openvpn-handshake.pcap    # Captura del tráfico del handshake
└── openvpn-tun0.pcap         # Captura del tráfico cifrado por el túnel


SERVER_1/
├── SERVER_C/            
│   ├── udp_server            # Binario servidor
│   └── udp_server.c          # Código fuente
├── configuracion.txt         # Notas de configuración
├── openvpn-ca/               # Archivos de certificados
│   ├── ca.cert.pem           # Certificado de la CA
│   ├── server.cert.pem       # Certificado firmado del servidor
│   ├── server.key.pem        # Clave privada del servidor
│   ├── dh.pem                # Parámetros Diffie-Hellman (para TLS clásico)
│   ├── server.ovpn           # Configuración del servidor OpenVPN
│   ├── openvpn.log           # Log de ejecución
│   └── start_server.sh       # Script de arranque y captura de tráfico
└── openvpn-handshake-server.pcap  # Captura del tráfico TLS desde el servidor



## CLIENT_2 y SERVER_2

Estas versiones del cliente y servidor constituyen entornos de **prueba avanzada**, diseñados para replicar manualmente las funciones de un **handshake TLS híbrido** y el establecimiento de un túnel seguro, sin depender directamente de OpenVPN para la negociación inicial.

Se han implementado a bajo nivel utilizando **sockets de Berkeley**, integrando funcionalidades de bibliotecas como **OpenSSL 3.5** con soporte para **oqs-provider** y esquemas post-cuánticos como **ML-KEM (Kyber768)**. Esta aproximación permite observar, controlar y depurar con mayor detalle el proceso completo de establecimiento de claves y posterior levantamiento del túnel seguro.

### CLIENT_2/

```bash
CLIENT_2/
├── build/            # Binarios objeto generados por el Makefile
├── captures/         # Capturas de tráfico TLS y túnel con tcpdump/Wireshark
├── certs/            # Certificados, claves públicas y privadas del cliente
├── include/          # Cabeceras de funciones auxiliares de criptografía y handshake
├── logs/             # Log de ejecución de OpenVPN
├── SAVES/            # Copias de seguridad del código fuente
├── src/              # Código fuente del cliente TLS y funciones auxiliares
├── Makefile          # Compilación del cliente TLS manual
├── client.conf       # Configuración propia del túnel manual
├── client_tls        # Binario generado tras compilar
└── shared.key        # Clave precompartida para el túnel VPN (symmetric key)

SERVER_2/
├── build/            # Binarios objeto generados por el Makefile
├── captures/         # Capturas completas del proceso híbrido y del túnel
├── certs/            # Certificados, claves públicas y privadas del servidor
├── config/           # Configuración OpenVPN y notas
├── include/          # Cabeceras de criptografía y handshake del lado servidor
├── logs/             # Log de ejecución de OpenVPN
├── SAVES/            # Copias de seguridad del código fuente
├── scripts/          # Script de lanzamiento del servidor (start_server.sh)
├── src/              # Código fuente del servidor TLS y utilidades criptográficas
├── Makefile          # Compilación del servidor TLS manual
├── server.conf       # Configuración propia del túnel manual
├── server_tls        # Binario generado tras compilar
└── shared.key        # Clave precompartida para el túnel VPN
