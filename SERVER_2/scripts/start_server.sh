#!/bin/bash

set -e

mkdir -p captures logs

CAPTURE_FILE="captures/handshake_and_vpn.pcap"
LOG_FILE="logs/openvpn_server.log"

echo "📡 Iniciando captura en puertos 11194 (handshake) y 1194 (VPN)..."
sudo tcpdump -i any port 11194 or port 1194 -w "$CAPTURE_FILE" &
TCPDUMP_PID=$!

echo "🔐 Lanzando servidor TLS personalizado..."
./server_tls &
SERVER_PID=$!

# Manejar Ctrl+C
trap "echo -e '\n🛑 Terminando procesos...'; kill $SERVER_PID 2>/dev/null || true; sudo kill $TCPDUMP_PID 2>/dev/null || true; echo '✅ Captura guardada en $CAPTURE_FILE'; exit 0" INT

wait $SERVER_PID
