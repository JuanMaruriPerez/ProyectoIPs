#!/bin/bash

CONFIG="client.ovpn"
KEYLOG=/root/openvpn-keys.log
CAPTURE_ETH0=/root/openvpn-handshake.pcap
#CAPTURE_TUN0=~/openvpn-tun0.pcap

export SSLKEYLOGFILE=$KEYLOG
echo "[+] SSLKEYLOGFILE=$SSLKEYLOGFILE"

# Capturar handshake en eth0 (antes de conectar)
sudo tcpdump -i eth0 udp port 1194 -w $CAPTURE_ETH0 &
TCPDUMP_ETH0_PID=$!
echo "[+] Captura en eth0 iniciada (PID $TCPDUMP_ETH0_PID)"

sleep 3

# Lanzar OpenVPN en background para que cree tun0
openvpn --config $CONFIG --verb 5 &
OPENVPN_PID=$!
echo "[+] OpenVPN iniciado (PID $OPENVPN_PID)"

# Esperar un poco a que tun0 se cree
#echo "[*] Esperando a que tun0 esté disponible..."
#while ! ip link show tun0 > /dev/null 2>&1; do
#    sleep 0.5
#done

#echo "[+] tun0 detectado, iniciando captura en tun0..."
#sudo tcpdump -i tun0 -w $CAPTURE_TUN0 &
#TCPDUMP_TUN0_PID=$!
#echo "[+] Captura en tun0 iniciada (PID $TCPDUMP_TUN0_PID)"

# Esperar a que OpenVPN termine (CTRL+C para interrumpir)
wait $OPENVPN_PID

echo "[+] OpenVPN detenido, matando capturas..."
kill $TCPDUMP_ETH0_PID
#kill $TCPDUMP_TUN0_PID

echo "[+] Capturas guardadas:"
echo "  Handshake: $CAPTURE_ETH0"
#echo "  Tráfico tun0: $CAPTURE_TUN0"
