#!/bin/bash
# start-openvpn-server.sh

CONFIG="server.ovpn"
KEYLOG=/root/openvpn-keys-server.log

export SSLKEYLOGFILE=$KEYLOG
echo "[+] SSLKEYLOGFILE=$SSLKEYLOGFILE"

CAPTURE=~/openvpn-handshake-server.pcap
IFACE="eth0"
sudo tcpdump -i $IFACE port 1194 -w $CAPTURE &
TCPDUMP_PID=$!
echo "[+] Captura iniciada (PID $TCPDUMP_PID)"

openvpn --config $CONFIG --verb 5

kill $TCPDUMP_PID
echo "[+] Captura detenida, archivo en $CAPTURE"
