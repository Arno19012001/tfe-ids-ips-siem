#!/bin/bash
# Scénario A — Balayage réseau (Nmap)
# Itération : MVP
# Cible : DMZ 10.0.10.0/24
# Exécuter depuis la machine kali-attacker dans GNS3

TARGET="10.0.10.0/24"

echo "[*] Scénario A — Balayage réseau Nmap"
echo "[*] Cible : $TARGET"
echo "[*] Début : $(date)"

# Phase 1 : découverte des hôtes
echo "[*] Phase 1 : découverte des hôtes actifs"
nmap -sn $TARGET

# Phase 2 : scan de ports SYN + détection de services
echo "[*] Phase 2 : scan de ports et services"
nmap -sS -sV -p- --open $TARGET

# Phase 3 : détection OS
echo "[*] Phase 3 : détection OS"
nmap -O $TARGET

echo "[*] Fin : $(date)"
