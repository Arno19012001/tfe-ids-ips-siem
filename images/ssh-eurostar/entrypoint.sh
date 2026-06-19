#!/bin/bash
set -e

# ── Configuration réseau persistante ──────────────────────────
ip addr flush dev eth0
ip addr add 10.0.10.20/24 dev eth0
ip link set eth0 up
ip route add default via 10.0.10.1

echo "[ssh-eurostar] IP 10.0.10.20/24 configurée, gateway 10.0.10.1"

# ── Génération des clés hôtes SSH (si absentes) ───────────────
ssh-keygen -A
echo "[ssh-eurostar] Clés hôtes SSH générées"

# ── Démarrage SSHD ────────────────────────────────────────────
/usr/sbin/sshd -D &
SSHD_PID=$!
echo "[ssh-eurostar] SSHD démarré (PID: $SSHD_PID)"

echo "[ssh-eurostar] Conteneur prêt – SSH actif sur 10.0.10.20:22"
echo "[ssh-eurostar] Utilisateur cible : eurostar"

# Maintien du conteneur en vie
wait $SSHD_PID
