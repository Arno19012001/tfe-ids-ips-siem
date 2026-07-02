#!/bin/bash
set -e

# ── Interface LAN eth0 ────────────────────────────────────────
ip addr add 10.0.20.50/24 dev eth0 2>/dev/null || true
ip link set eth0 up
ip route add default via 10.0.20.1 2>/dev/null || true
echo "[entrypoint] workstation-it : 10.0.20.50/24"

# ── Affichage injecté par GNS3 (Xvfb/x11vnc) ──────────────────
if [ -z "$DISPLAY" ]; then
    export DISPLAY=:0
fi
sleep 3

# ── Gestionnaire de fenêtres léger ─────────────────────────────
fluxbox &
sleep 2

# ── Terminal ────────────────────────────────────────────────────
xterm -geometry 100x30+0+0 &

# ── Navigateur ────────────────────────────────────────────────
firefox-esr --no-remote &

# Garde le conteneur actif
tail -f /dev/null
