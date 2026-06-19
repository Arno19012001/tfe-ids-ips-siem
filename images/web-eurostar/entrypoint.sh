#!/bin/bash
set -e

# ── Configuration réseau persistante ──────────────────────────
ip addr flush dev eth0
ip addr add 10.0.10.10/24 dev eth0
ip link set eth0 up
ip route add default via 10.0.10.1

echo "[web-eurostar] IP 10.0.10.10/24 configurée, gateway 10.0.10.1"

# ── Apache2 ───────────────────────────────────────────────────
mkdir -p /var/run/apache2
apache2ctl start
echo "[web-eurostar] Apache2 démarré"

# ── MariaDB ───────────────────────────────────────────────────
if [ ! -d "/var/lib/mysql/mysql" ]; then
    mysqld --initialize-insecure --user=root
fi
mysqld_safe --user=root &
echo "[web-eurostar] MySQL démarré"

echo "[web-eurostar] Conteneur prêt – services actifs sur 10.0.10.10"

# Maintien du conteneur en vie
tail -f /var/log/apache2/access.log /var/log/apache2/error.log
