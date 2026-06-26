#!/bin/bash
set -e

echo "[entrypoint] Configuration du bridge inline br0 (eth0 <-> eth1)..."

# Création du bridge si inexistant
if ! ip link show br0 &>/dev/null; then
    ip link add name br0 type bridge
fi

# Rattachement des interfaces au bridge
ip link set eth0 master br0
ip link set eth1 master br0

# Activation du bridge et des interfaces membres
ip link set br0 up
ip link set eth0 up
ip link set eth1 up

echo "[entrypoint] Bridge br0 configuré avec succès."
ip link show type bridge

# --- Interface MGMT eth2 ---
ip addr add 10.0.30.20/24 dev eth2 2>/dev/null || true
ip link set eth2 up
echo "[entrypoint] MGMT eth2 : 10.0.30.20/24"

# --- Répertoires de logs Suricata ---
mkdir -p /var/log/suricata /etc/suricata/rules

# --- Règle ICMP de test (validation du démarrage) ---
if [ ! -f /etc/suricata/rules/suricata.rules ]; then
    echo 'alert icmp any any -> any any (msg:"ICMP ping detected"; sid:1000001; rev:1;)' \
        > /etc/suricata/rules/suricata.rules
    echo "[entrypoint] Règle ICMP de test créée."
fi

# --- Règle NFQueue : tout le trafic bridgé est redirigé vers la queue 0 ---
iptables -I FORWARD -m physdev --physdev-is-bridged -j NFQUEUE --queue-num 0
echo "[entrypoint] Règle NFQueue activée (FORWARD -> queue 0)"

# --- Lancement Suricata en mode IPS inline (arrière-plan) ---
echo "[entrypoint] Démarrage Suricata en mode IPS inline (NFQueue 0)..."
suricata -c /etc/suricata/suricata.yaml -q 0 &

# Attendre que Suricata soit prêt avant de rendre la main
sleep 2
echo "[entrypoint] Suricata démarré. Console interactive disponible."
echo "[entrypoint] Logs : tail -f /var/log/suricata/eve.json"

# Shell interactif (processus principal — garde le conteneur actif)
exec /bin/bash
