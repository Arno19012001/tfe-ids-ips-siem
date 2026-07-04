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

# --- Répertoire de logs Suricata ---
mkdir -p /var/log/suricata

# --- Règles : versionnées dans l'image (cf. Issue #12), plus de génération runtime ---
echo "[entrypoint] Règles chargées : $(find /etc/suricata/rules -name '*.rules' | tr '\n' ' ')"

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

# --- Enrôlement automatique de l'agent Wazuh (auto-enrollment via wazuh-authd) ---
# NB : rendu non-fatal (BNF-02 disponibilité) suite au crash du 2026-07-04 :
# une course de démarrage avec wazuh-stack (nœud QEMU, boot lent) faisait
# échouer agent-auth et interrompait tout le conteneur via "set -e",
# alors que Suricata avait déjà démarré correctement.
WAZUH_MANAGER_IP="10.0.30.10"

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[entrypoint] Agent Wazuh non enregistré, enrollment vers $WAZUH_MANAGER_IP..."
    if ! /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER_IP" -A suricata-sensor; then
        echo "[entrypoint] AVERTISSEMENT : échec de l'enrollment Wazuh (Manager injoignable au démarrage). Suricata reste fonctionnel. Réessayer manuellement : agent-auth -m $WAZUH_MANAGER_IP -A suricata-sensor"
    fi
else
    echo "[entrypoint] Agent Wazuh déjà enregistré (client.keys présent)."
fi

echo "[entrypoint] Démarrage de l'agent Wazuh..."
/var/ossec/bin/wazuh-control start || echo "[entrypoint] AVERTISSEMENT : wazuh-control start a échoué (agent probablement non enrôlé). Non-bloquant."

# Shell interactif (processus principal — garde le conteneur actif)
exec /bin/bash
