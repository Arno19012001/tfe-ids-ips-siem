#!/bin/bash
set -e

# ── Configuration réseau persistante ──────────────────────────
ip addr flush dev eth0
ip addr add 10.0.10.20/24 dev eth0
ip link set eth0 up
ip route add default via 10.0.10.1

echo "[ssh-eurostar] IP 10.0.10.20/24 configurée, gateway 10.0.10.1"

# ── Démarrage rsyslog (requis pour que sshd écrive dans auth.log) ─
mkdir -p /var/spool/rsyslog
/usr/sbin/rsyslogd
echo "[ssh-eurostar] rsyslogd démarré"

# ── Génération des clés hôtes SSH (si absentes) ───────────────
ssh-keygen -A
echo "[ssh-eurostar] Clés hôtes SSH générées"

# ── Démarrage SSHD ────────────────────────────────────────────
/usr/sbin/sshd -D &
SSHD_PID=$!
echo "[ssh-eurostar] SSHD démarré (PID: $SSHD_PID)"

echo "[ssh-eurostar] Conteneur prêt – SSH actif sur 10.0.10.20:22"
echo "[ssh-eurostar] Utilisateur cible : eurostar"

# ── Enrôlement automatique de l'agent Wazuh (non-fatal) ───────
WAZUH_MANAGER_IP="10.0.30.10"

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[ssh-eurostar] Agent Wazuh non enregistré, enrollment vers $WAZUH_MANAGER_IP..."
    if ! /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER_IP" -A ssh-eurostar; then
        echo "[ssh-eurostar] AVERTISSEMENT : échec de l'enrollment Wazuh (Manager injoignable au démarrage). SSH reste fonctionnel. Réessayer manuellement : agent-auth -m $WAZUH_MANAGER_IP -A ssh-eurostar"
    fi
else
    echo "[ssh-eurostar] Agent Wazuh déjà enregistré (client.keys présent)."
fi

/var/ossec/bin/wazuh-control start || echo "[ssh-eurostar] AVERTISSEMENT : wazuh-control start a échoué (agent probablement non enrôlé). Non-bloquant."

# Maintien du conteneur en vie
wait $SSHD_PID
