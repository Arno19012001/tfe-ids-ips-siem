#!/bin/bash
set -e

echo "[entrypoint] Configuration de l'interface MGMT eth0..."
ip addr add 10.0.30.30/24 dev eth0 2>/dev/null || true
ip route add default via 10.0.30.1 2>/dev/null || true
ip link set eth0 up
echo "[entrypoint] MGMT eth0 : 10.0.30.30/24 (passerelle 10.0.30.1)"

echo "[entrypoint] Démarrage du serveur Ollama (CPU-only, modèle pré-téléchargé au build)..."
ollama serve &

# Attente active de la disponibilité de l'API Ollama — pas de sleep fixe,
# cohérent avec le principe de validation empirique plutôt que supposition.
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:11434/ >/dev/null 2>&1; then
        echo "[entrypoint] API Ollama disponible (tentative $i)."
        break
    fi
    sleep 1
done

echo "[entrypoint] Modèle(s) disponible(s) :"
ollama list

echo "[entrypoint] Agent IA prêt. Code source : /opt/ai-agent/"
echo "[entrypoint] Ex. : python3 /opt/ai-agent/it2/alert_prioritization.py"

# Shell interactif (processus principal — garde le conteneur actif, cohérent
# avec le pattern déjà utilisé sur suricata-sensor)
exec /bin/bash
