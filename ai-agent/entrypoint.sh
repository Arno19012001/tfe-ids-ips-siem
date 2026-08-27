#!/bin/bash
set -e

echo "[entrypoint] Configuration de l'interface MGMT eth0..."
ip addr add 10.0.30.30/24 dev eth0 2>/dev/null || echo "[entrypoint] AVERTISSEMENT : configuration IP échouée (capacité NET_ADMIN requise — normal hors GNS3)"
ip route add default via 10.0.30.1 2>/dev/null || true
ip link set eth0 up 2>/dev/null || echo "[entrypoint] AVERTISSEMENT : activation eth0 échouée (capacité NET_ADMIN requise — normal hors GNS3)"
echo "[entrypoint] MGMT eth0 : tentative 10.0.30.30/24 (passerelle 10.0.30.1)"

echo "[entrypoint] Démarrage du serveur Ollama (supervision avec redémarrage automatique, CPU-only, modèles pré-téléchargés au build)..."
(
    while true; do
        ollama serve >> /var/log/ollama.log 2>&1
        code=$?
        echo "[entrypoint] ALERTE : ollama serve s'est arrêté (code ${code}) — relance dans 2s..." | tee -a /var/log/ollama.log >&2
        sleep 2
    done
) &

# Attente active de la disponibilité de l'API Ollama — pas de sleep fixe,
# cohérent avec le principe de validation empirique plutôt que supposition.
OLLAMA_READY=0
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:11434/ >/dev/null 2>&1; then
        echo "[entrypoint] API Ollama disponible (tentative $i)."
        OLLAMA_READY=1
        break
    fi
    sleep 1
done

if [ "$OLLAMA_READY" -eq 0 ]; then
    echo "[entrypoint] ERREUR : Ollama indisponible après 30s au démarrage. Voir /var/log/ollama.log." >&2
fi

echo "[entrypoint] Modèle(s) disponible(s) :"
ollama list || echo "[entrypoint] ERREUR : impossible de lister les modèles (voir /var/log/ollama.log)."

echo "[entrypoint] Agent IA prêt. Code source : /opt/ai-agent/"
echo "[entrypoint] Ex. (déterministe) : python3 /opt/ai-agent/it2/alert_prioritization.py"
echo "[entrypoint] Ex. (kill chain)   : python3 /opt/ai-agent/it3/killchain_reconstruction.py --hours 6"
echo "[entrypoint] Ex. (agentic AI)   : python3 /opt/ai-agent/agentic_ai/app.py start"

# Shell interactif (processus principal — garde le conteneur actif, cohérent
# avec le pattern déjà utilisé sur suricata-sensor)
exec /bin/bash
