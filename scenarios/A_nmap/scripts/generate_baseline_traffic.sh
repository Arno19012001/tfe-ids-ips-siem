#!/bin/bash
# Génère du trafic bénin réaliste (HTTP + SSH) depuis workstation-it vers la DMZ.
# Capturé par Suricata au même titre que le trafic du Scénario A (schéma identique),
# utilisé comme baseline pour l entraînement de l Isolation Forest (Issue #15).

WEB_TARGET="10.0.10.10"
SSH_TARGET="10.0.10.20"
SSH_USER="eurostar"
DURATION_MIN=25
END_TIME=$(( $(date +%s) + DURATION_MIN * 60 ))

echo "[baseline] Démarrage ($DURATION_MIN min, HTTP + SSH)..."

while [ "$(date +%s)" -lt "$END_TIME" ]; do
    curl -s -o /dev/null "http://$WEB_TARGET/"
    curl -s -o /dev/null "http://$WEB_TARGET/index.html"
    echo "[baseline] $(date +%H:%M:%S) - requête HTTP vers $WEB_TARGET"

    sleep $(( (RANDOM % 15) + 5 ))

    if [ $(( RANDOM % 3 )) -eq 0 ]; then
        # StrictHostKeyChecking=no et BatchMode=yes : choix pragmatique pour un
        # script automatisé sur un lab isolé (aucune paire de clés configurée
        # entre workstation-it et ssh-eurostar, confirmé empiriquement). L échec
        # d authentification qui en résulte est acceptable : seule la connexion
        # TCP + le handshake SSH nous intéressent pour peupler le baseline.
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes \
            "$SSH_USER@$SSH_TARGET" "uptime; exit" 2>/dev/null
        echo "[baseline] $(date +%H:%M:%S) - tentative SSH vers $SSH_TARGET"
    fi

    sleep $(( (RANDOM % 20) + 10 ))
done

echo "[baseline] Terminé. Récupérer eve.json depuis suricata-sensor pour cette fenêtre temporelle."
