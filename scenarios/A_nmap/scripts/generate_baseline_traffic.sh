#!/bin/bash
# Génère du trafic bénin réaliste (HTTP + SSH) depuis workstation-it vers la DMZ.
# Capturé par Suricata au même titre que le trafic du Scénario A (schéma identique),
# utilisé comme baseline pour l'entraînement de l'Isolation Forest (Issue #15).
#
# v2 : diversité de chemins HTTP élargie + durée allongée (45 min au lieu de 25),
# pour disposer d'un échantillon suffisant pour un split en trois
# (entraînement / validation du seuil / test), et réduire le risque de faux
# positifs liés à un profil de normalité appris trop étroit.

WEB_TARGET="10.0.10.10"
SSH_TARGET="10.0.10.20"
SSH_USER="eurostar"
DURATION_MIN=45
END_TIME=$(( $(date +%s) + DURATION_MIN * 60 ))

# Chemins variés — qu'ils existent (200) ou non (404) sur web-eurostar,
# les deux cas produisent des flux HTTP légitimes de tailles différentes,
# ce qui enrichit la diversité du profil de normalité appris.
HTTP_PATHS=("/" "/index.html" "/about.html" "/contact.html" "/robots.txt" "/favicon.ico" "/login.html")

echo "[baseline] Démarrage ($DURATION_MIN min, HTTP multi-chemins + SSH)..."

while [ "$(date +%s)" -lt "$END_TIME" ]; do
    PATH_CHOISI="${HTTP_PATHS[$((RANDOM % ${#HTTP_PATHS[@]}))]}"
    curl -s -o /dev/null "http://$WEB_TARGET$PATH_CHOISI"
    echo "[baseline] $(date +%H:%M:%S) - requête HTTP vers $WEB_TARGET$PATH_CHOISI"

    sleep $(( (RANDOM % 15) + 5 ))

    if [ $(( RANDOM % 3 )) -eq 0 ]; then
        # StrictHostKeyChecking=no et BatchMode=yes : choix pragmatique pour un
        # script automatisé sur un lab isolé (aucune paire de clés configurée
        # entre workstation-it et ssh-eurostar, confirmé empiriquement). L'échec
        # d'authentification qui en résulte est acceptable : seule la connexion
        # TCP + le handshake SSH nous intéressent pour peupler le baseline.
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes \
            "$SSH_USER@$SSH_TARGET" "uptime; exit" 2>/dev/null
        echo "[baseline] $(date +%H:%M:%S) - tentative SSH vers $SSH_TARGET"
    fi

    sleep $(( (RANDOM % 20) + 10 ))
done

echo "[baseline] Terminé. Récupérer eve.json depuis suricata-sensor pour cette fenêtre temporelle."
