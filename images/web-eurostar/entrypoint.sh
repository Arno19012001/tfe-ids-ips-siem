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

# ── Initialisation base applicative (Scénario C, Issue #19) ───
if [ ! -f /var/lib/mysql/.eurostar_db_initialized ]; then
    echo "[web-eurostar] Initialisation de la base eurostar_db..."
    for i in $(seq 1 30); do
        mysqladmin ping --silent && break
        sleep 1
    done

    mysql -u root <<-EOSQL
        CREATE DATABASE IF NOT EXISTS eurostar_db;
        CREATE USER IF NOT EXISTS 'eurostar_app'@'localhost' IDENTIFIED BY 'EurostarApp2026!';
        GRANT ALL PRIVILEGES ON eurostar_db.* TO 'eurostar_app'@'localhost';
        FLUSH PRIVILEGES;

        USE eurostar_db;
        CREATE TABLE IF NOT EXISTS reservations (
            id INT PRIMARY KEY AUTO_INCREMENT,
            nom VARCHAR(50),
            prenom VARCHAR(50),
            numero_reservation VARCHAR(20),
            trajet VARCHAR(100)
        );

        INSERT INTO reservations (nom, prenom, numero_reservation, trajet) VALUES
            ('Dupont', 'Marie', 'EU2026-0001', 'Bruxelles-Midi -> London St Pancras'),
            ('Martin', 'Jean', 'EU2026-0002', 'Paris Nord -> London St Pancras'),
            ('Janssens', 'Sophie', 'EU2026-0003', 'Amsterdam Centraal -> London St Pancras');
EOSQL

    touch /var/lib/mysql/.eurostar_db_initialized
    echo "[web-eurostar] Base eurostar_db initialisée (3 enregistrements factices)."
else
    echo "[web-eurostar] Base eurostar_db déjà initialisée."
fi

# ── Enrôlement automatique de l'agent Wazuh (non-fatal) ───────
WAZUH_MANAGER_IP="10.0.30.10"

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[web-eurostar] Agent Wazuh non enregistré, enrollment vers $WAZUH_MANAGER_IP..."
    if ! /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER_IP" -A web-eurostar; then
        echo "[web-eurostar] AVERTISSEMENT : échec de l'enrollment Wazuh (Manager injoignable au démarrage). Apache/MySQL restent fonctionnels. Réessayer manuellement : agent-auth -m $WAZUH_MANAGER_IP -A web-eurostar"
    fi
else
    echo "[web-eurostar] Agent Wazuh déjà enregistré (client.keys présent)."
fi

/var/ossec/bin/wazuh-control start || echo "[web-eurostar] AVERTISSEMENT : wazuh-control start a échoué (agent probablement non enrôlé). Non-bloquant."

echo "[web-eurostar] Conteneur prêt – services actifs sur 10.0.10.10"

# Maintien du conteneur en vie
tail -f /var/log/apache2/access.log /var/log/apache2/error.log
