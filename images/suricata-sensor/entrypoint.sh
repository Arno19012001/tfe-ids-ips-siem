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

# Garde le conteneur actif avec un shell interactif
exec /bin/bash
