# gns3/ — Topologie réseau du laboratoire

`tfe-ids-ips-siem.gns3` : fichier de projet GNS3 (v2.2.59), 13 nœuds —
3 VM QEMU (`pfsense-fw`, `kali-attacker`, `metasploitable2`), 1 VM QEMU
supplémentaire (`wazuh-stack`), 5 conteneurs Docker (`workstation-it`,
`ssh-eurostar`, `web-eurostar`, `suricata-sensor`, `ai-agent`), 3 switches
et 1 nœud NAT vers Internet (accès nécessaire uniquement au build des
images, le lab est isolé une fois déployé).

À importer dans GNS3 pour reconstruire la topologie. Le détail de
l'architecture réseau (zones, plan d'adressage) est dans le schéma
`docs/schema_architecture_labo.pdf`.
