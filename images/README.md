# images/ — Images Docker des hôtes du laboratoire

Une image par hôte simulé du lab (hors `wazuh-stack`, qui est une VM QEMU —
voir `wazuh/`, et `ai-agent`, packagé séparément — voir `ai-agent/README.md`).
Chaque image Debian 12 embarque un agent Wazuh HIDS (sauf `workstation-it`,
poste client sans exposition à surveiller) pointant vers `wazuh-stack`
(10.0.30.10), avec persistance de l'identité (`client.keys`) via volume
Docker au-delà d'un stop/start du nœud.

## Contenu

| Dossier | Hôte | Zone / IP | Rôle |
|---|---|---|---|
| `web-eurostar/` | `web-eurostar` | DMZ — 10.0.10.10 | Apache2 + MariaDB + PHP, cible du Scénario C (injection SQL). Logs Apache collectés par l'agent Wazuh (Issue #20). |
| `ssh-eurostar/` | `ssh-eurostar` | DMZ — 10.0.10.20 | Serveur OpenSSH, cible du Scénario B (brute force Hydra). `auth.log` collecté par l'agent Wazuh (Issue #17). |
| `suricata-sensor/` | `suricata-sensor` | MGMT — 10.0.30.20 | Capteur IDS/IPS Suricata en pont L2 inline (NFQueue). Contient aussi le ruleset complet (`rules/`) — voir `docs/recapitulatif_regles.md` pour le détail. |
| `workstation-it/` | `workstation-it` | LAN — 10.0.20.50 | Poste client (Firefox ESR, générateur de trafic bénin pour l'entraînement Isolation Forest — voir `ai-agent/mvp/`). |

`metasploitable2` (cible du Scénario D) n'a pas d'image ici : c'est une VM
QEMU préexistante, trop ancienne pour héberger un agent Wazuh moderne — voir
`scenarios/D_metasploit/setup_syslog_metasploitable.md`.

## suricata-sensor/rules/

| Fichier | Rôle |
|---|---|
| `base.rules` | Règles génériques, hors scénarios. |
| `scenarios/scenario_{A,B,C,D}_*.rules` | Règles de détection spécifiques à chaque scénario, avec métadonnées MITRE ATT&CK. |

Détail complet de chaque règle : `docs/recapitulatif_regles.md`.
