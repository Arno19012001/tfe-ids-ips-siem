# TFE — Déploiement d'une solution IDS/IPS et SIEM avec intégration IA

**Étudiant :** Arno Stärkel  
**Établissement :** EPHEC — Bachelier en Technologie de l'Informatique  
**Année académique :** 2025–2026 (seconde session)  
**Rapporteur :** Laurent Schalkwijk  
**Clients :** Sophie Veron & Marco Citta (Eurostar)  
**Dépôt du rapport :** 17 août 2026

---

## Présentation du projet

Ce dépôt contient l'ensemble des fichiers techniques produits dans le cadre du Travail
de Fin d'Études portant sur le déploiement d'une solution IDS/IPS et SIEM en
environnement de laboratoire virtualisé, avec intégration d'un composant d'intelligence
artificielle comme différenciateur central.

L'environnement est entièrement composé d'outils libres et open source. Aucune donnée
réelle n'est utilisée : tous les scénarios s'appuient sur des adresses IP, noms d'hôtes
et identifiants fictifs, conformément aux exigences du RGPD.

---

## Stack technique

| Rôle | Outil |
|---|---|
| Simulation réseau | GNS3 |
| Conteneurisation | Docker |
| IDS/IPS | Suricata (mode IPS inline NFQueue) |
| SIEM | Wazuh (Manager + Indexer + Dashboard) |
| Agent HIDS | Wazuh Agent |
| Déploiement | Ansible *(prévu, non encore implémenté — voir Issue #39)* |
| LLM local | Ollama + Llama 3.1 8B |
| Agent IA | LangChain Python |
| Versioning | GitHub |
| Rédaction | LaTeX / Overleaf |

**Machine hôte :** Ubuntu 24.04 LTS — Intel Core i5-12450H — 16 Go RAM — 512 Go SSD

---

## Architecture réseau

```
WAN (kali-attacker — 192.168.1.50)
        │
   [pfsense-fw]  ← inline NFQueue
        │
   ┌────┴──────────────────┐
   │                       │
DMZ 10.0.10.0/24     Management 10.0.30.0/24
web-eurostar             suricata-sensor
ssh-eurostar             wazuh-stack
metasploitable           ai-agent
   │
LAN 10.0.20.0/24
workstation-it
```

---

## Scénarios d'attaque

| ID | Outil | Cible | Itération |
|---|---|---|---|
| A | Nmap | DMZ complète | MVP |
| B | Hydra | ssh-eurostar (10.0.10.20) | Itération 2 |
| C | sqlmap | web-eurostar (10.0.10.10) | Itération 2 |
| D | Metasploit vsftpd | metasploitable (10.0.10.30) | Itération 3 |

---

## Approche itérative

État d'avancement au 06/08/2026 — suivi détaillé via les [GitHub Issues](https://github.com/Arno19012001/tfe-ids-ips-siem/issues) et [Projects](https://github.com/Arno19012001/tfe-ids-ips-siem) du dépôt (Sprints 1 à 6).

### MVP — Itération 1 (Sprints 1–2) ✅ Terminé
- Environnement de laboratoire opérationnel
- Détection du scénario A (balayage réseau)
- Premier modèle IA : détection d'anomalies (Isolation Forest)
- Dashboard SIEM minimal

### Itération 2 (Sprints 3–4) ✅ Terminé
- Scénarios B et C ajoutés
- Corrélation des événements, reconstruction partielle de la kill chain
- Priorisation automatique des alertes par IA
- Déploiement des agents HIDS

### Itération 3 (Sprint 5) 🔄 En cours
- Scénario D ajouté ✅
- Reconstruction automatique complète de la kill chain par IA — 🔄 en cours (Issue #27)
- Dashboard SOC complet — 🔄 en cours (Issue #28)
- Mécanismes d'aide à la réponse à incident — 🔄 en cours (Issue #29)

### Rédaction et dépôt (Sprint 6) ⏳ À venir
- Rédaction des chapitres du rapport final
- Relecture et mise en page
- Dépôt (17 août 2026) et préparation de la défense (septembre 2026)

---

## Structure du dépôt

```
tfe-ids-ips-siem/
├── images/                  # Images Docker du laboratoire
│   ├── suricata-sensor/     #   Sensor inline NFQueue (Debian 12)
│   ├── web-eurostar/        #   Serveur web Apache2 + MariaDB (10.0.10.10)
│   └── ssh-eurostar/        #   Serveur SSH OpenSSH (10.0.10.20)
├── ansible/                 # Inventaire (playbooks à venir, Issue #39)
├── wazuh/                   # Configuration SIEM (règles, décodeurs, config réseau)
├── ai-agent/                # Agent IA LangChain + Ollama (3 itérations)
├── scenarios/               # Scripts d'attaque et résultats
│   ├── A_nmap/
│   ├── B_hydra/
│   ├── C_sqlmap/
│   └── D_metasploit/
├── results/                 # Bilans d'itération, analyses IA (Isolation Forest, LLM)
├── gns3/                    # Topologie réseau GNS3
├── docs/                    # Runbooks et documentation de dépannage
└── report/                  # Sources LaTeX du rapport final (à venir, Sprint 6)
```

---

## Documents académiques

Les documents produits en amont de la phase pratique, dans le cadre des évaluations
EPHEC, sont disponibles dans `docs/` :

- `cdc_tfe_arno_starkel_final.pdf` — Cahier des charges
- `analyse_tfe_arno_starkel_final.pdf` — Analyse
- `schema_architecture_labo.pdf` — Schéma d'architecture réseau

Le schéma d'architecture sera régénéré à partir des sources LaTeX du rapport final une
fois celui-ci rédigé (Sprint 6).

---

## Lancer l'environnement

> L'automatisation complète du déploiement (Ansible) est prévue mais pas encore
> implémentée — voir [Issue #39](https://github.com/Arno19012001/tfe-ids-ips-siem/issues/39).
> À ce stade, le déploiement se fait manuellement via l'import de la topologie GNS3
> (`gns3/tfe-ids-ips-siem.gns3`) et le build des images Docker sous `images/`.

```bash
# Déploiement automatisé via Ansible (à venir — Issue #39)
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_suricata.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_wazuh.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_ai_agent.yml
```

---

## Licence

Ce projet est réalisé à des fins académiques. Tous les outils utilisés sont soumis à
leurs licences respectives (GPL, Apache 2.0, MIT). Aucun usage commercial n'est prévu.
