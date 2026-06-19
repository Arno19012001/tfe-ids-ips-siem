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
| Déploiement | Ansible |
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

### MVP — Itération 1 (fin juin 2026)
- Environnement de laboratoire opérationnel
- Détection du scénario A (balayage réseau)
- Premier modèle IA : détection d'anomalies (Isolation Forest)
- Dashboard SIEM minimal

### Itération 2 (juillet S1–S2)
- Scénarios B et C ajoutés
- Corrélation des événements, reconstruction partielle de la kill chain
- Priorisation automatique des alertes par IA
- Déploiement des agents HIDS

### Itération 3 (juillet S3–S4)
- Scénario D ajouté
- Reconstruction automatique complète de la kill chain par IA
- Dashboard SOC complet
- Mécanismes d'aide à la réponse à incident

---

## Structure du dépôt

```
tfe-ids-ips-siem/
├── images/                  # Images Docker du laboratoire
│   ├── suricata-sensor/     #   Sensor inline NFQueue (Debian 12)
│   ├── web-eurostar/        #   Serveur web Apache2 + MariaDB (10.0.10.10)
│   └── ssh-eurostar/        #   Serveur SSH OpenSSH (10.0.10.20)
├── ansible/                 # Playbooks de déploiement
├── wazuh/                   # Configuration SIEM
├── ai-agent/                # Agent IA LangChain + Ollama (3 itérations)
├── scenarios/               # Scripts d'attaque et résultats
│   ├── A_nmap/
│   ├── B_hydra/
│   ├── C_sqlmap/
│   └── D_metasploit/
├── gns3/                    # Topologie réseau GNS3
├── docs/                    # Documents académiques (CDC, analyse, schéma)
└── report/                  # Sources LaTeX du rapport final
```

---

## Documents académiques

Les documents produits en amont de la phase pratique sont disponibles dans `docs/` :

- `cdc.pdf` — Cahier des charges (15 pages)
- `analyse_tfe_arno_starkel_final.pdf` — Analyse (32 pages)
- `schema_architecture_labo.pdf` — Schéma d'architecture réseau

---

## Lancer l'environnement

> La procédure complète de déploiement sera documentée ici à l'issue du MVP.

```bash
# Déploiement via Ansible (à venir)
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_suricata.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_wazuh.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/deploy_ai_agent.yml
```

---

## Licence

Ce projet est réalisé à des fins académiques. Tous les outils utilisés sont soumis à
leurs licences respectives (GPL, Apache 2.0, MIT). Aucun usage commercial n'est prévu.
