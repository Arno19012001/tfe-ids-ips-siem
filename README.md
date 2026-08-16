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
environnement de laboratoire virtualisé, avec un agent IA autonome d'investigation
comme différenciateur central — voir [`ai-agent/agentic_ai/`](ai-agent/agentic_ai/README.md).

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
| LLM local | Ollama — Llama 3.1 8B (pipelines déterministes) et Qwen3 8B (agent agentique) |
| Agent IA | LangChain + tool-calling (investigation autonome), Flask (interface web) |
| Versioning | GitHub |
| Rédaction | LaTeX / Overleaf |

**Machine hôte :** Ubuntu 24.04 LTS — Intel Core i5-12450H — 16 Go RAM — 512 Go SSD
(inférence CPU-only, pas de GPU dédié)

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

État d'avancement au 16/08/2026 — suivi détaillé via les [GitHub Issues](https://github.com/Arno19012001/tfe-ids-ips-siem/issues) et [Projects](https://github.com/Arno19012001/tfe-ids-ips-siem) du dépôt (Sprints 1 à 6).

### MVP — Itération 1 (Sprints 1–2) ✅ Terminé
- Environnement de laboratoire opérationnel
- Détection du scénario A (balayage réseau)
- Premier modèle IA : détection d'anomalies (Isolation Forest)
- Dashboard SIEM minimal

Détail : [`ai-agent/mvp/README.md`](ai-agent/mvp/README.md)

### Itération 2 (Sprints 3–4) ✅ Terminé
- Scénarios B et C ajoutés
- Corrélation des événements, reconstruction partielle de la kill chain
- Priorisation automatique des alertes par IA
- Déploiement des agents HIDS

Détail : [`ai-agent/it2/README.md`](ai-agent/it2/README.md)

### Itération 3 (Sprint 5) ✅ Terminé (avec limite assumée)
- Scénario D ajouté ✅
- Reconstruction automatique complète de la kill chain, architecture déterministe — ✅ validée empiriquement sur les 4 scénarios (Issue #27, fermée)
- Dashboard SOC complet — limite assumée (Issue #28, toujours ouverte) : seul le Scénario A est couvert par un dashboard Wazuh dédié ; partiellement compensé par l'interface de l'agent agentique (Itération 4)
- Sert de base de comparaison validée à l'agent agentique de l'Itération 4

Détail : [`ai-agent/it3/README.md`](ai-agent/it3/README.md)

### Itération 4 — Agent IA agentique (Sprint 5) ✅ Terminé — **livrable central du TFE**
- Agent d'investigation autonome par tool-calling : le LLM (Qwen3 8B) choisit
  lui-même ses appels d'outils pour mener une investigation SOC sur les
  alertes Wazuh, plutôt que de suivre un pipeline figé à l'avance
- 9 outils exposés (recherche, agrégation, chronologie, inventaire hôte,
  corrélation inter-agents, vulnérabilités...)
- Interface web (Flask, streaming en direct, historique des investigations)
- Mécanismes d'aide à la réponse à incident validés empiriquement sur
  6 tests (Issue #29, fermée) ; une partie du besoin de dashboard SOC
  (Issue #28, toujours ouverte) est couverte par l'interface, un dashboard
  Wazuh dédié reste à construire

Détail : [`ai-agent/agentic_ai/README.md`](ai-agent/agentic_ai/README.md)

### Rédaction et dépôt (Sprint 6) 🔄 En cours
- Rédaction des chapitres du rapport final — ✅ terminée
- Relecture et mise en page — ✅ terminée
- Dépôt (17 août 2026) — ⏳ à venir, et préparation de la défense (septembre 2026)

---

## Structure du dépôt

```
tfe-ids-ips-siem/
├── ai-agent/                # Agent IA — 4 itérations, voir ai-agent/README.md
│   ├── mvp/                 #   Itération 1 : détection d'anomalies (Isolation Forest)
│   ├── it2/                 #   Itération 2 : priorisation + corrélation + kill chain textuelle
│   ├── it3/                 #   Itération 3 : kill chain complète, architecture déterministe
│   └── agentic_ai/          #   Itération 4 : agent autonome par tool-calling — livrable central
├── images/                  # Images Docker du laboratoire (web/ssh-eurostar, suricata-sensor, workstation-it)
├── scenarios/               # Scripts d'attaque et résultats (Scénarios A à D)
├── wazuh/                   # Configuration SIEM (règles, décodeurs, config réseau)
├── ansible/                 # Inventaire (playbooks à venir, Issue #39)
├── gns3/                    # Topologie réseau GNS3
└── docs/                    # Documentation académique, runbooks, dépannage
```

Chaque dossier a son propre README détaillant son contenu.

---

## Documents académiques

Les documents produits en amont de la phase pratique, dans le cadre des évaluations
EPHEC, sont disponibles dans `docs/` (voir [`docs/README.md`](docs/README.md) pour
l'index complet) :

- `cdc_tfe_arno_starkel_final.pdf` — Cahier des charges
- `analyse_tfe_arno_starkel_final.pdf` — Analyse
- `schema_architecture_labo.pdf` — Schéma d'architecture réseau

`docs/` contient aussi des runbooks et fiches de dépannage documentant la démarche de
validation et de troubleshooting du lab.

Le rapport final et son volume d'annexes ne sont pas versionnés dans ce dépôt (privé) : ils
sont déposés séparément via Moodle, conformément aux modalités du TFE.

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
