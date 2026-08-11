# Agentic AI — investigation autonome par tool-calling (Itération 4 — livrable central du TFE)

> Adapté de [octopus237/Agentic-AI](https://github.com/octopus237/Agentic-AI). Ce
> dossier constitue le **livrable central de ce TFE** : un agent IA autonome qui mène
> lui-même son investigation SOC (recherche, agrégation, corrélation inter-hôtes) sur
> les alertes Wazuh, au lieu de suivre un pipeline figé à l'avance. Il s'appuie sur les
> enseignements des itérations précédentes — en particulier la séparation
> déterministe/LLM validée en `it2/` et `it3/`. `it3/killchain_reconstruction.py`
> reste une approche complémentaire, entièrement déterministe, qui sert de référence
> de comparaison et de base de repli validée sur les 4 scénarios.

## Statut

| | `agentic_ai/` (Itération 4 — livrable central) | `it3/killchain_reconstruction.py` (Itération 3) |
|---|---|---|
| Rôle | Investigation autonome — différenciateur du TFE | Pipeline déterministe complémentaire |
| Modèle | Qwen3:8b | Llama 3.1:8b |
| Architecture | Boucle agentique : le LLM choisit lui-même ses appels d'outils | Python déterministe (calculs/structure) + LLM restreint à la prose |
| Validation | Empirique, sur les 4 scénarios + 2 retests (Issue #29, fermée) — voir `results/README.md` | Empirique, complète sur les 4 scénarios |

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `client.py` | Couche données : authentification Wazuh API (token, port 55000, retry avec backoff), requêtes Wazuh Indexer/OpenSearch (port 9200), inventaire syscollector, fréquence baseline des règles. Bibliothèque pure — pas de point d'entrée CLI. |
| `agent_tools.py` | 9 outils exposés au LLM en function-calling (schémas JSON) + boucle agentique (`run_agent`) + CLI autonome pour tester hors interface web. |
| `app.py` | Interface Flask : streaming SSE de l'investigation en direct, historique des investigations (`investigations.json`), planification automatique, gestion démon (`start`/`stop`/`restart`/`status`). |
| `.env.example` | Modèle de configuration (hôtes Wazuh API/Indexer/Ollama, modèle) — pas de secrets réels committés. |
| `results/` | Validation empirique : captures d'écran et description des tests menés — voir `results/README.md`. |

Les commentaires et docstrings des trois fichiers Python sont en français ;
seuls le `SYSTEM_PROMPT` et les descriptions des schémas d'outils JSON (dans
`agent_tools.py`) restent en anglais, car c'est le texte réellement envoyé au
modèle comme instructions.

## Outils disponibles

| Outil | Description |
|---|---|
| `search_alerts` | Recherche plein texte dans les alertes |
| `aggregate_alerts` | Agrégation des alertes par champ (vue d'ensemble) |
| `get_agent_timeline` | Chronologie des événements d'un agent |
| `get_inventory` | Inventaire hôte brut (packages/ports/processus/fichiers) via syscollector |
| `get_rule_frequency` | Fréquence de base d'un groupe de règles (bruit vs anomalie) |
| `find_entity_across_agents` | Corrélation inter-hôtes d'un indicateur (IP, hash, utilisateur, processus) |
| `get_vulnerabilities` | CVE détectées par le vulnerability-detector Wazuh |
| `get_active_agents` | Agents actifs sur une fenêtre donnée (lu depuis l'indexer) |
| `list_agents` | Liste des agents enrôlés |

Seuls `list_agents` et `get_inventory` nécessitent le compte Wazuh API
(`WAZUH_USER`/`WAZUH_PASS`, port 55000) ; les 7 autres passent uniquement par
l'indexer (port 9200).

> `get_event_sequence` de l'implémentation d'origine a été retiré : il dépend des
> champs `data.win.eventdata.*` (Sysmon/Windows), absents de ce lab (Linux/Suricata/SSH
> uniquement).

## Lancer

```bash
# Test ponctuel en CLI (sans interface web)
python3 agent_tools.py "corrèle les événements de sévérité 12 des dernières 24h"
python3 agent_tools.py --agent ssh-eurostar "que s'est-il passé sur cet hôte ?"

# Interface web (SSE + historique + planification)
python3 app.py start      # démarre en arrière-plan
python3 app.py status
python3 app.py stop
python3 app.py run        # premier plan (debug)
```

Interface accessible sur `http://<ip-ai-agent>:5000` (port configurable via `.env`).

## Résultats

Voir [`results/README.md`](results/README.md) pour les captures d'écran et
tests de validation menés à ce jour.
