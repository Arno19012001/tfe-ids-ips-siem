# ai-agent — Agent IA du TFE (4 itérations)

Ce dossier contient les 4 itérations successives du composant IA du TFE,
packagées dans un unique conteneur Docker (`ai-agent`, image `debian:12` +
Ollama CPU-only). Chaque itération a son propre README détaillant son rôle,
son architecture et comment la lancer.

## Par où commencer

Si tu découvres ce dossier, le point d'entrée le plus pertinent est
[`agentic_ai/`](agentic_ai/README.md) — l'agent d'investigation autonome,
**livrable central du TFE**. Les 3 itérations précédentes (`mvp/`, `it2/`,
`it3/`) documentent la démarche empirique qui y a mené : chaque étape a
validé une brique (détection d'anomalies, priorisation, corrélation, kill
chain déterministe) avant d'aboutir à l'agent agentique.

## Les 4 itérations

| Dossier | Itération | Rôle | README |
|---|---|---|---|
| `mvp/` | 1 | Détection d'anomalies par Isolation Forest (Scénario A) | [mvp/README.md](mvp/README.md) |
| `it2/` | 2 | Priorisation d'alertes + corrélation multi-étapes + kill chain textuelle (Scénarios B, C) | [it2/README.md](it2/README.md) |
| `it3/` | 3 | Reconstruction complète de la kill chain, architecture déterministe (Scénarios A→D) | [it3/README.md](it3/README.md) |
| `agentic_ai/` | 4 — **livrable central** | Agent IA autonome, investigation par tool-calling | [agentic_ai/README.md](agentic_ai/README.md) |

## Fichiers à la racine du dossier

| Fichier | Rôle |
|---|---|
| `Dockerfile` | Image du conteneur `ai-agent` (Debian 12 + Ollama CPU-only + Llama 3.1 8B et Qwen3 8B pré-téléchargés au build). Copie le code des 4 itérations dans `/opt/ai-agent/`. |
| `entrypoint.sh` | Configure l'interface MGMT, démarre Ollama, affiche les commandes de lancement de chaque itération. |
| `requirements.txt` | Dépendances Python communes (LangChain, scikit-learn, Flask, etc.). |
| `.dockerignore` | Exclusions du build Docker. |

## Architecture commune

Toutes les itérations partagent le même principe : **le calcul et la
structuration restent en Python déterministe** (scores, segmentation en
phases, tags MITRE ATT&CK), le LLM local (Ollama, CPU-only) est cantonné à
la classification contextuelle ou à la rédaction de prose. L'agent
agentique (`agentic_ai/`) est la seule exception : le LLM y choisit
lui-même ses appels d'outils, ce qui a nécessité un changement de modèle
(Qwen3:8b) après l'échec empirique documenté de Llama 3.1 8B sur cette
tâche (voir `it3/README.md`).

## Lancer le conteneur

Déployé via la topologie GNS3 (`gns3/tfe-ids-ips-siem.gns3`), zone MGMT
(10.0.30.30). Une fois démarré, `entrypoint.sh` affiche les commandes
d'exemple pour chaque itération — voir le README de chaque dossier pour le
détail.
