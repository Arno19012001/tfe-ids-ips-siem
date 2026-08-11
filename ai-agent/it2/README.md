# Itération 2 — Corrélation multi-scénarios et priorisation IA

Deuxième itération du TFE : ajout des Scénarios B (brute force SSH) et C
(injection SQL), et première couche d'intelligence artificielle appliquée
aux alertes déjà détectées — priorisation, corrélation multi-étapes et
reconstruction textuelle de kill chain (Issues #21 à #24).

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `alert_prioritization.py` | Pipeline complet : récupération des alertes (Wazuh Indexer), regroupement par incident, score composite déterministe, classification contextuelle par LLM (Llama 3.1 8B), évaluation de la précision. |
| `run_it21_llm_comparison.py` | Invoque `run_llm_batch()` d'`alert_prioritization.py` (non appelé par défaut, ~20-35 min en CPU-only) et compare score seul vs score + LLM. |
| `kill_chain_report.py` | Réutilise le regroupement par incident d'`alert_prioritization.py` pour générer un rapport textuel de kill chain (segmentation déterministe des étapes + rédaction par LLM), sur l'enchaînement Scénario A → B. |
| `.env.example` | Configuration de connexion au Wazuh Indexer. |
| `results/` | Bilan complet et artefacts de validation — voir `results/README.md`. |

## Architecture retenue

Même principe que le reste du projet : le calcul et la structuration restent
en Python déterministe (score composite, segmentation en étapes de kill
chain, tags MITRE), le LLM local est cantonné à la classification
contextuelle ou à la rédaction de prose. Cette séparation a été validée
empiriquement à plusieurs reprises — voir `results/bilan_iteration_2.md`,
section 2.

`alert_prioritization.py` documente dans son en-tête l'historique complet
des versions, y compris un incident réseau ayant bloqué un run (résolu
depuis — voir `results/bilan_iteration_2.md` pour les résultats obtenus).

## Lancer

```bash
python3 alert_prioritization.py          # pipeline complet, sans le batch LLM
python3 run_it21_llm_comparison.py       # + comparaison score seul vs score+LLM (~20-35 min)
python3 kill_chain_report.py             # rapport de kill chain sur l'incident A→B
```

## Résultats

Voir [`results/README.md`](results/README.md).
