# Itération 3 — Reconstruction complète de la kill chain (A→B→C→D)

Troisième itération du TFE : ajout du Scénario D (Metasploit vsftpd) et
reconstruction automatique complète de la kill chain sur les 4 scénarios
(Issue #27). Cette approche déterministe sert de base de comparaison et de
référence validée à l'agent autonome de l'Itération 4 (`agentic_ai/`), qui
constitue le **livrable central du TFE**.

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `killchain_reconstruction.py` | Reconstruit la kill chain complète (Reconnaissance → Initial Access → Execution → Command and Control) à partir des alertes Wazuh. Segmentation en phases et mapping MITRE ATT&CK entièrement déterministes ; le LLM (Llama 3.1 8B) rédige uniquement la description de chaque phase et un résumé narratif global. |
| `.env.example` | Configuration (Wazuh Indexer + modèle Ollama). |
| `tests/` | Tests hors ligne (`test_logic_offline.py`, `test_nmap_seul.py`) — jouent des jeux de données synthétiques sans dépendre du lab ni d'Ollama. |
| `results/` | *(à venir)* |

## Pourquoi une architecture déterministe (pas agentic)

Comme pour `it2/`, la segmentation en phases et le calcul MITRE ATT&CK sont
en Python pur — le LLM ne reçoit jamais la chronologie brute et ne produit
jamais de tactique, technique ou horodatage, seulement de la prose. Ce choix
fait suite à un test empirique de l'alternative agentic tool-calling
(documenté dans l'en-tête du fichier) qui a montré, sur ce matériel
CPU-only, avec Llama 3.1 8B : hallucinations de valeurs factuelles, échecs
du protocole de tool-calling natif, et temps de réponse de plusieurs
dizaines de minutes. Cette limite a depuis été revisitée avec un modèle
différent (Qwen3:8b), ouvrant la voie à l'agent autonome de `agentic_ai/`
(Itération 4) — le livrable central du TFE.

## Mapping scénario → phase de la kill chain

| Scénario | Outil | Phase |
|---|---|---|
| A | Nmap | Reconnaissance |
| B | Hydra SSH | Initial Access |
| C | sqlmap | Execution |
| D | Metasploit vsftpd | Command and Control |

## Lancer

```bash
python3 killchain_reconstruction.py --hours 6
python3 killchain_reconstruction.py --hours 6 --attacker-ip 192.168.1.50 --output rapport.json
```

## Résultats

Voir [`results/README.md`](results/README.md).
