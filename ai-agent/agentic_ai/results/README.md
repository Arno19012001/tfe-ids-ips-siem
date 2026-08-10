# Résultats — Agentic AI (Qwen3, tool-calling)

Résultats bruts des tests de validation empirique de `ai-agent/agentic_ai/`
(piste exploratoire/parallèle à `killchain_reconstruction.py`, Issue #27).
Contexte complet dans l'[Issue #46](../../../../issues/46).

## Captures d'écran

| Fichier | Description |
|---|---|
| `2026-08-10_triage-severite10-sortie-live.png` | Panneau SORTIE en direct — prompt "Liste les agents actifs et corrèle les alertes de sévérité 10 sur les dernières 24 heures". 4 appels d'outils structurés (`get_active_agents`, `aggregate_alerts`, `get_agent_timeline` ×2), verdict final en français. ~30 min avec Qwen3 8B, CPU-only. |
| `2026-08-10_triage-severite10-rapport-rendu.png` | Même investigation, rendu Markdown dans l'onglet Rapports (historique + journal des 4 appels d'outils). |
| `2026-08-10_list-agents-echec-401.png` | Échec initial de `list_agents` (401 Unauthorized) — `.env` contenait encore `WAZUH_PASS=<A_COMPLETER>` non remplacé. Le modèle n'a pas halluciné de fausse liste d'agents face à l'échec, comportement correct. |
| `2026-08-10_list-agents-succes.png` | Même prompt après correction du `.env` — succès, `list_agents` répond en un seul appel avec les 4 agents réels du lab (dont `ssh-eurostar`/`web-eurostar` en `disconnected`, signalé sans invention de cause par le modèle). |
| `2026-08-10_historique-investigations-multiples.png` | Onglet Rapports, historique de 5 investigations successives (11h56 à 13h42) — démontre la persistance de `investigations.json` entre les runs et la stabilité de l'agent sur plusieurs sollicitations consécutives. |
| `2026-08-10_reconstruction-killchain-aucune-attaque.png` | Prompt "Peux-tu reconstruire la kill chain des attaques qui ont eu lieu ces dernières 24h ?" — 4 appels d'outils (`search_alerts`, `aggregate_alerts` ×2, `get_agent_timeline`). Comportement notable : l'agent a repéré des alertes réelles de niveau 12 (tactique "Impact", liées à une saturation mémoire système — probable résidu des tests de charge RAM menés en parallèle sur ce même hôte) et a **correctement refusé de les interpréter comme une kill chain**, recommandant une vérification des ressources système plutôt qu'une fausse alerte de sécurité. Contre-exemple concret aux hallucinations documentées avec Llama 3.1 le 09/08. |

## Limites observées (détail dans l'Issue #46)

- `aggregate_alerts(group_by="agent_id")` retombe silencieusement sur `rule.groups`
  (mauvais nom de champ dans le code : `agent_id` au lieu de `agent.id`)
- Un rapport affirme l'absence d'indicateur partagé entre deux hôtes sans que
  `find_entity_across_agents` (l'outil dédié) apparaisse dans le journal des appels

## À compléter

- Rapport JSON brut (`investigations.json`) de ces runs
- Mesure du pic RAM sur un run complet (partielle à ce stade : ≥ 7,5 Go observés
  sur un run interrompu prématurément, budget documenté de 5,5 Go insuffisant)
