# Résultats — Agent IA agentique (Itération 4, Qwen3 8B)

Ce dossier contient les captures d'écran des tests de l'agent IA « agentique »
(voir le [README d'ensemble](../README.md) pour le contexte). Contrairement à la
reconstruction de kill chain de l'Itération 3, qui suit toujours les mêmes étapes
programmées à l'avance, ici c'est le modèle d'IA qui décide lui-même, à chaque
question, quelles informations aller chercher dans Wazuh avant de répondre.

## Ce que montrent ces captures

| Capture | Ce qu'elle illustre |
|---|---|
| `2026-08-10_triage-severite10-sortie-live.png` | L'agent répond à la question « Liste les agents actifs et corrèle les alertes de sévérité 10 sur les dernières 24 heures ». On le voit enchaîner 4 appels d'outils (recherche des agents actifs, agrégation, puis chronologie sur deux hôtes) avant de rendre un verdict rédigé en français. Durée observée : environ 30 minutes, en calcul CPU uniquement. |
| `2026-08-10_triage-severite10-rapport-rendu.png` | La même investigation, affichée cette fois sous forme de rapport lisible dans l'onglet « Rapports » de l'interface, avec l'historique des appels d'outils utilisés. |
| `2026-08-10_list-agents-echec-401.png` | Un test où l'outil `list_agents` échoue proprement (erreur d'authentification, mot de passe non configuré) : l'agent signale l'échec au lieu d'inventer une fausse réponse. |
| `2026-08-10_list-agents-succes.png` | Le même test après correction du mot de passe : l'agent liste correctement les 4 hôtes du labo, y compris deux marqués comme déconnectés, sans en inventer la cause. |
| `2026-08-10_historique-investigations-multiples.png` | L'onglet « Rapports » avec 5 investigations successives menées la même journée, montrant que l'historique est bien conservé d'un test à l'autre. |
| `2026-08-10_reconstruction-killchain-aucune-attaque.png` | Un test où l'agent a repéré de vraies alertes de sévérité élevée, mais a correctement identifié qu'elles étaient liées à une saturation mémoire du système plutôt qu'à une attaque — et l'a signalé comme tel plutôt que d'inventer une kill chain. |

## Pour aller plus loin

Le fonctionnement des outils utilisés par l'agent (recherche, agrégation,
chronologie, etc.) est détaillé dans le [README d'ensemble d'`agentic_ai/`](../README.md).
