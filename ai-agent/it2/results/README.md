# Résultats — Itération 2

Ce dossier documente les résultats de l'Itération 2 : détection sur les
Scénarios B et C, et première couche d'intelligence artificielle
(priorisation d'alertes, corrélation multi-étapes, reconstruction de kill
chain).

## Ce que contient ce dossier

[`bilan_iteration_2.md`](bilan_iteration_2.md) est le document de synthèse :
résultats de détection (Suricata + Wazuh) sur B et C, comparaison des deux
méthodes de priorisation (score composite vs LLM), validation de la
corrélation multi-étapes, et bilan de la reconstruction de kill chain.

[`llm_prioritization/`](llm_prioritization/) contient les résultats bruts de
la priorisation par LLM : un CSV par incident (avant et après correction
d'un biais de classification), avec son propre README.

## Résultat marquant

Le score composite déterministe atteint un F1-macro de 1,000 sur
l'échantillon disponible (42 incidents) — provisoire, un risque de
surapprentissage est explicitement documenté. Le LLM local atteint 0,656
après correction d'un bug de détection. Détail complet dans
`bilan_iteration_2.md`, section 2.1.

## Pour aller plus loin

Voir le [README d'ensemble du dossier `it2/`](../README.md).
