# docs/ — Documentation académique et technique

## Contenu

| Fichier / dossier | Rôle |
|---|---|
| `recapitulatif_regles.md` | Synthèse de toutes les règles de détection/corrélation (Suricata + Wazuh) et décodeurs personnalisés du lab, par scénario — document de référence pour la soutenance. |
| `runbooks/` | Procédures de secours. |
| `troubleshooting/` | Fiches de résolution de problèmes rencontrés en cours de projet. |
| `cdc_tfe_arno_starkel_final.pdf` | Cahier des charges (évaluation académique EPHEC). |
| `analyse_tfe_arno_starkel_final.pdf` | Document d'analyse (évaluation académique EPHEC). |
| `schema_architecture_labo.pdf` | Schéma d'architecture réseau du lab. |

## runbooks/

| Fichier | Rôle |
|---|---|
| `dashboard_scenario_a_reproductibilite.md` | Procédure de réinstallation du dashboard SIEM du Scénario A si la VM `wazuh-stack` devait être reconstruite. |

## troubleshooting/

| Fichier | Rôle |
|---|---|
| `wazuh_agent_duplicate.md` | Résolution du conflit « Duplicate agent name » au redémarrage de `suricata-sensor`. |
| `wazuh_agent_info_race_condition.md` | Résolution des erreurs (1103) liées à une race condition au démarrage des daemons Wazuh. |
