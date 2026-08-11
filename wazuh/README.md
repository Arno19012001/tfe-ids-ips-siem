# wazuh/ — Configuration du SIEM (Manager + Indexer + Dashboard)

Configuration de `wazuh-stack` (VM QEMU, Amazon Linux 2023, 10.0.30.10,
zone MGMT — **à ne jamais supprimer/recréer**, contrairement aux conteneurs
Docker du lab, sous peine de perdre l'overlay copy-on-write). Détail de
chaque règle et décodeur : `docs/recapitulatif_regles.md`.

## Contenu

| Fichier / dossier | Rôle |
|---|---|
| `ossec.conf` | Configuration principale du Wazuh Manager : rootcheck, intégration osquery, inventaire système, FIM (syscheck), réponse active (blocage IP, désactivé par défaut — voir commentaires du fichier), listener syslog pour `metasploitable2` (Scénario D). |
| `rules/custom_rules.xml` | Règles de corrélation personnalisées (kill chain A→B, D, persistance) — plage d'ID 100050-100099. |
| `decoders/custom_decoders.xml` | Décodeurs personnalisés (peuplement de `srcip` pour les alertes Suricata, décodage du syslog `useradd` de `metasploitable2`). |
| `dashboards/scenario_a_dashboard.ndjson` | Export du dashboard SIEM du Scénario A (visualisations + index pattern), réimportable — voir `docs/runbooks/dashboard_scenario_a_reproductibilite.md`. |
| `20-eth0.network` | Configuration systemd-networkd de l'interface MGMT (adresse statique 10.0.30.10/24). |
| `config/filebeat.yml`, `config/opensearch.yml`, `config/opensearch_dashboards.yml` | Configuration des trois composants du stack all-in-one (Manager + Indexer OpenSearch + Dashboard). |

## Points d'attention

- `network.host` dans `opensearch.yml` doit inclure `_local_` en plus de
  l'IP explicite (10.0.30.10) — sinon les composants locaux (Filebeat,
  Dashboard) ne peuvent plus joindre l'Indexer.
- La réponse active (blocage IP automatique, A4/B4) est **désactivée par
  défaut** dans `ossec.conf` — capacité démontrée en test mais volontairement
  coupée, voir les commentaires du fichier pour le contexte.
