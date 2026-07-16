# Résultats — Scénario C (Injection SQL / sqlmap)

## Méthodologie
- Date des tests : 16/07/2026
- Environnement : GNS3, attaque depuis kali-attacker (192.168.1.50) vers web-eurostar (10.0.10.10)
- Commande exécutée : scenarios/C_sqlmap/attack.sh (sqlmap --level=2 puis --dbs contre index.php?id=1)
- Bases de données identifiées par sqlmap : eurostar_db, information_schema
- Capteurs validés : Suricata 7.0.10 (inline NFQueue, suricata-sensor) + Wazuh 4.14.5 (agent HIDS sur web-eurostar, apache access.log/error.log)

## Résultats Suricata (réseau)
12 règles chargées (`suricata -T`, 0 échec), dont 6 spécifiques au Scénario C (SID 1000301-1000306).

Volume : 88 requêtes HTTP réelles vers index.php (access.log, campagne attack.sh)

| SID | Règle | Alertes | Couverture |
|---|---|---|---|
| 1000301 | User-Agent sqlmap | 87/88 | Quasi-exhaustif (limite : --random-agent) |
| 1000302 | UNION SELECT | 9 | Sous-ensemble des requêtes UNION-based |
| 1000303 | Quote/Boolean (fusionnée) | 16 | Boolean-based + error-based quote |
| 1000304 | Time-based blind | 9 | SLEEP/BENCHMARK/WAITFOR |
| 1000305 | Volumétrie de campagne | 1 | Signal "campagne", déclenché dès le 1er burst (52 req. en <1s) — comportement voulu |
| 1000306 | Error-based fonctions MySQL | validée par test ciblé | EXTRACTVALUE, UPDATEXML, GTID_SUBSET, JSON_KEYS, EXP |

**Note méthodologique sur 1000306** : ajoutée après analyse des payloads de la campagne initiale (donc absente du run original). Validée par rejeu ciblé d'un payload EXTRACTVALUE réel capturé dans access.log. Aucune requantification sur une campagne complète post-ajout n'a été effectuée — limite assumée.

Taux de FN Suricata : 1/88 sur la détection User-Agent.

## Résultats Wazuh (applicatif / HIDS)
Ruleset natif Wazuh, aucune règle custom nécessaire :

| Rule ID | Niveau | Description | Groupes / MITRE |
|---|---|---|---|
| 31171 | 6 | SQL injection attempt | web, accesslog, attack, sqlinjection |
| 31103 | 7 | SQL injection attempt (variante) | sql_injection |
| 31106 | 6 | Web attack returned code 200 (success) | T1190 / Initial Access |
| 31122 | 5 | Web server 500 error (Internal Error) | system_error — non spécifique SQLi, corrélatif uniquement |

Vue Discover filtrée (`data.url:*index.php* and not rule.groups:sca`) : **74 alertes pertinentes**. Ce filtrage exclut le bruit des règles SCA (19007-19009, audits de conformité système sans rapport avec l'attaque), qui représentaient 72,9% des 284 hits bruts observés avant filtrage — point de vigilance méthodologique documenté.

## Test de faux positifs
Requête bénigne `GET /index.php?id=2` (curl, hors sqlmap) :
- Suricata : aucune signature ne peut matcher par construction (pas de quote/UNION/SLEEP/fonction MySQL, User-Agent curl)
- Wazuh : 0 résultat dans `wazuh-alerts-*`

→ FP = 0/1 sur ce test (échantillon limité à un seul cas de contrôle)

## Limites connues (assumées, à reprendre dans le rapport)
- Détection User-Agent contournable via `--random-agent`
- Règles 1000302-1000304/1000306 ancrées sur le paramètre `id=`, spécifiques à ce lab
- FN résiduel non couvert : technique `GROUP BY ... HAVING MIN(0)`, payloads de fuzzing génériques
- Règle Wazuh 31122 non spécifique SQLi — signal corrélatif, pas une preuve isolée
- 1000306 non requantifiée sur une campagne complète
- Test de FP limité à un seul cas de contrôle

## Commits associés
- `caafcedd` — Règles initiales + prérequis applicatif (Dockerfile/index.php/entrypoint.sh)
- `4ebfa48e` — Correctif rule-files (suricata.yaml)
- `c380f95f` — SID 1000306 + documentation calibrage

## Captures d'écran
- `screenshot_wazuh_discover_raw_284hits.png`
- `screenshot_wazuh_rule_id_top5_sca_noise.png`
- `screenshot_kali_attack_execution_and_fp_test.png`
- `screenshot_wazuh_discover_filtered_74hits.png`
- `screenshot_wazuh_fp_test_no_results.png`
