# Résultats — Scénario C (Injection SQL / sqlmap)

## Méthodologie
- Environnement : GNS3, attaque depuis kali-attacker (192.168.1.50) vers web-eurostar (10.0.10.10)
- Commande : `scenarios/C_sqlmap/attack.sh` (sqlmap détection puis `--dbs`, deux phases)
- Bases de données identifiées : `eurostar_db`, `information_schema`
- Capteurs : Suricata 7.0.10 (inline NFQueue) + Wazuh 4.14.5 (HIDS sur `web-eurostar`, apache access.log/error.log)

## Résultats Suricata (réseau) — campagne du 07/08/2026, 16:17:49 → 16:18:14 UTC

| SID | Règle | Déclenchée ? |
|---|---|---|
| 1000301 | User-Agent sqlmap | ✅ (très nombreuses occurrences) |
| 1000302 | UNION SELECT Pattern | ✅ confirmée |
| 1000303 | Quote/Boolean (fusionnée) | ✅ confirmée |
| 1000304 | Time-Based Blind | ✅ confirmée |
| 1000305 | Volumétrie de campagne (20 req/10s) | ✅ confirmée (2 occurrences, une par phase du script) |
| 1000306 | MySQL Error-Based Functions | ✅ confirmée (EXTRACTVALUE, UPDATEXML, GTID_SUBSET, JSON_KEYS, EXP) |

**Les 6 signatures se déclenchent sur une campagne complète.**

### Correction d'un constat antérieur (Issue #45)

Un rejeu du 06/08/2026 avait observé seulement 1/6 SID actives (1000301 seule), laissant croire à un défaut de calibrage sur les 5 autres. La campagne du 07/08 (ci-dessus) contredit ce constat. Hypothèse retenue : le rejeu du 06/08 générait un volume de requêtes insuffisant pour couvrir l'ensemble des techniques testées par sqlmap (le script actuel enchaîne une phase de détection puis une phase `--dbs`, ~148 requêtes HTTP au total) — pas un défaut des règles elles-mêmes.

**Correction méthodologique associée** : une hypothèse de bug avait été formulée sur la règle 1000302 (`content:"UNION"; content:"SELECT"; distance:0`), en supposant que `distance:0` exigeait une adjacence stricte entre les deux mots-clés — donc une incompatibilité avec `UNION ALL SELECT` (mot-clé `ALL` intercalé). Vérification empirique : c'est faux. `distance:N` fixe une distance *minimale*, pas une adjacence stricte ; sans `within`, `distance:0` autorise toute distance ≥ 0. La règle fonctionne correctement sans modification.

## Résultats Wazuh (applicatif / HIDS)

Ruleset natif, aucune règle custom nécessaire :

| Rule ID | Niveau | Description | MITRE |
|---|---|---|---|
| 31171 | 6 | SQL injection attempt | — |
| 31103 | 7 | SQL injection attempt (variante) | T1190 |
| 31106 | 6 | Web attack returned code 200 (success) | T1190 |
| 31122 | 5 | Web server 500 error — corrélatif, non spécifique SQLi | — |

Vue filtrée (`data.url:*index.php* and not rule.groups:sca`) : 74 alertes pertinentes sur 284 hits bruts (le reste étant du bruit SCA, audits de conformité système sans rapport avec l'attaque).

## Test de faux positifs

Requête bénigne `GET /index.php?id=2` (curl, hors sqlmap) : aucune signature Suricata ne matche, 0 résultat Wazuh. FP = 0/1.

## Limites connues (assumées, à reprendre dans le rapport)

- Détection User-Agent (1000301) contournable via `--random-agent`
- Règles 1000302-1000304/1000306 ancrées sur le paramètre `id=`, spécifiques à ce lab
- FN résiduel non couvert par choix : `GROUP BY ... HAVING MIN(0)`, payloads de fuzzing de délimiteurs — argument en faveur de la complémentarité avec l'approche comportementale/IA
- Règle Wazuh 31122 non spécifique SQLi (signal corrélatif uniquement)
- Test de FP limité à un seul cas de contrôle

## Captures d'écran
- `screenshot_wazuh_discover_raw_284hits.png`
- `screenshot_wazuh_rule_id_top5_sca_noise.png`
- `screenshot_kali_attack_execution_and_fp_test.png`
- `screenshot_wazuh_discover_filtered_74hits.png`
- `screenshot_wazuh_fp_test_no_results.png`
