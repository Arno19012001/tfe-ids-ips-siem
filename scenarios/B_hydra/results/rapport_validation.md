# Scénario B — Résultats de validation (Issue #17)

## Contexte

- **Commande** : `hydra -l eurostar -P wordlist_scenario_B.txt -t 4 -f ssh://10.0.10.20:22 -V`
- **Campagne analysée** : 15/07/2026, 09:29:12 → 09:30:53 UTC (~1min40 de durée totale)
- **Source attaquante** : kali-attacker (192.168.1.50)
- **Cible** : ssh-eurostar (10.0.10.20)
- **Résultat Hydra** : mot de passe trouvé (`eurostar` / `Eurostar2024!`, position 120/150)

## Détection NIDS — Suricata (SID 1000201, rev:2)

6 alertes déclenchées, une par rafale de connexions Hydra, toutes depuis l'unique source 192.168.1.50 :

| # | Timestamp (UTC) | src_ip |
|---|---|---|
| 1 | 09:29:12.906 | 192.168.1.50 |
| 2 | 09:29:30.228 | 192.168.1.50 |
| 3 | 09:29:47.500 | 192.168.1.50 |
| 4 | 09:30:07.640 | 192.168.1.50 |
| 5 | 09:30:24.919 | 192.168.1.50 |
| 6 | 09:30:42.200 | 192.168.1.50 |

- **Taux de faux négatifs** : 0% (6/6 rafales détectées, seuil `count 4, seconds 15` calibré en Issue #16)
- **Faux positifs** : aucun — vérification sur l'ensemble des données `eve.json` disponibles, seule 192.168.1.50 déclenche SID 1000201

## Détection HIDS — Wazuh (agent `ssh-eurostar`, ID 010)

Événements représentatifs observés sur la fenêtre de la campagne (source : `wazuh-alerts-*`, Discover) :

| rule.id | Niveau | Description | Timestamp |
|---|---|---|---|
| 5760 | 5 | `sshd: authentication failed.` (répété, un par mot de passe échoué) | 09:29:12 → 09:30:51 |
| 2502 | 10 | `syslog: User missed the password more than one time` | 09:30:53.185 |
| **40112** | **12** | **`Multiple authentication failures followed by a success.`** | **09:30:51.170** |
| 5501 / 5502 | 3 | Ouverture / fermeture de session PAM associée | 09:30:51 |

La règle **40112** est la découverte la plus significative de cette validation : c'est une règle de **corrélation native du ruleset Wazuh par défaut** (`sshd_rules.xml`), déclenchée automatiquement sur l'événement `Accepted password for eurostar from 192.168.1.50 port 47716 ssh2`. Elle réalise exactement la corrélation échec→succès anticipée dans l'analyse du projet pour le Scénario B, **sans qu'une règle de corrélation personnalisée n'ait dû être écrite**.

## Validation croisée NIDS + HIDS

| | Suricata (NIDS) | Wazuh (HIDS) |
|---|---|---|
| Détection du volume d'attaque | ✅ SID 1000201, 6/6 rafales | ✅ ~119 événements `rule.id 5760` |
| Détection de la réussite (échec→succès) | ❌ hors de portée (SSH chiffré, cf. en-tête `scenario_B_hydra.rules`) | ✅ `rule.id 40112`, niveau 12 |
| Faux positifs observés | 0 | 0 (aucune autre source sur `ssh-eurostar` durant la fenêtre) |

**Critère de validation de l'Issue #17 atteint** : l'attaque est détectée par les deux couches (NIDS et HIDS), avec des rôles complémentaires cohérents avec la conception du Scénario B — Suricata pour le volume, Wazuh pour la corrélation d'issue.

## Limites et remarques méthodologiques

- Seule cette campagne complète (avec succès, 09:29-09:30) a été analysée en détail côté HIDS. La campagne de calibrage antérieure (09:14-09:16, Issue #16) n'a pas été revérifiée a posteriori côté Wazuh.
- L'entrée `rule.id 2502` apparaît quelques secondes après le succès (09:30:53 vs 09:30:51) — hypothèse la plus probable : un des 4 threads Hydra parallèles (`-t 4`) n'a pas immédiatement reçu l'ordre d'arrêt (`-f`) après qu'un autre thread a trouvé le mot de passe, et a soumis une dernière tentative. Non bloquant pour la validation, mentionné par souci d'exhaustivité.
- Décompte exact des ~119 événements `rule.id 5760` non exporté quantitativement (estimation par cohérence avec le nombre de tentatives Hydra, pas un comptage exhaustif vérifié événement par événement).
