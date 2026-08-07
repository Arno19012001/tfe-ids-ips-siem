# Scénario A — Résultats de validation (Issues #13, #36, #37, Sprint 6)

## Contexte

- **Script** : `scenarios/A_nmap/attack.sh` — Phase 1 (découverte hôtes), Phase 2 (scan ports/services -sV), Phase 3 (détection OS -O)
- **Campagne analysée** : 07/08/2026, 22:08:05 → 22:12:04 CEST (20:08:05 → 20:12:04 UTC)
- **Source** : kali-attacker (192.168.1.50)
- **Cible** : 10.0.10.0/24 — 3 hôtes actifs cette campagne (10.0.10.1 passerelle, 10.0.10.10 web-eurostar, 10.0.10.20 ssh-eurostar)

## Règles actives (état final)

| SID | Règle | Seuil |
|---|---|---|
| 1000101 (rev:7) | SYN Scan Detected | `count 15, seconds 10, track by_src` |
| 1000104 (rev:4) | Service/Version Detection Probe | `count 1, seconds 10, track by_both` |

SID 1000102/1000103 (OS fingerprinting T2/T3-T7) retirées définitivement — cf. section Issue #37 ci-dessous.

## Résultats Suricata — campagne du 07/08/2026

### SID 1000101 (SYN Scan)

Déclenchement régulier toutes les ~10 secondes sur l'intégralité de la campagne (20:08:35 → 20:12:04 UTC), cohérent avec le comportement attendu du seuil `count 15, seconds 10` sous charge SYN soutenue (Phase 2, scan complet du `/24`). Au moins 20 occurrences confirmées sur la fenêtre observée.

### SID 1000104 (Service/Version Detection) — validation du fix Issue #36

| Timestamp UTC | Hôte cible | Service |
|---|---|---|
| 20:11:35.872 | 10.0.10.20 (ssh-eurostar) | SSH |
| 20:11:41.851 | 10.0.10.10 (web-eurostar) | HTTP |

**2/2 hôtes couverts** sur cette campagne — confirme empiriquement, sur un jeu de données totalement indépendant, le fix de l'Issue #36 (`count:1, track by_both`, root cause : seuil trop élevé pour un service à faible échange applicatif + agrégation `by_src` masquant les hôtes secondaires).

## Historique des révisions de règles

### Issue #36 — Recalibrage SID 1000104 (clôturée)

Root cause : seuil `count:3` trop élevé pour des services n'échangeant qu'un seul paquet applicatif (HTTP, SSH), combiné à `track by_src` agrégeant tous les hôtes DMZ sous un compteur unique par IP source. Fix validé le 06/08/2026 (3/3 hôtes couverts, fenêtre 15:28:14–15:32:51 UTC, 2 FP mesurés sur trafic légitime). Une approche par corrélation Wazuh a été envisagée puis explicitement écartée : le Scénario A a la complexité la plus faible (⋆), les critères A1-A4 ne ciblent que SID 1000101, et la contrainte BNF-07 (Cahier des charges) proscrit la complexité excessive.

### Issue #37 — Retrait SID 1000102/1000103 (clôturée)

Audit complet du ruleset : ces deux signatures (sondes de fingerprinting OS à flags anormaux, Null/FIN-PSH-URG) sont architecturalement mortes — pfSense (pare-feu à état) rejette silencieusement tout paquet ne correspondant pas au début d'une session TCP légitime (SYN isolé), avant même que le paquet n'atteigne le capteur. Preuve empirique : capture réseau double-interface pfSense confirmant les paquets visibles côté WAN mais absents côté Suricata. Non requises par aucun critère d'acceptation (A1-A4 ne ciblent que 1000101). Retirées plutôt que laissées en code mort non documenté — traitées via le chemin "impossibilité technique documentée".

## A4 — Blocage IP automatique (Wazuh active-response)

**Architecture** : `firewall-drop` déclenché par la règle Wazuh custom **100050** (isole SID Suricata 1000101), ciblant l'agent `suricata-sensor` (agent_id 019 — non stable à travers une suppression complète du nœud GNS3, revérifié après chaque recréation). Timeout 120s.

**Justification architecturale** : le mot-clé `threshold` de Suricata ne limite que la fréquence de log des alertes, pas les effets de bord (`xbits`/`drop`) — un blocage fiable "après N matches" n'est pas réalisable nativement dans une règle Suricata pure, d'où le choix de l'active-response Wazuh plutôt qu'un mécanisme Suricata natif.

**Validation antérieure** (commit `a80d6e3`, 07/08/2026) : cycle complet détection→blocage→libération confirmé dans `active-responses.log` avant désactivation par défaut (choix documenté, pas un oubli — réactivable en retirant `<disabled>yes</disabled>`). **Désactivée pour la campagne ci-dessus** afin de valider A1/A3 sur l'intégralité du scan sans interruption réseau (le blocage se déclencherait tôt en Phase 2, avant que les Phases 2-3 ne se terminent). Un test dédié au blocage isolé (scan SYN ciblé, A4 réactivée) est prévu en suivi, même méthodologie que B4-bis.

## Découverte : chevauchement inter-scénarios (SID 1000201 / règle Wazuh 100054)

Pendant la Phase 3 (détection OS, sondage répété du port 22 sur ssh-eurostar), la règle Suricata **1000201** (conçue pour le Scénario B, brute force Hydra — `count 4, seconds 15` sur connexions vers `$SSH_PORTS`) s'est déclenchée à plusieurs reprises, et la règle Wazuh **100054** qui l'isole (liée à l'active-response B4-bis) a compté **13 déclenchements** sur cette seule campagne A.

**Explication** : le sondage OS de Nmap envoie plusieurs paquets vers un port ouvert dans une fenêtre courte — un pattern suffisamment proche d'une rafale de connexions SSH pour franchir le même seuil que celui pensé pour détecter Hydra.

**Impact réel** : nul — l'active-response liée à 100054 est désactivée par défaut (cf. rapport Scénario B). Mais si elle avait été active pour un autre test, ce scan A aurait déclenché un blocage de kali-attacker sans lien avec le Scénario B. **Limitation à documenter** : les campagnes A et B ne doivent pas être testées en parallèle si B4-bis est active, sous peine de faux déclenchement croisé.

## Synthèse des critères d'acceptation

| Critère | Preuve |
|---|---|
| A1 (détection scan réseau) | SID 1000101, déclenchement soutenu sur toute la campagne |
| A3 (détection service/version) | SID 1000104, 2/2 hôtes couverts |
| A4 (blocage IP automatique) | Active-response validée bout-en-bout (commit `a80d6e3`), désactivée par défaut, réactivable |

*(A2 non applicable — hors périmètre des critères formels du document d'analyse pour ce scénario, complexité ⋆.)*

## Limites et remarques méthodologiques

- 1000102/1000103 retirées : limitation architecturale du laboratoire (pfSense stateful), pas un défaut de conception des règles.
- Comptage exact des occurrences de 1000101 non exhaustif sur cette campagne (fenêtre `tail -20` utilisée, pas un `grep -c` complet).
- Chevauchement 1000201/100054 avec le Scénario A (cf. section dédiée ci-dessus) — tests A et B4-bis à ne pas superposer.
- Hôte FTP (10.0.10.30, metasploitable2) absent des hôtes actifs sur cette campagne — n'affecte pas la validation A1/A3/A4, qui ne dépendent pas de cet hôte.

## Références
- Suricata User Guide — Thresholding — https://docs.suricata.io/en/latest/rules/thresholding.html
- OpenBSD PF User's Guide — Stateful Filtering — https://www.openbsd.org/faq/pf/filter.html
- MITRE ATT&CK — T1046 (Network Service Discovery), T1595.001 (Active Scanning)
