# Scénario B — Résultats de validation (Issues #17, #22, Sprint 6)

## Contexte

- **Commande** : `hydra -l eurostar -P wordlist_scenario_B.txt -t 4 -f ssh://10.0.10.20:22 -V`
- **Source attaquante** : kali-attacker (192.168.1.50)
- **Cible** : ssh-eurostar (10.0.10.20)

## Détection NIDS — Suricata (SID 1000201, rev:2)

Seuil calibré empiriquement (Issue #16) : `threshold: type both, track by_src, count 4, seconds 15`.

Deux campagnes complètes ont confirmé la stabilité de la règle :

| Campagne | Rafales détectées | Taux de FN |
|---|---|---|
| 15/07/2026, 09:29:12 → 09:30:53 UTC | 6/6 | 0% |
| 07/08/2026, 14:54:35 → 14:56:01 UTC | 6/6 | 0% |

Aucun faux positif observé sur l'ensemble des données `eve.json` disponibles : seule 192.168.1.50 déclenche SID 1000201.

## Détection HIDS — Wazuh (agent `ssh-eurostar`)

Règle **40112** (`sshd_rules.xml`, native, non custom) : `Multiple authentication failures followed by a success.` Se déclenche automatiquement sur l'événement `Accepted password for eurostar from <ip> port <port> ssh2` — réalise la corrélation échec→succès attendue pour B2 **sans règle personnalisée**.

Confirmée sur les deux campagnes (09:30:51 UTC le 15/07 ; 14:56:14.282 UTC le 07/08).

## Corrélation kill chain A→B — Wazuh (règle custom 100051, Issue #22)

Règle niveau 15, `if_sid=40112`, `if_matched_sid=100050` (SID Suricata 1000101 isolé), `same_source_ip`, `<global_frequency/>` (obligatoire pour corrélation inter-agents — cf. Issue #22). Valide B3 en confirmant que la compromission SSH est précédée d'une reconnaissance réseau dans une fenêtre de 10 minutes.

## B4 — Blocage IP automatique (Wazuh active-response, validé le 07/08/2026)

**Architecture retenue** : active-response `firewall-drop` déclenché par la règle **40112** (pas par un seuil Suricata brut), ciblant l'agent `suricata-sensor` (pas `ssh-eurostar`, qui ne dispose pas d'iptables). Timeout 120s.

**Justification du déclencheur** : bloquer sur la règle 40112 — qui ne se déclenche qu'*après* le succès de connexion — préserve la corrélation B2/B3 (rule 100051) en laissant la campagne Hydra se dérouler jusqu'à son terme. Un blocage prématuré basé sur le volume (SID 1000201) aurait coupé la campagne avant que le mot de passe ne soit trouvé, empêchant toute validation de B2/B3 sur la même campagne.

**Validation empirique** (campagne du 07/08/2026, 14:54–14:56 UTC) :

| Timestamp UTC | Événement |
|---|---|
| 14:56:13.535 | Succès SSH (`sshd`, `Accepted password for eurostar from 192.168.1.50`) |
| 14:56:14.282 | Règle 40112 déclenchée (niveau 12) |
| 14:56:14 | `firewall-drop` exécuté (`active-responses.log` : `add` + `check_keys`), cible 192.168.1.50 |

Délai détection→blocage : **0,7 seconde**. Critère B4 atteint.

## Variante testée : blocage anticipé (B4-bis, non retenue par défaut)

Pour évaluer une alternative plus réaliste (bloquer *avant* que l'attaquant ne réussisse), une règle Wazuh dédiée (**100054**, isolant le SID Suricata 1000201 via la règle générique 86601) a été câblée à un second active-response `firewall-drop`, testée en conditions réelles puis désactivée.

**Résultat du test** (campagne du 07/08/2026, 15:38:00–15:38:01 UTC) :
- Règle 100054 déclenchée 2 fois (confirmé dashboard, `rule.firedtimes: 2`)
- `firewall-drop` exécuté à 15:38:01, ~1s après la 1ʳᵉ rafale Suricata — bien avant la position 120/150 de la wordlist
- `iptables -L -n -v` : règle DROP avec 76 paquets / 7744 octets déjà rejetés — preuve que les tentatives de connexion post-blocage ont réellement été bloquées, pas seulement loguées

**Conséquence attendue et observée** : ce déclencheur casse volontairement B2/B3 sur la campagne concernée (Hydra ne peut plus atteindre le succès une fois bloqué). B2/B3/B4 restent validés séparément via 40112 (cf. section précédente, même session).

**Décision** : capacité démontrée mais **désactivée par défaut** (`<disabled>yes</disabled>` dans `ossec.conf`), même traitement que A4. 40112 reste le déclencheur retenu pour ne pas casser B2/B3 sur les campagnes de démonstration. Réactivable en retirant la ligne `<disabled>`.

## Synthèse des critères d'acceptation

| Critère | Preuve |
|---|---|
| B1 (détection volumétrique) | SID 1000201, 6/6 rafales sur 2 campagnes |
| B2 (corrélation échec→succès) | Règle native 40112 |
| B3 (alerte niveau 15) | Règle 100051 (kill chain A→B) |
| B4 (blocage IP automatique) | Active-response sur 40112, délai 0,7s, confirmé `iptables` |

## Limites et remarques méthodologiques

- La règle 40112 est native au ruleset Wazuh par défaut — aucune règle de corrélation SSH n'a dû être écrite pour ce volet (contrairement à la corrélation A→B, qui elle est custom).
- Test B4-bis volontairement limité à une seule campagne de démonstration ; pas de mesure de FP sur cette variante (non retenue en production).

## Références
- Wazuh Ruleset Documentation — `sshd_rules.xml` (rule 40112)
- Suricata User Guide — Thresholding — https://docs.suricata.io/en/latest/rules/thresholding.html
- MITRE ATT&CK — T1110.001 (Password Guessing), T1078 (Valid Accounts)
