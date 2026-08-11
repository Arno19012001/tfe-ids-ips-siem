# Résultats — Itération 3 : reconstruction complète de la kill chain (Issue #27)

## Run de validation (11/08/2026, 09:20–09:28 UTC)

- IP attaquante : `192.168.1.50`
- Couverture : **4/4 phases** avec au moins une preuve
- Aboutissement confirmé par le SIEM : 2/4 (Phases 2 et 4) ; indéterminé : 2/4 (Phases 1 et 3 — non instrumenté pour statuer, ne signifie pas un échec)
- Chevauchement temporel détecté entre les Phases 1 et 2 (le Scénario B a démarré avant la fin du Scénario A — enchaînement non strictement séquentiel, cohérent avec le script d'attaque)
- Latence de rédaction LLM (Llama 3.1 8B, CPU-only) : 425,7 s (~7 min)

## Détail par phase

| Phase | Scénario | Cible | Alertes | Tactique / Technique | Statut |
|---|---|---|---|---|---|
| 1 — Reconnaissance | A (Nmap) | DMZ_NET (10.0.10.0/24) | 42 | TA0007 Discovery / T1046 | Indéterminé — aucune règle Wazuh ne statue sur l'aboutissement d'une reconnaissance |
| 2 — Initial Access | B (Hydra SSH) | ssh-eurostar (10.0.10.20:22) | 22 | TA0006 Credential Access / T1110.001 | **Confirmé** — règle Wazuh 100051 (niv. 15) |
| 3 — Execution | C (sqlmap) | web-eurostar (10.0.10.10:80/443) | 8 | TA0001 Initial Access / T1190 | Indéterminé — aucune règle de corrélation Wazuh n'existe pour le Scénario C |
| 4 — Command and Control | D (Metasploit vsftpd) | metasploitable2 (10.0.10.30:21) | 4 | TA0001 Initial Access / T1190 | **Confirmé** — règle Wazuh 100053 (niv. 15, 2x) |

Les Phases 1 et 3 sont indéterminées faute de règle de corrélation Wazuh
dédiée (aucune n'a été implémentée pour statuer sur l'aboutissement d'une
reconnaissance, et aucune n'existe pour le Scénario C) — **Suricata détecte
bien l'activité dans les deux cas** (42 alertes pour A, 8 pour C), seul le
SIEM ne peut pas se prononcer sur le succès.

Les Phases 3 et 4 partagent le même tag `TA0001_InitialAccess/T1190` : ce
n'est pas un artefact du mapping, les règles Suricata des deux scénarios
sont littéralement taguées ainsi (`scenario_C_sqlmap.rules`,
`scenario_D_metasploit.rules`) — les deux exploitent une application exposée
publiquement, malgré des rôles différents dans la séquence narrative A→B→C→D.

## Vision NIDS uniquement — alertes hors périmètre

Sur les 329 alertes de la fenêtre, seules 76 correspondent aux 11 SID
Suricata des 4 scénarios connus ; les 253 restantes (76,9 %) ne sont pas
comptées dans ce rapport. Une part importante correspond à la face HIDS des
mêmes attaques (échecs d'authentification SSH natifs Wazuh, PAM, etc.)
plutôt qu'à une activité étrangère — le rapport le signale explicitement
plutôt que de laisser croire à un périmètre plus large que celui réellement
couvert.

## Résumé narratif (généré par le LLM)

> L'attaque a commencé par une reconnaissance du réseau DMZ, suivie d'une
> tentative de compromission SSH par force brute qui a abouti. Ensuite, une
> tentative d'injection SQL a été détectée, mais le SIEM n'a pas pu confirmer
> son issue. Finalement, une backdoor VSFTPD a été déclenchée et un crash de
> séparation de privilèges observé, confirmant l'aboutissement réussi de la
> phase finale.

## Conclusion

Le critère de validation de l'Issue #27 est atteint : couverture complète
(4/4 phases avec preuve), reconstruction correcte de l'enchaînement malgré
un chevauchement temporel réel entre les Scénarios A et B, latence de
rédaction (~7 min) très inférieure aux temps de plusieurs dizaines de
minutes observés avec l'approche agentic tool-calling sur ce même matériel
CPU-only (voir `agentic_ai/README.md`).

## Artefacts

- `killchain_report_20260811_093748.json` — rapport JSON complet du run
