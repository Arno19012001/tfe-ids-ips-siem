# Scénario D — Résultats de validation (Issues #25, #26, Sprint 6)

## Contexte

- **Cible** : `metasploitable2` (10.0.10.30, zone DMZ), backdoor vsftpd 2.3.4 (CVE-2011-2523)
- **Script** : `scenarios/D_metasploit/attack.rc`
- **Payload retenu** : `cmd/unix/bind_netcat` sur le port 6201 — le backdoor natif est un *bind shell*, pas un *reverse shell* (le trafic sortant DMZ→WAN étant filtré par pfSense, un payload reverse échoue systématiquement). Deux règles pfSense supplémentaires ajoutées (WAN→DMZ : 6200/tcp backdoor natif, 6201/tcp bind shell du payload).
- **Résultat** : session shell root confirmée (`uid=0(root) gid=0(root)`)
- **Campagnes analysées** : deux cycles complets, 05/08/2026, 17:07 et 18:07 UTC

## Règles Suricata

| SID | Déclencheur | Rôle |
|---|---|---|
| 1000401 | `USER` + `:)` dans les 30 octets suivants, port 21 | Signal principal — tentative de déclenchement du backdoor |
| 1000402 | Réponse serveur `500 OOPS: priv_sock_get_result` | Signal secondaire — confirme le crash consécutif au trigger |

Note technique : `ftp.command`/`ftp.command_data` indisponibles en Suricata 7.0.10 (introduits en 8.0) — les règles utilisent un `content` générique sur le flux TCP reconstruit.

## Comportement observé — particularités du backdoor

- Le backdoor déclenche un **crash du processus vsftpd privilégié** au moment du traitement de la commande `USER` contenant le smiley. C'est ce crash, pas un comportement voulu, qui empêche toute journalisation applicative de l'événement.
- Des déclenchements répétés sans fermeture propre de session peuvent laisser le port 6200 dans un état orphelin (`Backdoor already in-use`) ; un redémarrage du service `vsftpd` restaure un état propre.

## Corrélation kill chain — Wazuh (règles custom 100052/100053, ajoutées le 06/08/2026)

- **100052** (niveau 10) : isole SID Suricata 1000401 (`if_sid=86601`, filtre `signature_id`)
- **100053** (niveau 15, `frequency=2`, `timeframe=300`) : corrèle 100052 avec l'alerte 1000402, via `same_field flow_id` — description *"Kill chain: accès initial confirmé — backdoor VSFTPD déclenchée et crash de séparation de privilèges observé"*

**Point technique notable** : `same_source_ip` échouerait ici de manière symétrique au problème déjà rencontré sur le Scénario B — le champ `data.srcip` s'inverse entre les deux alertes (192.168.1.50 pour 1000401, `to_server` ; 10.0.10.30 pour 1000402, `to_client`, réponse du serveur suite au crash). `same_field flow_id` contourne le problème, confirmé identique dans les deux échantillons.

## Détection Wazuh applicative — non retenue, cause documentée

Piste initialement envisagée : forwarding syslog de `vsftpd.log` vers Wazuh. **Écartée après test empirique** : le crash du processus privilégié survient *avant* que vsftpd n'atteigne le code d'écriture de la ligne de log applicative (confirmé par un marqueur dédié `testclock:)`, absent de `/var/log/vsftpd.log` malgré `xferlog_enable=YES`). Structurellement incapable de capturer cet événement, indépendamment de la configuration.

## Faux positif croisé inter-scénarios (déjà documenté, Issue #25)

La règle **1000104** (Scénario A, Service/Version Detection) se déclenche à tort sur la commande `PASS` envoyée lors du trigger du backdoor D — même famille de chevauchement que celui découvert le 07/08/2026 entre le Scénario A (OS detection) et la règle 1000201/100054 du Scénario B. Sans conséquence sur la corrélation 100052/100053 (`if_matched_sid` filtre déjà sur `signature_id=1000401` spécifiquement), mais confirme un motif récurrent : **les scénarios ne doivent pas être testés en parallèle** sans vérifier les chevauchements de signatures comportementales.

## Synthèse des critères d'acceptation

| Critère | Statut | Preuve / raison |
|---|---|---|
| D1 (exploitation vsftpd détectée, Suricata) | ✅ | SID 1000401/1000402, 2 cycles complets confirmés dans `eve.json` |
| D2 (création user root, HIDS) | ❌ **non satisfait** | Aucun agent Wazuh déployé sur `metasploitable2` (noyau 2.6.24 / glibc obsolète, jugé hors budget) — et le script `attack.rc` actuel obtient un accès root direct via le backdoor, sans étape explicite de création d'utilisateur à détecter |
| D3 (service systemd suspect, HIDS FIM) | ❌ **non satisfait** | Même cause que D2 — pas d'agent HIDS sur la cible pour un FIM |
| D4 (kill chain 3 étapes, alerte composite) | ⚠️ **2 étapes, pas 3** | Règle 100053 (niveau 15) corrèle 2 alertes (1000401→1000402) — pas 3 étapes MITRE distinctes comme formulé dans le critère |

## Limites connues (assumées, à reprendre dans le rapport)

- **D2/D3 non satisfaits** : limitation architecturale documentée, pas un oubli — `metasploitable2` (noyau 2.6.24, glibc obsolète) est structurellement incompatible avec un agent Wazuh moderne ; le déploiement n'a pas été tenté (hors budget de l'issue). Une piste alternative (forwarding syslog) a été explorée et écartée pour raison technique documentée ci-dessus.
- **D4 partiel** : la corrélation actuelle relie 2 alertes Suricata (même agent), pas 3 étapes MITRE distinctes au sens strict du critère du document d'analyse — argument à nuancer dans le rapport (kill chain réelle du CVE : trigger → crash → accès root, dont seules les 2 premières étapes réseau sont observables sans HIDS).
- Faux positif croisé avec SID 1000104 (Scénario A) — non bloquant mais documenté, cf. section dédiée.

## Références
- CVE-2011-2523
- MITRE ATT&CK — T1190 (Exploit Public-Facing Application, Initial Access)
