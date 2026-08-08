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

## D2 — Création d'utilisateur root détectée (piste syslog, validée le 08/08/2026)

**Objectif** : détecter la création d'un compte de persistance (T1136.001) sur `metasploitable2` après compromission, sans agent Wazuh HIDS (incompatible : noyau 2.6.24 / glibc obsolète).

**Architecture retenue** : forwarding syslog réseau classique (`sysklogd`, `/etc/syslog.conf : *.* @10.0.30.10`) vers un listener syslog dédié sur le manager Wazuh (`<remote><connection>syslog</connection><port>514</port><protocol>udp</protocol>`, `allowed-ips 10.0.10.30/32`). Règle pfSense DMZ→MGMT UDP/514 ajoutée.

**Difficulté résolue** : le forward réseau de ce `sysklogd` ancien omet le timestamp ET le hostname RFC 3164 (présents dans `/var/log/auth.log` local, absents du paquet UDP — confirmé par capture `tcpdump`). Les décodeurs natifs Wazuh (dont la règle 5902) échouent donc sur ce format tronqué (`No decoder matched`). Un décodeur custom dédié a été écrit (`wazuh/decoders/custom_decoders.xml`, décodeur `metasploitable-useradd`) : le `<prematch>` utilise la syntaxe OSMatch (sregex, qui ne supporte ni `\d` ni les crochets échappés — piège identifié via la documentation Wazuh), l'extraction fine des champs est déléguée au `<regex>` enfant OSRegex.

**Validation empirique** (08/08/2026) :
- `wazuh-logtest` : décodeur `metasploitable-useradd` matché, extraction `dstuser`/`uid`/`gid` correcte, règle 100055 (niveau 10, T1136.001) déclenchée
- Conditions réelles : `useradd -m -s /bin/bash finaltest2` sur metasploitable2 → alerte 100055 dans le dashboard, `data.dstuser: finaltest2`, `data.uid/gid: 1009`, `rule.mitre.id: T1136.001`, `rule.mitre.tactic: Persistence`

**Note d'implémentation** : le redémarrage de `wazuh-manager` est nécessaire après modification du décodeur — `wazuh-logtest` relit les fichiers à chaque appel, mais le pipeline temps réel charge le ruleset en mémoire au démarrage uniquement.

**Rattachement de l'alerte** : les événements syslog externes sont rattachés à l'agent manager (`agent.id 000`, `agent.name wazuh-server`), pas à un agent dédié à metasploitable2 — comportement attendu du listener syslog, pas un défaut.

## Détection Wazuh applicative FTP — non retenue, cause documentée

Piste initialement envisagée : forwarding syslog de `vsftpd.log`. **Écartée après test empirique** : le crash du processus privilégié survient *avant* que vsftpd n'atteigne le code d'écriture de la ligne de log applicative (marqueur dédié `testclock:)` absent de `/var/log/vsftpd.log` malgré `xferlog_enable=YES`). Structurellement incapable de capturer l'événement de trigger FTP lui-même. (Distinct de D2 ci-dessus, qui détecte la création d'utilisateur *post-compromission*, pas le trigger FTP.)

## Faux positif croisé inter-scénarios (déjà documenté, Issue #25)

La règle **1000104** (Scénario A, Service/Version Detection) se déclenche à tort sur la commande `PASS` envoyée lors du trigger du backdoor D — même famille de chevauchement que celui découvert le 07/08/2026 entre le Scénario A (OS detection) et la règle 1000201/100054 du Scénario B. Sans conséquence sur la corrélation 100052/100053 (`if_matched_sid` filtre déjà sur `signature_id=1000401` spécifiquement).

## Synthèse des critères d'acceptation

| Critère | Statut | Preuve / raison |
|---|---|---|
| D1 (exploitation vsftpd détectée, Suricata) | ✅ | SID 1000401/1000402, 2 cycles complets confirmés dans `eve.json` |
| D2 (création user root, HIDS) | ✅ | Règle custom 100055 via forward syslog + décodeur dédié — validé en conditions réelles (08/08/2026) |
| D3 (service systemd suspect, HIDS FIM) | ❌ **structurellement inapplicable** | metasploitable2 = Ubuntu 8.04 (2008), **antérieur à systemd** (adopté ~2015). Aucun service systemd n'existe sur la cible, quel que soit l'agent déployé — décalage entre l'énoncé générique du critère et la cible historique choisie pour ce scénario |
| D4 (kill chain 3 étapes, alerte composite) | ⚠️ **2 étapes corrélées** | Règle 100053 (niveau 15) corrèle 2 alertes Suricata (1000401→1000402), pas 3 étapes MITRE distinctes au sens strict |

## Limites connues (assumées, à reprendre dans le rapport)

- **D3 inapplicable par nature** : Ubuntu 8.04 précède systemd — ce n'est pas un manque d'effort mais une incompatibilité entre le critère (générique) et la cible historique. À reformuler ou marquer explicitement N/A dans le rapport.
- **D4 partiel** : la corrélation relie 2 alertes Suricata (même agent), pas 3 étapes MITRE distinctes. La kill chain réelle du CVE (trigger → crash → accès root) n'a que ses 2 premières étapes réseau observables sans HIDS sur la cible.
- **Décodeur `metasploitable-useradd` volontairement large** : `<prematch>useradd</prematch>` matche tout message syslog contenant "useradd" depuis n'importe quelle source. Acceptable dans ce lab (metasploitable2 est la seule source syslog externe), mais à restreindre en production.
- Faux positif croisé avec SID 1000104 (Scénario A) — non bloquant, documenté.

## Références
- CVE-2011-2523
- MITRE ATT&CK — T1190 (Exploit Public-Facing Application), T1136.001 (Create Account: Local Account)
- Wazuh Documentation — Regular Expression Syntax (OSMatch/OSRegex/PCRE2), Sibling Decoders
