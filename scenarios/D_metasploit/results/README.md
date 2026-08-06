# Scénario D — Exploitation vsftpd 2.3.4 (Metasploit)

## Objectif

Exploiter la backdoor CVE-2011-2523 (vsftpd 2.3.4) contre `metasploitable2` (10.0.10.30, zone DMZ) et valider la détection réseau via Suricata.

## Résumé du déroulé

1. Vérification de la cible : bannière `vsFTPd 2.3.4` confirmée (`nmap -sV -p21`)
2. Script Metasploit (`attack.rc`) : plusieurs itérations nécessaires suite à des incompatibilités de payload avec Metasploit 6.4.116-dev (voir `msf_console.log` pour le détail complet des tentatives)
3. Payload final retenu : `cmd/unix/bind_netcat` sur le port 6201 (le backdoor natif est un *bind shell*, pas un *reverse shell* — le trafic sortant DMZ→WAN étant filtré par pfSense, un payload de type reverse échoue systématiquement)
4. Deux règles pfSense supplémentaires ajoutées (WAN→DMZ) : `metasploitable:6200/tcp` (backdoor natif) et `metasploitable:6201/tcp` (bind shell du payload)
5. Session shell root confirmée (`uid=0(root) gid=0(root)`)
6. Détection réseau validée via deux règles Suricata dédiées (SID 1000401, 1000402)

## Fichiers de ce dossier

- `msf_console.log` — journal complet de la console Metasploit, spoolé automatiquement (`spool` dans `attack.rc`). Inclut les tentatives échouées, conservées telles quelles pour la traçabilité du dépannage.
- `eve_scenario_D_extract.json` — extrait brut de `/var/log/suricata/eve.json` sur `suricata-sensor`, filtré sur les `signature_id` 1000401 et 1000402. Deux cycles de test complets (17:07 et 18:07 UTC, 05/08/2026).

## Règles Suricata

| SID | Déclencheur | Rôle |
|---|---|---|
| 1000401 | `USER` + `:)` dans les 30 octets suivants, port 21 | Signal principal — détecte la tentative de déclenchement du backdoor |
| 1000402 | Réponse serveur `500 OOPS: priv_sock_get_result` | Signal secondaire — corrélation, confirme le crash consécutif au trigger |

Note technique : `ftp.command`/`ftp.command_data` (buffers applicatifs FTP dédiés) sont indisponibles en Suricata 7.0.10 — introduits en 8.0 uniquement. Les règles utilisent un `content` générique sur le flux TCP reconstruit.

## Comportement observé — particularités du backdoor

- Le backdoor déclenche un **crash du processus vsftpd privilégié** (`500 OOPS: priv_sock_get_result`) au moment du traitement de la commande `USER` contenant le smiley. C'est ce crash, pas un comportement voulu, qui empêche toute journalisation applicative de l'événement (voir section Wazuh ci-dessous).
- Des déclenchements répétés et rapprochés sans fermeture propre de session (`exit`) peuvent laisser le port 6200 dans un état orphelin (`Backdoor already in-use` côté Metasploit). Un redémarrage du service `vsftpd` (ou de la VM) sur la cible restaure un état propre.

## Détection Wazuh — non retenue pour cet événement, cause documentée

Piste initialement envisagée : forwarding syslog des logs `vsftpd.log` vers Wazuh. **Écartée après test empirique** : le crash du processus privilégié survient *avant* que vsftpd n'atteigne le code d'écriture de la ligne de log applicative — confirmé par un test contrôlé avec un marqueur dédié (`testclock:)`), dont aucune trace n'apparaît dans `/var/log/vsftpd.log` malgré `xferlog_enable=YES`. Le forwarding syslog est donc structurellement incapable de capturer cet événement précis, indépendamment de la configuration retenue.

Aucun agent Wazuh HIDS natif n'est déployé sur `metasploitable2` (incompatibilité probable avec le noyau 2.6.24 / glibc obsolète — non testée, jugée hors budget de l'issue).

La détection retenue repose donc uniquement sur Suricata, avec ingestion vers Wazuh via le pipeline `eve.json` (agent Wazuh sur `suricata-sensor`). Ce mécanisme est correctement configuré côté `ossec.conf`, mais son bon fonctionnement n'a pas pu être vérifié en conditions réelles lors de cette session, en raison d'une panne d'infrastructure préexistante et indépendante du Scénario D (voir Issue #43 du dépôt).

## Faux positifs observés

La règle `SID 1000104` (`SCENARIO_A Nmap Service/Version Detection Probe`) se déclenche à tort sur la commande `PASS` envoyée lors du trigger du backdoor — faux positif croisé entre scénarios, déjà documenté depuis le Scénario D initial (Issue #25).

## Références

- CVE-2011-2523
- MITRE ATT&CK T1190 (Exploit Public-Facing Application, Initial Access)
- Issues GitHub : #25 (script d'attaque), #26 (exécution et détection), #43 (panne d'infrastructure Wazuh)
