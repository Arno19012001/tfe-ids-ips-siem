# Scénario D — Configuration syslog sur metasploitable2 (critère D2)

Étapes de configuration **manuelles** à effectuer sur `metasploitable2` (10.0.10.30)
pour activer la détection D2 (création d'utilisateur root, T1136.001). Ces étapes ne
sont pas versionnées dans une image (metasploitable2 est une VM QEMU préexistante) :
à rejouer après toute réinitialisation de la VM.

## Contexte

metasploitable2 (Ubuntu 8.04, noyau 2.6.24) ne peut pas héberger d'agent Wazuh
moderne (glibc obsolète). La détection D2 repose donc sur un forward syslog réseau
classique vers le manager Wazuh, décodé par une règle custom (100055).

## 1. Firewall pfSense (DMZ -> MGMT)

Règle Pass : source 10.0.10.30, destination 10.0.30.10, protocole UDP port 514.
(Positionnée avant la règle de blocage catch-all DMZ->MGMT.)

## 2. Forward syslog sur metasploitable2 (root)

    printf '\052.\052    @10.0.30.10\n' >> /etc/syslog.conf
    /etc/init.d/sysklogd restart

Vérification : `tail -3 /etc/syslog.conf` doit montrer `*.*    @10.0.30.10`.

Note : `\052` est le code octal de `*` (utile si le clavier VNC ne permet pas de
taper l'astérisque directement).

## 3. Côté Wazuh (versionné dans ce dépôt)

- `wazuh/ossec.conf` : listener `<remote><connection>syslog</connection>` UDP/514,
  `allowed-ips 10.0.10.30/32`
- `wazuh/decoders/custom_decoders.xml` : décodeur `metasploitable-useradd`
- `wazuh/rules/custom_rules.xml` : règle 100055 (niveau 10, T1136.001)

Après tout déploiement de ces fichiers : `systemctl restart wazuh-manager`
(le pipeline temps réel charge le ruleset en mémoire au démarrage uniquement --
`wazuh-logtest` relit les fichiers à chaque appel, mais pas le service).

## 4. Particularité du format syslog reçu

Ce `sysklogd` ancien omet timestamp ET hostname RFC 3164 lors du forward réseau
(présents en local dans /var/log/auth.log, absents du paquet UDP -- vérifié par
capture tcpdump). Le décodeur custom matche donc directement sur `useradd`, sans
dépendre du hostname. Le `<prematch>` utilise la syntaxe OSMatch (sregex) qui ne
supporte ni `\d` ni les crochets échappés (piège identifié via la documentation
Wazuh) -- l'extraction fine des champs est déléguée au `<regex>` enfant OSRegex.

## 5. Console série GNS3 (optionnel)

Pour basculer la console GNS3 de VNC à telnet, un getty sur ttyS0 est requis
(Ubuntu 8.04 ne l'active pas par défaut) :

    echo 'T0:23:respawn:/sbin/getty -L ttyS0 9600 vt100' >> /etc/inittab
    telinit q

Non nécessaire au fonctionnement de D2 -- confort de saisie uniquement.

## 6. Validation

Un lancement de `scenarios/D_metasploit/attack.rc` (à froid : `msfconsole -r attack.rc`)
déclenche en une seule passe :
- D1 : SID Suricata 1000401 (trigger backdoor) + 1000402 (crash séparation privilèges)
- D2 : règle Wazuh 100055 (useradd détecté via syslog)
- D4 : règle Wazuh 100053 (corrélation kill chain 1000401->1000402, niveau 15)

D3 (service systemd suspect) est structurellement inapplicable : Ubuntu 8.04 est
antérieur à systemd.
