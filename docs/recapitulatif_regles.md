# Récapitulatif des règles de détection — TFE Eurostar (IDS/IPS & SIEM)

Ce document synthétise l'ensemble des règles de détection, de corrélation et des décodeurs
personnalisés du laboratoire, réparties sur les deux capteurs :

- **Suricata** (NIDS, capteur réseau `suricata-sensor`) : analyse le trafic réseau en mode
  inline (pont L2 transparent). Fichiers `.rules`, identifiants numériques appelés **SID**.
- **Wazuh** (SIEM/HIDS) : analyse les journaux (logs) des hôtes et ingère les alertes
  Suricata. Règles XML, identifiants appelés **rule id**.

Chaque attaque suit une progression logique (*kill chain*) cartographiée sur le référentiel
**MITRE ATT&CK** (codes `Txxxx`). Le principe directeur est la **complémentarité NIDS + HIDS** :
le réseau détecte la tentative, l'hôte confirme le succès.

---

## 1. Règles Suricata (NIDS) — détection réseau

### Scénario A — Reconnaissance réseau (Nmap) · plage SID 1000100–1000199

| SID | Nom | Rôle en une phrase | MITRE |
|-----|-----|--------------------|-------|
| **1000101** | Nmap SYN Scan Detected | Détecte un balayage de ports furtif (`nmap -sS`) en comptant les paquets SYN : se déclenche au-delà de 15 SYN en 10 s depuis une même source. | T1046 |
| **1000104** | Nmap Service/Version Detection Probe | Détecte les sondes d'identification de service et de version (`nmap -sV`), une alerte par couple source/destination, sur les trois hôtes de la DMZ. | T1046 |

> *Note : les SID 1000102 et 1000103 (empreinte du système d'exploitation, `nmap -O`) ont été retirées — les paquets à drapeaux TCP anormaux qu'elles ciblaient sont filtrés par le pare-feu pfSense (à états) avant même d'atteindre le capteur. Limitation architecturale documentée, non un défaut de conception (Issue #37).*

### Scénario B — Force brute SSH (Hydra) · plage SID 1000200–1000299

| SID | Nom | Rôle en une phrase | MITRE |
|-----|-----|--------------------|-------|
| **1000201** | SSH Brute Force – High Connection Rate | SSH étant chiffré, la règle ne peut pas voir les mots de passe : elle détecte le *volume anormal* de connexions (proxy indirect d'une attaque par force brute), seuil de 4 connexions en 15 s. | T1110.001 |

> *Note : la confirmation du succès (échec → succès d'authentification) relève du HIDS Wazuh, pas de Suricata — voir règle native 40112 ci-dessous.*

### Scénario C — Injection SQL (sqlmap) · plage SID 1000300–1000399

| SID | Nom | Rôle en une phrase | MITRE |
|-----|-----|--------------------|-------|
| **1000301** | sqlmap User-Agent Detected | Repère l'outil d'attaque par sa signature réseau la plus simple : la présence de « sqlmap » dans l'en-tête User-Agent HTTP. | T1190 |
| **1000302** | UNION SELECT Pattern | Détecte les injections de type UNION (extraction de données via fusion de résultats) en repérant les mots-clés `UNION` puis `SELECT` dans l'URL. | T1190 |
| **1000303** | Quote/Boolean Injection Pattern | Détecte les injections booléennes et à guillemet (`OR 1=1`, apostrophe d'échappement) qui testent la structure de la base par vrai/faux. | T1190 |
| **1000304** | Time-Based Blind Pattern | Détecte les injections « aveugles » temporisées, qui déduisent l'information via des délais de réponse (`SLEEP`, `BENCHMARK`, `WAITFOR DELAY`). | T1190 |
| **1000305** | High Request Volume on Injectable Endpoint | Détecte le comportement de campagne (par opposition à une requête isolée) : plus de 20 requêtes sur le paramètre injectable en 10 s. | T1213 |
| **1000306** | MySQL Error-Based Function Pattern | Détecte les injections basées sur les erreurs, qui font fuiter des données via des fonctions MySQL détournées (`EXTRACTVALUE`, `UPDATEXML`, etc.). | T1190 |

> *Note : le trafic HTTP étant en clair (contrairement à SSH), Suricata a une visibilité complète sur les URL et charges utiles, d'où une détection par signature bien plus fine que pour le scénario B.*

### Scénario D — Exploitation backdoor vsftpd 2.3.4 (Metasploit) · plage SID 1000400–1000499

| SID | Nom | Rôle en une phrase | MITRE |
|-----|-----|--------------------|-------|
| **1000401** | VSFTPD Backdoor Trigger – Smiley in Username | Détecte le déclenchement de la porte dérobée CVE-2011-2523 : un nom d'utilisateur FTP contenant le smiley `:)` qui active le shell root caché. | T1190 |
| **1000402** | VSFTPD Privilege Separation Crash | Détecte l'effet de bord caractéristique du déclenchement : le message d'erreur `500 OOPS: priv_sock_get_result` renvoyé par le serveur lors du crash — signal de corroboration fiable. | T1190 |

---

## 2. Règles Wazuh (SIEM/HIDS) — corrélation et détection sur hôte

Les événements Suricata arrivent tous dans Wazuh via une **règle générique 86601** (décodeur JSON
par défaut). Pour cibler un SID précis — afin de le corréler ou d'y attacher une réponse
automatique — il faut d'abord l'**isoler** dans une règle personnalisée. C'est le rôle des règles
« isolantes » ci-dessous (100050, 100052, 100054).

### Règles d'isolation (préalable technique) · plage 100050–100099

| Rule id | Niveau | Rôle en une phrase |
|---------|--------|--------------------|
| **100050** | 7 | Isole le SID Suricata 1000101 (scan SYN, scénario A) pour permettre sa corrélation et le blocage automatique A4. |
| **100052** | 10 | Isole le SID Suricata 1000401 (déclenchement backdoor, scénario D) pour permettre la corrélation kill chain. |
| **100054** | 7 | Isole le SID Suricata 1000201 (rafale SSH, scénario B) pour un blocage anticipé — capacité démontrée mais désactivée par défaut. |

### Règles de corrélation (kill chain) — le cœur de la valeur SIEM

| Rule id | Niveau | Rôle en une phrase | MITRE |
|---------|--------|--------------------|-------|
| **40112** *(native Wazuh)* | 12 | Règle native du ruleset SSH : détecte plusieurs échecs d'authentification suivis d'un succès — c'est elle qui confirme la *réussite* de la force brute du scénario B (ce que Suricata ne peut pas voir). | T1110, T1078 |
| **100051** | 15 | **Kill chain A→B** : corrèle une reconnaissance Nmap (100050) suivie d'une compromission SSH réussie (40112) depuis la même IP source, dans une fenêtre de 10 min. | T1046, T1110.001, T1078 |
| **100053** | 15 | **Kill chain D** : corrèle le déclenchement du backdoor (1000401) et son crash consécutif (1000402) via un identifiant de flux commun (`flow_id`), confirmant un accès initial abouti. | T1190 |
| **100055** | 10 | **Persistance (scénario D)** : détecte la création d'un compte utilisateur sur la cible compromise (metasploitable2), signal de persistance post-exploitation. | T1136.001 |

> **Pourquoi `flow_id` et non l'adresse IP source pour la règle 100053 ?** Entre les deux alertes du
> scénario D, l'adresse source s'inverse (la 1ʳᵉ va client→serveur, la 2ᵈᵉ est la réponse
> serveur→client). Une corrélation sur l'IP source échouerait ; l'identifiant de flux, lui, reste
> constant — d'où son choix.
>
> **Pourquoi la balise `global_frequency` sur la règle 100051 ?** Les deux événements corrélés
> viennent de deux agents différents (le capteur Suricata et l'hôte SSH). Par défaut, Wazuh ne
> compte les événements qu'au sein d'un même agent ; sans cette balise, la corrélation inter-agents
> ne se déclencherait jamais.

---

## 3. Décodeurs personnalisés Wazuh

Un décodeur extrait les champs utiles d'un journal brut *avant* que les règles ne s'appliquent.
Deux décodeurs custom ont été nécessaires dans ce laboratoire.

| Décodeur | Rôle en une phrase |
|----------|--------------------|
| **json** *(frère du décodeur natif)* | Peuple le champ `srcip` pour les alertes Suricata, que le décodeur JSON générique ne remplit pas — indispensable pour la corrélation par IP source de la règle 100051. |
| **metasploitable-useradd** | Décode les journaux `useradd` transmis par metasploitable2 : cet hôte trop ancien (Ubuntu 8.04) ne peut pas héberger d'agent Wazuh, et son syslog envoie un format tronqué (sans horodatage ni nom d'hôte) que les décodeurs natifs rejettent. Alimente la règle 100055. |

> *Détail technique : le champ `<prematch>` d'un décodeur utilise la syntaxe **OSMatch** (dite sregex), plus restreinte que les expressions régulières classiques — elle ne supporte pas `\d` ni les crochets échappés. L'extraction fine est déléguée au `<regex>` enfant qui, lui, utilise la syntaxe **OSRegex**.*

---

## 4. Synthèse par critère d'acceptation

| Scénario | Détection réseau (NIDS) | Confirmation hôte (HIDS) | Corrélation kill chain | Réponse automatique |
|----------|--------------------------|--------------------------|------------------------|---------------------|
| **A — Nmap** | 1000101, 1000104 | dashboard (86601) | 100050 → 100051 | 100050 → firewall-drop *(désactivé par défaut)* |
| **B — Hydra** | 1000201 | 40112 (native) | 100051 (A→B) | 40112 → firewall-drop |
| **C — sqlmap** | 1000301 → 1000306 | 31103/31106/31171 (natives) | — | — |
| **D — vsftpd** | 1000401, 1000402 | 100055 (useradd via syslog) | 100052 → 100053 | — |

---

*Document généré pour la soutenance — vue d'ensemble destinée au jury. Le détail complet
(justifications, calibrages empiriques, limites) figure dans les rapports `resultats_scenario_X.md`
de chaque scénario et dans les commentaires des fichiers de règles.*
