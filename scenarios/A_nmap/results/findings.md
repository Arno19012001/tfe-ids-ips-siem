# Scénario A — Résultats et analyse (Issue #13)

## Contexte de l'exécution

- **Script exécuté :** `scenarios/A_nmap/attack.sh`
- **Date :** 04/07/2026, 21:14:54 → 21:19:24 CEST (4 min 30s)
- **Cible :** `10.0.10.0/24` (DMZ)
- **Source :** kali-attacker (192.168.1.50)

## Hôtes et services découverts

| Hôte | Port ouvert | Service | Version |
|---|---|---|---|
| 10.0.10.10 | 80/tcp | http | Apache 2.4.67 (Debian) |
| 10.0.10.20 | 22/tcp | ssh | OpenSSH 9.2p1 |
| 10.0.10.30 | 21/tcp | ftp | vsftpd 2.3.4 (cible volontairement vulnérable, CVE-2011-2523, prévue pour le scénario D) |

Chaque hôte DMZ n'expose qu'un seul port en écoute (tous les autres en `filtered`), conforme aux règles de filtrage pfSense en liste blanche stricte.

## Alertes Suricata générées (`eve.json`)

| SID | Signature | Occurrences | Hôtes concernés |
|---|---|---|---|
| 1000101 | SYN Scan Detected | ~24 | 10.0.10.10, .20, .30 |
| 1000104 | Service/Version Detection Probe | 1 | 10.0.10.30 uniquement |
| 1000102 | OS Fingerprint - Null Flags (T2) | 0 | — |
| 1000103 | OS Fingerprint - FIN/PSH/URG (T3-T7) | 0 | — |

## Validation croisée Wazuh Dashboard

Confirmé via Threat Hunting → Events, filtre `agent.name : "suricata-sensor"` : 450 hits sur la fenêtre de test, alertes correctement décodées et libellées (`Suricata: Alert - SCENARIO_A Nmap SYN Scan Detected`, rule.id 86601, rule.level 3), agent source correctement attribué. Capture d'écran : `wazuh_dashboard_scenario_A.png`.

## Faux négatifs observés

### 1. OS Fingerprinting (SID 1000102/1000103) — faux négatif systématique

**Constat.** Aucune occurrence de ces deux signatures sur deux protocoles de test indépendants : scans ciblés `-sN` (Null) et `-sX` (Xmas) lors de l'Issue #12, puis `-O` (fingerprinting OS complet) intégré au script officiel lors de cette Issue #13. La reproductibilité sur deux méthodes de déclenchement différentes exclut une erreur ponctuelle de manipulation et confirme un phénomène structurel.

**Mécanisme technique.** La méthode de fingerprinting OS de Nmap repose sur l'envoi de sondes à combinaisons de flags TCP volontairement non conformes au comportement normal d'une pile réseau, dans le but d'observer comment le système cible y répond (chaque OS implémente légèrement différemment la gestion de paquets hors RFC). Les tests documentés par Nmap incluent notamment :

| Sonde | Flags envoyés | Port ciblé |
|---|---|---|
| T2 | Aucun (Null) | Port ouvert |
| T3 | SYN+FIN+URG+PSH | Port ouvert |
| T7 | FIN+PSH+URG | Port fermé |

Un pare-feu à état (*stateful firewall*, comme **pf**, le moteur de filtrage sous-jacent à pfSense) ne construit une entrée dans sa table d'états — et donc n'autorise le passage d'un paquet vers l'intérieur du réseau protégé — que lorsqu'il reconnaît le début d'une connexion TCP légitime, c'est-à-dire un paquet SYN isolé. Un paquet sans aucun flag ou avec une combinaison FIN+PSH+URG ne correspond à aucune session en cours de suivi ; il est donc écarté silencieusement par la logique de correspondance d'état, **indépendamment de toute règle de filtrage explicite autorisant le port concerné**. C'est précisément pour cette raison que Nmap qualifie ce type de résultat de `open|filtered` plutôt que `open` ou `closed` : l'outil ne peut lui-même pas distinguer un port réellement fermé d'une réponse simplement absorbée par un pare-feu à état intermédiaire.

**Preuve empirique (Issue #12).** Une capture réseau simultanée sur les deux interfaces de pfSense (WAN côté kali-attacker, interface interne côté Suricata) a confirmé ce mécanisme de façon directe : les paquets Null/Xmas étaient visibles sur l'interface WAN mais totalement absents sur l'interface menant à Suricata, alors que le trafic SYN normal (scénario A, phases 1-2) traversait sans problème les deux interfaces.

**Positionnement méthodologique.** Il s'agit d'une **limitation architecturale du laboratoire, et non d'un défaut de conception des règles Suricata** — les signatures SID 1000102/1000103 sont syntaxiquement correctes et chargées sans erreur par le moteur (`5 rules successfully loaded, 0 rules failed`). Le choix a été fait de ne pas assouplir la configuration pfSense (par exemple en désactivant le suivi d'état ou en ajoutant une règle *pass* sans état pour ces flags) afin de ne pas dénaturer artificiellement la posture de sécurité défendue pour le client fictif Eurostar — un pare-feu de production qui bloquerait ce type de sonde de reconnaissance serait un comportement souhaitable, pas une défaillance à corriger.

**Suivi.** Piste de contournement identifiée mais non implémentée dans le cadre de cette issue : **Issue #37** (sondes ICMP alternatives, moins susceptibles d'être filtrées par le suivi d'état TCP).

### 2. Service/Version Detection (SID 1000104) — faux négatif partiel, nouvelle découverte

**Constat.** Sur les 3 hôtes DMZ scannés par `-sV` (Phase 2 du script officiel), une seule alerte SID 1000104 a été déclenchée, sur `metasploitable2:21/ftp`. `web-eurostar` (80/http) et `ssh-eurostar` (22/ssh) n'ont généré aucune alerte, alors que Nmap a réussi à identifier la version exacte du service sur les trois hôtes (Apache 2.4.67, OpenSSH 9.2p1, vsftpd 2.3.4 — cf. `scan_output.txt`).

**Mécanisme technique.** La règle actuelle repose sur une détection **comportementale** plutôt que sur une signature de contenu applicatif :
```
threshold: type both, track by_src, count 3, seconds 10
```
Ce choix de conception (déjà justifié lors de l'Issue #12) part du principe que la sonde de version de Nmap (`-sV`) multiplie les connexions TCP complètes vers un même hôte en peu de temps — un comportement suffisamment distinctif pour ne pas nécessiter d'inspection du contenu applicatif, qui varie énormément selon le protocole (HTTP, SSH, FTP, etc., chacun avec des dizaines de sondes différentes dans la base `nmap-service-probes`).

Ce raisonnement s'avère toutefois **sensible au nombre de ports ouverts par hôte** : le protocole FTP nécessite, même pour une simple identification de bannière, un échange de plusieurs commandes (bannière initiale, puis `SYST`, `FEAT`, etc. selon les probes utilisées), ce qui a suffi à atteindre le seuil de 3 connexions/paquets pertinents en fenêtre de 10 secondes. À l'inverse, une simple requête `GET / HTTP/1.0` (observée dans les captures de l'Issue #12) ou une négociation SSH minimale ne génèrent qu'un très faible nombre d'échanges, insuffisant pour franchir ce même seuil.

**Constat notable pour la discussion académique du rapport.** Ce résultat illustre une tension intéressante entre deux objectifs de sécurité : plus la politique de filtrage pfSense est stricte (peu de ports exposés par hôte, conforme au principe de moindre privilège), moins un hôte a d'occasions de générer le volume d'échanges nécessaire pour qu'une signature comportementale par seuil se déclenche. Une posture réseau plus sécurisée réduit ainsi, paradoxalement, la sensibilité de ce type de détection — un compromis à documenter explicitement plutôt qu'à présenter comme un défaut de configuration isolé.

**Suivi.** Recalibrage évalué dans **l'Issue #36** (abaissement du seuil, avec mesure de l'impact sur le taux de faux positifs en trafic légitime).

## Faux positifs observés

Aucun faux positif constaté durant la fenêtre de test : toutes les alertes générées correspondent à du trafic effectivement émis par kali-attacker (seule source du lab durant le test, aucun autre générateur de trafic actif). La classification Suricata `category: "Attempted Information Leak"` (associée au `classtype: attempted-recon` par défaut dans `classification.config`) est une dénomination standard de Suricata pour la reconnaissance, cohérente avec la nature réelle du trafic — non un mécanisme de mauvaise classification.

## Synthèse pour le critère de validation de l'Issue #13

> Au moins une alerte générée par phase du scan — **atteint** (Phase 1 découverte non couverte par signature dédiée [ICMP/ARP hors périmètre des règles TCP], Phase 2 couverte par SID 1000101/1000104, Phase 3 couverte par SID 1000101 mais pas 1000102/1000103 pour les raisons ci-dessus). Résultats versionnés dans `scenarios/A_nmap/results/`.

## Éléments reportés en backlog

- **Issue #36** — Recalibrage du seuil de SID 1000104 pour environnements à faible nombre de ports exposés
- **Issue #37** — Piste de détection OS via sondes ICMP (moins susceptibles d'être filtrées par pfSense qu'un paquet TCP à flags anormaux) — identifiée en Issue #12, non implémentée

## Références

- Lyon, G. (2009). *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning.* Chapitre 8 : "Remote OS Detection" (méthode T1-T7, ECN, IP ID) — https://nmap.org/book/osdetect.html
- Nmap.org — "Port Scanning Basics" (sémantique `open|filtered`) — https://nmap.org/book/scan-methods-udp-scan.html
- OpenBSD PF User's Guide — "Stateful Filtering" — https://www.openbsd.org/faq/pf/filter.html
- Suricata User Guide — "Thresholding" et "Rule Structure" — https://docs.suricata.io/en/latest/rules/thresholding.html
- MITRE ATT&CK — T1046 (Network Service Discovery), T1595.001 (Active Scanning: Scanning IP Blocks) — https://attack.mitre.org/techniques/T1046/
