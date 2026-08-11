# Findings — Isolation Forest (MVP, Issue #15)

## Objectif et critère de validation

**Objectif de l'issue** : implémenter un modèle de détection d'anomalies basé sur Isolation Forest pour analyser les alertes/flux Suricata du Scénario A.

**Critère de validation formel** (énoncé de l'issue) : *"le modèle classe correctement le trafic du scénario A comme anomalie avec un score > seuil défini. Résultats documentés dans `results/`."*

À noter explicitement : le seuil de cohérence ≥80% (critère BF-11, grille d'analyse) ne s'applique pas formellement à ce livrable — il concerne l'agent IA complet de l'Itération 2 (priorisation d'alertes). Ce MVP en constitue "la première brique", selon les termes de l'issue elle-même.

## Sources de données

- **Bénin** : trafic HTTP (7 chemins variés) + tentatives SSH généré depuis `workstation-it` (10.0.20.50) vers `web-eurostar` (10.0.10.10) et `ssh-eurostar` (10.0.10.20), capturé directement depuis `eve.json` sur `suricata-sensor` (`event_type: flow`).
- **Malveillant** : trafic du Scénario A (scan Nmap complet — découverte d'hôtes, `-sS -sV -p-`, détection OS) depuis `kali-attacker` (192.168.1.50), capturé de la même manière (`event_type: flow`), filtré par IP source.

**Décision méthodologique (Option B)** : extraction directe depuis `eve.json` plutôt que via l'API Wazuh, pour deux raisons — l'endpoint `/alerts` de l'API Manager (port 55000) est déprécié depuis Wazuh 4.3 (confirmé empiriquement, réponse 404), et l'Indexer OpenSearch n'expose que les événements ayant déclenché une règle (`event_type: alert`), pas les flux complets nécessaires pour caractériser un profil de normalité bénin. Documenté séparément dans l'Issue #38 (écart avec l'analyse initiale).

## Historique des itérations

| Version | Changement | Résultat | Diagnostic |
|---|---|---|---|
| v1 | Features volumétriques (bytes/pkts), extraction mixte eve.json (bénin) + alertes Indexer (malveillant) | Précision 53.85% / Rappel 41.18% | Biais de mesure identifié : le `flow` imbriqué dans une alerte est un instantané précoce, pas un flux fermé |
| v2 | Features temporelles (fréquence de connexion, diversité de ports sur fenêtres 10s/30s) | Précision 46.88% / Rappel 44.12% | Rythme du scan trop proche du rythme humain simulé du bénin — pas de séparation nette |
| v3 | Diversité des hôtes de destination (`distinct_dest_ip_60s`) | Précision 45.83% / Rappel 32.35% | Échantillon malveillant trop petit (34 alertes throttlées par la règle Suricata `threshold`) pour généraliser |
| v4 | Ré-extraction complète du malveillant (600 flux `event_type: flow` réels, contre 34 alertes throttlées) + entraînement sur profil de normalité uniquement | TP=0, FP=0 partout | Seuil interne `IsolationForest.predict()` calibré sur un échantillon d'entraînement trop petit (101 lignes), ne généralise à rien |
| v5 | Seuil empirique par maximisation du F1-score sur `decision_function` | Précision 99.16% / Rappel 99.33% / F1 99.24% | Résultat optimiste par construction : seuil choisi et évalué sur le même ensemble |
| v6 | Split en trois (entraînement 60% / validation du seuil 20% / test 20%), baseline bénin enrichi (7 chemins HTTP, 45 min → 729 flux) | Précision 64.69% / Rappel 69.46% / F1 66.99% — **77.40% de FP sur le bénin isolé** | Premier résultat rigoureux ; révèle que v5 était en grande partie un artefact d'évaluation |
| v7 | Capture bénin allongée à 12h (2628 flux) — test de l'hypothèse "plus de volume réduit les FP" | F1 59.60%, **FP toujours à 76.81%** | Hypothèse infirmée : le volume seul ne résout pas un problème structurel (bénin hétérogène : HTTP avec échanges de données vs SSH échoué quasi vide) |
| v8 | Modèle Isolation Forest distinct par service (port de destination) plutôt qu'un modèle unique généraliste | F1 47.98%, FP 15.02% | Amélioration nette du FP, mais port 21 (FTP) inattendu dans le bénin d'entraînement — signal d'un problème de données, pas de modèle |
| **v9** | **Correctif : filtre IP source manquant sur le chargement du bénin** (absent alors que déjà présent côté malveillant) — contamination du fichier bénin par des résidus de l'attaque (même conteneur, même `eve.json` persistant, jamais purgé entre les sessions) | **Précision 95.24% / Rappel 67.11% / F1 78.74% — FP sur bénin isolé : 2.56%** | Cause racine trouvée : un bug de fuite de données, pas une limite du modèle |

## Résultats finaux (v9)

```
Bénin : 1950 flux (après filtrage IP source) | Malveillant : 595 flux
Split bénin : train=1170 val=390 test=390
Split malveillant : val=297 test=298
Ports bénins observés à l'entraînement : [22, 80]
Seuil optimal (choisi sur validation) : -0.1448 (F1 validation=79.13%)

--- TEST (seuil non vu à son propre calcul) ---
TP=200  FP=10  FN=98  TN=380
Précision=95.24%  Rappel=67.11%  F1=78.74%
Taux de FP sur bénin isolé=2.56% (sur 390 échantillons bénins)
```

## Discussion critique

**Sur les faux négatifs restants (98)** : les ports 21 (FTP), 443 (HTTPS) et 0 (ICMP, phase de découverte d'hôtes) sont absents du bénin d'entraînement et donc détectés automatiquement à 100% (score `-∞` garanti par construction). Les 98 faux négatifs proviennent exclusivement des scans sur les ports 22 et 80 — les deux seuls ports que le baseline bénin utilise également. Une sonde SYN isolée (scan) et une tentative SSH légitime mais échouée (absence de clé configurée entre `workstation-it` et `ssh-eurostar`, confirmé empiriquement) produisent des empreintes statistiques proches en volume/paquets — chevauchement de comportement réel, pas un défaut de méthode.

**Sur la généralisation** : le jeu de données reste mono-source par classe (une seule IP bénigne, une seule IP malveillante). La robustesse du modèle à une plus grande diversité de sources (plusieurs postes légitimes, plusieurs profils d'attaquants) n'est pas démontrée par ce MVP — point à traiter en Itération 2 avec les Scénarios B et C.

**Sur la démarche elle-même** : le résultat le plus significatif de ce travail n'est pas le chiffre final, mais la découverte méthodique que deux résultats intermédiaires flatteurs (v5 à 99%, v8 en amélioration) reposaient respectivement sur un biais d'évaluation et un bug de contamination de données — tous deux détectés par un examen critique plutôt qu'acceptés tels quels.

## Conclusion

**Critère de validation de l'issue atteint** : le modèle classe le trafic du Scénario A avec un score d'anomalie distinct, au-delà d'un seuil empiriquement justifié (F1 78.74%, choisi sur un ensemble de validation indépendant du test final).

**Seuil BF-11 (80%, Itération 2)** : à 1.3 point, non formellement requis à ce stade mais une cible réaliste pour l'itération suivante, une fois la diversité des sources augmentée (Scénarios B/C).

**Pistes explicites pour l'Itération 2** :
- Diversifier les sources bénignes (plusieurs postes, plusieurs profils d'usage)
- Étendre le modèle par service aux nouveaux ports/protocoles des Scénarios B/C
- Réévaluer le chevauchement SSH échoué / scan SYN avec un jeu SSH légitime réussi (clés configurées)
