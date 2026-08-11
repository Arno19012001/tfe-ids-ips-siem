# Résultats — Isolation Forest (Itération 1 / MVP)

Ce dossier documente la validation du premier modèle d'IA du TFE : un
détecteur d'anomalies (Isolation Forest) entraîné à reconnaître le trafic
réseau « normal », pour repérer le Scénario A (reconnaissance Nmap) sans
connaître de signature d'attaque à l'avance.

## Ce que contient ce dossier

[`findings_isolation_forest.md`](findings_isolation_forest.md) retrace toute
la démarche : les 9 versions successives du modèle, les erreurs de méthode
détectées en cours de route (un résultat à 99 % qui s'est révélé être un
artefact d'évaluation, puis un bug de fuite de données qui gonflait
artificiellement les faux positifs), et le résultat final retenu.

**Résultat final (v9)** : le modèle distingue correctement le trafic du
Scénario A du trafic normal avec une précision de 95.24 % et un rappel de
67.11 % (F1 = 78.74 %), pour seulement 2.56 % de fausses alertes sur du
trafic bénin isolé.

## Pour aller plus loin

Voir le [README d'ensemble du dossier `mvp/`](../README.md) pour savoir
comment relancer le script et reproduire ces résultats.
