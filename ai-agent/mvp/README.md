# MVP — Détection d'anomalies par Isolation Forest (Itération 1)

Première itération du TFE : environnement de laboratoire opérationnel + premier
modèle d'IA de détection d'anomalies (Issue #15), validé sur le Scénario A
(reconnaissance Nmap).

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `anomaly_detection.py` | Entraîne un modèle Isolation Forest distinct par port de destination (service) sur du trafic bénin, puis score le trafic du Scénario A pour détecter les flux anormaux. |
| `results/` | Résultats et démarche de validation — voir `results/README.md`. |

## Approche

Le modèle apprend un profil de « normalité » par service (un Isolation Forest
par port de destination observé dans le trafic bénin d'entraînement), plutôt
qu'un seul modèle générique — un port jamais vu en bénin (ex. FTP) est
automatiquement considéré comme anomalie. Neuf versions ont été nécessaires
pour arriver à un résultat rigoureux ; l'historique complet (biais
d'évaluation détectés, bug de fuite de données trouvé et corrigé) est
documenté dans `results/findings_isolation_forest.md`.

## Lancer

```bash
python3 anomaly_detection.py
```

Attend deux fichiers `eve.json` en entrée (bénin et malveillant, extraits
directement depuis Suricata — voir `results/findings_isolation_forest.md`
pour le détail des sources de données) et produit un CSV de scores dans
`results/` (non committé — artefact généré localement à l'exécution).

## Résultat final (v9)

Précision 95.24 % / Rappel 67.11 % / F1 78.74 %, taux de faux positifs sur
bénin isolé de 2.56 %. Détail complet : [`results/README.md`](results/README.md).
