# Bilan — Itération 2 (Issue #24)

## Périmètre

L'Itération 2 couvre deux volets : la détection multi-couches (NIDS + HIDS) sur les
Scénarios B (brute force SSH, Hydra) et C (injection SQL, sqlmap), et une première
couche d'intelligence artificielle appliquée aux alertes déjà détectées — priorisation
(Issue #21), corrélation multi-étapes (Issue #22) et reconstruction textuelle de kill
chain (Issue #23). Ce document synthétise les résultats déjà documentés en détail dans
`scenarios/B_hydra/results/`, `scenarios/C_sqlmap/results/` et `results/llm_prioritization_it2/`,
sans les dupliquer intégralement — se référer aux fichiers sources pour le détail
méthodologique complet de chaque scénario.

**Hors périmètre** : le Scénario A (scan Nmap + détection par Isolation Forest)
appartient au MVP / Itération 1 et a été clôturé avant le début de l'Itération 2
(Issue #15) — ses résultats sont documentés séparément dans
`results/findings_isolation_forest.md`, non repris ici.

## 1. Détection — Scénarios B et C

| Scénario | Capteur | Règle(s) | Résultat | Taux de détection | Faux positifs (sur test de contrôle) |
|---|---|---|---|---|---|
| B — Hydra SSH | Suricata (NIDS) | SID 1000201 | 6/6 rafales détectées | 100% (0 FN) | 0 sur l'ensemble du trafic `eve.json` disponible (pas un test de contrôle synthétique dédié comme pour C) |
| B — Hydra SSH | Wazuh (HIDS, native) | 40112 (corrélation échec→succès) | Succès confirmé automatiquement | — (règle native, aucun FN observé sur la campagne analysée) | 0 sur l'ensemble des sources actives sur `ssh-eurostar` durant la fenêtre |
| C — sqlmap | Suricata (NIDS) | SID 1000301 (User-Agent) | 87/88 requêtes détectées | 98,9% (1 FN) | 0 alerte sur 1 requête de contrôle bénigne testée |
| C — sqlmap | Suricata (NIDS) | SID 1000302-1000306 (payloads) | Couverture par technique (UNION, boolean/error, time-based, volumétrie, fonctions MySQL) | Variable par SID, cf. détail | 0 alerte sur 1 requête de contrôle bénigne testée |
| C — sqlmap | Wazuh (HIDS, natif) | 31171, 31103, 31106, 31122 | 74 alertes pertinentes (sur 284 hits bruts, 72,9% de bruit SCA filtré) | — (aucun FN quantifié isolément côté Wazuh) | 0 alerte sur 1 requête de contrôle bénigne testée |

**Constat central, valable pour B et C** : le ruleset Wazuh natif a suffi à couvrir la
détection applicative/HIDS dans les deux scénarios, sans qu'aucune règle de corrélation
personnalisée n'ait dû être écrite au niveau scénario isolé (`40112` pour B, `31171`/`31103`/`31106`
pour C) — la seule règle de corrélation personnalisée du projet (`100051`) sert la
corrélation **inter-scénarios** (A→B), pas la détection intra-scénario.

**Limites déjà documentées par scénario** (détail complet dans les fichiers sources,
non repris intégralement ici) : contournement de la détection User-Agent via
`--random-agent` (C), bruit des règles SCA nécessitant un filtrage explicite dans
Discover (C), règle Wazuh 31122 non spécifique SQLi (C), test de faux positifs C
limité à une seule requête de contrôle synthétique (méthodologie différente de B, qui
s'appuie sur une vérification de l'ensemble du trafic disponible plutôt qu'un test
synthétique dédié — à harmoniser si un test de FP plus systématique est refait en
It.3), décompte des événements `rule.id 5760` non exporté quantitativement (B).

## 2. Couche IA

### 2.1 Priorisation des alertes (Issue #21)

Deux méthodes indépendantes comparées sur les 42 incidents groupés (Scénarios A/B/C) :
un score composite déterministe (`compute_composite_score()`) et une classification
par LLM local (`classify_with_llm()`, Llama 3.1 8B via Ollama/LangChain).

| Méthode | F1-macro | Remarque |
|---|---|---|
| Score composite seul | 1,000 | Provisoire — seuils calibrés sur le même échantillon de 42 incidents, risque de surapprentissage documenté (Issue #40) |
| LLM seul | 0,656 | Après correctif `contains_attack_success` (bug initial : F1-macro 0,412, dû à un détecteur de succès ne couvrant que la corrélation multi-étapes, pas les règles natives 40112/31106) |

**Biais résiduel identifié, non corrigé cette itération** : 11/35 incidents "normale"
classés "haute" par le LLM — diagnostiqué comme un biais de prudence sous ambiguïté de
prompt, pas un défaut de lecture des features. Suivi : Issue #42.

### 2.2 Corrélation multi-étapes (Issue #22)

Règle Wazuh composite `100051` (niveau 15) : scan Nmap (`100050`) suivi d'un brute force
SSH abouti (`40112`) dans une fenêtre de 10 minutes, avec correspondance de source IP
inter-agents. Validée le 03/08/2026 : scan détecté 10:14:30→10:15:52 (agent
`suricata-sensor`), compromission confirmée à 10:17:39 (agent `ssh-eurostar`), écart
d'environ 1min47s à 3min09s, source cohérente (`192.168.1.50`) sur les deux agents.

**Point technique notable** : la corrélation inter-agents nécessite explicitement le
tag `<global_frequency/>` — sans lui, Wazuh ne comptabilise `frequency`/`timeframe`
qu'au sein d'un même agent, et la règle ne se déclenche jamais en conditions réelles
multi-agents malgré un fonctionnement correct en test isolé (`wazuh-logtest`).

### 2.3 Reconstruction textuelle de la kill chain (Issue #23)

Rapport structuré généré par LangChain + Ollama à partir de l'incident corrélé
ci-dessus, couvrant 2 étapes (Discovery/T1046 → Credential Access + Lateral
Movement/T1021.004+T1110+T1110.001). Développement en 4 itérations empiriques :

| Version | Constat | Correctif |
|---|---|---|
| v1/v2 | Le LLM, chargé de segmenter ET de recopier les tags MITRE fournis, substitue une tactique par une autre de façon non fiable et instable (`Discovery` → `Initial Access`), même avec un prompt renforcé | Diagnostic : limite du modèle 8B local sur la recopie factuelle structurée, pas un problème de prompt engineering |
| v3 | Segmentation et tags MITRE déplacés en Python déterministe ; LLM restreint à la rédaction de texte | Substitution de tactique éliminée par construction |
| v4 | Chevauchement temporel réel découvert entre Scénarios A et B dans le trafic capturé (alertes génériques de l'autre scénario tombant dans la fenêtre temporelle) | Descriptions transmises au LLM restreintes aux alertes taguées MITRE |

Latence observée (rédaction LLM uniquement, hors segmentation Python) : 212 à 288
secondes selon les runs, sur un incident de 194 alertes brutes.

**Limitation résiduelle connue** : la prose rédigée par le LLM peut occasionnellement
mal attribuer le rôle d'une technique (ex. inversion T1021.004/T1110 dans la
formulation) malgré des champs structurés fiables — relecture humaine recommandée
avant intégration verbatim dans un document final.

## 3. Points forts

- Détection en couches (NIDS + HIDS) validée comme complémentaire et non redondante
  sur les deux scénarios : Suricata capture le volume/la signature réseau, Wazuh la
  confirmation applicative — schéma cohérent avec la conception initiale du lab.
- Le ruleset Wazuh natif a couvert la quasi-totalité des besoins de détection
  applicative sans développement de règles personnalisées (40112, 31106, 31171,
  31103), limitant le développement custom à la seule corrélation inter-scénarios.
- Séparation systématique entre traitement déterministe et jugement/rédaction par LLM,
  validée empiriquement à trois reprises dans des contextes différents (score composite
  vs classification LLM ; segmentation kill chain vs rédaction de description) —
  schéma architectural robuste, reproductible pour l'Itération 3.
- Méthodologie empirique itérative appliquée de façon constante : chaque anomalie
  observée (biais LLM, chevauchement temporel, décodeur manquant) a été diagnostiquée
  sur données réelles avant correctif, plutôt que supposée a priori.

## 4. Limites connues et non résolues

- Biais de sur-classification "haute" du LLM sous ambiguïté (Issue #42) — caractérisé,
  non corrigé.
- F1-macro = 1,000 du score composite provisoire, risque de surapprentissage sur un
  échantillon de 42 incidents non séparé en train/validation (Issue #40).
- Chevauchement temporel réel entre Scénarios A et B dans le trafic capturé (découvert
  lors du développement de l'Issue #23) — à mentionner explicitement dans la
  méthodologie du rapport final, potentiellement lié au script d'attaque enchaînant
  les deux campagnes sans délai de séparation strict.
- Latence des composants LLM locaux (Llama 3.1 8B, CPU-only) : de l'ordre de la minute
  pour une classification simple, de 3 à 5 minutes pour une génération de rapport
  structuré — contrainte à documenter pour toute discussion de déploiement en
  production dans le rapport.
- Limites spécifiques à B et C déjà documentées dans les fichiers sources (cf. section 1).

## 5. Pistes d'amélioration pour l'Itération 3

- Corriger le biais de prudence du LLM (Issue #42) en clarifiant la frontière
  "normale"/"haute" dans le prompt, si le temps le permet avant dépôt du rapport.
- Réévaluer les seuils du score composite sur un échantillon élargi ou une séparation
  train/validation explicite (Issue #40), si de nouveaux incidents deviennent
  disponibles via le Scénario D.
- Étendre la reconstruction de kill chain à une séquence à 3 étapes ou plus une fois
  le Scénario D (Metasploit vsftpd) disponible, en réutilisant le patron déterministe
  validé ici (`build_kill_chain_steps`).

## Artefacts et références

- `scenarios/B_hydra/results/rapport_validation.md`
- `scenarios/C_sqlmap/results/resultats_scenario_C.md` (+ 5 captures d'écran)
- `results/llm_prioritization_it2/incidents_score_llm_final.csv` (+ version avant correctif)
- `ai-agent/it2/alert_prioritization.py`, `ai-agent/it2/kill_chain_report.py`
- `wazuh/rules/custom_rules.xml`, `wazuh/decoders/custom_decoders.xml`
- Issues GitHub : #17, #19, #20 (B/C), #21, #22, #23, #40, #42
