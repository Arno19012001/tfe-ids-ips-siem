# Résultats — Agent IA agentique (Itération 4, Qwen3 8B)

Ce dossier contient les captures d'écran des tests de l'agent IA « agentique »
(voir le [README d'ensemble](../README.md) pour le contexte). Contrairement à la
reconstruction de kill chain de l'Itération 3, qui suit toujours les mêmes étapes
programmées à l'avance, ici c'est le modèle d'IA qui décide lui-même, à chaque
question, quelles informations aller chercher dans Wazuh avant de répondre.

## Ce que montrent ces captures

| Capture | Ce qu'elle illustre |
|---|---|
| `2026-08-10_triage-severite10-sortie-live.png` | L'agent répond à la question « Liste les agents actifs et corrèle les alertes de sévérité 10 sur les dernières 24 heures ». On le voit enchaîner 4 appels d'outils (recherche des agents actifs, agrégation, puis chronologie sur deux hôtes) avant de rendre un verdict rédigé en français. Durée observée : environ 30 minutes, en calcul CPU uniquement. |
| `2026-08-10_triage-severite10-rapport-rendu.png` | La même investigation, affichée cette fois sous forme de rapport lisible dans l'onglet « Rapports » de l'interface, avec l'historique des appels d'outils utilisés. |
| `2026-08-10_list-agents-echec-401.png` | Un test où l'outil `list_agents` échoue proprement (erreur d'authentification, mot de passe non configuré) : l'agent signale l'échec au lieu d'inventer une fausse réponse. |
| `2026-08-10_list-agents-succes.png` | Le même test après correction du mot de passe : l'agent liste correctement les 4 hôtes du labo, y compris deux marqués comme déconnectés, sans en inventer la cause. |
| `2026-08-10_historique-investigations-multiples.png` | L'onglet « Rapports » avec 5 investigations successives menées la même journée, montrant que l'historique est bien conservé d'un test à l'autre. |
| `2026-08-10_reconstruction-killchain-aucune-attaque.png` | Un test où l'agent a repéré de vraies alertes de sévérité élevée, mais a correctement identifié qu'elles étaient liées à une saturation mémoire du système plutôt qu'à une attaque — et l'a signalé comme tel plutôt que d'inventer une kill chain. |

## Pour aller plus loin

Le fonctionnement des outils utilisés par l'agent (recherche, agrégation,
chronologie, etc.) est détaillé dans le [README d'ensemble d'`agentic_ai/`](../README.md).

---

## Validation Issue #29 — recommandation de réponse par scénario (11/08/2026)

Quatre prompts, un par scénario (A/B/C/D), demandant explicitement à l'agent
d'investiguer puis de terminer par une recommandation de réponse concrète —
critère de validation formel de l'Issue #29. Captures disponibles pour B, C,
D et les deux retests A'/C' (`2026-08-11_issue29-*.png`) ; seul le test A
original est documenté à partir du texte collé, sans capture.

| Scénario | Verdict | Recommandations fournies | Fiabilité du raisonnement |
|---|---|---|---|
| A — Nmap | La preuve réelle est trouvée (règle de corrélation kill chain, IP `192.168.1.50`, niveau 15) mais **écartée à tort** comme « probable faux positif » dans la conclusion | 4 recommandations concrètes (bloquer l'IP, vérifier les règles, surveiller le DMZ, durcir les accès) | ⚠️ Contradiction interne : la preuve citée contredit la conclusion |
| B — Hydra SSH | Détecté correctement (échecs SSH/PAM, alerte de niveau 8) | 4 recommandations concrètes (identifiants renforcés, blocage IP, rate limiting, surveillance) | ⚠️ Le chiffre « 20 échecs en 30s » cité dans la corrélation n'apparaît dans aucun appel d'outil du journal ; aucune tentative de retrouver l'IP source malgré la recommandation de la bloquer |
| C — sqlmap | **Faux négatif** : conclut à l'absence d'activité SQLi alors que 8 alertes réelles existent (confirmé indépendamment par `ai-agent/it3/results/`) | 3 recommandations génériques (vérifier les règles, logs, comportements atypiques) | ❌ Résultat incorrect. Cause structurelle identifiée : le Scénario C n'a jamais eu de règle de corrélation Wazuh dédiée, contrairement à A/B/D — un angle mort du modèle de données, pas seulement une requête mal formulée |
| D — Backdoor vsftpd | La preuve réelle est trouvée (141 correspondances, alerte de niveau 15 « accès initial confirmé ») mais **écartée à tort** : « aucune alerte ne mentionne directement l'IP » — c'est pourtant la raison même du résultat de la recherche | 4 recommandations concrètes (vérifier l'enregistrement de l'hôte, analyser les alertes, mettre à jour VSFTPD, surveiller les flux) | ⚠️ Même contradiction interne que A |

### Constat transversal

Sur les 4 tests initiaux, deux (A et D) présentent le même défaut : l'agent
trouve la bonne preuve via ses appels d'outils, puis la rejette à tort dans
sa synthèse finale (« probable faux positif », « aucune alerte ne mentionne
directement l'IP » — alors que c'est justement pour ça que la recherche a
matché). Ces deux mêmes tests recommandent `find_entity_across_agents`
comme action de suivi sans jamais l'appeler pendant l'investigation. B et C
ont des défauts distincts : B invente un chiffre non présent dans le journal
d'outils (« 20 échecs en 30s ») et n'identifie jamais l'IP source malgré la
recommandation de la bloquer ; C est un vrai faux négatif, avec une cause
structurelle identifiée (absence de règle de corrélation Wazuh pour ce
scénario, indépendante du raisonnement du LLM).

### Retests A' et C' — la formulation du prompt a un effet réel (11/08/2026)

Deux prompts reformulés ont été relancés pour vérifier si les échecs de A et
C tenaient à la formulation initiale plutôt qu'à une limite de l'agent : A'
sans la notation CIDR littérale (`10.0.10.0/24` → noms des hôtes DMZ), C' en
mentionnant explicitement « sqlmap » plutôt que « injection SQL ».

| Retest | Résultat |
|---|---|
| A' | ✅ Détecte correctement la kill chain A→B (règle niveau 15, IP 192.168.1.50) et le verdict correspond cette fois à la preuve citée — la contradiction interne du test A initial ne se reproduit pas. |
| C' | ✅ Détecte 8 alertes SQLi réelles (règle Wazuh native, niveau 10, agent `web-eurostar`), sur une fenêtre élargie automatiquement à 30 jours après deux recherches infructueuses. La mention explicite de « sqlmap » a orienté l'agent vers `get_agent_timeline` sur l'hôte plutôt qu'une recherche texte, contournant l'angle mort de corrélation Wazuh. |

**Nuance méthodologique** : dans les deux retests, la stratégie d'outils
choisie par l'agent a changé en même temps que le prompt (passage à
`get_agent_timeline` par hôte plutôt qu'à une recherche texte) — impossible
d'isoler complètement si c'est la formulation seule ou le changement de
stratégie qui explique l'amélioration. Ce que confirment les deux retests :
le comportement de l'agent est sensible à la formulation de la question, ce
qui est cohérent avec un LLM 8B et doit être documenté comme une limite
opérationnelle plutôt qu'ignoré.

**Bug confirmé dans le code (retest C')** : le journal d'outils de C' montre
deux appels `search_alerts` avec `"agent_id": "015,019"` (comma-séparé, sur
le modèle de ce qui fonctionne pour `aggregate_alerts(group_by=...)`). Mais
`_resolve_agent()` dans `agent_tools.py` ne découpe jamais une valeur sur la
virgule — contrairement au traitement de `group_by`, qui gère explicitement
ce cas. `_resolve_agent("015,019")` renvoie la chaîne littérale
`"015,019"`, utilisée dans un filtre `{"term": {"agent.id": "015,019"}}` qui
ne correspond à aucun document réel : les deux appels étaient condamnés à 0
résultat indépendamment du texte de recherche. Le verdict final affirme
« aucune alerte détectée sur l'agent 019 » — cette conclusion est un
artefact du bug, pas une vérification réelle. Bug jumeau de celui déjà
documenté sur `aggregate_alerts(group_by="agent_id")`, mais plus trompeur
car totalement silencieux (aucune erreur renvoyée). À corriger dans
`_resolve_agent()` : découper sur la virgule et résoudre chaque ID
individuellement, ou documenter clairement dans le schéma de l'outil que
`agent_id` n'accepte qu'une seule valeur.

### Conclusion vis-à-vis du critère de l'Issue #29

Le critère formel — *« pour chaque scénario, l'agent IA propose au moins une
recommandation de réponse pertinente et documentée »* — est rempli à la
lettre sur les 4 scénarios : chaque verdict se termine par des
recommandations concrètes et actionnables. La fiabilité du raisonnement
sous-jacent reste toutefois inégale (1 faux négatif, un pattern récurrent de
rejet erroné de preuves valides sur 2 tests), ce qui confirme la limite déjà
notée dans les tests du 10/08 : relecture humaine recommandée avant toute
intégration verbatim du verdict.
