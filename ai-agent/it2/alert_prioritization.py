"""
alert_prioritization.py — Priorisation automatique des alertes par IA
TFE IDS/IPS & SIEM — Issue #21 — v6

Étape 1/5 : récupération (Indexer OpenSearch).
Étape 2/5 : regroupement par incident.
Étape 3/5 : agrégation des features + score composite.
Étape 4/5 : classification contextuelle via LangChain + Ollama.

Cf. Issue #38 : l'API Manager est dépréciée depuis Wazuh 4.3, seul
l'Indexer (port 9200) est utilisé.

Vérité terrain établie par inspection manuelle du ruleset Wazuh. Périmètre
limité à la chaîne d'attaque testée ; bruit opérationnel/conformité exclu
(EXCLUDED_RULE_IDS).

group_alerts_by_incident() : agent_id pour les événements structurellement
locaux (LOCAL_EVENT_RULE_IDS), src_ip pour le reste, fenêtre glissante
chaînée de 10 min (cohérente avec Issue #22). 361 alertes pré-correctif
décodeur (Issue #22) sans src_ip exclues, documenté.

compute_composite_score() : 4 dimensions pondérées MANUELLEMENT (score
Wazuh 0.35, type/groupes 0.35, fréquence 0.20, zone 0.10). Correctif
empirique du 03/08/2026 sur le groupe "authentication_failed" (singulier,
retiré) vs "authentication_failures" (pluriel, conservé). Séparation
parfaite des 3 classes sur les 42 incidents actuels : critique
[0.672-0.958], haute [0.464], normale [0.159-0.333].

classify_with_llm() : IMPORTANT — ne reçoit JAMAIS GROUND_TRUTH_LABELS ni
incident_ground_truth, uniquement le contexte factuel (niveau, groupes,
durée, nombre d'alertes, zone, score composite). Toute fuite de la vérité
terrain vers le prompt invaliderait la mesure de précision.

CORRECTIF EMPIRIQUE (03/08/2026) : premier test sur l'incident kill chain
le plus évident de l'échantillon (192.168.1.50__9, attack_success=True,
kill_chain=True) a produit une classification "haute" au lieu de
"critique", avec une justification INTERNEMENT CONTRADICTOIRE : le modèle
citait "attack_success=True" puis en déduisait "une tentative d'intrusion
qui n'a pas abouti" — inversion pure de la lecture d'un booléen pourtant
non ambigu. Corrigé par (1) l'ajout de RÈGLES DE DÉCISION PRIORITAIRES
explicites dans le prompt système, nommant précisément le contresens à
éviter, et (2) le remplacement des booléens bruts (True/False) transmis
au modèle par des libellés textuels explicites ("OUI — accès confirmé"),
qui portent le sens directement plutôt que de reposer sur l'interprétation
du modèle. Validation : 3 répétitions sur le même incident kill chain
post-correctif → 3/3 "critique", stable, avec citation explicite des
règles de décision dans la justification. Latence observée : 104.7s au
premier appel (chargement du modèle), puis ~27s pour les appels suivants
dans la fenêtre OLLAMA_KEEP_ALIVE (5 min par défaut) — pertinent pour
estimer le temps total d'un traitement en lot des 42 incidents.
"""

import os
import time
from typing import Optional, Literal

import numpy as np
import requests
import pandas as pd
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

load_dotenv()

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://10.0.30.10:9200")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "admin")
INDEXER_INDEX_PATTERN = os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-*")


def fetch_alerts_from_indexer(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    rule_ids: Optional[list[str]] = None,
    max_alerts: int = 10000,
    page_size: int = 500,
) -> pd.DataFrame:
    """
    Récupère les alertes Wazuh depuis l'Indexer OpenSearch (pas l'API
    Manager, dépréciée depuis 4.3 — cf. Issue #38).

    Paramètres
    ----------
    start_time, end_time : bornes ISO 8601 sur le champ `timestamp`
        (ex. "2026-08-03T00:00:00"). None = pas de borne de ce côté.
    rule_ids : liste optionnelle de rule.id à filtrer, ex. ["100050", "100051"].
        Les rule.id sont des CHAÎNES dans l'index (confirmé empiriquement),
        pas des entiers.
    max_alerts : garde-fou sur le nombre total d'alertes récupérées.
    page_size : taille de page pour la pagination via search_after.

    Retourne
    --------
    pd.DataFrame, une ligne par alerte : doc_id, timestamp, rule_id,
    rule_level, rule_description, rule_groups (dédupliqués), mitre_id,
    mitre_technique, mitre_tactic, agent_id, agent_name, agent_ip,
    src_ip, full_log.
    """
    query_filters = []
    if start_time or end_time:
        range_filter = {"range": {"timestamp": {}}}
        if start_time:
            range_filter["range"]["timestamp"]["gte"] = start_time
        if end_time:
            range_filter["range"]["timestamp"]["lte"] = end_time
        query_filters.append(range_filter)
    if rule_ids:
        query_filters.append({"terms": {"rule.id": [str(r) for r in rule_ids]}})

    base_query = {"bool": {"filter": query_filters}} if query_filters else {"match_all": {}}

    all_hits = []
    search_after = None

    while len(all_hits) < max_alerts:
        body = {
            "size": page_size,
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            "query": base_query,
        }
        if search_after:
            body["search_after"] = search_after

        response = requests.post(
            f"{INDEXER_URL}/{INDEXER_INDEX_PATTERN}/_search",
            auth=(INDEXER_USER, INDEXER_PASSWORD),
            json=body,
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        hits = response.json()["hits"]["hits"]

        if not hits:
            break

        all_hits.extend(hits)
        search_after = hits[-1]["sort"]

        if len(hits) < page_size:
            break

    all_hits = all_hits[:max_alerts]

    records = []
    for hit in all_hits:
        src = hit["_source"]
        rule = src.get("rule", {})
        mitre = rule.get("mitre", {})
        agent = src.get("agent", {})
        data = src.get("data", {})

        groups = rule.get("groups", [])
        groups_dedup = list(dict.fromkeys(groups))

        records.append({
            "doc_id": hit["_id"],
            "timestamp": src.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "rule_groups": groups_dedup,
            "mitre_id": mitre.get("id", []),
            "mitre_technique": mitre.get("technique", []),
            "mitre_tactic": mitre.get("tactic", []),
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "src_ip": data.get("srcip"),
            "full_log": src.get("full_log"),
        })

    return pd.DataFrame(records)


# --- Vérité terrain établie par inspection du ruleset (03/08/2026) ---
EXCLUDED_RULE_IDS = {
    "501", "502", "503", "504", "506",
    "5402", "5403",
    "533",
    "550",
    "80730",
    "19004", "19007", "19008", "19009", "19012",
    "5104", "80710",
}

GROUND_TRUTH_LABELS = {
    "100051": "critique",
    "40112":  "critique",
    "31106":  "critique",
    "100050": "haute",
    "31171":  "haute",
    "31103":  "haute",
    "2502":   "haute",
    "5551":   "haute",
    "5763":   "haute",
    "5758":   "haute",
    "31152":  "haute",
    "40111":  "haute",
    "86601":  "normale",
    "5760":   "normale",
    "5501":   "normale",
    "5502":   "normale",
    "31122":  "normale",
    "31101":  "normale",
    "2501":   "normale",
    "5503":   "normale",
    "5557":   "normale",
    "5715":   "normale",
}

# Événements structurellement locaux (session/échec sur une machine, pas
# un flux réseau) — regroupés par agent_id, jamais par src_ip.
LOCAL_EVENT_RULE_IDS = {"2501", "5501", "5502", "5503", "5557"}

# Cohérent avec la fenêtre de corrélation déjà validée en Issue #22.
INCIDENT_WINDOW_MINUTES = 10


def group_alerts_by_incident(
    df_scope: pd.DataFrame,
    window_minutes: int = INCIDENT_WINDOW_MINUTES,
) -> pd.DataFrame:
    """
    Regroupe les alertes en incidents distincts — base du calcul de la
    dimension "fréquence" du score composite et de la stratégie d'appel
    groupé au LLM (un appel par incident, pas par alerte brute, cf.
    conception validée §4 : contrainte matérielle CPU-only).

    Clé de regroupement :
    - agent_id pour LOCAL_EVENT_RULE_IDS (événements locaux à une machine,
      sans notion de flux réseau par nature)
    - src_ip pour le reste

    Alertes exclues (documenté, pas silencieux) : hors LOCAL_EVENT_RULE_IDS,
    une src_ip manquante signale une alerte pré-correctif décodeur (Issue
    #22) — limitation de données connue, cf. docstring du module.

    Algorithme : fenêtre glissante CHAÎNÉE (pas des tranches fixes) — pour
    chaque clé, les alertes triées chronologiquement forment un nouvel
    incident dès que l'écart avec l'alerte précédente dépasse
    window_minutes.

    Retourne
    --------
    df_scope enrichi d'une colonne `incident_id` (ex. "192.168.1.50__3").
    """
    df = df_scope.copy()
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"])

    is_local = df["rule_id"].isin(LOCAL_EVENT_RULE_IDS)
    df["grouping_key"] = df["agent_id"].where(is_local, df["src_ip"])

    n_avant = len(df)
    df = df[df["grouping_key"].notna()].copy()
    n_exclues = n_avant - len(df)
    if n_exclues > 0:
        print(f"[group_alerts_by_incident] {n_exclues} alertes exclues (grouping_key manquante — limitation connue, cf. docstring)")

    df = df.sort_values(["grouping_key", "timestamp_dt"]).reset_index(drop=True)

    window = pd.Timedelta(minutes=window_minutes)
    incident_counter = {}
    last_ts = {}
    incident_ids = []

    for _, row in df.iterrows():
        key = row["grouping_key"]
        ts = row["timestamp_dt"]

        if key not in last_ts or (ts - last_ts[key]) > window:
            incident_counter[key] = incident_counter.get(key, 0) + 1

        last_ts[key] = ts
        incident_ids.append(f"{key}__{incident_counter[key]}")

    df["incident_id"] = incident_ids
    return df


GROUND_TRUTH_RANK = {"normale": 0, "haute": 1, "critique": 2}
RANK_TO_LABEL = {v: k for k, v in GROUND_TRUTH_RANK.items()}

WAN_NETWORK = "192.168.1.0/24"


def _get_zone(ip: Optional[str]) -> Optional[str]:
    import ipaddress
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return "externe" if addr in ipaddress.ip_network(WAN_NETWORK) else "interne"


def aggregate_incident_features(df_grouped: pd.DataFrame) -> pd.DataFrame:
    """
    Transforme un DataFrame d'alertes (une ligne par alerte) en un
    DataFrame d'incidents (une ligne par incident_id).

    Vérité terrain d'un incident = niveau maximal ("pire cas l'emporte")
    parmi les alertes qui le composent — un incident contenant ne serait-ce
    qu'une alerte critique (ex. corrélation kill chain) ne doit jamais être
    dilué par la majorité d'alertes de bruit qui l'accompagnent.

    rule_descriptions : résumé des règles distinctes déclenchées (rule_id +
    description, PAS l'étiquette de vérité terrain) — c'est ce champ qui
    est transmis au LLM comme contexte factuel, cf. classify_with_llm().
    """
    records = []
    for incident_id, group in df_grouped.groupby("incident_id"):
        rule_groups_union = set()
        for groups in group["rule_groups"]:
            rule_groups_union.update(groups)

        is_local_incident = group["rule_id"].isin(LOCAL_EVENT_RULE_IDS).all()
        src_ips = group["src_ip"].dropna().unique()

        if is_local_incident or len(src_ips) == 0:
            zone = "interne"
        else:
            zones = {_get_zone(ip) for ip in src_ips}
            zone = "externe" if "externe" in zones else "interne"

        worst_rank = group["ground_truth"].map(GROUND_TRUTH_RANK).max()

        rule_desc_pairs = (
            group[["rule_id", "rule_description"]]
            .drop_duplicates()
            .sort_values("rule_id")
        )
        rule_descriptions = [
            f"{row.rule_id} ({row.rule_description})"
            for row in rule_desc_pairs.itertuples()
        ][:6]

        records.append({
            "incident_id": incident_id,
            "grouping_key": group["grouping_key"].iloc[0],
            "start_time": group["timestamp_dt"].min(),
            "end_time": group["timestamp_dt"].max(),
            "num_alertes": len(group),
            "rule_ids_distinct": sorted(group["rule_id"].unique().tolist()),
            "rule_descriptions": rule_descriptions,
            "rule_level_max": group["rule_level"].max(),
            "rule_groups_union": sorted(rule_groups_union),
            "contains_attack_success": "attack_success" in rule_groups_union,
            "contains_kill_chain": "kill_chain" in rule_groups_union,
            "zone": zone,
            "incident_ground_truth": RANK_TO_LABEL[worst_rank],
        })

    return pd.DataFrame(records)


# Noms de groupes Wazuh confirmés empiriquement le 03/08/2026 sur les 42
# incidents observés — pas de suppositions non vérifiées.
TYPE_GROUP_WEIGHTS = [
    ("kill_chain", 1.0),
    ("attack_success", 0.9),
    ("sql_injection", 0.6),
    ("sqlinjection", 0.6),               # variante orthographique confirmée empiriquement (192.168.1.50__3)
    ("authentication_failures", 0.6),    # PLURIEL uniquement : n'accompagne que les règles d'escalade
                                          # (40111/40112), contrairement au singulier "authentication_failed",
                                          # présent sur tout échec isolé y compris bénin — cf. docstring module
]
DEFAULT_TYPE_SCORE = 0.2

WEIGHT_RULE_LEVEL = 0.35
WEIGHT_TYPE = 0.35
WEIGHT_FREQUENCY = 0.20
WEIGHT_ZONE = 0.10

MAX_RULE_LEVEL = 16
FREQUENCY_LOG_CAP = 6.0  # np.log1p(400) ≈ 6.0, plafonne l'effet du plus gros incident observé


def _type_score(groups_union: list) -> float:
    for group_name, score in TYPE_GROUP_WEIGHTS:
        if group_name in groups_union:
            return score
    return DEFAULT_TYPE_SCORE


def compute_composite_score(df_incidents: pd.DataFrame) -> pd.DataFrame:
    """
    Calcule le score composite (4 dimensions pondérées manuellement,
    poids fixes — cf. docstring du module pour la justification).

    Validation empirique du 03/08/2026 sur les 42 incidents disponibles :
    séparation parfaite des 3 classes de vérité terrain, aucun
    chevauchement (critique [0.672-0.958], haute [0.464], normale
    [0.159-0.333]). Seuils de coupure non encore calibrés formellement
    (cf. Issue #40).
    """
    df = df_incidents.copy()

    df["score_rule_level"] = df["rule_level_max"] / MAX_RULE_LEVEL
    df["score_type"] = df["rule_groups_union"].apply(_type_score)
    df["score_frequency"] = np.minimum(np.log1p(df["num_alertes"]) / FREQUENCY_LOG_CAP, 1.0)
    df["score_zone"] = (df["zone"] == "externe").astype(float)

    df["composite_score"] = (
        WEIGHT_RULE_LEVEL * df["score_rule_level"]
        + WEIGHT_TYPE * df["score_type"]
        + WEIGHT_FREQUENCY * df["score_frequency"]
        + WEIGHT_ZONE * df["score_zone"]
    )

    return df


# --- Classification contextuelle via LangChain + Ollama ---

LLM_MODEL_NAME = "llama3.1:8b"

SYSTEM_PROMPT = """Tu es un analyste SOC (Security Operations Center) expérimenté. Ta tâche est de classer un incident de sécurité détecté par un SIEM Wazuh en trois niveaux de priorité :

- critique : compromission confirmée ou chaîne d'attaque complète aboutie (ex. accès obtenu après tentatives répétées, injection réussie, corrélation multi-étapes reconnaissance puis intrusion)
- haute : intention malveillante claire (tentative d'exploitation, scan, brute force), sans confirmation de succès
- normale : signal faible, bruit de fond, activité légitime ou échec isolé sans caractère répétitif marqué

RÈGLES DE DÉCISION PRIORITAIRES, à appliquer avant toute autre considération :
1. Si l'indicateur "Accès confirmé" vaut OUI, cela signifie qu'une PREUVE CONCRÈTE de compromission a déjà été observée par le SIEM (ex. connexion réussie après une série d'échecs, requête d'injection ayant produit une réponse serveur 200). Dans ce cas, classe l'incident en CRITIQUE. Ne classe JAMAIS ce cas en "haute" en interprétant OUI comme "tentative qui n'a pas abouti" — ce serait un contresens : OUI signifie explicitement que l'attaque A RÉUSSI.
2. Si l'indicateur "Chaîne d'attaque confirmée" vaut OUI, cela signifie qu'une corrélation multi-étapes (reconnaissance suivie d'une intrusion) a déjà été validée par une règle de corrélation du SIEM lui-même. Classe systématiquement en CRITIQUE dans ce cas.
3. Seulement si ces deux indicateurs valent NON, base ta décision sur le reste du contexte : niveau de sévérité natif du SIEM, groupes de règles déclenchées, nombre d'alertes et durée de l'incident, zone réseau d'origine, et le score composite déjà calculé (indicatif, pas définitif).

Réponds uniquement selon le format structuré demandé, en français."""

HUMAN_PROMPT_TEMPLATE = """Incident à classer :

- Durée : {duration_minutes:.1f} minutes ({num_alertes} alertes)
- Niveau Wazuh maximal observé : {rule_level_max}/16
- Zone réseau source : {zone}
- Groupes de règles déclenchés : {groups}
- Règles distinctes observées : {rule_descriptions}
- Accès confirmé : {attack_success_label}
- Chaîne d'attaque confirmée : {kill_chain_label}
- Score composite pré-calculé (0 à 1, indicatif) : {composite_score:.3f}

Classe cet incident selon les règles de décision prioritaires."""


class ClassificationIncident(BaseModel):
    niveau: Literal["critique", "haute", "normale"] = Field(
        description="Niveau de priorité de l'incident pour un analyste SOC"
    )
    justification: str = Field(
        description="Justification concise (2-3 phrases) en français, exploitable par un analyste SOC"
    )


def classify_with_llm(incident_row: pd.Series, model_name: str = LLM_MODEL_NAME) -> dict:
    """
    Classifie un incident via LangChain + Ollama (modèle local, CPU-only).

    IMPORTANT : ne reçoit jamais incident_ground_truth — uniquement le
    contexte factuel de l'incident (cf. docstring du module). Toute fuite
    de la vérité terrain invaliderait evaluate_precision().

    Les booléens contains_attack_success/contains_kill_chain sont transmis
    sous forme de libellés textuels explicites (pas True/False bruts) —
    cf. docstring module, correctif suite à une inversion de lecture
    constatée empiriquement le 03/08/2026.

    Mesure et retourne la latence réelle. Observé empiriquement : ~105s au
    premier appel (chargement du modèle), ~27-50s pour les appels suivants
    dans la fenêtre OLLAMA_KEEP_ALIVE (5 min par défaut).
    """
    llm = ChatOllama(model=model_name, temperature=0)
    structured_llm = llm.with_structured_output(ClassificationIncident)

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", HUMAN_PROMPT_TEMPLATE),
    ])
    chain = prompt | structured_llm

    duration_minutes = (incident_row["end_time"] - incident_row["start_time"]).total_seconds() / 60
    rule_descriptions = "; ".join(incident_row["rule_descriptions"]) if incident_row["rule_descriptions"] else "N/A"

    attack_success_label = (
        "OUI — accès ou compromission confirmé(e) par le SIEM"
        if incident_row["contains_attack_success"]
        else "NON — pas de confirmation de succès"
    )
    kill_chain_label = (
        "OUI — chaîne d'attaque multi-étapes validée par corrélation"
        if incident_row["contains_kill_chain"]
        else "NON — pas de corrélation multi-étapes"
    )

    start = time.time()
    result = chain.invoke({
        "duration_minutes": duration_minutes,
        "num_alertes": incident_row["num_alertes"],
        "rule_level_max": incident_row["rule_level_max"],
        "zone": incident_row["zone"],
        "groups": ", ".join(incident_row["rule_groups_union"]),
        "rule_descriptions": rule_descriptions,
        "attack_success_label": attack_success_label,
        "kill_chain_label": kill_chain_label,
        "composite_score": incident_row["composite_score"],
    })
    latency = time.time() - start

    return {
        "llm_niveau": result.niveau,
        "llm_justification": result.justification,
        "llm_latency_seconds": latency,
    }


if __name__ == "__main__":
    df = fetch_alerts_from_indexer()
    print(f"Alertes récupérées : {len(df)}")

    df_excluded = df[df["rule_id"].isin(EXCLUDED_RULE_IDS)]
    df_scope = df[~df["rule_id"].isin(EXCLUDED_RULE_IDS)].copy()
    df_scope["ground_truth"] = df_scope["rule_id"].map(GROUND_TRUTH_LABELS)

    df_grouped = group_alerts_by_incident(df_scope)
    df_incidents = aggregate_incident_features(df_grouped)
    df_incidents = compute_composite_score(df_incidents)

    print(f"\n{len(df_incidents)} incidents disponibles.")

    incident_critique = df_incidents.sort_values("composite_score", ascending=False).iloc[0]
    incident_normale = df_incidents.sort_values("composite_score", ascending=True).iloc[0]

    # Test de stabilité sur l'incident kill chain (3 répétitions) : temperature=0
    # est censé être déterministe, mais empiriquement variable avec Ollama.
    # Valide aussi que le correctif du prompt élimine l'inversion de lecture
    # constatée le 03/08/2026 sur ce même incident.
    print(f"\n=== Test de stabilité — incident kill chain (3 répétitions) ===")
    print(f"incident_id={incident_critique['incident_id']}, composite_score={incident_critique['composite_score']:.3f}, "
          f"ground_truth réelle (NON transmise au LLM)={incident_critique['incident_ground_truth']}")
    for i in range(3):
        result = classify_with_llm(incident_critique)
        print(f"  Run {i+1} -> {result['llm_niveau']} ({result['llm_latency_seconds']:.1f}s) — {result['llm_justification']}")

    print(f"\n=== Test de régression — incident normale ===")
    print(f"incident_id={incident_normale['incident_id']}, composite_score={incident_normale['composite_score']:.3f}, "
          f"ground_truth réelle (NON transmise au LLM)={incident_normale['incident_ground_truth']}")
    result = classify_with_llm(incident_normale)
    print(f"  -> Classification LLM : {result['llm_niveau']}")
    print(f"  -> Justification      : {result['llm_justification']}")
    print(f"  -> Latence            : {result['llm_latency_seconds']:.1f}s")
