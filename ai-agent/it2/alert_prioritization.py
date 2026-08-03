"""
alert_prioritization.py — Priorisation automatique des alertes par IA
TFE IDS/IPS & SIEM — Issue #21 — v4

Étape 1/5 : récupération (Indexer OpenSearch).
Étape 2/5 : regroupement par incident.
Étape 3/5 : agrégation des features + score composite (seuils NON calibrés,
            reporté après Issue #40 — enrichissement du jeu de données).

Cf. Issue #38 : l'API Manager est dépréciée depuis Wazuh 4.3, seul
l'Indexer (port 9200) est utilisé.

Vérité terrain établie par inspection manuelle du ruleset Wazuh. Périmètre
limité à la chaîne d'attaque testée ; bruit opérationnel/conformité exclu
(EXCLUDED_RULE_IDS).

group_alerts_by_incident() : agent_id pour les événements structurellement
locaux (LOCAL_EVENT_RULE_IDS), src_ip pour le reste, fenêtre glissante
chaînée de 10 min (cohérente avec Issue #22). 361 alertes pré-correctif
décodeur (Issue #22) sans src_ip exclues, documenté — décision motivée par
la préservation de 16/16 alertes critiques (cf. historique de conception).

compute_composite_score() : 4 dimensions pondérées MANUELLEMENT (pas
apprises — 42 incidents est insuffisant pour apprendre des poids sans
surapprentissage) :
- score Wazuh natif (rule_level_max / 16)           poids 0.35
- type (groupes Wazuh : kill_chain, attack_success,
  sql_injection/sqlinjection, authentication_failures) poids 0.35
- fréquence (log1p(nombre d'alertes), plafonné)       poids 0.20
- IP source (zone externe WAN vs interne)             poids 0.10
Seuls les 2 seuils de coupure (normale/haute, haute/critique) seront
calibrés empiriquement par F1-macro, après enrichissement du jeu de
données via Issue #40 (42 incidents actuels jugés insuffisants pour une
calibration statistiquement robuste).

CORRECTIF EMPIRIQUE (03/08/2026) : TYPE_GROUP_WEIGHTS utilisait initialement
"authentication_failed" (singulier) avec un poids de 0.6 — ce groupe Wazuh
générique est présent sur N'IMPORTE QUEL échec d'authentification isolé,
y compris bénin (rule_id 5760 seul, classé "normale"), pas seulement sur un
vrai pattern de brute-force. Conséquence observée : l'incident 010__4 (86
alertes, normale) obtenait un score composite de 0.468, SUPÉRIEUR au seul
incident "haute" de l'échantillon (0.324) — inversion d'ordre inacceptable.
Remplacé par "authentication_failures" (PLURIEL), qui n'accompagne
empiriquement que les règles d'escalade réelles (40111/40112, seuil de
répétition atteint). La dimension "fréquence" du score capture déjà le
signal de répétition ; le singulier générique faisait double emploi, et
mal. Découverte également d'une variante orthographique du ruleset Wazuh
lui-même : "sqlinjection" (sans underscore) coexiste avec "sql_injection"
selon les règles (31103/31171 vs 31106/31152) — les deux sont maintenant
couvertes. Après correctif, séparation parfaite des 3 classes sur
l'échantillon actuel : critique [0.672-0.958], haute [0.464], normale
[0.159-0.333], aucun chevauchement.
"""

import os
from typing import Optional

import numpy as np
import requests
import pandas as pd
from dotenv import load_dotenv

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
    conception validée §4 : contrainte matérielle CPU-only, ~12s/appel).

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

        records.append({
            "incident_id": incident_id,
            "grouping_key": group["grouping_key"].iloc[0],
            "start_time": group["timestamp_dt"].min(),
            "end_time": group["timestamp_dt"].max(),
            "num_alertes": len(group),
            "rule_ids_distinct": sorted(group["rule_id"].unique().tolist()),
            "rule_level_max": group["rule_level"].max(),
            "rule_groups_union": sorted(rule_groups_union),
            "contains_attack_success": "attack_success" in rule_groups_union,
            "contains_kill_chain": "kill_chain" in rule_groups_union,
            "zone": zone,
            "incident_ground_truth": RANK_TO_LABEL[worst_rank],
        })

    return pd.DataFrame(records)


# Noms de groupes Wazuh confirmés empiriquement le 03/08/2026 sur les 42
# incidents observés (cf. section de vérification en fin de script) —
# pas de suppositions non vérifiées.
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


if __name__ == "__main__":
    df = fetch_alerts_from_indexer()
    print(f"Alertes récupérées : {len(df)}")

    df_excluded = df[df["rule_id"].isin(EXCLUDED_RULE_IDS)]
    df_scope = df[~df["rule_id"].isin(EXCLUDED_RULE_IDS)].copy()
    df_scope["ground_truth"] = df_scope["rule_id"].map(GROUND_TRUTH_LABELS)

    print(f"Alertes dans le périmètre : {len(df_scope)} ({len(df_scope)/len(df)*100:.1f}%)")

    df_grouped = group_alerts_by_incident(df_scope)
    print(f"Alertes conservées après regroupement : {len(df_grouped)}")
    print(f"Nombre d'incidents distincts : {df_grouped['incident_id'].nunique()}")

    df_incidents = aggregate_incident_features(df_grouped)
    df_incidents = compute_composite_score(df_incidents)

    print("\nAperçu des incidents :")
    print(df_incidents[[
        "incident_id", "num_alertes", "rule_level_max",
        "contains_attack_success", "contains_kill_chain", "zone",
        "incident_ground_truth", "composite_score"
    ]].sort_values("composite_score", ascending=False).to_string(index=False))

    print("\nDistribution du score composite par vérité terrain (seuils PAS ENCORE calibrés) :")
    print(df_incidents.groupby("incident_ground_truth")["composite_score"].describe())

    print("\nGroupes réels par incident (vérification des mots-clés de TYPE_GROUP_WEIGHTS) :")
    for _, row in df_incidents.iterrows():
        print(f"  {row['incident_id']:20s} ground_truth={row['incident_ground_truth']:9s} type_score={row['score_type']:.2f}  groups={row['rule_groups_union']}")
