"""
alert_prioritization.py — Priorisation automatique des alertes par IA
TFE IDS/IPS & SIEM — Issue #21 — v7 (NON TESTÉ — checkpoint de fin de session)

ATTENTION : cette version a été écrite et présentée le 03/08/2026 mais
n'a JAMAIS pu être exécutée avec succès dans le conteneur ai-agent, à
cause d'un problème réseau distinct (eth0 absent du conteneur après un
`docker restart` effectué en dehors de l'interface GNS3 — GNS3 gère
lui-même la création des interfaces virtuelles vers Switch1 et n'est pas
informé d'un redémarrage déclenché directement via Docker). Committé tel
quel comme point de sauvegarde, à valider à la prochaine session après
un Stop/Start du nœud via l'interface GNS3 (pas `docker restart`).

Étape 1/5 : récupération (Indexer OpenSearch).
Étape 2/5 : regroupement par incident.
Étape 3/5 : agrégation des features + score composite.
Étape 4/5 : classification contextuelle via LangChain + Ollama.
Étape 5/5 : évaluation de la précision (score seul vs score + LLM).

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
Wazuh 0.35, type/groupes 0.35, fréquence 0.20, zone 0.10). Séparation
parfaite des 3 classes sur les 42 incidents actuels : critique
[0.672-0.958], haute [0.464], normale [0.159-0.333].

classify_with_llm() : ne reçoit JAMAIS incident_ground_truth. Correctif du
03/08/2026 sur une inversion de lecture de booléen (cf. historique commit
GitHub) — validé stable sur 3 répétitions + test de régression.

evaluate_precision() / find_optimal_thresholds() : seuils de coupure
calibrés par recherche en grille (maximisation F1-macro) sur les 42
incidents ACTUELS — résultat PROVISOIRE, à recalibrer après enrichissement
du jeu de données (Issue #40). Avec seulement 42 points et une séparation
déjà parfaite des classes par le score composite, un F1=1.0 sur cet
échantillon ne garantit pas la généralisation — risque de surapprentissage
documenté explicitement plutôt que présenté comme un résultat définitif.

run_llm_batch() : exécution du LLM sur un ensemble d'incidents, AVEC
REPRISE SUR INTERRUPTION (checkpoint CSV) — un run complet sur 42
incidents peut prendre 20-35 minutes en CPU-only, une interruption ne doit
pas obliger à tout recommencer. Fonction séparée, pas appelée
automatiquement dans __main__ (coût de temps trop élevé pour un run par
défaut) — à invoquer volontairement, cf. instructions en bas de fichier.
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
from sklearn.metrics import classification_report, confusion_matrix, f1_score

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
    """Récupère les alertes Wazuh depuis l'Indexer OpenSearch (cf. Issue #38)."""
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

LOCAL_EVENT_RULE_IDS = {"2501", "5501", "5502", "5503", "5557"}
INCIDENT_WINDOW_MINUTES = 10


def group_alerts_by_incident(
    df_scope: pd.DataFrame,
    window_minutes: int = INCIDENT_WINDOW_MINUTES,
) -> pd.DataFrame:
    """Regroupe les alertes en incidents (fenêtre glissante chaînée)."""
    df = df_scope.copy()
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"])

    is_local = df["rule_id"].isin(LOCAL_EVENT_RULE_IDS)
    df["grouping_key"] = df["agent_id"].where(is_local, df["src_ip"])

    n_avant = len(df)
    df = df[df["grouping_key"].notna()].copy()
    n_exclues = n_avant - len(df)
    if n_exclues > 0:
        print(f"[group_alerts_by_incident] {n_exclues} alertes exclues (grouping_key manquante)")

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
    """Transforme un DataFrame d'alertes en un DataFrame d'incidents."""
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


TYPE_GROUP_WEIGHTS = [
    ("kill_chain", 1.0),
    ("attack_success", 0.9),
    ("sql_injection", 0.6),
    ("sqlinjection", 0.6),
    ("authentication_failures", 0.6),
]
DEFAULT_TYPE_SCORE = 0.2

WEIGHT_RULE_LEVEL = 0.35
WEIGHT_TYPE = 0.35
WEIGHT_FREQUENCY = 0.20
WEIGHT_ZONE = 0.10

MAX_RULE_LEVEL = 16
FREQUENCY_LOG_CAP = 6.0


def _type_score(groups_union: list) -> float:
    for group_name, score in TYPE_GROUP_WEIGHTS:
        if group_name in groups_union:
            return score
    return DEFAULT_TYPE_SCORE


def compute_composite_score(df_incidents: pd.DataFrame) -> pd.DataFrame:
    """Score composite (4 dimensions pondérées manuellement, poids fixes)."""
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
    Classifie un incident via LangChain + Ollama. Ne reçoit jamais
    incident_ground_truth. Cf. docstring module pour l'historique du
    correctif d'inversion de lecture de booléen.
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


def find_optimal_thresholds(df_incidents: pd.DataFrame, n_steps: int = 100) -> dict:
    """
    Recherche en grille des 2 seuils de coupure (normale/haute,
    haute/critique) maximisant le F1-macro sur df_incidents.

    ATTENTION : calibration PROVISOIRE sur l'échantillon actuel (42
    incidents au 03/08/2026) — cf. avertissement docstring module.
    À recalibrer après enrichissement du jeu de données (Issue #40).
    """
    scores = df_incidents["composite_score"].values
    y_true = df_incidents["incident_ground_truth"].map(GROUND_TRUTH_RANK).values

    score_min, score_max = scores.min(), scores.max()
    candidates = np.linspace(score_min, score_max, n_steps)

    best_f1 = -1.0
    best_thresholds = (0.4, 0.6)

    for t_haute in candidates:
        for t_critique in candidates:
            if t_critique <= t_haute:
                continue
            y_pred = np.where(scores >= t_critique, 2, np.where(scores >= t_haute, 1, 0))
            f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_thresholds = (t_haute, t_critique)

    return {
        "threshold_haute": best_thresholds[0],
        "threshold_critique": best_thresholds[1],
        "f1_macro": best_f1,
    }


def evaluate_precision(
    df_incidents: pd.DataFrame,
    threshold_haute: float,
    threshold_critique: float,
    llm_column: Optional[str] = None,
) -> dict:
    """
    Calcule précision/rappel/F1 par classe, à partir du score composite
    seul (toujours) et, si llm_column est fourni (résultats déjà calculés
    via run_llm_batch), en comparaison avec la classification LLM.

    Ne nécessite PAS Ollama si llm_column est None — exécution immédiate.
    """
    df = df_incidents.copy()
    df["score_only_rank"] = np.where(
        df["composite_score"] >= threshold_critique, 2,
        np.where(df["composite_score"] >= threshold_haute, 1, 0)
    )
    df["score_only_label"] = df["score_only_rank"].map(RANK_TO_LABEL)

    y_true = df["incident_ground_truth"]
    y_pred_score = df["score_only_label"]

    results = {
        "score_only": {
            "report": classification_report(y_true, y_pred_score, zero_division=0, output_dict=True),
            "confusion_matrix": confusion_matrix(y_true, y_pred_score, labels=["normale", "haute", "critique"]),
            "f1_macro": f1_score(y_true, y_pred_score, average="macro", zero_division=0),
        }
    }

    print("\n=== Évaluation : SCORE COMPOSITE SEUL ===")
    print(f"Seuils utilisés : haute >= {threshold_haute:.3f}, critique >= {threshold_critique:.3f}")
    print(classification_report(y_true, y_pred_score, zero_division=0))
    print("Matrice de confusion (lignes=réel, colonnes=prédit) [normale, haute, critique] :")
    print(results["score_only"]["confusion_matrix"])

    if llm_column and llm_column in df.columns:
        y_pred_llm = df[llm_column]
        results["score_plus_llm"] = {
            "report": classification_report(y_true, y_pred_llm, zero_division=0, output_dict=True),
            "confusion_matrix": confusion_matrix(y_true, y_pred_llm, labels=["normale", "haute", "critique"]),
            "f1_macro": f1_score(y_true, y_pred_llm, average="macro", zero_division=0),
        }
        print("\n=== Évaluation : SCORE + LLM ===")
        print(classification_report(y_true, y_pred_llm, zero_division=0))
        print("Matrice de confusion (lignes=réel, colonnes=prédit) [normale, haute, critique] :")
        print(results["score_plus_llm"]["confusion_matrix"])

        print(f"\n=== Comparaison F1-macro ===")
        print(f"Score seul   : {results['score_only']['f1_macro']:.3f}")
        print(f"Score + LLM  : {results['score_plus_llm']['f1_macro']:.3f}")

    return results


def run_llm_batch(df_incidents: pd.DataFrame, checkpoint_path: str = "/opt/ai-agent/it2/llm_batch_checkpoint.csv") -> pd.DataFrame:
    """
    Exécute classify_with_llm() sur tous les incidents de df_incidents,
    AVEC REPRISE SUR INTERRUPTION : les résultats sont sauvegardés au fur
    et à mesure dans checkpoint_path. Si le fichier existe déjà, les
    incident_id déjà traités sont sautés (reprise, pas de recalcul).

    Durée estimée : 20-35 min pour 42 incidents en CPU-only (cf. latences
    mesurées le 03/08/2026 : ~105s au premier appel, ~27-50s ensuite dans
    la fenêtre OLLAMA_KEEP_ALIVE). Nécessite qu'Ollama soit démarré.

    Fonction volontairement NON appelée dans __main__ (coût de temps trop
    élevé pour un run par défaut) — à invoquer explicitement.
    """
    if os.path.exists(checkpoint_path):
        df_done = pd.read_csv(checkpoint_path)
        done_ids = set(df_done["incident_id"])
        print(f"[run_llm_batch] Reprise : {len(done_ids)} incidents déjà traités dans {checkpoint_path}")
    else:
        df_done = pd.DataFrame(columns=["incident_id", "llm_niveau", "llm_justification", "llm_latency_seconds"])
        done_ids = set()

    remaining = df_incidents[~df_incidents["incident_id"].isin(done_ids)]
    print(f"[run_llm_batch] {len(remaining)} incidents restants sur {len(df_incidents)}")

    for i, (_, incident_row) in enumerate(remaining.iterrows()):
        try:
            result = classify_with_llm(incident_row)
            new_row = {
                "incident_id": incident_row["incident_id"],
                "llm_niveau": result["llm_niveau"],
                "llm_justification": result["llm_justification"],
                "llm_latency_seconds": result["llm_latency_seconds"],
            }
            df_done = pd.concat([df_done, pd.DataFrame([new_row])], ignore_index=True)
            df_done.to_csv(checkpoint_path, index=False)
            print(f"[run_llm_batch] ({i+1}/{len(remaining)}) {incident_row['incident_id']} -> {result['llm_niveau']} ({result['llm_latency_seconds']:.1f}s)")
        except Exception as e:
            print(f"[run_llm_batch] ERREUR sur {incident_row['incident_id']} : {e} — checkpoint conservé, relancer run_llm_batch() pour reprendre")
            raise

    return df_done


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

    calibration = find_optimal_thresholds(df_incidents)
    print(f"\n=== Calibration des seuils (PROVISOIRE — 42 incidents, cf. Issue #40) ===")
    print(f"Seuil haute    : {calibration['threshold_haute']:.3f}")
    print(f"Seuil critique : {calibration['threshold_critique']:.3f}")
    print(f"F1-macro       : {calibration['f1_macro']:.3f}")

    evaluate_precision(
        df_incidents,
        threshold_haute=calibration["threshold_haute"],
        threshold_critique=calibration["threshold_critique"],
    )

    print("\n" + "=" * 70)
    print("Pour lancer la comparaison SCORE + LLM (20-35 min, nécessite Ollama démarré) :")
    print("  df_llm = run_llm_batch(df_incidents)")
    print("  df_incidents_merged = df_incidents.merge(df_llm, on='incident_id')")
    print("  evaluate_precision(df_incidents_merged, calibration['threshold_haute'],")
    print("                      calibration['threshold_critique'], llm_column='llm_niveau')")
    print("=" * 70)
