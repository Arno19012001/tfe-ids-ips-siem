"""
anomaly_detection.py — Détection d anomalies (Isolation Forest) sur trafic Suricata
TFE IDS/IPS & SIEM — Issue #15

Sources duales (ajustement documenté suite à la perte de l eve.json historique
du Scénario A lors d une recréation du nœud suricata-sensor, /var/log/suricata
n étant pas déclaré comme volume persistant à ce moment) :
  - Bénin  : eve.json brut extrait de suricata-sensor (event_type: flow)
  - Malveillant : export Indexer OpenSearch (event_type: alert, avec data.flow imbriqué)
Le schéma de features final est identique pour les deux classes malgré l origine
différente — seuls les champs bruts extraits diffèrent avant harmonisation.
"""

import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# --- 1a. Chargement du bénin — eve.json brut (event_type: flow) ---

def load_benign_from_eve_json(eve_json_path: str) -> pd.DataFrame:
    flows = []
    with open(eve_json_path, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "flow":
                continue
            flow = event.get("flow", {})
            flows.append({
                "flow_id": event.get("flow_id"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "start": flow.get("start"),
                "label": 0,
            })
    return pd.DataFrame(flows)


# --- 1b. Chargement du malveillant — export Indexer OpenSearch (event_type: alert) ---

def load_malicious_from_indexer_export(export_path: str) -> pd.DataFrame:
    with open(export_path, "r") as f:
        payload = json.load(f)

    rows = []
    for hit in payload["hits"]["hits"]:
        d = hit["_source"]["data"]
        flow = d.get("flow", {})
        rows.append({
            "flow_id": d.get("flow_id"),
            "src_ip": d.get("src_ip"),
            "dest_ip": d.get("dest_ip"),
            "proto": d.get("proto"),
            "src_port": d.get("src_port"),
            "dest_port": d.get("dest_port"),
            "pkts_toserver": flow.get("pkts_toserver", 0),
            "pkts_toclient": flow.get("pkts_toclient", 0),
            "bytes_toserver": flow.get("bytes_toserver", 0),
            "bytes_toclient": flow.get("bytes_toclient", 0),
            "start": flow.get("start"),
            "label": 1,
            "signature_id": d.get("alert", {}).get("signature_id"),
        })
    return pd.DataFrame(rows)


# --- 2. Feature engineering ---

def build_features(df: pd.DataFrame):
    df = df.copy()
    for col in ["dest_port", "src_port", "pkts_toserver", "pkts_toclient",
                "bytes_toserver", "bytes_toclient"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["is_wellknown_dport"] = (df["dest_port"] < 1024).astype(int)
    df["total_bytes"] = df["bytes_toserver"] + df["bytes_toclient"]
    df["total_pkts"] = df["pkts_toserver"] + df["pkts_toclient"]
    df["bytes_ratio"] = df["bytes_toserver"] / df["total_bytes"].replace(0, 1)
    df["src_ip_conn_count"] = df.groupby("src_ip")["flow_id"].transform("count")

    feature_cols = [
        "dest_port", "is_wellknown_dport", "total_bytes",
        "total_pkts", "bytes_ratio", "src_ip_conn_count",
    ]
    return df, feature_cols


# --- 3. Entraînement ---

def train_isolation_forest(df: pd.DataFrame, feature_cols: list, contamination: float):
    X = df[feature_cols].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X_scaled)

    df["anomaly_score"] = model.decision_function(X_scaled)
    df["predicted_anomaly"] = (model.predict(X_scaled) == -1).astype(int)
    return df, model, scaler


# --- 4. Évaluation vs label réel ---

def evaluate(df: pd.DataFrame):
    tp = ((df["predicted_anomaly"] == 1) & (df["label"] == 1)).sum()
    fp = ((df["predicted_anomaly"] == 1) & (df["label"] == 0)).sum()
    fn = ((df["predicted_anomaly"] == 0) & (df["label"] == 1)).sum()
    tn = ((df["predicted_anomaly"] == 0) & (df["label"] == 0)).sum()

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Précision={precision:.2%}  Rappel={recall:.2%}")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall}


if __name__ == "__main__":
    df_benin = load_benign_from_eve_json("eve_baseline_benin.json")
    df_attaque = load_malicious_from_indexer_export("scenario_A_indexer_export.json")

    print(f"Bénin : {len(df_benin)} flux | Malveillant : {len(df_attaque)} flux")

    df_all = pd.concat([df_benin, df_attaque], ignore_index=True)
    contamination_estimee = df_all["label"].mean()
    print(f"Contamination estimée : {contamination_estimee:.3%}")

    df_all, feature_cols = build_features(df_all)
    df_all, model, scaler = train_isolation_forest(df_all, feature_cols, contamination_estimee)

    metrics = evaluate(df_all)
    df_all.to_csv("results/isolation_forest_scenario_A_scores.csv", index=False)
