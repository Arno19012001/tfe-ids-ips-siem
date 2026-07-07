"""
anomaly_detection.py — Détection d'anomalies (Isolation Forest) sur trafic Suricata
TFE IDS/IPS & SIEM — Issue #15 — v4 (méthodologie finale)

Historique : v1 (biais mesure alert/flow) -> v2 (temporel, rythme scan proche
du bénin) -> v3 (diversité hôtes, échantillon encore trop petit) -> v4 :
régénération complète du eve.json malveillant (600 flux réels contre 34
alertes throttlées auparavant, cf. seuil `threshold` des règles Suricata),
et passage à un entraînement sur profil de normalité uniquement (usage
canonique de l'Isolation Forest), plutôt qu'un entraînement sur mélange
bénin+malveillant avec contamination dérivée du label — nécessaire de toute
façon puisque le malveillant est désormais majoritaire (contamination >50%
invalide pour scikit-learn).
"""

import os
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# --- 1. Loader unique pour les deux classes (event_type: flow) ---

def load_flows_from_eve_json(eve_json_path: str, label: int, filter_src_ip: str = None) -> pd.DataFrame:
    flows = []
    with open(eve_json_path, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "flow":
                continue
            if filter_src_ip and event.get("src_ip") != filter_src_ip:
                continue
            flow = event.get("flow", {})
            flows.append({
                "flow_id": event.get("flow_id"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
                "dest_port": event.get("dest_port"),
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "start": flow.get("start"),
                "label": label,
            })
    return pd.DataFrame(flows)


# --- 2. Feature engineering ---

def build_features(df: pd.DataFrame):
    df = df.copy()
    for col in ["dest_port", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["is_wellknown_dport"] = (df["dest_port"] < 1024).astype(int)
    df["total_bytes"] = df["bytes_toserver"] + df["bytes_toclient"]
    df["total_pkts"] = df["pkts_toserver"] + df["pkts_toclient"]
    df["bytes_ratio"] = df["bytes_toserver"] / df["total_bytes"].replace(0, 1)

    df["ts"] = pd.to_datetime(df["start"], errors="coerce", utc=True)
    df = df.sort_values("ts").reset_index(drop=True)

    distinct_dest_ips = []
    for _, row in df.iterrows():
        mask_60s = (
            (df["src_ip"] == row["src_ip"]) &
            (df["ts"] >= row["ts"] - pd.Timedelta(seconds=60)) &
            (df["ts"] <= row["ts"])
        )
        distinct_dest_ips.append(df.loc[mask_60s, "dest_ip"].nunique())
    df["distinct_dest_ip_60s"] = distinct_dest_ips

    feature_cols = [
        "dest_port", "is_wellknown_dport", "total_bytes",
        "total_pkts", "bytes_ratio", "distinct_dest_ip_60s",
    ]
    return df, feature_cols


# --- 3. Entraînement sur profil de normalité uniquement ---

def train_on_benign_only(df_benin_train: pd.DataFrame, feature_cols: list, contamination: float = 0.05):
    X = df_benin_train[feature_cols].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X_scaled)
    return model, scaler


def score(df: pd.DataFrame, feature_cols: list, model, scaler):
    X_scaled = scaler.transform(df[feature_cols].values)
    df = df.copy()
    df["anomaly_score"] = model.decision_function(X_scaled)
    df["predicted_anomaly"] = (model.predict(X_scaled) == -1).astype(int)
    return df


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
    df_benin = load_flows_from_eve_json("eve_baseline_benin.json", label=0)
    df_attaque = load_flows_from_eve_json("eve_scenario_A_complet.json", label=1, filter_src_ip="192.168.1.50")
    print(f"Bénin : {len(df_benin)} flux | Malveillant : {len(df_attaque)} flux")

    df_all = pd.concat([df_benin, df_attaque], ignore_index=True)
    df_all, feature_cols = build_features(df_all)

    df_benin_feat = df_all[df_all["label"] == 0].sample(frac=1, random_state=42)
    split = int(len(df_benin_feat) * 0.8)
    df_benin_train, df_benin_test = df_benin_feat.iloc[:split], df_benin_feat.iloc[split:]
    df_attaque_feat = df_all[df_all["label"] == 1]

    model, scaler = train_on_benign_only(df_benin_train, feature_cols, contamination=0.05)

    df_test = pd.concat([df_benin_test, df_attaque_feat], ignore_index=True)
    df_test = score(df_test, feature_cols, model, scaler)

    metrics = evaluate(df_test)

    os.makedirs("results", exist_ok=True)
    df_test.to_csv("results/isolation_forest_scenario_A_scores.csv", index=False)
