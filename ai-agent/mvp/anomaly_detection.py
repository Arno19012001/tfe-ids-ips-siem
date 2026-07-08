"""
anomaly_detection.py — Détection d'anomalies (Isolation Forest) sur trafic Suricata
TFE IDS/IPS & SIEM — Issue #15 — v8 (modèle par service)

Historique : v1 (biais mesure alert/flow) -> v2 (temporel) -> v3 (diversité
hôtes) -> v4 (eve.json malveillant complet, 600 flux) -> v5 (seuil F1, biaisé
par évaluation sur le même ensemble) -> v6 (split train/val/test, révèle 77%
de FP réels) -> v7 (capture bénin 12h, 2628 flux — le taux de FP ne baisse
quasiment pas : 76.81%, confirmant que le volume seul ne résout pas le
problème) -> v8 : le bénin mélange deux profils structurellement différents
(HTTP avec échanges de données réels, SSH qui échoue systématiquement avec
quasiment aucun octet) que demander à UN SEUL modèle générique d'apprendre
comme une notion unique de normalité pousse à se chevaucher avec le
comportement du scan. Remplacé par un modèle Isolation Forest DISTINCT par
port de destination observé dans le bénin d'entraînement — chaque modèle
apprend une notion de normalité cohérente pour un seul service, plutôt
qu'un compromis flou entre plusieurs profils incompatibles. Un port jamais
observé dans le bénin d'entraînement (ex. FTP 21, HTTPS 443, présents
uniquement côté malveillant) est automatiquement considéré comme anomalie,
sans même nécessiter de modèle pour ce cas.
"""

import os
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


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


def _distinct_dest_ip_sliding_window(group: pd.DataFrame, window_seconds: int = 60) -> np.ndarray:
    ts = group["ts"].to_numpy()
    dest_ips = group["dest_ip"].to_numpy()
    window = pd.Timedelta(seconds=window_seconds).to_numpy()

    result = np.zeros(len(group), dtype=int)
    counts = {}
    distinct = 0
    left = 0

    for right in range(len(group)):
        d = dest_ips[right]
        counts[d] = counts.get(d, 0) + 1
        if counts[d] == 1:
            distinct += 1

        while ts[right] - ts[left] > window:
            dl = dest_ips[left]
            counts[dl] -= 1
            if counts[dl] == 0:
                distinct -= 1
            left += 1

        result[right] = distinct

    return result


def build_features(df: pd.DataFrame):
    df = df.copy()
    for col in ["dest_port", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["dest_port"] = df["dest_port"].astype(int)
    df["total_bytes"] = df["bytes_toserver"] + df["bytes_toclient"]
    df["total_pkts"] = df["pkts_toserver"] + df["pkts_toclient"]
    df["bytes_ratio"] = df["bytes_toserver"] / df["total_bytes"].replace(0, 1)

    df["ts"] = pd.to_datetime(df["start"], errors="coerce", utc=True)
    df = df.sort_values(["src_ip", "ts"]).reset_index(drop=True)

    diversity = np.zeros(len(df), dtype=int)
    for _, group in df.groupby("src_ip"):
        diversity[group.index.to_numpy()] = _distinct_dest_ip_sliding_window(group)
    df["distinct_dest_ip_60s"] = diversity

    # dest_port retiré des features des sous-modèles : il devient la clé de
    # regroupement elle-même (constant au sein de chaque modèle par service),
    # donc non informatif à l'intérieur d'un sous-modèle.
    service_feature_cols = ["total_bytes", "total_pkts", "bytes_ratio", "distinct_dest_ip_60s"]
    return df, service_feature_cols


def train_per_service(df_benin_train: pd.DataFrame, feature_cols: list, min_samples: int = 20, contamination: float = 0.05):
    """Un modèle Isolation Forest distinct par port de destination observé dans le bénin d'entraînement."""
    models = {}
    for port in df_benin_train["dest_port"].unique():
        subset = df_benin_train[df_benin_train["dest_port"] == port]
        if len(subset) < min_samples:
            print(f"  Port {port} : {len(subset)} échantillons, insuffisant (< {min_samples}) — ignoré")
            continue
        X = subset[feature_cols].values
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        model.fit(X_scaled)
        models[port] = (model, scaler)
        print(f"  Port {port} : modèle entraîné sur {len(subset)} échantillons")
    return models


def score_per_service(df: pd.DataFrame, feature_cols: list, models: dict) -> pd.DataFrame:
    """
    Score chaque flux avec le modèle de SON port. Un port jamais observé dans
    le bénin d'entraînement reçoit un score -inf (anomalie automatique,
    quel que soit le seuil retenu ensuite).
    """
    df = df.copy()
    df["anomaly_score"] = -np.inf
    for port, (model, scaler) in models.items():
        mask = df["dest_port"] == port
        if mask.sum() == 0:
            continue
        X_scaled = scaler.transform(df.loc[mask, feature_cols].values)
        df.loc[mask, "anomaly_score"] = model.decision_function(X_scaled)
    return df


def find_best_threshold(df_val: pd.DataFrame):
    """
    Seuil maximisant le F1-score sur l'ensemble de VALIDATION. La grille de
    recherche est bornée sur les scores réels (ports connus) uniquement ;
    les lignes -inf (port jamais vu en bénin) sont toujours comptées comme
    anomalie, quel que soit le seuil testé, et participent donc à l'évaluation
    du F1 sans fausser la grille de recherche elle-même.
    """
    known = df_val[np.isfinite(df_val["anomaly_score"])]
    if known.empty:
        thresholds = [0.0]
    else:
        thresholds = np.linspace(known["anomaly_score"].min(), known["anomaly_score"].max(), 200)

    best_f1, best_threshold = -1, None
    for t in thresholds:
        pred = (df_val["anomaly_score"] < t).astype(int)
        tp = ((pred == 1) & (df_val["label"] == 1)).sum()
        fp = ((pred == 1) & (df_val["label"] == 0)).sum()
        fn = ((pred == 0) & (df_val["label"] == 1)).sum()
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        if f1 > best_f1:
            best_f1, best_threshold = f1, t

    return best_threshold, best_f1


def evaluate_at_threshold(df: pd.DataFrame, threshold: float, label_ensemble: str):
    pred = (df["anomaly_score"] < threshold).astype(int)
    tp = ((pred == 1) & (df["label"] == 1)).sum()
    fp = ((pred == 1) & (df["label"] == 0)).sum()
    fn = ((pred == 0) & (df["label"] == 1)).sum()
    tn = ((pred == 0) & (df["label"] == 0)).sum()
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fp_rate_benin = fp / (fp + tn) if (fp + tn) else 0

    print(f"--- {label_ensemble} ---")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Précision={precision:.2%}  Rappel={recall:.2%}  F1={f1:.2%}")
    print(f"Taux de FP sur bénin isolé={fp_rate_benin:.2%} (sur {fp + tn} échantillons bénins)")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall,
            "f1": f1, "fp_rate_benin": fp_rate_benin}


if __name__ == "__main__":
    df_benin = load_flows_from_eve_json("eve_baseline_benin.json", label=0)
    df_attaque = load_flows_from_eve_json("eve_scenario_A_complet.json", label=1, filter_src_ip="192.168.1.50")
    print(f"Bénin : {len(df_benin)} flux | Malveillant : {len(df_attaque)} flux")

    df_all = pd.concat([df_benin, df_attaque], ignore_index=True)
    df_all, feature_cols = build_features(df_all)

    df_benin_shuf = df_all[df_all["label"] == 0].sample(frac=1, random_state=42).reset_index(drop=True)
    n = len(df_benin_shuf)
    split_train, split_val = int(n * 0.6), int(n * 0.8)
    df_benin_train = df_benin_shuf.iloc[:split_train]
    df_benin_val = df_benin_shuf.iloc[split_train:split_val]
    df_benin_test = df_benin_shuf.iloc[split_val:]

    df_attaque_shuf = df_all[df_all["label"] == 1].sample(frac=1, random_state=42).reset_index(drop=True)
    m = len(df_attaque_shuf)
    split_att = int(m * 0.5)
    df_attaque_val = df_attaque_shuf.iloc[:split_att]
    df_attaque_test = df_attaque_shuf.iloc[split_att:]

    print(f"Split bénin : train={len(df_benin_train)} val={len(df_benin_val)} test={len(df_benin_test)}")
    print(f"Split malveillant : val={len(df_attaque_val)} test={len(df_attaque_test)}")
    print(f"\nPorts bénins observés à l'entraînement : {sorted(df_benin_train['dest_port'].unique().tolist())}")
    print(f"Ports malveillants observés (val+test) : {sorted(df_attaque_shuf['dest_port'].unique().tolist())}\n")

    print("Entraînement des modèles par service :")
    models = train_per_service(df_benin_train, feature_cols)

    df_val = pd.concat([df_benin_val, df_attaque_val], ignore_index=True)
    df_val = score_per_service(df_val, feature_cols, models)
    best_threshold, val_f1 = find_best_threshold(df_val)
    print(f"\nSeuil optimal (choisi sur validation) : {best_threshold:.4f} (F1 validation={val_f1:.2%})\n")

    df_test = pd.concat([df_benin_test, df_attaque_test], ignore_index=True)
    df_test = score_per_service(df_test, feature_cols, models)
    metrics_test = evaluate_at_threshold(df_test, best_threshold, "TEST (seuil non vu à son propre calcul)")

    os.makedirs("results", exist_ok=True)
    df_test.to_csv("results/isolation_forest_scenario_A_scores.csv", index=False)
