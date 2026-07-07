"""
anomaly_detection.py — Détection d'anomalies (Isolation Forest) sur trafic Suricata
TFE IDS/IPS & SIEM — Issue #15 — v7 (calcul de features optimisé pour gros volumes)

Historique : v1 (biais mesure alert/flow) -> v2 (temporel) -> v3 (diversité
hôtes, échantillon trop petit) -> v4 (eve.json malveillant complet, 600 flux,
entraînement sur profil de normalité) -> v5 (seuil empirique F1, mais choisi
sur le même ensemble que le test) -> v6 (split entraînement/validation/test,
baseline enrichi 729 flux/45min — révèle un taux de FP réel de 77% sur le
bénin, démontrant que le résultat v5 était en grande partie un artefact de
l'évaluation) -> v7 : remplacement de la boucle O(n²) de calcul de diversité
des hôtes de destination par une fenêtre glissante O(n) par groupe (deux
pointeurs + compteur), nécessaire pour absorber le volume d'une capture de
baseline de 12h (plusieurs milliers de flux attendus, contre 729 en v6).
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
    """
    Calcule, pour chaque ligne d'un groupe (déjà trié par ts), le nombre
    d'adresses IP de destination distinctes contactées dans les `window_seconds`
    précédentes — via une fenêtre glissante à deux pointeurs (O(n) amorti),
    au lieu de reconstruire un masque sur tout le DataFrame à chaque ligne (O(n²)).
    """
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
    df["is_wellknown_dport"] = (df["dest_port"] < 1024).astype(int)
    df["total_bytes"] = df["bytes_toserver"] + df["bytes_toclient"]
    df["total_pkts"] = df["pkts_toserver"] + df["pkts_toclient"]
    df["bytes_ratio"] = df["bytes_toserver"] / df["total_bytes"].replace(0, 1)

    df["ts"] = pd.to_datetime(df["start"], errors="coerce", utc=True)
    df = df.sort_values(["src_ip", "ts"]).reset_index(drop=True)

    # Fenêtre glissante calculée séparément par IP source (groupby), puis
    # réassemblée dans l'ordre d'origine du DataFrame via l'index.
    diversity = np.zeros(len(df), dtype=int)
    for _, group in df.groupby("src_ip"):
        diversity[group.index.to_numpy()] = _distinct_dest_ip_sliding_window(group)
    df["distinct_dest_ip_60s"] = diversity

    feature_cols = [
        "dest_port", "is_wellknown_dport", "total_bytes",
        "total_pkts", "bytes_ratio", "distinct_dest_ip_60s",
    ]
    return df, feature_cols


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
    return df


def find_best_threshold(df_val: pd.DataFrame):
    """Recherche du seuil maximisant le F1-score, sur l'ensemble de VALIDATION uniquement."""
    thresholds = np.linspace(df_val["anomaly_score"].min(), df_val["anomaly_score"].max(), 200)
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

    model, scaler = train_on_benign_only(df_benin_train, feature_cols, contamination=0.05)

    df_val = pd.concat([df_benin_val, df_attaque_val], ignore_index=True)
    df_val = score(df_val, feature_cols, model, scaler)
    best_threshold, val_f1 = find_best_threshold(df_val)
    print(f"\nSeuil optimal (choisi sur validation) : {best_threshold:.4f} (F1 validation={val_f1:.2%})\n")

    df_test = pd.concat([df_benin_test, df_attaque_test], ignore_index=True)
    df_test = score(df_test, feature_cols, model, scaler)
    metrics_test = evaluate_at_threshold(df_test, best_threshold, "TEST (seuil non vu à son propre calcul)")

    os.makedirs("results", exist_ok=True)
    df_test.to_csv("results/isolation_forest_scenario_A_scores.csv", index=False)
