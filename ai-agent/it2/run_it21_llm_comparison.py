"""
run_it21_llm_comparison.py — Issue #21, étape 3/3
Invocation manuelle de run_llm_batch() (non appelée dans __main__ de
alert_prioritization.py, coût de temps trop élevé pour un run par défaut)
et comparaison finale SCORE SEUL vs SCORE + LLM.

Durée estimée : 20-35 min en CPU-only. Reprise sur interruption automatique
via checkpoint CSV (/opt/ai-agent/it2/llm_batch_checkpoint.csv) — si le
script est interrompu, le relancer tel quel reprend là où il s'est arrêté.
"""

from alert_prioritization import (
    fetch_alerts_from_indexer,
    group_alerts_by_incident,
    aggregate_incident_features,
    compute_composite_score,
    find_optimal_thresholds,
    evaluate_precision,
    run_llm_batch,
    EXCLUDED_RULE_IDS,
    GROUND_TRUTH_LABELS,
)

df = fetch_alerts_from_indexer()
print(f"Alertes récupérées : {len(df)}")

df_excluded = df[df["rule_id"].isin(EXCLUDED_RULE_IDS)]
df_scope = df[~df["rule_id"].isin(EXCLUDED_RULE_IDS)].copy()
df_scope["ground_truth"] = df_scope["rule_id"].map(GROUND_TRUTH_LABELS)

df_grouped = group_alerts_by_incident(df_scope)
df_incidents = aggregate_incident_features(df_grouped)
df_incidents = compute_composite_score(df_incidents)

print(f"{len(df_incidents)} incidents disponibles.")

calibration = find_optimal_thresholds(df_incidents)
print(f"Seuil haute    : {calibration['threshold_haute']:.3f}")
print(f"Seuil critique : {calibration['threshold_critique']:.3f}")

print("\n=== Lancement run_llm_batch() ===")
df_llm = run_llm_batch(df_incidents)

df_incidents_merged = df_incidents.merge(df_llm, on="incident_id")

print("\n=== Évaluation : SCORE SEUL (rappel) ===")
evaluate_precision(
    df_incidents,
    threshold_haute=calibration["threshold_haute"],
    threshold_critique=calibration["threshold_critique"],
)

print("\n=== Évaluation : SCORE + LLM ===")
evaluate_precision(
    df_incidents_merged,
    threshold_haute=calibration["threshold_haute"],
    threshold_critique=calibration["threshold_critique"],
    llm_column="llm_niveau",
)

output_path = "/opt/ai-agent/it2/incidents_score_llm_final.csv"
df_incidents_merged.to_csv(output_path, index=False)
print(f"\nRésultats complets (score + LLM, par incident) sauvegardés dans {output_path}")
