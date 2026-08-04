"""
kill_chain_report.py — Reconstruction textuelle partielle de la kill chain
TFE IDS/IPS & SIEM — Issue #23 — v2

Réutilise les briques de alert_prioritization.py (Issues #21/#22) :
groupement par incident (group_alerts_by_incident) et le patron
LangChain + ChatOllama + with_structured_output déjà validé pour
classify_with_llm().

Portée couverte : 2 étapes uniquement (Reconnaissance -> Initial Access),
correspondant à l'enchaînement Scénario A (scan Nmap, technique MITRE
T1046) -> Scénario B (brute force SSH abouti, T1110.001 + T1078), détecté
par la règle de corrélation Wazuh 100051 (Issue #22). Ce n'est PAS une
reconstruction de la kill chain complète (modèle Lockheed Martin à
7 étapes) : présenté explicitement comme partiel dans le rapport généré,
conformément au titre de l'Issue #23.

CORRECTIF v2 (04/08/2026) — suite au premier run empirique (latence
268,1s, incident 192.168.1.50__9) :

1. Wazuh résout TOUTES les tactiques ATT&CK associées à chaque technique
   déclarée dans <mitre> d'une règle, pas une seule (contrairement à
   l'hypothèse implicite de la v1). Ex. la règle 100051 (T1046 +
   T1110.001 + T1078) résout vers 6 tactiques distinctes : Discovery,
   Credential Access, Defense Evasion, Persistence, Privilege Escalation,
   Initial Access. La règle 100050 (T1046 seul) résout uniquement vers
   Discovery.

2. Le premier rapport généré a substitué "Initial Access" à la tactique
   réellement fournie pour la règle 100050 ("Discovery") — le modèle a
   remplacé le libellé empirique par une étiquette qu'il jugeait plus
   pédagogique pour désigner une reconnaissance, en violation de la
   règle anti-hallucination du prompt v1. Correctif : règle de prompt
   renforcée, imposant la recopie EXACTE du libellé fourni.

3. Le résumé narratif du premier rapport minimisait le succès de la
   compromission SSH ("une tentative de compromission"), alors que la
   règle 100051 documente un succès confirmé (if_sid=40112,
   "authentication failures followed by a success"). La v1 ne
   transmettait aucun indicateur explicite de succès au LLM — correctif :
   ajout d'un indicateur attack_success_label dans le prompt, réutilisant
   contains_attack_success (déjà calculé par aggregate_incident_features,
   même patron que classify_with_llm() pour ce champ).

Ces deux correctifs n'ont pas encore été validés empiriquement sur un
second run — à faire avant de clôturer l'Issue #23.
"""

import time
from typing import Optional

import pandas as pd
from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

from alert_prioritization import (
    fetch_alerts_from_indexer,
    EXCLUDED_RULE_IDS,
    GROUND_TRUTH_LABELS,
    group_alerts_by_incident,
    aggregate_incident_features,
    LLM_MODEL_NAME,
)


def list_kill_chain_incidents(df_incidents: pd.DataFrame) -> pd.DataFrame:
    """Incidents où la règle de corrélation 100051 a fait passer contains_kill_chain à True."""
    return df_incidents[df_incidents["contains_kill_chain"]].copy()


def build_kill_chain_timeline(df_grouped: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    """
    Reconstruit la chronologie détaillée d'un incident depuis les alertes
    individuelles (df_grouped, sortie de group_alerts_by_incident), en
    conservant les métadonnées MITRE par alerte — perdues lors de
    l'agrégation faite par aggregate_incident_features().
    """
    incident_alerts = df_grouped[df_grouped["incident_id"] == incident_id].copy()
    incident_alerts = incident_alerts.sort_values("timestamp_dt")

    timeline = []
    for _, row in incident_alerts.iterrows():
        timeline.append({
            "timestamp": row["timestamp_dt"],
            "rule_id": row["rule_id"],
            "rule_description": row["rule_description"],
            "rule_groups": row["rule_groups"],
            "mitre_id": row["mitre_id"] if isinstance(row["mitre_id"], list) else [],
            "mitre_technique": row["mitre_technique"] if isinstance(row["mitre_technique"], list) else [],
            "mitre_tactic": row["mitre_tactic"] if isinstance(row["mitre_tactic"], list) else [],
        })

    return pd.DataFrame(timeline)


def _format_timeline_for_prompt(df_timeline: pd.DataFrame) -> str:
    """
    Formate la chronologie en texte, avec offset relatif au premier
    événement. Le champ tactique(s) est explicitement étiqueté pour que
    le prompt puisse imposer sa recopie exacte (cf. correctif v2 point 2).
    """
    if df_timeline.empty:
        return "(aucune alerte)"
    t0 = df_timeline["timestamp"].min()
    lines = []
    for _, row in df_timeline.iterrows():
        offset = (row["timestamp"] - t0).total_seconds()
        mitre_ids = ", ".join(row["mitre_id"]) if row["mitre_id"] else "N/A"
        tactics = ", ".join(row["mitre_tactic"]) if row["mitre_tactic"] else "N/A"
        lines.append(
            f"- t+{offset:.0f}s | règle {row['rule_id']} ({row['rule_description']}) "
            f"| groupes: {', '.join(row['rule_groups'])} | technique(s) MITRE: {mitre_ids} "
            f"| tactique(s) MITRE fournie(s) pour cette règle: {tactics}"
        )
    return "\n".join(lines)


class EtapeKillChain(BaseModel):
    ordre: int = Field(description="Position chronologique de l'étape (1, 2, ...)")
    tactique_mitre: str = Field(
        description="Tactique(s) MITRE ATT&CK de cette étape, RECOPIÉE(S) EXACTEMENT depuis le "
                    "champ 'tactique(s) MITRE fournie(s)' de la chronologie fournie en contexte, "
                    "sans aucune reformulation ni substitution"
    )
    techniques_mitre: str = Field(
        description="Identifiant(s) de technique MITRE ATT&CK associés (ex. T1046, T1110.001), "
                    "tels que fournis dans le contexte"
    )
    description: str = Field(
        description="Description factuelle et concise (1-2 phrases) de ce qui a été observé à "
                    "cette étape, basée uniquement sur les alertes fournies"
    )


class RapportKillChain(BaseModel):
    etapes: list[EtapeKillChain] = Field(
        description="Étapes de la kill chain, dans l'ordre chronologique"
    )
    resume_narratif: str = Field(
        description="Résumé narratif de 3 à 5 phrases en français, pour un analyste SOC, "
                    "décrivant l'enchaînement complet de l'attaque, reflétant fidèlement le "
                    "statut de compromission indiqué dans le contexte (ne pas minimiser un "
                    "succès confirmé en le présentant comme une simple tentative)"
    )
    limite_couverture: str = Field(
        description="Rappel explicite, en une phrase, que cette reconstruction ne couvre que "
                    "les étapes effectivement détectées, pas la kill chain complète"
    )


KILLCHAIN_SYSTEM_PROMPT = """Tu es un analyste SOC chargé de rédiger un rapport de reconstruction de kill chain à partir d'une chronologie d'alertes SIEM déjà corrélées.

RÈGLES STRICTES, à respecter impérativement :
1. Ne t'appuie QUE sur les alertes et métadonnées MITRE ATT&CK fournies dans le contexte. N'invente JAMAIS d'étape, de tactique ou de technique absente des alertes listées.
2. Pour le champ tactique_mitre de chaque étape, RECOPIE EXACTEMENT le ou les libellé(s) de tactique fourni(s) dans la chronologie pour la ou les règles correspondantes (champ "tactique(s) MITRE fournie(s) pour cette règle"). Ne substitue JAMAIS ce libellé par une tactique que tu juges plus appropriée, plus intuitive ou plus pédagogique — même si le libellé fourni te semble contre-intuitif pour l'étape concernée (ex. ne remplace pas "Discovery" par "Initial Access" pour décrire une reconnaissance : recopie "Discovery" tel quel).
3. Si l'indicateur "Statut de compromission selon le SIEM" indique un succès confirmé, le résumé narratif DOIT refléter ce succès sans l'atténuer (ne pas écrire "tentative" si le SIEM documente un accès obtenu).
4. Ne complète PAS la séquence avec des étapes hypothétiques du modèle Cyber Kill Chain (Weaponization, Delivery, C2, Actions on Objectives, etc.) si elles ne sont pas détectées empiriquement — documenter que la reconstruction reste PARTIELLE fait partie de l'objectif de ce rapport.
5. Chaque étape du rapport correspond à un regroupement d'alertes par rôle dans l'attaque, dans l'ordre chronologique.
6. Reste factuel et concis. Le résumé narratif s'adresse à un analyste SOC, pas à un public non technique.

Réponds uniquement selon le format structuré demandé, en français."""

KILLCHAIN_HUMAN_PROMPT_TEMPLATE = """Chronologie d'alertes corrélées pour l'incident {incident_id} (source : {grouping_key}) :

{timeline_text}

Statut de compromission selon le SIEM : {attack_success_label}

Génère le rapport de reconstruction de kill chain pour cet incident, à partir uniquement des alertes et du statut de compromission ci-dessus."""


def generate_kill_chain_report(
    incident_row: pd.Series,
    df_grouped: pd.DataFrame,
    model_name: str = LLM_MODEL_NAME,
) -> dict:
    """
    Génère un rapport structuré de reconstruction partielle de la kill
    chain, via LangChain + Ollama (même patron que classify_with_llm(),
    Issue #21).

    incident_row : ligne de df_incidents (sortie de
    aggregate_incident_features), utilisée pour incident_id et
    contains_attack_success. Ne transmet pas incident_ground_truth,
    même logique de séparation que classify_with_llm().
    """
    incident_id = incident_row["incident_id"]
    df_timeline = build_kill_chain_timeline(df_grouped, incident_id)
    if df_timeline.empty:
        raise ValueError(f"Aucune alerte trouvée pour incident_id={incident_id}")

    grouping_key = df_grouped.loc[df_grouped["incident_id"] == incident_id, "grouping_key"].iloc[0]
    timeline_text = _format_timeline_for_prompt(df_timeline)

    attack_success_label = (
        "OUI — accès ou compromission confirmé(e) par le SIEM"
        if incident_row["contains_attack_success"]
        else "NON — pas de confirmation de succès dans les alertes disponibles"
    )

    llm = ChatOllama(model=model_name, temperature=0)
    structured_llm = llm.with_structured_output(RapportKillChain)

    prompt = ChatPromptTemplate.from_messages([
        ("system", KILLCHAIN_SYSTEM_PROMPT),
        ("human", KILLCHAIN_HUMAN_PROMPT_TEMPLATE),
    ])
    chain = prompt | structured_llm

    start = time.time()
    result = chain.invoke({
        "incident_id": incident_id,
        "grouping_key": grouping_key,
        "timeline_text": timeline_text,
        "attack_success_label": attack_success_label,
    })
    latency = time.time() - start

    return {
        "incident_id": incident_id,
        "rapport": result,
        "timeline": df_timeline,
        "latency_seconds": latency,
    }


if __name__ == "__main__":
    df = fetch_alerts_from_indexer()
    df_scope = df[~df["rule_id"].isin(EXCLUDED_RULE_IDS)].copy()
    df_scope["ground_truth"] = df_scope["rule_id"].map(GROUND_TRUTH_LABELS)

    df_grouped = group_alerts_by_incident(df_scope)
    df_incidents = aggregate_incident_features(df_grouped)

    kill_chain_incidents = list_kill_chain_incidents(df_incidents)
    print(f"{len(kill_chain_incidents)} incident(s) kill chain détecté(s) sur {len(df_incidents)}.")

    if len(kill_chain_incidents) == 0:
        print("Aucun incident kill chain disponible — vérifier que la règle 100051 a bien "
              "déclenché dans les données actuelles (cf. Issue #22).")
    else:
        target_incident_row = kill_chain_incidents.iloc[0]
        target_incident_id = target_incident_row["incident_id"]
        print(f"\nGénération du rapport pour l'incident : {target_incident_id}\n")
        output = generate_kill_chain_report(target_incident_row, df_grouped)

        print(f"Latence : {output['latency_seconds']:.1f}s\n")
        print("=== Chronologie brute ===")
        print(output["timeline"][["timestamp", "rule_id", "rule_description", "mitre_tactic"]].to_string(index=False))
        print("\n=== Rapport structuré ===")
        for etape in output["rapport"].etapes:
            print(f"  {etape.ordre}. [{etape.tactique_mitre} — {etape.techniques_mitre}] {etape.description}")
        print(f"\nRésumé narratif :\n{output['rapport'].resume_narratif}")
        print(f"\nLimite de couverture : {output['rapport'].limite_couverture}")
