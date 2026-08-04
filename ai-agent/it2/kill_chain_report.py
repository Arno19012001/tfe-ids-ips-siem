"""
kill_chain_report.py — Reconstruction textuelle partielle de la kill chain
TFE IDS/IPS & SIEM — Issue #23 — v4

Réutilise les briques de alert_prioritization.py (Issues #21/#22) :
groupement par incident (group_alerts_by_incident) et le patron
LangChain + ChatOllama + with_structured_output déjà validé pour
classify_with_llm().

Portée couverte : 2 étapes (Reconnaissance/Discovery -> compromission
SSH/Credential Access), correspondant à l'enchaînement Scénario A (scan
Nmap) -> Scénario B (brute force SSH abouti), détecté par la règle de
corrélation Wazuh 100051 (Issue #22).

HISTORIQUE DES CORRECTIFS :

v1 (04/08/2026) : premier run empirique (incident 192.168.1.50__9,
latence 268,1s). Le LLM (Llama 3.1 8B, CPU-only) devait à la fois
segmenter les étapes ET recopier fidèlement les tactiques/techniques
MITRE fournies dans le contexte. Résultat : substitution non sollicitée
de "Initial Access" à la tactique réellement fournie pour la règle
100050 ("Discovery"), en violation de la règle anti-hallucination du
prompt.

v2 (04/08/2026) : renforcement du prompt (règle de recopie stricte +
indicateur de succès explicite attack_success_label). Second run
empirique : le problème persiste à l'identique (même substitution
Discovery -> Initial Access), ET une étape supplémentaire non désirée
apparaît ("User missed the password more than one time" isolée en
étape 3), montrant que la segmentation par le LLM n'est pas stable
d'un run à l'autre malgré temperature=0. Diagnostic : un LLM 8B local
n'est pas fiable pour de la recopie factuelle structurée fidèle, quelle
que soit la formulation du prompt — ce n'est pas un problème de prompt
engineering mais une limite du modèle sur cette tâche précise.

v3 (04/08/2026) : changement d'architecture. La segmentation en étapes
ET le calcul des tactiques/techniques MITIRE par étape sont désormais
ENTIÈREMENT déterministes (Python pur, build_kill_chain_steps()), basés
sur la structure connue et validée du lab (règle 100050 = fin de
l'étape Scénario A, règle 100051 = fin de l'étape Scénario B / clôture
de la corrélation — structure documentée depuis les Issues #12-22, pas
une inférence automatique). Le LLM ne reçoit plus la chronologie brute
alerte par alerte : il reçoit un résumé déjà segmenté et étiqueté, et
son unique tâche est de rédiger une description en français par étape
déjà numérotée, plus un résumé narratif global. Il ne peut plus
halluciner de tactique/technique puisqu'on ne lui demande plus de les
produire — même logique de séparation que compute_composite_score()
(déterministe) vs classify_with_llm() (jugement contextuel).

Effet de bord à documenter dans le rapport de TFE : les tactiques
MITRE réellement résolues par Wazuh sont "Discovery" (T1046) et
"Credential Access" (séquence SSH), pas littéralement "Reconnaissance"
et "Initial Access" comme formulé dans le titre de l'Issue #23 —
Discovery est la tactique ATT&CK officiellement associée à T1046, et
"Initial Access" n'apparaît que sur l'alerte de corrélation agrégée
100051 (résultat de l'union de TOUTES les tactiques de ses 3 techniques
déclarées T1046+T1110.001+T1078, T1078 étant une technique
multi-tactique) — pas une caractéristique propre de l'étape 2 isolée.

v4 (04/08/2026) : run empirique de v3 concluant (plus de substitution de
tactique — étape 1 strictement Discovery/T1046, comme garanti par
construction). Mais la description rédigée par le LLM pour l'étape 1
mentionnait la force brute SSH, et celle de l'étape 2 mentionnait le
scan Nmap. Ce n'est PAS une hallucination du LLM : la chronologie brute
confirme un CHEVAUCHEMENT TEMPOREL RÉEL entre les deux scénarios dans
le trafic capturé — l'alerte Suricata générique 86601 "SCENARIO_B SSH
Brute Force" apparaît dès 10:14:26, avant la dernière occurrence de la
règle 100050 (10:15:52) qui délimite la fin de l'étape 1 ; et des
alertes 86601 "SCENARIO_A Nmap ... Probe" continuent d'apparaître
jusqu'à 10:17:32, en plein milieu de l'étape 2. Résultat empirique
intéressant en soi (probablement Hydra démarré avant la fin complète
du scan Nmap dans le script d'attaque) — à mentionner dans le rapport
de TFE — mais qui polluait le texte rédigé, car build_kill_chain_steps()
transmettait au LLM TOUTES les descriptions de règles de la fenêtre
temporelle de chaque étape, y compris les alertes génériques Suricata
non taguées MITRE (86601, sans distinction de scénario au niveau du
champ description une fois filtré). Correctif : le champ "descriptions"
transmis au LLM est désormais restreint aux alertes taguées MITRE
(celles qui déterminent réellement la tactique/technique de l'étape),
via _step_dict(). nb_alertes reste un décompte honnête du volume BRUT
de la fenêtre (chevauchement inclus) ; nb_alertes_taguees_mitre est
ajouté pour rendre ce chevauchement traçable et discutable dans le
rapport plutôt que masqué.

Découverte empirique supplémentaire (v4) : la règle native Wazuh 5760
("sshd: authentication failed") porte la technique T1021.004 (Remote
Services: SSH — tactique Lateral Movement), donnée native de la base
MITRE de Wazuh, non anticipée dans la conception initiale de l'Issue
#23 (qui ne prévoyait que Discovery -> Initial Access).
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
            "rule_id": str(row["rule_id"]),
            "rule_description": row["rule_description"],
            "rule_groups": row["rule_groups"],
            "mitre_id": row["mitre_id"] if isinstance(row["mitre_id"], list) else [],
            "mitre_technique": row["mitre_technique"] if isinstance(row["mitre_technique"], list) else [],
            "mitre_tactic": row["mitre_tactic"] if isinstance(row["mitre_tactic"], list) else [],
        })

    return pd.DataFrame(timeline)


def _union_tags(sub_df: pd.DataFrame, column: str) -> list[str]:
    """Union triée, sans doublon, des valeurs d'une colonne liste (mitre_tactic ou mitre_id)."""
    values: set[str] = set()
    for tags in sub_df[column]:
        values.update(tags)
    return sorted(values)


def _step_dict(ordre: int, sub_df: pd.DataFrame) -> dict:
    """
    Construit le dictionnaire d'une étape à partir de sa fenêtre
    d'alertes brute (sub_df, non filtrée). tactiques/techniques =
    union sur TOUTE la fenêtre (signal MITRE de l'étape). descriptions
    = restreintes aux alertes taguées MITRE (celles qui déterminent
    réellement tactiques/techniques), pour éviter de transmettre au LLM
    des descriptions d'alertes génériques appartenant en réalité à
    l'autre scénario (chevauchement temporel réel, cf. docstring
    module v4). Si aucune alerte de la fenêtre n'est taguée MITRE, on
    retombe sur l'ensemble de la fenêtre plutôt que sur une liste vide.
    """
    tagged = sub_df[sub_df["mitre_tactic"].apply(lambda t: len(t) > 0)]
    source_descriptions = tagged if len(tagged) > 0 else sub_df
    return {
        "ordre": ordre,
        "rule_ids": sorted(sub_df["rule_id"].unique().tolist()),
        "tactiques": _union_tags(sub_df, "mitre_tactic"),
        "techniques": _union_tags(sub_df, "mitre_id"),
        "nb_alertes": int(len(sub_df)),
        "nb_alertes_taguees_mitre": int(len(tagged)),
        "descriptions": sorted(source_descriptions["rule_description"].unique().tolist()),
    }


def build_kill_chain_steps(df_timeline: pd.DataFrame) -> tuple[list[dict], dict]:
    """
    Segmentation DÉTERMINISTE en étapes (aucun appel LLM ici).

    Étape 1 : toutes les alertes jusqu'à la DERNIÈRE occurrence de la
    règle 100050 incluse (recon confirmée, Scénario A).
    Étape 2 : toutes les alertes suivantes jusqu'à la règle 100051
    (exclue de l'étape 2 elle-même — cf. correlation_info ci-dessous),
    Scénario B.

    tactique_mitre / techniques_mitre par étape = union triée des
    mitre_tactic / mitre_id des alertes de l'étape qui en portent.
    La règle 100051 est traitée séparément (correlation_info) : ses
    tags MITRE sont l'agrégat des DEUX étapes, pas le signal propre de
    l'étape 2, et l'inclure dans l'étape 2 fausserait sa caractérisation.

    nb_alertes (volume brut de la fenêtre temporelle) peut être
    sensiblement supérieur à nb_alertes_taguees_mitre : les deux
    scénarios se chevauchent réellement dans le trafic capturé (cf.
    docstring module v4) — des alertes génériques de l'autre scénario
    tombent dans la fenêtre temporelle sans pour autant porter de tag
    MITRE ni influencer la description rédigée de l'étape.

    Suppose un incident kill chain complet (contains_kill_chain=True) —
    lève une erreur explicite sinon plutôt qu'un résultat partiel silencieux.
    """
    df = df_timeline.sort_values("timestamp").reset_index(drop=True)

    idx_100050 = df.index[df["rule_id"] == "100050"]
    idx_100051 = df.index[df["rule_id"] == "100051"]

    if len(idx_100050) == 0 or len(idx_100051) == 0:
        raise ValueError(
            "Segmentation impossible : règle 100050 et/ou 100051 absente de la "
            "chronologie fournie — cette fonction suppose un incident kill chain "
            "complet (cf. list_kill_chain_incidents)."
        )

    cut_step1 = idx_100050.max()
    cut_step2 = idx_100051.max()

    step1_alerts = df.loc[:cut_step1]
    step2_window = df.loc[cut_step1 + 1: cut_step2]
    step2_alerts = step2_window[step2_window["rule_id"] != "100051"]
    correlation_alert = df.loc[cut_step2]

    steps = [
        _step_dict(1, step1_alerts),
        _step_dict(2, step2_alerts),
    ]

    correlation_info = {
        "rule_id": "100051",
        "description": correlation_alert["rule_description"],
        "tactiques": correlation_alert["mitre_tactic"],
        "techniques": correlation_alert["mitre_id"],
    }

    return steps, correlation_info


def _format_steps_for_prompt(steps: list[dict], correlation_info: dict) -> str:
    """Résumé texte des étapes déjà segmentées, à destination du prompt LLM."""
    lines = []
    for step in steps:
        techniques = ", ".join(step["techniques"]) if step["techniques"] else "aucune technique renseignée nativement"
        tactiques = ", ".join(step["tactiques"]) if step["tactiques"] else "aucune tactique renseignée nativement"
        lines.append(
            f"Étape {step['ordre']} :\n"
            f"- Règles Wazuh/Suricata impliquées : {', '.join(step['rule_ids'])}\n"
            f"- Tactique(s) MITRE ATT&CK : {tactiques}\n"
            f"- Technique(s) MITRE ATT&CK : {techniques}\n"
            f"- Nombre d'alertes dans la fenêtre temporelle : {step['nb_alertes']} "
            f"(dont {step['nb_alertes_taguees_mitre']} directement rattachées aux "
            f"tactiques/techniques ci-dessus — les autres sont des alertes génériques "
            f"qui tombent dans cette fenêtre sans nécessairement appartenir à cette étape)\n"
            f"- Descriptions de règles observées (alertes taguées uniquement) : "
            f"{'; '.join(step['descriptions'])}"
        )
    lines.append(
        f"\nCorrélation de kill chain confirmée par la règle Wazuh {correlation_info['rule_id']} "
        f"({correlation_info['description']})."
    )
    return "\n\n".join(lines)


class DescriptionEtape(BaseModel):
    ordre: int = Field(
        description="Doit correspondre EXACTEMENT au numéro d'étape fourni dans le contexte "
                    "(1 ou 2) — ne pas réordonner, fusionner ou ajouter d'étape"
    )
    description: str = Field(
        description="Description factuelle et concise (1-2 phrases) en français de ce qui a "
                    "été observé à cette étape, basée uniquement sur les règles, tactiques et "
                    "volumes d'alertes fournis pour cette étape"
    )


class RapportKillChain(BaseModel):
    descriptions_etapes: list[DescriptionEtape] = Field(
        description="Exactement une description par étape fournie en contexte, dans l'ordre"
    )
    resume_narratif: str = Field(
        description="Résumé narratif de 3 à 5 phrases en français, pour un analyste SOC, "
                    "décrivant l'enchaînement complet de l'attaque, reflétant fidèlement le "
                    "statut de compromission indiqué dans le contexte (ne pas minimiser un "
                    "succès confirmé en le présentant comme une simple tentative)"
    )
    limite_couverture: str = Field(
        description="Rappel explicite, en une phrase, que cette reconstruction ne couvre que "
                    "les 2 étapes fournies, pas la kill chain complète (modèle Lockheed Martin "
                    "à 7 étapes)"
    )


KILLCHAIN_SYSTEM_PROMPT = """Tu es un analyste SOC chargé de rédiger la partie textuelle d'un rapport de reconstruction de kill chain. La segmentation en étapes et les tactiques/techniques MITRE ATT&CK de chaque étape ont déjà été calculées automatiquement et te sont fournies telles quelles — ce n'est PAS ta tâche de les déterminer, de les reformuler ou de les corriger.

RÈGLES STRICTES, à respecter impérativement :
1. Ta seule tâche est de rédiger, pour chaque étape déjà numérotée, une description factuelle en français, et de rédiger un résumé narratif global.
2. N'invente JAMAIS d'étape supplémentaire, ne fusionne jamais les étapes fournies, ne modifie jamais leur numéro d'ordre.
3. Si l'indicateur "Statut de compromission selon le SIEM" indique un succès confirmé, le résumé narratif DOIT refléter ce succès sans l'atténuer (ne pas écrire "tentative" si le SIEM documente un accès obtenu).
4. Ne complète PAS la séquence avec des étapes hypothétiques du modèle Cyber Kill Chain (Weaponization, Delivery, C2, Actions on Objectives, etc.) — la reconstruction reste volontairement PARTIELLE (2 étapes), et le rappeler fait partie de l'objectif de ce rapport.
5. Reste factuel et concis. Le résumé s'adresse à un analyste SOC, pas à un public non technique.

Réponds uniquement selon le format structuré demandé, en français."""

KILLCHAIN_HUMAN_PROMPT_TEMPLATE = """Étapes de la kill chain pour l'incident {incident_id} (source : {grouping_key}), déjà segmentées et étiquetées :

{steps_summary}

Statut de compromission selon le SIEM : {attack_success_label}

Rédige la description de chaque étape ci-dessus (une description par ordre fourni), ainsi que le résumé narratif global et le rappel de limite de couverture."""


def generate_kill_chain_report(
    incident_row: pd.Series,
    df_grouped: pd.DataFrame,
    model_name: str = LLM_MODEL_NAME,
) -> dict:
    """
    Génère un rapport de reconstruction partielle de la kill chain.
    Segmentation et tags MITRE : déterministes (build_kill_chain_steps).
    Rédaction (description par étape + résumé narratif) : LangChain +
    Ollama, même patron que classify_with_llm() (Issue #21).

    incident_row : ligne de df_incidents (sortie de
    aggregate_incident_features), utilisée pour incident_id et
    contains_attack_success. Ne transmet pas incident_ground_truth,
    même logique de séparation que classify_with_llm().
    """
    incident_id = incident_row["incident_id"]
    df_timeline = build_kill_chain_timeline(df_grouped, incident_id)
    if df_timeline.empty:
        raise ValueError(f"Aucune alerte trouvée pour incident_id={incident_id}")

    steps, correlation_info = build_kill_chain_steps(df_timeline)
    grouping_key = df_grouped.loc[df_grouped["incident_id"] == incident_id, "grouping_key"].iloc[0]
    steps_summary = _format_steps_for_prompt(steps, correlation_info)

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
    llm_result = chain.invoke({
        "incident_id": incident_id,
        "grouping_key": grouping_key,
        "steps_summary": steps_summary,
        "attack_success_label": attack_success_label,
    })
    latency = time.time() - start

    # Fusion : tags MITRE déterministes (steps) + description rédigée par le LLM,
    # appariés par ordre. Si le LLM ne renvoie pas exactement une description par
    # étape (ordre manquant ou dupliqué), on le signale plutôt que de fusionner
    # silencieusement un mauvais alignement.
    descriptions_by_ordre = {d.ordre: d.description for d in llm_result.descriptions_etapes}
    missing = [step["ordre"] for step in steps if step["ordre"] not in descriptions_by_ordre]
    if missing:
        raise ValueError(
            f"Le LLM n'a pas fourni de description pour l'/les étape(s) {missing} — "
            f"reçu : {sorted(descriptions_by_ordre.keys())}, attendu : "
            f"{[s['ordre'] for s in steps]}. Réponse brute : {llm_result.descriptions_etapes}"
        )

    etapes_finales = [
        {
            "ordre": step["ordre"],
            "tactiques": step["tactiques"],
            "techniques": step["techniques"],
            "rule_ids": step["rule_ids"],
            "nb_alertes": step["nb_alertes"],
            "nb_alertes_taguees_mitre": step["nb_alertes_taguees_mitre"],
            "description": descriptions_by_ordre[step["ordre"]],
        }
        for step in steps
    ]

    return {
        "incident_id": incident_id,
        "etapes": etapes_finales,
        "resume_narratif": llm_result.resume_narratif,
        "limite_couverture": llm_result.limite_couverture,
        "correlation_info": correlation_info,
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

        print(f"Latence (rédaction LLM uniquement) : {output['latency_seconds']:.1f}s\n")
        print("=== Étapes (segmentation et tags MITRE déterministes) ===")
        for etape in output["etapes"]:
            print(f"  Étape {etape['ordre']} — règles {etape['rule_ids']} "
                  f"({etape['nb_alertes']} alertes dans la fenêtre, dont "
                  f"{etape['nb_alertes_taguees_mitre']} taguées MITRE)")
            print(f"    Tactique(s) : {', '.join(etape['tactiques']) or 'N/A'}")
            print(f"    Technique(s) : {', '.join(etape['techniques']) or 'N/A'}")
            print(f"    Description  : {etape['description']}")
        print(f"\nRésumé narratif :\n{output['resume_narratif']}")
        print(f"\nLimite de couverture : {output['limite_couverture']}")
