"""
killchain_reconstruction.py — Reconstruction automatique complète de la kill
chain (Scénarios A -> B -> C -> D)
TFE IDS/IPS & SIEM — Issue #27

ARCHITECTURE — pattern déterministe, pas agentic tool-calling
----------------------------------------------------------------------------
La segmentation en 4 phases ET le calcul des tactiques/techniques MITRE
ATT&CK sont ENTIÈREMENT déterministes (Python pur, build_phase_summaries()).
Le LLM (Llama 3.1 8B via Ollama/LangChain) ne reçoit jamais la chronologie
brute et ne produit jamais de tactique/technique ni d'horodatage : sa seule
tâche est de rédiger, en français, une description par phase déjà segmentée
et étiquetée, plus un résumé narratif global. Même séparation que
compute_composite_score()/classify_with_llm() (Issue #21) et
build_kill_chain_steps()/generate_kill_chain_report() (Issue #23).

Ce choix n'est pas une préférence a priori : il fait suite à un test
empirique documenté le 09/08/2026 de l'alternative agentic tool-calling
(fork adapté de octopus237/Agentic-AI), qui a montré sur ce matériel
CPU-only (i5-12450H, pas de GPU dédié — confirmé via lspci) :
  - hallucination de valeurs factuelles (IP, technique MITRE, horodatage
    hors période) quand les résultats d'outils étaient vides,
  - échec du protocole de tool calling natif (JSON écrit en texte brut
    au lieu d'un appel d'outil structuré),
  - temps de réponse de plusieurs dizaines de minutes (voire un run resté
    sans réponse après 30+ min), incompatible avec une génération de
    rapport rapide ou une démonstration.
Trois runs, trois modes d'échec différents — cf. ai-agent/it3/agentic_test/
pour les résultats bruts. Qwen3:8b n'a pas pu être testé jusqu'au bout
(conteneur ai-agent sans sortie DNS vers registry.ollama.ai, contournement
par copie manuelle des blobs abandonné après échecs répétés) ; de toute
façon, le facteur limitant identifié (CPU-only, pas de GPU) est indépendant
du modèle utilisé.

MAPPING SID -> PHASE / MITRE ATT&CK — source de vérité
----------------------------------------------------------------------------
Construit directement depuis les métadonnées des fichiers .rules Suricata
(images/suricata-sensor/rules/scenarios/scenario_{A,B,C,D}_*.rules), pas
depuis une inférence automatique sur les champs rule.mitre.* de Wazuh :
ces champs ne sont disponibles que pour les alertes passant par une règle
de corrélation Wazuh personnalisée (100050-100053 pour A/B/D), et
AUCUNE règle de corrélation Wazuh n'existe pour le Scénario C
(wazuh/rules/custom_rules.xml ne définit que les groupes scenario_a,
scenario_b et scenario_d) — les 6 alertes de C remontent uniquement via la
règle générique Wazuh 86601, sans tag MITRE natif au niveau Wazuh. Le
mapping SID_METADATA ci-dessous compense cette lacune en portant les
tactiques/techniques directement depuis les métadonnées Suricata,
uniformément pour les 4 scénarios.

Mapping scénario -> phase de la kill chain (confirmé avec Arno le 09/08/2026) :
  A (Nmap)              -> Reconnaissance
  B (Hydra SSH)          -> Initial Access
  C (sqlmap)              -> Execution
  D (Metasploit vsftpd)  -> Command and Control

Note sur le Scénario D et l'IP source : le SID 1000402 (effet de bord du
crash de séparation de privilèges) est un flux to_client (réponse du
serveur vers l'attaquant) — data.srcip y désigne l'hôte DMZ (10.0.10.30),
PAS l'attaquant. C'est le même phénomène qui avait nécessité same_field
flow_id plutôt que same_source_ip dans la règle Wazuh 100053. Pour ne pas
rapporter une IP source erronée, seule l'IP source des SID en direction
to_server (le déclenchement réel par l'attaquant) est retenue comme IP
attaquante de chaque phase — cf. champ "direction" dans SID_METADATA et
_attacker_ip() ci-dessous.

Note sur la CIBLE de chaque phase (ajoutée le 09/08/2026, run empirique) :
le champ agent.name ne désigne PAS l'hôte visé, mais l'agent Wazuh qui a
transmis l'alerte -- pour les 4 scénarios, détectés au niveau réseau par
Suricata, c'est systématiquement l'agent "suricata-sensor", quelle que
soit la cible réelle du trafic (constaté empiriquement : les 4 phases
affichaient "suricata-sensor" sans distinction). Par ailleurs, aucune IP
de destination n'est disponible dans l'index : wazuh/decoders/
custom_decoders.xml ne peuple que le champ statique srcip (regex dédiée,
Issue #22), pas de décodeur équivalent pour dest_ip. La cible de chaque
phase est donc portée directement par SID_METADATA (champ "target"),
construite depuis l'architecture documentée du lab (quel scénario vise
quel hôte DMZ), pas depuis un champ d'alerte qui n'existe pas ou qui ne
reflète pas la bonne information.

HYPOTHÈSE NON VÉRIFIÉE EMPIRIQUEMENT — À CONTRÔLER AVANT LE PREMIER RUN :
wazuh-alerts-* (attendu : "data.alert.signature_id", d'après le chemin XML
<field name="alert.signature_id"> utilisé par les règles de corrélation
Wazuh). VÉRIFIÉ le 09/08/2026 : le champ existe bien sous ce nom et est de
type "keyword" (chaîne) — la clause de secours en entier dans fetch_alerts()
est donc inutile en pratique, conservée sans effet de bord.

AMÉLIORATIONS v2 (09/08/2026, après premier run empirique concluant) :

1. CORRÉLATION PAR IP ATTAQUANTE (identify_campaigns()). La v1 groupait
   toutes les alertes de la fenêtre par SID en supposant implicitement une
   campagne unique : deux attaquants distincts opérant simultanément
   auraient été fusionnés silencieusement en une seule kill chain fictive.
   La reconstruction est désormais restreinte à une IP source (la campagne
   couvrant le plus de phases par défaut, ou --attacker-ip), et la présence
   d'autres sources est signalée explicitement plutôt que masquée. C'est le
   contrôle qu'effectue la règle Wazuh 100051 via <same_source_ip/>, que la
   v1 n'exploitait pas.

2. SUCCÈS CONFIRMÉ VIA LES RÈGLES DE CORRÉLATION WAZUH
   (fetch_correlation_alerts(), CORRELATION_RULES). La v1 ne distinguait pas
   une tentative d'une compromission aboutie, alors que le SIEM le sait
   déjà : les règles 100051 (kill chain A->B confirmée), 100053 (accès
   initial D corroboré) et 100055 (persistance D2, T1136.001) portent
   précisément cette information, absente des SID Suricata seuls (Suricata
   voit passer la tentative, Wazuh corrèle et confirme l'aboutissement).
   Ces règles sont interrogées séparément car elles utilisent rule.id, pas
   data.alert.signature_id.

2-bis. STATUT D'ABOUTISSEMENT À TROIS ÉTATS (correctif du 09/08/2026, sur
   remarque d'Arno après le run v2). La v2 présentait à tort toute phase
   sans corrélation comme "aucune corrélation ne confirme d'aboutissement",
   ce qui suggère un échec. C'est un raccourci logique invalide pour le
   Scénario C : AUCUNE règle de corrélation n'existe pour sqlmap dans
   custom_rules.xml, donc le SIEM ne peut structurellement PAS se prononcer
   -- une injection SQL peut très bien avoir abouti sans qu'aucune règle ne
   soit en mesure de le corroborer. Confondre absence d'instrumentation et
   preuve d'échec fausserait les conclusions du rapport. D'où trois états
   distincts (cf. PHASE_CORRELATION_COVERAGE) : "confirme" (règle
   déclenchée), "non_confirme" (règle existante n'ayant pas déclenché),
   "indetermine" (aucune règle définie pour cette phase -- A et C). Le
   prompt système interdit explicitement au LLM de conclure à un échec sur
   un statut "indetermine".

3. DÉTECTION DU CHEVAUCHEMENT TEMPOREL (_compute_overlaps()). Le premier
   run a confirmé que la Phase 2 démarre (14:25:48) AVANT la fin de la
   Phase 1 (14:35:30) — l'enchaînement n'est donc pas strictement
   séquentiel, phénomène déjà documenté dans kill_chain_report.py (Hydra
   démarré avant la fin complète du scan Nmap). Signalé explicitement dans
   la sortie plutôt que laissé implicite.

LIMITE CONNUE À DOCUMENTER DANS LE RAPPORT (pas un défaut du code) : le
mapping scénario -> phase est une simplification pédagogique alignée sur le
modèle Lockheed Martin, pas une correspondance MITRE ATT&CK stricte. Les
phases 3 (Execution) et 4 (Command and Control) portent toutes deux la
tactique TA0001_InitialAccess, héritée des métadonnées Suricata réelles.
Même nature de tension que celle déjà documentée dans kill_chain_report.py
(Discovery/Credential Access réels vs "Reconnaissance"/"Initial Access" du
titre de l'Issue #23) — à assumer et expliquer plutôt qu'à masquer par une
correspondance artificielle.

Note complémentaire sur le champ SID :
wazuh-alerts-* (attendu : "data.alert.signature_id", d'après le chemin XML
<field name="alert.signature_id"> utilisé par les règles de corrélation
Wazuh). Le mapping de ce champ (texte vs entier) n'a pas été vérifié contre
l'index réel — fetch_alerts() interroge donc à la fois en chaîne et en
entier (bool/should) pour rester robuste aux deux cas, mais un simple
GET wazuh-alerts-*/_mapping/field/data.alert.signature_id avant le premier
run confirmerait le bon comportement plutôt que de s'y fier aveuglément.
"""

import os
import sys
import json
import argparse
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Optional

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
LLM_MODEL_NAME = os.getenv("KILLCHAIN_LLM_MODEL", "llama3.1:8b")


# ---------------------------------------------------------------------------
# Mapping déterministe SID Suricata -> phase / MITRE ATT&CK
# Source : images/suricata-sensor/rules/scenarios/scenario_{A,B,C,D}_*.rules
# (ground truth relevée le 09/08/2026, pas une inférence automatique)
# ---------------------------------------------------------------------------

PHASE_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Command and Control"]

SID_METADATA = {
    # Scénario A -- Reconnaissance
    "1000101": {"scenario": "A", "phase": "Reconnaissance",
                "tactic": "TA0007_Discovery", "technique": "T1046",
                "direction": "to_server",
                "target": "DMZ_NET (10.0.10.0/24) -- balayage réseau, pas un hôte unique",
                "description": "SCENARIO_A Nmap SYN Scan Detected"},
    "1000104": {"scenario": "A", "phase": "Reconnaissance",
                "tactic": "TA0007_Discovery", "technique": "T1046",
                "direction": "to_server",
                "target": "DMZ_NET (10.0.10.0/24) -- balayage réseau, pas un hôte unique",
                "description": "SCENARIO_A Nmap Service/Version Detection Probe"},

    # Scénario B -- Initial Access
    "1000201": {"scenario": "B", "phase": "Initial Access",
                "tactic": "TA0006_CredentialAccess", "technique": "T1110.001",
                "direction": "to_server",
                "target": "ssh-eurostar (10.0.10.20:22)",
                "description": "SCENARIO_B SSH Brute Force - High Connection Rate"},

    # Scénario C -- Execution
    "1000301": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLMAP User-Agent Detected"},
    "1000302": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLI UNION SELECT Pattern"},
    "1000303": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLI Quote/Boolean Injection Pattern"},
    "1000304": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLI Time-Based Blind Pattern"},
    "1000305": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0009_Collection", "technique": "T1213",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLMAP Campaign - High Request Volume"},
    "1000306": {"scenario": "C", "phase": "Execution",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "web-eurostar (10.0.10.10:80/443)",
                "description": "SCENARIO_C SQLI MySQL Error-Based Function Pattern"},

    # Scénario D -- Command and Control
    "1000401": {"scenario": "D", "phase": "Command and Control",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_server",
                "target": "metasploitable2 (10.0.10.30:21)",
                "description": "SCENARIO_D VSFTPD 2.3.4 Backdoor Trigger"},
    "1000402": {"scenario": "D", "phase": "Command and Control",
                "tactic": "TA0001_InitialAccess", "technique": "T1190",
                "direction": "to_client",  # effet de bord -- pas l'IP attaquante, cf. docstring
                "target": "metasploitable2 (10.0.10.30:21)",
                "description": "SCENARIO_D VSFTPD Privilege Separation Crash"},
}

ALL_SIDS = list(SID_METADATA.keys())


# ---------------------------------------------------------------------------
# Règles de corrélation Wazuh (wazuh/rules/custom_rules.xml)
# Ces règles portent la notion de SUCCÈS CONFIRMÉ, absente des SID Suricata
# seuls : Suricata voit passer une tentative, Wazuh corrèle et confirme
# l'aboutissement. Interrogées séparément car elles utilisent le champ
# rule.id (règle Wazuh), pas data.alert.signature_id (SID Suricata).
# ---------------------------------------------------------------------------

CORRELATION_RULES = {
    "100051": {
        "phase": "Initial Access",
        "level": 15,
        "meaning": "Kill chain confirmée : reconnaissance (Scénario A) suivie d'une "
                   "compromission SSH par force brute aboutie (Scénario B)",
        "confirms_success": True,
    },
    "100053": {
        "phase": "Command and Control",
        "level": 15,
        "meaning": "Accès initial confirmé : backdoor VSFTPD déclenchée ET crash de "
                   "séparation de privilèges observé sur le même flux (Scénario D)",
        "confirms_success": True,
    },
    "100055": {
        "phase": "Command and Control",
        "level": 10,
        "meaning": "Persistance : nouvel utilisateur système créé sur metasploitable2 "
                   "(T1136.001, piste D2 via forward syslog)",
        "confirms_success": True,
    },
}

CORRELATION_RULE_IDS = list(CORRELATION_RULES.keys())


# ---------------------------------------------------------------------------
# Couverture de corrélation par phase — distinction ESSENTIELLE
#
# Une phase sans alerte de corrélation Wazuh peut relever de DEUX situations
# radicalement différentes, qu'il serait faux de présenter identiquement :
#
#   (a) une règle de corrélation EXISTE pour cette phase mais n'a pas
#       déclenché -> l'aboutissement n'est effectivement pas confirmé ;
#   (b) AUCUNE règle de corrélation n'a été définie pour cette phase ->
#       le SIEM n'est tout simplement pas instrumenté pour se prononcer,
#       ce qui ne dit RIEN sur le succès ou l'échec réel de l'attaque.
#
# Le cas (b) concerne le Scénario C (sqlmap) : custom_rules.xml ne définit
# aucune règle de corrélation pour ses 6 SID (groupes scenario_a, scenario_b
# et scenario_d uniquement). Une injection SQL peut parfaitement avoir
# abouti sans qu'aucune règle Wazuh ne soit en mesure de le corroborer.
# Il concerne aussi le Scénario A : la reconnaissance n'a pas de notion
# d'"aboutissement" corrélable en soi (la règle 100050 isole le SID 1000101
# pour alimenter la corrélation 100051, elle ne confirme pas un succès).
#
# Conclure "non abouti" à partir de (b) serait une erreur de raisonnement
# (absence de preuve confondue avec preuve d'absence) — d'où ce mapping
# explicite plutôt qu'un simple booléen.
# ---------------------------------------------------------------------------

PHASE_CORRELATION_COVERAGE = {
    "Reconnaissance": {
        "instrumentee": False,
        "note": "aucune règle de corrélation Wazuh ne statue sur l'aboutissement "
                "d'une phase de reconnaissance (la règle 100050 isole le SID 1000101 "
                "pour alimenter la corrélation 100051, elle ne confirme pas un succès)",
    },
    "Initial Access": {
        "instrumentee": True,
        "note": "règle 100051 (corrélation A->B avec same_source_ip) capable de "
                "confirmer une compromission SSH aboutie",
    },
    "Execution": {
        "instrumentee": False,
        "note": "AUCUNE règle de corrélation Wazuh n'existe pour le Scénario C "
                "(sqlmap) — le SIEM n'est pas instrumenté pour statuer sur "
                "l'aboutissement d'une injection SQL dans ce lab",
    },
    "Command and Control": {
        "instrumentee": True,
        "note": "règles 100053 (backdoor VSFTPD + crash corrélés sur le même flow_id) "
                "et 100055 (création d'utilisateur, persistance) capables de confirmer "
                "un aboutissement",
    },
}


# ---------------------------------------------------------------------------
# Récupération des alertes (Indexer OpenSearch, port 9200)
# ---------------------------------------------------------------------------

def fetch_alerts(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_alerts: int = 5000,
    page_size: int = 500,
) -> pd.DataFrame:
    """
    Récupère les alertes des 4 scénarios (filtrage sur data.alert.signature_id
    parmi ALL_SIDS) dans la fenêtre temporelle donnée. Requête défensive :
    interroge le champ à la fois en chaîne et en entier (cf. hypothèse non
    vérifiée en docstring de module) via un bool/should.
    """
    range_filter = None
    if start_time or end_time:
        range_filter = {"range": {"timestamp": {}}}
        if start_time:
            range_filter["range"]["timestamp"]["gte"] = start_time
        if end_time:
            range_filter["range"]["timestamp"]["lte"] = end_time

    sid_filter = {
        "bool": {
            "should": [
                {"terms": {"data.alert.signature_id": ALL_SIDS}},
                {"terms": {"data.alert.signature_id": [int(s) for s in ALL_SIDS]}},
                {"terms": {"data.alert.signature_id.keyword": ALL_SIDS}},
            ],
            "minimum_should_match": 1,
        }
    }

    must = [sid_filter]
    if range_filter:
        must.append(range_filter)
    base_query = {"bool": {"must": must}}

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
        data = src.get("data", {})
        alert = data.get("alert", {})
        agent = src.get("agent", {})

        sid = str(alert.get("signature_id", "")).strip()
        if sid not in SID_METADATA:
            continue  # sécurité : ne garder que les SID connus, malgré le filtre requête

        meta = SID_METADATA[sid]
        records.append({
            "doc_id": hit["_id"],
            "timestamp": src.get("timestamp"),
            "sid": sid,
            "scenario": meta["scenario"],
            "phase": meta["phase"],
            "tactic": meta["tactic"],
            "technique": meta["technique"],
            "direction": meta["direction"],
            "target": meta["target"],
            "rule_description": meta["description"],
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "src_ip": data.get("srcip"),
            # Pas de champ "dest_ip"/"destip" : le décodeur personnalisé
            # (wazuh/decoders/custom_decoders.xml, Issue #22) ne peuple que
            # srcip, aucun décodeur équivalent n'existe pour la destination.
            # La cible réelle vient de SID_METADATA["target"] (déterministe),
            # pas d'un champ d'alerte -- cf. docstring de module.
        })

    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Segmentation déterministe en 4 phases (aucun appel LLM ici)
# ---------------------------------------------------------------------------

def fetch_correlation_alerts(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_alerts: int = 500,
) -> pd.DataFrame:
    """
    Récupère les alertes des règles de CORRÉLATION Wazuh (rule.id dans
    CORRELATION_RULE_IDS) sur la fenêtre donnée.

    Distinct de fetch_alerts() : celles-ci portent la notion de succès
    confirmé (une kill chain A->B réellement aboutie, un accès initial D
    corroboré), que les SID Suricata seuls ne permettent pas d'établir.
    Sans ça, le rapport ne pourrait pas distinguer une tentative d'une
    compromission réussie -- alors que le SIEM, lui, le sait déjà.
    """
    must = [{"terms": {"rule.id": CORRELATION_RULE_IDS}}]
    if start_time or end_time:
        range_filter = {"range": {"timestamp": {}}}
        if start_time:
            range_filter["range"]["timestamp"]["gte"] = start_time
        if end_time:
            range_filter["range"]["timestamp"]["lte"] = end_time
        must.append(range_filter)

    body = {
        "size": max_alerts,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"must": must}},
    }

    response = requests.post(
        f"{INDEXER_URL}/{INDEXER_INDEX_PATTERN}/_search",
        auth=(INDEXER_USER, INDEXER_PASSWORD),
        json=body,
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    hits = response.json()["hits"]["hits"]

    records = []
    for hit in hits:
        src = hit["_source"]
        rule = src.get("rule", {})
        data = src.get("data", {})
        rule_id = str(rule.get("id", "")).strip()
        if rule_id not in CORRELATION_RULES:
            continue
        meta = CORRELATION_RULES[rule_id]
        records.append({
            "timestamp": src.get("timestamp"),
            "rule_id": rule_id,
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "phase": meta["phase"],
            "meaning": meta["meaning"],
            "confirms_success": meta["confirms_success"],
            "src_ip": data.get("srcip"),
        })

    return pd.DataFrame(records)


def identify_campaigns(df: pd.DataFrame) -> list[dict]:
    """
    Identifie les IP sources distinctes présentes dans les alertes, avec le
    nombre de phases distinctes que chacune couvre.

    Motivation (limite identifiée le 09/08/2026) : sans ce contrôle,
    build_phase_summaries() groupe toutes les alertes de la fenêtre par SID
    et suppose implicitement qu'elles appartiennent à UNE SEULE campagne. Si
    deux attaquants distincts opéraient dans la même fenêtre, leurs actions
    seraient fusionnées silencieusement en une kill chain unique et fictive.
    C'est exactement le contrôle qu'effectue la règle Wazuh 100051 via
    <same_source_ip/>, et que ce script n'exploitait pas.

    Ne filtre rien de lui-même : renvoie l'inventaire, à charge de
    generate_full_killchain_report() de filtrer sur une IP et de signaler
    explicitement dans le rapport si plusieurs sources coexistent.
    Les alertes en direction to_client sont exclues du décompte (leur srcip
    est l'hôte DMZ, pas l'attaquant -- cf. docstring de module).
    """
    to_server = df[df["direction"] == "to_server"]
    campaigns = []
    for ip, sub in to_server.groupby("src_ip"):
        if not ip:
            continue
        campaigns.append({
            "src_ip": ip,
            "nb_alertes": int(len(sub)),
            "phases_couvertes": sorted(
                sub["phase"].unique().tolist(),
                key=lambda p: PHASE_ORDER.index(p),
            ),
            "nb_phases": int(sub["phase"].nunique()),
            "first_timestamp": sub["timestamp"].min(),
            "last_timestamp": sub["timestamp"].max(),
        })
    # Campagne principale = celle couvrant le plus de phases, puis le plus
    # d'alertes (départage déterministe, pas de choix arbitraire).
    campaigns.sort(key=lambda c: (c["nb_phases"], c["nb_alertes"]), reverse=True)
    return campaigns


def _compute_overlaps(phases: list[dict]) -> None:
    """
    Marque, pour chaque phase, si elle a DÉMARRÉ avant la fin de la phase
    précédente (chevauchement temporel réel). Modifie `phases` en place.

    Motivation : le chevauchement A/B est un phénomène déjà documenté dans
    kill_chain_report.py (Issue #23) -- Hydra démarre avant la fin complète
    du scan Nmap dans les scripts d'attaque. Le signaler explicitement dans
    la sortie le rend discutable dans le rapport de TFE, plutôt que de
    laisser croire à un enchaînement strictement séquentiel que les
    horodatages contredisent.
    """
    previous_end = None
    for p in phases:
        if p["nb_alertes"] == 0 or p["first_timestamp"] is None:
            p["chevauche_phase_precedente"] = None
            continue
        if previous_end is not None and p["first_timestamp"] < previous_end:
            p["chevauche_phase_precedente"] = True
        else:
            p["chevauche_phase_precedente"] = False
        previous_end = p["last_timestamp"]


def fetch_out_of_scope_context(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    top_n: int = 5,
) -> dict:
    """
    Mesure le volume d'alertes de la fenêtre qui N'APPARTIENNENT PAS aux
    11 SID des 4 scénarios connus, avec le top des règles concernées.

    Motivation (limite d'architecture assumée, ajoutée le 09/08/2026) : ce
    script raisonne en MONDE FERMÉ -- il ne peut structurellement détecter
    que les 4 scénarios prévus (ALL_SIDS). Toute autre activité est
    INVISIBLE pour la reconstruction.

    NUANCE IMPORTANTE constatée au run du 09/08/2026 (254 alertes non
    couvertes sur 321, soit 79,1 %) : ce volume ne correspond PAS à de
    l'activité étrangère aux scénarios. Le top des règles concernées était
    "sshd: authentication failed" (137), "PAM: User login failed" (21),
    "Maximum authentication attempts exceeded" (20)... c'est-à-dire la face
    HIDS du Scénario B -- le brute force Hydra vu depuis l'hôte
    ssh-eurostar par les règles natives Wazuh, là où les 11 SID ne couvrent
    que la face NIDS (trafic vu par Suricata sur le pont).

    Ce script raisonne donc sur la vision RÉSEAU uniquement, alors même que
    la règle 100051 qu'il exploite pour confirmer le succès de la Phase 2
    dépend, elle, de la règle native 40112 (vision hôte). La corrélation
    NIDS/HIDS est faite côté Wazuh, pas dans ce script -- ce n'est pas une
    incohérence, mais c'est un point à expliciter dans le rapport de TFE
    (complémentarité NIDS/HIDS) plutôt qu'à laisser deviner.

    Le compteur ne doit donc pas être lu comme "79 % d'activité non
    examinée" : une part importante est du signal HIDS rattaché aux mêmes
    scénarios, détecté par une autre couche.

    Sans ce décompte, un rapport annonçant "4/4 phases" laisserait croire à
    une couverture exhaustive de l'activité de la fenêtre, alors qu'il ne
    couvre que ce qu'il sait déjà chercher. Le mesurer explicitement rend
    cet angle mort quantifiable et discutable dans le rapport de TFE
    plutôt que silencieux.

    N'est PAS transmis au LLM : purement factuel, calculé en Python et
    joint au rapport tel quel (aucun risque d'interprétation erronée).
    Utilise les agrégations OpenSearch (pas de pagination) -- coût
    négligeable, une seule requête size=0.
    """
    range_filter = None
    if start_time or end_time:
        range_filter = {"range": {"timestamp": {}}}
        if start_time:
            range_filter["range"]["timestamp"]["gte"] = start_time
        if end_time:
            range_filter["range"]["timestamp"]["lte"] = end_time

    base_query = {"bool": {"filter": [range_filter]}} if range_filter else {"match_all": {}}

    body = {
        "size": 0,
        "query": base_query,
        "aggs": {
            "total": {"value_count": {"field": "rule.id"}},
            "dans_scenarios": {
                "filter": {"terms": {"data.alert.signature_id": ALL_SIDS}},
                "aggs": {"n": {"value_count": {"field": "rule.id"}}},
            },
            "hors_scenarios": {
                "filter": {
                    "bool": {
                        "must_not": [{"terms": {"data.alert.signature_id": ALL_SIDS}}]
                    }
                },
                "aggs": {
                    "top_regles": {
                        "terms": {"field": "rule.description", "size": top_n}
                    },
                    "niveau_max": {"max": {"field": "rule.level"}},
                },
            },
        },
    }

    try:
        response = requests.post(
            f"{INDEXER_URL}/{INDEXER_INDEX_PATTERN}/_search",
            auth=(INDEXER_USER, INDEXER_PASSWORD),
            json=body,
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        aggs = response.json()["aggregations"]
    except Exception as exc:
        # Non bloquant : ce contexte est informatif, son absence ne doit pas
        # empêcher la génération du rapport principal.
        return {"disponible": False, "erreur": str(exc)}

    total = int(aggs["total"]["value"])
    dans = int(aggs["dans_scenarios"]["n"]["value"])
    hors_bucket = aggs["hors_scenarios"]
    hors = int(hors_bucket["doc_count"])
    niveau_max = hors_bucket.get("niveau_max", {}).get("value")

    top = [
        {"description": b["key"], "count": int(b["doc_count"])}
        for b in hors_bucket["top_regles"]["buckets"]
    ]

    return {
        "disponible": True,
        "total_alertes_fenetre": total,
        "alertes_dans_scenarios": dans,
        "alertes_non_couvertes_par_sid": hors,
        "part_non_couverte_pct": round(100 * hors / total, 1) if total else 0.0,
        "niveau_max_non_couvert": int(niveau_max) if niveau_max is not None else None,
        "top_regles_non_couvertes": top,
        "avertissement": (
            "Ce rapport reconstruit la kill chain à partir des 11 SID Suricata "
            "des 4 scénarios connus, soit la vision NIDS (réseau) uniquement. "
            "Les alertes comptées ci-dessus ne sont PAS nécessairement une "
            "activité étrangère aux scénarios : une part importante correspond "
            "typiquement à la face HIDS des mêmes attaques (règles natives Wazuh "
            "sur les hôtes, ex : 5760 sshd, 40112, PAM), complémentaire de la "
            "détection réseau. Le solde peut relever d'une activité réellement "
            "distincte, non analysée ici (raisonnement en monde fermé). "
            "Voir le top des règles ci-dessus pour trancher au cas par cas."
        ),
    }


def _attacker_ip(sub_df: pd.DataFrame) -> Optional[str]:
    """
    IP source la plus probable de l'attaquant pour une phase : mode des
    src_ip parmi les alertes en direction to_server uniquement (exclut le
    SID 1000402 du Scénario D, dont le srcip est l'hôte DMZ -- cf. docstring
    de module). Retourne None si aucune alerte to_server dans la phase.
    """
    to_server = sub_df[sub_df["direction"] == "to_server"]
    ips = to_server["src_ip"].dropna()
    if ips.empty:
        return None
    return Counter(ips).most_common(1)[0][0]


def build_phase_summaries(
    df: pd.DataFrame,
    df_correlation: Optional[pd.DataFrame] = None,
) -> list[dict]:
    """
    Construit les 4 phases dans l'ordre fixe PHASE_ORDER, à partir du
    mapping déterministe SID_METADATA -- pas de découpage par "coupures"
    temporelles comme dans build_kill_chain_steps() (Issue #23) : ici
    chaque alerte porte déjà sa phase par construction (son SID), donc le
    découpage est un simple groupby, robuste même si le scénario C n'a pas
    de règle de corrélation Wazuh dédiée (cf. docstring de module).

    Une phase sans aucune alerte dans la fenêtre interrogée est incluse
    quand même, avec nb_alertes=0 -- le rapport doit le dire explicitement
    plutôt que d'omettre silencieusement la phase.
    """
    phases = []
    for ordre, phase_name in enumerate(PHASE_ORDER, start=1):
        sub = df[df["phase"] == phase_name].sort_values("timestamp")

        # Alertes de corrélation Wazuh rattachées à cette phase (succès confirmé).
        # Dédupliquées par rule_id : plusieurs occurrences de la MÊME règle
        # (ex : 100053 déclenchée 2 fois) confirment le même fait une seule
        # fois -- les répéter à l'identique en sortie n'apporte rien et
        # alourdit le contexte transmis au LLM. Le nombre d'occurrences est
        # conservé dans "occurrences" plutôt que perdu.
        correlations = []
        if df_correlation is not None and not df_correlation.empty:
            corr_sub = df_correlation[df_correlation["phase"] == phase_name]
            for rule_id, grp in corr_sub.groupby("rule_id"):
                first = grp.iloc[0]
                correlations.append({
                    "rule_id": rule_id,
                    "rule_level": first["rule_level"],
                    "meaning": first["meaning"],
                    "timestamp": grp["timestamp"].min(),
                    "occurrences": int(len(grp)),
                })

        # Statut à TROIS états, pas un booléen -- cf. PHASE_CORRELATION_COVERAGE.
        coverage = PHASE_CORRELATION_COVERAGE.get(
            phase_name, {"instrumentee": False, "note": "couverture non renseignée"}
        )
        # Une phase SANS AUCUNE ALERTE n'a pas d'aboutissement à qualifier :
        # lui attribuer "non_confirme" ou "indetermine" sous-entendrait qu'il
        # y avait quelque chose à confirmer. Statut dédié "sans_activite"
        # (constaté via simulation d'un run où seul le Scénario A a eu lieu).
        phase_vide = sub.empty
        if phase_vide:
            statut_aboutissement = "sans_activite"
        elif correlations:
            statut_aboutissement = "confirme"
        elif coverage["instrumentee"]:
            statut_aboutissement = "non_confirme"
        else:
            statut_aboutissement = "indetermine"

        if sub.empty:
            phases.append({
                "ordre": ordre,
                "phase": phase_name,
                "scenario": None,
                "sids": [],
                "nb_alertes": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "attacker_ip": None,
                "target": None,
                "agent_collecteur": [],
                "tactiques": [],
                "techniques": [],
                "descriptions": [],
                "correlations_wazuh": correlations,
                "succes_confirme": len(correlations) > 0,
                "statut_aboutissement": statut_aboutissement,
                "phase_instrumentee_pour_succes": coverage["instrumentee"],
                "note_couverture_correlation": coverage["note"],
            })
            continue

        phases.append({
            "ordre": ordre,
            "phase": phase_name,
            "scenario": sub["scenario"].iloc[0],
            "sids": sorted(sub["sid"].unique().tolist()),
            "nb_alertes": int(len(sub)),
            "first_timestamp": sub["timestamp"].iloc[0],
            "last_timestamp": sub["timestamp"].iloc[-1],
            "attacker_ip": _attacker_ip(sub),
            # Cible déterministe (SID_METADATA), pas un champ d'alerte --
            # cf. docstring de module (agent.name = agent collecteur,
            # pas la cible ; aucun champ dest_ip décodé).
            "target": sub["target"].iloc[0],
            # Agent Wazuh ayant transmis l'alerte -- pour les 4 scénarios
            # (détection réseau Suricata), c'est structurellement toujours
            # "suricata-sensor", quelle que soit la cible réelle. Conservé
            # à titre informatif, à ne pas confondre avec la cible ci-dessus.
            "agent_collecteur": sorted(sub["agent_name"].dropna().unique().tolist()),
            "tactiques": sorted(sub["tactic"].unique().tolist()),
            "techniques": sorted(sub["technique"].unique().tolist()),
            "descriptions": sorted(sub["rule_description"].unique().tolist()),
            # Succès confirmé par une règle de corrélation Wazuh (pas par
            # Suricata seul, qui ne voit que la tentative) -- cf.
            # CORRELATION_RULES et fetch_correlation_alerts().
            "correlations_wazuh": correlations,
            "succes_confirme": len(correlations) > 0,
            # Statut à trois états : "confirme" / "non_confirme" /
            # "indetermine". Ne JAMAIS interpréter "indetermine" comme un
            # échec de l'attaque -- cf. PHASE_CORRELATION_COVERAGE.
            "statut_aboutissement": statut_aboutissement,
            "phase_instrumentee_pour_succes": coverage["instrumentee"],
            "note_couverture_correlation": coverage["note"],
        })

    _compute_overlaps(phases)
    return phases


def _format_phases_for_prompt(phases: list[dict]) -> str:
    """Résumé texte des 4 phases déjà segmentées, à destination du prompt LLM."""
    lines = []
    for p in phases:
        if p["nb_alertes"] == 0:
            lines.append(
                f"Phase {p['ordre']} ({p['phase']}) : AUCUNE ALERTE trouvée dans la "
                f"fenêtre temporelle interrogée pour ce scénario."
            )
            continue
        chevauchement = ""
        if p.get("chevauche_phase_precedente"):
            chevauchement = ("\n- ATTENTION : cette phase a DÉMARRÉ avant la fin de la phase "
                             "précédente (chevauchement temporel réel, les deux scénarios se "
                             "recouvrent partiellement dans le trafic capturé)")

        if p["statut_aboutissement"] == "confirme":
            corr_parts = []
            for c in p["correlations_wazuh"]:
                occ = f", {c['occurrences']} occurrences" if c["occurrences"] > 1 else ""
                corr_parts.append(
                    f"règle Wazuh {c['rule_id']} (niveau {c['rule_level']}{occ}) -- {c['meaning']}"
                )
            corr_lines = "; ".join(corr_parts)
            statut = f"\n- STATUT D'ABOUTISSEMENT : SUCCÈS CONFIRMÉ par le SIEM -- {corr_lines}"
        elif p["statut_aboutissement"] == "non_confirme":
            statut = ("\n- STATUT D'ABOUTISSEMENT : NON CONFIRMÉ -- une règle de corrélation "
                      f"existe pour cette phase ({p['note_couverture_correlation']}) mais "
                      "elle n'a pas déclenché sur ces données")
        else:
            statut = ("\n- STATUT D'ABOUTISSEMENT : INDÉTERMINÉ -- "
                      f"{p['note_couverture_correlation']}. IMPORTANT : cela ne signifie PAS "
                      "que l'attaque a échoué, seulement que le SIEM n'a aucun moyen de se "
                      "prononcer sur son aboutissement. Ne présente donc cette phase NI comme "
                      "un succès, NI comme un échec : décris uniquement l'activité détectée.")

        lines.append(
            f"Phase {p['ordre']} ({p['phase']}, Scénario {p['scenario']}) :\n"
            f"- SID Suricata impliqués : {', '.join(p['sids'])}\n"
            f"- Tactique(s) MITRE ATT&CK : {', '.join(p['tactiques'])}\n"
            f"- Technique(s) MITRE ATT&CK : {', '.join(p['techniques'])}\n"
            f"- Nombre d'alertes : {p['nb_alertes']}\n"
            f"- Première alerte : {p['first_timestamp']}\n"
            f"- Dernière alerte : {p['last_timestamp']}\n"
            f"- IP source (attaquant) : {p['attacker_ip'] or 'non déterminée'}\n"
            f"- Cible réseau (hôte visé par ce scénario) : {p['target']}"
            f"{statut}{chevauchement}\n"
            f"- Descriptions de règles observées : {'; '.join(p['descriptions'])}"
        )
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Rédaction (LangChain + Ollama) -- prose uniquement, aucune donnée factuelle
# ---------------------------------------------------------------------------

class DescriptionPhase(BaseModel):
    ordre: int = Field(
        description="Doit correspondre EXACTEMENT au numéro de phase fourni "
                    "dans le contexte (1 à 4) -- ne pas réordonner, fusionner "
                    "ou ajouter de phase"
    )
    description: str = Field(
        description="Description factuelle et concise (1-3 phrases) en français "
                    "de ce qui a été observé à cette phase, basée UNIQUEMENT sur "
                    "les données fournies (SID, tactique, technique, IP, cible). "
                    "Utilise les horodatages propres à CETTE phase (première/derniere "
                    "alerte), jamais la fenêtre globale de la requête. Si la phase "
                    "indique explicitement qu'aucune alerte n'a été trouvée, "
                    "l'écrire tel quel -- ne jamais inventer une activité, une IP, "
                    "une technique, ni une conséquence ou un objectif de l'attaquant "
                    "non confirmé par les données, même atténué (potentiellement)."
    )


class RapportKillChainComplet(BaseModel):
    descriptions_phases: list[DescriptionPhase] = Field(
        description="Exactement une description par phase fournie en contexte (4 au total), dans l'ordre"
    )
    resume_narratif: str = Field(
        description="Résumé narratif de 3 à 6 phrases en français, pour un analyste "
                    "SOC, décrivant l'enchaînement de l'attaque à travers les phases "
                    "disposant d'une preuve. Ne pas décrire de phase comme observée "
                    "si son nombre d'alertes est de 0."
    )
    couverture: str = Field(
        description="Une phrase indiquant combien des 4 phases attendues "
                    "(Reconnaissance, Initial Access, Execution, Command and "
                    "Control) disposent d'au moins une alerte dans les données "
                    "fournies, et lesquelles en sont dépourvues le cas échéant."
    )


KILLCHAIN_SYSTEM_PROMPT = """Tu es un analyste SOC chargé de rédiger la partie textuelle d'un rapport de reconstruction de kill chain. La segmentation en 4 phases et les tactiques/techniques MITRE ATT&CK de chaque phase ont déjà été calculées automatiquement et te sont fournies telles quelles -- ce n'est PAS ta tâche de les déterminer, de les reformuler ou de les corriger.

RÈGLES STRICTES, à respecter impérativement :
1. Ta seule tâche est de rédiger, pour chaque phase déjà numérotée, une description factuelle en français, et de rédiger un résumé narratif global plus une phrase de couverture.
2. N'invente JAMAIS de phase supplémentaire, ne fusionne jamais les phases fournies, ne modifie jamais leur numéro d'ordre.
3. N'invente JAMAIS d'IP, d'horodatage, de technique MITRE ou d'activité qui ne figure pas explicitement dans les données fournies pour cette phase.
4. N'invente JAMAIS de mécanisme technique précis (ex : "backdoor", "exfiltration de données", "persistance", "shell inversé") qui ne serait pas explicitement nommé dans la description de règle ou la technique MITRE fournie pour cette phase -- y compris dans le résumé narratif global. N'attribue JAMAIS non plus de conséquence, d'objectif ou d'intention à l'attaquant qui ne figure pas explicitement dans les données fournies (ex : "pour exfiltrer des données", "dans le but de prendre le contrôle", "afin d'obtenir un accès persistant") -- MÊME atténués par des formulations comme "potentiellement", "probablement", "semble indiquer" ou "dans l'objectif de". Une conséquence hypothétique reste une invention, peu importe la formulation utilisée pour l'atténuer. Décris uniquement CE QUI A ÉTÉ OBSERVÉ (règle déclenchée, technique MITRE fournie), jamais ce que l'attaquant cherchait à accomplir au-delà.
5. RESPECTE STRICTEMENT le champ "STATUT D'ABOUTISSEMENT" de chaque phase, qui a TROIS valeurs possibles :
   - "SUCCÈS CONFIRMÉ" : le SIEM a corrélé un aboutissement réel. Ne présente PAS cette phase comme une simple tentative.
   - "NON CONFIRMÉ" : une règle de corrélation existait et n'a pas déclenché. Tu peux indiquer que l'aboutissement n'est pas confirmé.
   - "INDÉTERMINÉ" : AUCUNE règle de corrélation n'existe pour cette phase. Le SIEM ne peut PAS se prononcer. Dans ce cas, n'écris NI qu'il y a eu succès, NI qu'il n'y a pas eu d'aboutissement, NI qu'"aucune corrélation ne confirme le succès" (ce qui suggérerait à tort un échec). Décris uniquement l'activité détectée par Suricata, sans conclure sur son issue. Absence d'instrumentation n'est pas preuve d'échec.
6. Si une phase porte la mention "chevauchement temporel", mentionne-le : l'attaque n'était pas strictement séquentielle à cet endroit.
7. Si une phase indique explicitement "AUCUNE ALERTE trouvée", ta description DOIT le refléter tel quel -- ne décris jamais une activité pour cette phase.
8. Reste factuel et concis. Le résumé s'adresse à un analyste SOC, pas à un public non technique.

Réponds uniquement selon le format structuré demandé, en français."""

KILLCHAIN_HUMAN_PROMPT_TEMPLATE = """Phases de la kill chain reconstruite. La fenêtre {start} -> {end} ci-dessous est le contexte GLOBAL de la requête (bien plus large que la durée réelle de l'attaque) -- ne la répète PAS dans les descriptions de phase. Pour chaque phase, utilise UNIQUEMENT ses propres horodatages "Première alerte"/"Dernière alerte" fournis dans son résumé ci-dessous, qui reflètent la durée réelle de cette phase :

{phases_summary}

Rédige la description de chaque phase ci-dessus (une description par ordre fourni, 4 au total), ainsi que le résumé narratif global et la phrase de couverture."""


def generate_full_killchain_report(
    hours: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    model_name: str = LLM_MODEL_NAME,
    attacker_ip: Optional[str] = None,
) -> dict:
    """
    Génère le rapport de reconstruction complète de la kill chain (4 phases).
    Segmentation, tags MITRE, corrélation par IP, détection de chevauchement
    et statut de succès : déterministes (build_phase_summaries + helpers).
    Rédaction (description par phase + résumé + couverture) : LangChain +
    Ollama, même patron que generate_kill_chain_report() (Issue #23).

    hours : fenêtre glissante en heures depuis maintenant (ignoré si
    start_time est fourni). start_time/end_time : bornes ISO 8601
    explicites, prioritaires sur hours.

    attacker_ip : si fourni, restreint la reconstruction aux alertes de
    cette IP source. Si omis, la campagne principale (celle couvrant le
    plus de phases) est retenue automatiquement, et la présence éventuelle
    d'autres sources est signalée dans le rapport plutôt que fusionnée
    silencieusement -- cf. identify_campaigns().
    """
    if start_time is None and hours is not None:
        start_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if end_time is None:
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    df = fetch_alerts(start_time=start_time, end_time=end_time)
    df_correlation = fetch_correlation_alerts(start_time=start_time, end_time=end_time)
    # Alertes non couvertes par les 11 SID : quantifie ce que la reconstruction
    # NE couvre PAS (monde fermé, vision NIDS). Purement informatif, non
    # transmis au LLM -- cf. fetch_out_of_scope_context().
    contexte_hors_scope = fetch_out_of_scope_context(start_time=start_time, end_time=end_time)

    campaigns = identify_campaigns(df) if not df.empty else []

    # Sélection de la campagne à reconstruire. Les alertes to_client
    # (SID 1000402) sont conservées quelle que soit l'IP retenue : leur
    # srcip est l'hôte DMZ, elles appartiennent au flux de l'attaquant
    # sans porter son IP -- les filtrer sur src_ip les supprimerait à tort.
    selected_ip = attacker_ip
    if selected_ip is None and campaigns:
        selected_ip = campaigns[0]["src_ip"]

    if selected_ip is not None and not df.empty:
        df_scope = df[(df["src_ip"] == selected_ip) | (df["direction"] == "to_client")].copy()
    else:
        df_scope = df.copy()

    phases = build_phase_summaries(df_scope, df_correlation=df_correlation)
    phases_summary = _format_phases_for_prompt(phases)

    llm = ChatOllama(model=model_name, temperature=0)
    structured_llm = llm.with_structured_output(RapportKillChainComplet)

    prompt = ChatPromptTemplate.from_messages([
        ("system", KILLCHAIN_SYSTEM_PROMPT),
        ("human", KILLCHAIN_HUMAN_PROMPT_TEMPLATE),
    ])
    chain = prompt | structured_llm

    start_gen = time.time()
    llm_result = chain.invoke({
        "start": start_time,
        "end": end_time,
        "phases_summary": phases_summary,
    })
    latency = time.time() - start_gen

    descriptions_by_ordre = {d.ordre: d.description for d in llm_result.descriptions_phases}
    missing = [p["ordre"] for p in phases if p["ordre"] not in descriptions_by_ordre]
    if missing:
        raise ValueError(
            f"Le LLM n'a pas fourni de description pour la/les phase(s) {missing} -- "
            f"reçu : {sorted(descriptions_by_ordre.keys())}, attendu : "
            f"{[p['ordre'] for p in phases]}. Réponse brute : {llm_result.descriptions_phases}"
        )

    phases_finales = [
        {**p, "description": descriptions_by_ordre[p["ordre"]]}
        for p in phases
    ]

    return {
        "window": {"start": start_time, "end": end_time},
        "attacker_ip_retenue": selected_ip,
        "campagnes_detectees": campaigns,
        "autres_sources_presentes": len(campaigns) > 1,
        "phases": phases_finales,
        "resume_narratif": llm_result.resume_narratif,
        "couverture": llm_result.couverture,
        "phases_avec_preuve": sum(1 for p in phases if p["nb_alertes"] > 0),
        "phases_avec_succes_confirme": sum(
            1 for p in phases if p["statut_aboutissement"] == "confirme"),
        "phases_indeterminees": sum(
            1 for p in phases if p["statut_aboutissement"] == "indetermine"),
        "phases_sans_activite": sum(
            1 for p in phases if p["statut_aboutissement"] == "sans_activite"),
        "phases_non_confirmees": sum(
            1 for p in phases if p["statut_aboutissement"] == "non_confirme"),
        "phases_totales": len(PHASE_ORDER),
        "chevauchements_detectes": [
            p["ordre"] for p in phases if p.get("chevauche_phase_precedente")
        ],
        "contexte_alertes_non_couvertes": contexte_hors_scope,
        "model": model_name,
        "latency_seconds": latency,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def save_report_json(report: dict, path: str = None) -> str:
    """Sauvegarde le rapport en JSON, pour commit GitHub et indexation OpenSearch (Issue #28)."""
    if path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"killchain_report_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=6,
                         help="Fenêtre glissante en heures depuis maintenant (défaut 6)")
    parser.add_argument("--output", type=str, default=None,
                         help="Chemin du fichier JSON de sortie")
    parser.add_argument("--attacker-ip", type=str, default=None,
                         help="Restreindre la reconstruction à cette IP source "
                              "(sinon : campagne principale détectée automatiquement)")
    args = parser.parse_args()

    print(f"Reconstruction de la kill chain sur les {args.hours} dernières heures...")
    report = generate_full_killchain_report(hours=args.hours, attacker_ip=args.attacker_ip)

    print(f"\nIP attaquante retenue : {report['attacker_ip_retenue'] or 'aucune'}")
    if report["autres_sources_presentes"]:
        autres = [c for c in report["campagnes_detectees"]
                  if c["src_ip"] != report["attacker_ip_retenue"]]
        print(f"  ATTENTION : {len(autres)} autre(s) IP source détectée(s) dans la même "
              f"fenêtre, EXCLUE(S) de cette reconstruction :")
        for c in autres:
            print(f"    - {c['src_ip']} ({c['nb_alertes']} alertes, "
                  f"phase(s) : {', '.join(c['phases_couvertes'])})")
        print("  -> relancer avec --attacker-ip <IP> pour reconstruire leur chaîne.")

    print(f"\nCouverture : {report['phases_avec_preuve']}/{report['phases_totales']} "
          f"phases avec au moins une preuve.")
    print(f"  Aboutissement : {report['phases_avec_succes_confirme']} confirmé(s) par le SIEM, "
          f"{report['phases_indeterminees']} indéterminée(s) (phase non instrumentée pour "
          f"statuer -- ne signifie pas que l'attaque a échoué).")
    if report["chevauchements_detectes"]:
        print(f"Chevauchement temporel détecté sur la/les phase(s) : "
              f"{report['chevauchements_detectes']} (démarrage avant la fin de la "
              f"phase précédente -- enchaînement non strictement séquentiel).")
    print(f"Latence (rédaction LLM uniquement) : {report['latency_seconds']:.1f}s\n")

    print("=== Phases (segmentation et tags MITRE déterministes) ===")
    for p in report["phases"]:
        print(f"\n  Phase {p['ordre']} — {p['phase']} (Scénario {p['scenario'] or 'N/A'})")
        print(f"    Alertes      : {p['nb_alertes']}")
        if p["nb_alertes"] > 0:
            print(f"    Période      : {p['first_timestamp']} -> {p['last_timestamp']}")
            print(f"    IP attaquant : {p['attacker_ip']}")
            print(f"    Cible        : {p['target']}")
            print(f"    Tactique(s)  : {', '.join(p['tactiques'])}")
            print(f"    Technique(s) : {', '.join(p['techniques'])}")
            if p.get("chevauche_phase_precedente"):
                print(f"    Chevauchement: OUI (démarre avant la fin de la phase précédente)")
        if p["statut_aboutissement"] == "sans_activite":
            pass  # rien à qualifier : aucune activité détectée pour cette phase
        elif p["statut_aboutissement"] == "confirme":
            for c in p["correlations_wazuh"]:
                occ = f", {c['occurrences']}x" if c["occurrences"] > 1 else ""
                print(f"    SUCCÈS       : règle Wazuh {c['rule_id']} (niv. {c['rule_level']}{occ}) "
                      f"— {c['meaning']}")
        elif p["statut_aboutissement"] == "non_confirme":
            print(f"    Statut       : NON CONFIRMÉ — une règle de corrélation existe "
                  f"mais n'a pas déclenché")
        else:
            print(f"    Statut       : INDÉTERMINÉ — {p['note_couverture_correlation']}")
            print(f"                   (ne signifie PAS que l'attaque a échoué)")
        print(f"    Description  : {p['description']}")

    ctx = report.get("contexte_alertes_non_couvertes", {})
    if ctx.get("disponible"):
        print("\n=== Alertes non couvertes par les 11 SID Suricata (vision NIDS) ===")
        print(f"  Total alertes dans la fenêtre     : {ctx['total_alertes_fenetre']}")
        print(f"    dont SID Suricata scénarios A-D : {ctx['alertes_dans_scenarios']}")
        print(f"    dont NON couvertes par ces SID  : {ctx['alertes_non_couvertes_par_sid']} "
              f"({ctx['part_non_couverte_pct']}%)")
        if ctx.get("niveau_max_non_couvert") is not None:
            print(f"    niveau Wazuh max non couvert    : {ctx['niveau_max_non_couvert']}")
        if ctx["top_regles_non_couvertes"]:
            print("  Principales règles non couvertes (souvent la face HIDS des mêmes scénarios) :")
            for r in ctx["top_regles_non_couvertes"]:
                print(f"    - {r['count']:>5}x  {r['description'][:70]}")
        print(f"  /!\\ {ctx['avertissement']}")
    elif ctx:
        print(f"\n(Décompte des alertes non couvertes indisponible : {ctx.get('erreur')})")

    print(f"\nRésumé narratif :\n{report['resume_narratif']}")
    print(f"\nCouverture : {report['couverture']}")

    out_path = save_report_json(report, args.output)
    print(f"\nRapport sauvegardé : {out_path}")
