"""
alert_prioritization.py — Priorisation automatique des alertes par IA
TFE IDS/IPS & SIEM — Issue #21 — v2

Étape 1/5 : récupération des alertes depuis l'Indexer OpenSearch.
Cf. Issue #38 : l'API Manager (/alerts, port 55000) est dépréciée depuis
Wazuh 4.3 — l'Indexer (port 9200) est la seule source valide.

Structure de document validée empiriquement le 03/08/2026 sur une alerte
réelle de corrélation (rule.id 100051, Issue #22) : rule.id est une CHAÎNE
(pas un entier), l'IP source est sous data.srcip (jamais à la racine),
rule.groups peut contenir des doublons (groupes hérités des règles parentes
combinées par la corrélation).

Vérité terrain (GROUND_TRUTH_LABELS) établie par inspection manuelle du
ruleset (/var/ossec/ruleset/rules/*.xml) sur wazuh-stack le 03/08/2026,
pas par classification automatique. Périmètre limité aux règles liées à
la chaîne d'attaque testée (reconnaissance -> brute force -> injection) ;
le bruit opérationnel/conformité (cycle de vie agent, sudo légitime, SCA,
SELinux) est exclu du périmètre de mesure (EXCLUDED_RULE_IDS), pas fondu
dans la classe "normale".

Validation empirique du 03/08/2026 sur les 5967 alertes indexées à date :
- Alertes récupérées : 5967/5967 (pagination search_after intégrale,
  vérifiée contre un _count direct sur l'Indexer)
- Alertes exclues du périmètre : 4004 (67.1%)
- Alertes dans le périmètre, 100% mappées (aucune étiquette manquante) :
  1963 -> normale 1572 (80.1%), haute 375 (19.1%), critique 16 (0.8%)
"""

import os
from typing import Optional

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
# Cf. rapport, section méthodologie : ces mappings résultent d'une inspection
# manuelle de /var/ossec/ruleset/rules/*.xml, pas d'une classification
# automatique. Périmètre limité aux règles liées à la chaîne d'attaque testée
# (reconnaissance -> brute force -> injection) ; le bruit opérationnel/
# conformité (cycle de vie agent, sudo légitime, SCA, SELinux) est exclu du
# périmètre de mesure, pas fondu dans la classe "normale".

EXCLUDED_RULE_IDS = {
    "501", "502", "503", "504", "506",   # cycle de vie agent/manager
    "5402", "5403",                       # sudo légitime
    "533",                                 # changement ports netstat
    "550",                                 # intégrité fichier (syscheck)
    "80730",                               # SELinux AVC
    "19004", "19007", "19008", "19009", "19012",  # SCA (audit conformité)
    "5104", "80710",                       # mode promiscuous isolé, 02/07,
                                            # probable action de diagnostic
                                            # lors de la mise en place du lab
                                            # (non confirmé formellement)
}

GROUND_TRUTH_LABELS = {
    # --- Critique : compromission confirmée ou chaîne d'attaque complète ---
    "100051": "critique",  # corrélation kill chain (Issue #22)
    "40112":  "critique",  # brute force réussi (échecs multiples + succès)
    "31106":  "critique",  # SQLi réussie (HTTP 200)

    # --- Haute : intention malveillante claire, sans confirmation de succès ---
    "100050": "haute",  # scan Nmap isolé (custom, Issue #12/13)
    "31171":  "haute",  # tentative SQLi
    "31103":  "haute",  # tentative SQLi (variante)
    "2502":   "haute",  # mot de passe manqué répété
    "5551":   "haute",  # PAM, échecs multiples même IP
    "5763":   "haute",  # sshd, brute force même IP
    "5758":   "haute",  # nombre max tentatives auth dépassé
    "31152":  "haute",  # SQLi répétée même IP
    "40111":  "haute",  # échecs authentification multiples (générique)

    # --- Normale : signal faible ou bruit de fond ---
    "86601":  "normale",  # alerte Suricata générique (recon brute)
    "5760":   "normale",  # échec SSH isolé
    "5501":   "normale",  # session PAM ouverte
    "5502":   "normale",  # session PAM fermée
    "31122":  "normale",  # erreur serveur générique
    "31101":  "normale",  # erreur HTTP 400 générique (même famille que 31122)
    "2501":   "normale",  # échec de connexion générique
    "5503":   "normale",  # PAM, échec isolé
    "5557":   "normale",  # unix_chkpwd, échec isolé
    "5715":   "normale",  # succès SSH générique (pas de brute force préalable)
}


if __name__ == "__main__":
    df = fetch_alerts_from_indexer()
    print(f"Alertes récupérées : {len(df)}")

    df_excluded = df[df["rule_id"].isin(EXCLUDED_RULE_IDS)]
    df_scope = df[~df["rule_id"].isin(EXCLUDED_RULE_IDS)].copy()
    df_scope["ground_truth"] = df_scope["rule_id"].map(GROUND_TRUTH_LABELS)

    print(f"\nAlertes exclues du périmètre : {len(df_excluded)} ({len(df_excluded)/len(df)*100:.1f}%)")
    print(f"Alertes dans le périmètre    : {len(df_scope)} ({len(df_scope)/len(df)*100:.1f}%)")

    non_mappees = df_scope[df_scope["ground_truth"].isna()]
    if not non_mappees.empty:
        print(f"\n⚠ {len(non_mappees)} alertes dans le périmètre mais SANS étiquette de vérité terrain :")
        print(non_mappees["rule_id"].value_counts())

    print("\nRépartition de la vérité terrain :")
    print(df_scope["ground_truth"].value_counts())
