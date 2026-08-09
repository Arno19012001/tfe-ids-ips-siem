import sys, types
# Stubs pour les dépendances absentes de cet environnement de test
for mod in ["dotenv", "langchain_ollama", "langchain_core", "langchain_core.prompts", "pydantic"]:
    if mod not in sys.modules:
        m = types.ModuleType(mod); sys.modules[mod] = m
sys.modules["dotenv"].load_dotenv = lambda *a, **k: None
sys.modules["langchain_ollama"].ChatOllama = object
sys.modules["langchain_core.prompts"].ChatPromptTemplate = object
class _BM:
    def __init_subclass__(cls, **kw): pass
sys.modules["pydantic"].BaseModel = _BM
sys.modules["pydantic"].Field = lambda *a, **k: None

import pandas as pd
import importlib.util
spec = importlib.util.spec_from_file_location("kc", "/home/claude/killchain_reconstruction.py")
kc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kc)

# Jeu de données synthétique : DEUX attaquants distincts + chevauchement A/B
rows = []
def add(ts, sid, ip):
    m = kc.SID_METADATA[sid]
    rows.append({"timestamp": ts, "sid": sid, "scenario": m["scenario"], "phase": m["phase"],
                 "tactic": m["tactic"], "technique": m["technique"], "direction": m["direction"],
                 "target": m["target"], "rule_description": m["description"],
                 "agent_id": "019", "agent_name": "suricata-sensor", "src_ip": ip})

# Attaquant principal 192.168.1.50 : les 4 phases, avec chevauchement A/B
add("2026-08-09T14:25:50", "1000101", "192.168.1.50")
add("2026-08-09T14:35:30", "1000104", "192.168.1.50")
add("2026-08-09T14:25:48", "1000201", "192.168.1.50")   # démarre AVANT fin phase 1
add("2026-08-09T14:31:38", "1000201", "192.168.1.50")
add("2026-08-09T14:32:10", "1000301", "192.168.1.50")
add("2026-08-09T14:34:28", "1000401", "192.168.1.50")
add("2026-08-09T14:35:34", "1000402", "10.0.10.30")     # to_client : srcip = hôte DMZ
# Second attaquant 203.0.113.9 : recon seulement
add("2026-08-09T15:00:00", "1000101", "203.0.113.9")
add("2026-08-09T15:00:05", "1000101", "203.0.113.9")

df = pd.DataFrame(rows)

print("=== TEST 1 : identify_campaigns (détection multi-attaquants) ===")
camps = kc.identify_campaigns(df)
for c in camps:
    print(f"  {c['src_ip']}: {c['nb_alertes']} alertes, {c['nb_phases']} phase(s) -> {c['phases_couvertes']}")
assert camps[0]["src_ip"] == "192.168.1.50", "campagne principale mal identifiée"
assert len(camps) == 2, "second attaquant non détecté"
print("  OK: campagne principale = 192.168.1.50, second attaquant bien isolé\n")

print("=== TEST 2 : filtrage par IP + conservation du to_client ===")
sel = "192.168.1.50"
df_scope = df[(df["src_ip"] == sel) | (df["direction"] == "to_client")]
print(f"  {len(df)} alertes -> {len(df_scope)} après filtrage sur {sel}")
assert "1000402" in df_scope["sid"].values, "alerte to_client (1000402) perdue à tort !"
assert "203.0.113.9" not in df_scope["src_ip"].values, "second attaquant non exclu"
print("  OK: SID 1000402 conservé malgré son srcip différent, second attaquant exclu\n")

print("=== TEST 3 : corrélations Wazuh (succès confirmé) ===")
df_corr = pd.DataFrame([
    {"timestamp": "2026-08-09T14:31:40", "rule_id": "100051", "rule_level": 15,
     "rule_description": "kill chain", "phase": "Initial Access",
     "meaning": kc.CORRELATION_RULES["100051"]["meaning"], "confirms_success": True,
     "src_ip": "192.168.1.50"},
    {"timestamp": "2026-08-09T14:35:36", "rule_id": "100053", "rule_level": 15,
     "rule_description": "acces initial", "phase": "Command and Control",
     "meaning": kc.CORRELATION_RULES["100053"]["meaning"], "confirms_success": True,
     "src_ip": "192.168.1.50"},
])
phases = kc.build_phase_summaries(df_scope, df_correlation=df_corr)
for p in phases:
    statut = "SUCCÈS CONFIRMÉ" if p["succes_confirme"] else "tentative"
    chev = " [CHEVAUCHEMENT]" if p.get("chevauche_phase_precedente") else ""
    print(f"  Phase {p['ordre']} {p['phase']}: {p['nb_alertes']} alertes, {statut}{chev}")
    print(f"      IP={p['attacker_ip']}  cible={p['target'][:40]}")
assert phases[1]["succes_confirme"], "succès Phase 2 non détecté"
assert phases[3]["succes_confirme"], "succès Phase 4 non détecté"
assert not phases[0]["succes_confirme"], "faux succès sur Phase 1"
print("  OK: succès confirmés rattachés aux bonnes phases\n")

print("=== TEST 4 : chevauchement temporel ===")
assert phases[1]["chevauche_phase_precedente"] is True, "chevauchement A/B non détecté"
assert phases[0]["chevauche_phase_precedente"] is False, "faux chevauchement Phase 1"
print("  OK: chevauchement Phase 2 détecté, Phase 1 correctement marquée sans\n")

print("=== TEST 5 : IP attaquante en Phase 4 (piège du to_client) ===")
print(f"  Phase 4 IP attaquante = {phases[3]['attacker_ip']}")
assert phases[3]["attacker_ip"] == "192.168.1.50", "IP DMZ rapportée à tort comme attaquant !"
print("  OK: 192.168.1.50 (attaquant), pas 10.0.10.30 (hôte DMZ)\n")

print("=== TEST 6 : phase vide ===")
df_empty = df_scope[df_scope["phase"] != "Execution"]
ph = kc.build_phase_summaries(df_empty, df_correlation=df_corr)
assert ph[2]["nb_alertes"] == 0 and ph[2]["scenario"] is None
print(f"  Phase 3 sans alerte gérée proprement (nb_alertes=0, pas de crash)\n")

print("=== TEST 7 : statut à trois états (correctif remarque Arno) ===")
for p_ in phases:
    print(f"  Phase {p_['ordre']} {p_['phase']}: statut={p_['statut_aboutissement']}")
assert phases[0]["statut_aboutissement"] == "indetermine", "Phase 1 (A) devrait être indeterminee"
assert phases[1]["statut_aboutissement"] == "confirme", "Phase 2 (B) devrait être confirmee"
assert phases[2]["statut_aboutissement"] == "indetermine", "Phase 3 (C) devrait être INDETERMINEE, pas non_confirme"
assert phases[3]["statut_aboutissement"] == "confirme", "Phase 4 (D) devrait être confirmee"
print("  OK: C marquee 'indetermine' (aucune regle definie), PAS 'non confirme'")
print("      -> absence d'instrumentation n'est plus presentee comme un echec\n")

print("=== TEST 8 : deduplication des regles de correlation repetees ===")
df_corr_dup = pd.DataFrame([
    {"timestamp": "2026-08-09T14:35:36", "rule_id": "100053", "rule_level": 15,
     "rule_description": "x", "phase": "Command and Control",
     "meaning": kc.CORRELATION_RULES["100053"]["meaning"], "confirms_success": True,
     "src_ip": "192.168.1.50"},
    {"timestamp": "2026-08-09T14:35:40", "rule_id": "100053", "rule_level": 15,
     "rule_description": "x", "phase": "Command and Control",
     "meaning": kc.CORRELATION_RULES["100053"]["meaning"], "confirms_success": True,
     "src_ip": "192.168.1.50"},
])
ph_dup = kc.build_phase_summaries(df_scope, df_correlation=df_corr_dup)
corr4 = ph_dup[3]["correlations_wazuh"]
print(f"  2 alertes 100053 en entree -> {len(corr4)} entree(s) en sortie, "
      f"occurrences={corr4[0]['occurrences']}")
assert len(corr4) == 1, "doublon 100053 non dedupliqué"
assert corr4[0]["occurrences"] == 2, "compteur d'occurrences perdu"
print("  OK: dedupliquee, compteur conserve\n")

print("TOUS LES TESTS PASSENT")
