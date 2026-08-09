import sys, types
for mod in ["dotenv", "langchain_ollama", "langchain_core", "langchain_core.prompts", "pydantic"]:
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)
sys.modules["dotenv"].load_dotenv = lambda *a, **k: None
sys.modules["langchain_ollama"].ChatOllama = object
sys.modules["langchain_core.prompts"].ChatPromptTemplate = object
class _BM:
    def __init_subclass__(cls, **kw): pass
sys.modules["pydantic"].BaseModel = _BM
sys.modules["pydantic"].Field = lambda *a, **k: None

import pandas as pd, importlib.util
spec = importlib.util.spec_from_file_location("kc", "/home/claude/killchain_reconstruction.py")
kc = importlib.util.module_from_spec(spec); spec.loader.exec_module(kc)

# SCÉNARIO : uniquement un Nmap, rien d'autre
rows = []
for ts, sid in [("2026-08-09T20:10:00", "1000101"), ("2026-08-09T20:10:30", "1000101"),
                ("2026-08-09T20:11:05", "1000104")]:
    m = kc.SID_METADATA[sid]
    rows.append({"timestamp": ts, "sid": sid, "scenario": m["scenario"], "phase": m["phase"],
                 "tactic": m["tactic"], "technique": m["technique"], "direction": m["direction"],
                 "target": m["target"], "rule_description": m["description"],
                 "agent_id": "019", "agent_name": "suricata-sensor", "src_ip": "192.168.1.50"})
df = pd.DataFrame(rows)

phases = kc.build_phase_summaries(df, df_correlation=pd.DataFrame())
camps = kc.identify_campaigns(df)

print("IP attaquante retenue :", camps[0]["src_ip"] if camps else "aucune")
print(f"Couverture : {sum(1 for p in phases if p['nb_alertes']>0)}/4 phases avec au moins une preuve.")
print(f"  Aboutissement : {sum(1 for p in phases if p['statut_aboutissement']=='confirme')} confirmé(s), "
      f"{sum(1 for p in phases if p['statut_aboutissement']=='indetermine')} indéterminée(s)")
print()
for p in phases:
    print(f"  Phase {p['ordre']} — {p['phase']} (Scénario {p['scenario'] or 'N/A'})")
    print(f"    Alertes      : {p['nb_alertes']}")
    if p["nb_alertes"] > 0:
        print(f"    Période      : {p['first_timestamp']} -> {p['last_timestamp']}")
        print(f"    IP attaquant : {p['attacker_ip']}")
        print(f"    Cible        : {p['target'][:50]}")
    print(f"    Statut       : {p['statut_aboutissement']}")
print()
print("=" * 60)
print("CE QUI EST ENVOYÉ AU LLM :")
print("=" * 60)
print(kc._format_phases_for_prompt(phases))
