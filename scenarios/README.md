# scenarios/ — Scripts d'attaque et résultats de détection par scénario

Les 4 scénarios d'attaque validés dans le lab, chacun avec son script
d'exécution et son rapport de résultats détaillé. Pour la synthèse
transversale (règles Suricata + Wazuh, décodeurs) voir
`docs/recapitulatif_regles.md` ; pour l'usage de ces résultats par la
couche IA, voir `ai-agent/README.md`.

## Contenu

| Dossier | Scénario | Outil | Cible | Itération |
|---|---|---|---|---|
| `A_nmap/` | Reconnaissance réseau | Nmap | DMZ complète (10.0.10.0/24) | MVP |
| `B_hydra/` | Force brute SSH | Hydra | ssh-eurostar (10.0.10.20) | Itération 2 |
| `C_sqlmap/` | Injection SQL | sqlmap | web-eurostar (10.0.10.10) | Itération 2 |
| `D_metasploit/` | Exploitation backdoor vsftpd | Metasploit | metasploitable2 (10.0.10.30) | Itération 3 |

Chaque dossier suit la même structure : le script d'attaque à la racine
(`attack.sh` ou `attack.rc`), et `results/resultats_scenario_X.md` pour le
rapport de validation (règles déclenchées, taux de détection, faux
positifs, limites connues).

## Lancer un scénario

Scripts exécutés depuis `kali-attacker` (sauf mention contraire) :

```bash
bash scenarios/A_nmap/attack.sh
bash scenarios/B_hydra/attack.sh
bash scenarios/C_sqlmap/attack.sh
msfconsole -r scenarios/D_metasploit/attack.rc
```

## Particularités par scénario

- **A_nmap/** : contient aussi `scripts/generate_baseline_traffic.sh`, qui
  génère du trafic bénin (HTTP + SSH) depuis `workstation-it` — sert de
  baseline d'entraînement à l'Isolation Forest (`ai-agent/mvp/`), pas une
  attaque.
- **B_hydra/** : `wordlist_scenario_B.txt` est la liste de mots de passe
  utilisée par Hydra.
- **D_metasploit/** : `setup_syslog_metasploitable.md` documente la
  configuration manuelle requise sur `metasploitable2` (VM trop ancienne
  pour un agent Wazuh) pour activer la détection de persistance (D2).
  `results/` contient aussi les artefacts bruts (`msf_console.log`,
  `eve_scenario_D_extract.json`) en plus du rapport de synthèse.
