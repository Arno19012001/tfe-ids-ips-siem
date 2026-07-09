# Reproductibilité — Dashboard SIEM Scénario A

## Contexte
Le nœud `wazuh-stack` est une VM QEMU : contrairement aux conteneurs
Docker du projet, elle ne doit jamais être supprimée/recréée (perte de
l'overlay copy-on-write). Ce runbook documente la procédure de secours
si une réinstallation complète du Dashboard s'avérait malgré tout
nécessaire (ex. migration, restauration après incident).

## Contenu exporté
`wazuh/dashboards/scenario_a_dashboard.ndjson` contient 4 objets :
- Index pattern `wazuh-alerts-*` (dépendance, incluse automatiquement
  via "Include related objects")
- Visualisation `SCA-top-alertes` (Horizontal Bar — top signatures)
- Visualisation `SCA-top-ip-sources` (Data Table — top IP sources)
- Visualisation `SCA-timeline` (Vertical Bar — répartition temporelle ;
  volontairement en barres plutôt qu'en ligne, un burst court et isolé
  n'étant pas rendu visible par un graphique Line à un seul point)
- Dashboard `Dashboard - Scénario A -Nmap`

## Procédure de ré-import
1. Menu ☰ → **Dashboard management → Saved Objects**
2. Cliquer **Import** → sélectionner `scenario_a_dashboard.ndjson`
3. Si l'index pattern `wazuh-alerts-*` existe déjà (cas normal sur une
   installation Wazuh standard) : accepter l'**overwrite** proposé par
   l'assistant d'import — l'identifiant correspond à la convention
   utilisée par défaut par le plugin Wazuh, ce n'est donc pas une perte
   de données mais un remplacement à l'identique.
4. Ouvrir le dashboard importé → régler la plage temporelle via
   **Show dates** sur la fenêtre du test à visualiser, puis **Save**
   avec **"Store time with dashboard"** coché (la plage temporelle
   n'est pas préservée telle quelle si les timestamps des alertes
   d'origine ne sont plus dans la fenêtre par défaut).

## Filtre appliqué (rappel)
Toutes les visualisations utilisent le même filtre DQL pour isoler les
alertes du Scénario A parmi l'ensemble des alertes indexées :
```
data.alert.signature_id: (1000101 or 1000102 or 1000103 or 1000104)
```

## Limite connue
Seules 2 des 4 signatures (SID 1000101, 1000104) ont généré des alertes
lors des tests capturés dans ce dashboard — cohérent avec les Issues
#36 (recalibrage seuil SID 1000104) et #37 (détection OS ICMP) encore
ouvertes à ce stade.
