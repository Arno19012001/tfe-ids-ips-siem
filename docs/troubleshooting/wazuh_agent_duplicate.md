# Résolution — Conflit "Duplicate agent name" sur suricata-sensor

## Contexte

Le nœud `suricata-sensor` (conteneur Docker, GNS3) intègre un agent Wazuh HIDS
enregistré auprès de `wazuh-stack` (10.0.30.10). Un conflit d'enrôlement était
observé de façon récurrente au redémarrage du nœud :

```
[entrypoint] Agent Wazuh non enregistré, enrollment vers 10.0.30.10...
2026/07/06 12:09:32 agent-auth: ERROR: Duplicate agent name: suricata-sensor.
Unable to add agent (from manager)
```

## Diagnostic

Le message provient du Manager (`wazuh-authd`), pas d'un problème réseau : le
Manager refuse l'enrôlement car il connaît déjà un agent nommé
`suricata-sensor`. Le `Dockerfile` d'origine ne déclarait aucun `VOLUME` pour
`/var/ossec/etc` — `client.keys` vivait uniquement dans la couche writable
éphémère du conteneur. Résultat : à chaque redémarrage du nœud sans
persistance de cette clé, l'agent tentait un nouvel enrôlement sous un nom
déjà connu du Manager (VM QEMU persistante par conception), d'où le conflit.

## Options évaluées

| Option | Portée | Compromis |
|---|---|---|
| **A — Manager : bloc `<force>` dans `ossec.conf`** (auth.html#force, doc. officielle Wazuh) | Corrige le symptôme côté serveur, quel que soit l'état du sensor | Affaiblit la protection anti-usurpation native de l'enrôlement Wazuh (accepte le remplacement d'un agent actif) |
| **B — Sensor : `VOLUME ["/var/ossec/etc"]`** | Corrige la cause racine (persistance de l'identité) | Ne protège pas contre une suppression/recréation complète du nœud GNS3 (nouveau volume à chaque fois dans ce cas) |

## Décision retenue

Option **B seule**. Justification : la pratique de travail actuelle
(suppression/recréation du nœud) reste rare comparée aux simples cycles
stop/start effectués lors des tests. Le risque résiduel accepté est documenté
ci-dessous plutôt que neutralisé par un second correctif jugé disproportionné
à ce stade du projet.

## Correctif implémenté

`images/suricata-sensor/Dockerfile`, commit
[`7f359b7`](https://github.com/Arno19012001/tfe-ids-ips-siem/commit/7f359b762518564633ede36407507992697bde1e) :

```dockerfile
# --- Persistance de l'identité Wazuh (client.keys) au-delà d'un stop/start du nœud ---
VOLUME ["/var/ossec/etc"]
```

## Validation empirique

Test réalisé le 06/07/2026 : capture de `client.keys` avant et après un cycle
stop/start complet du nœud (sans suppression).

| | Avant | Après |
|---|---|---|
| Taille | 89 octets | 89 octets |
| MD5 | `ae5e38736e65da98f2a049eca486dc9d` | `ae5e38736e65da98f2a049eca486dc9d` |
| Horodatage | Jul 6 12:50 | Jul 6 12:50 (inchangé) |

Log de démarrage confirmant l'absence de nouvelle tentative d'enrôlement :
`[entrypoint] Agent Wazuh déjà enregistré (client.keys présent).`

**Conclusion : persistance confirmée sur un cycle stop/start.** La
persistance sur suppression/recréation complète du nœud n'a pas été testée et
n'est pas garantie par cette option (cf. tableau des options ci-dessus).

## Risque résiduel accepté

En cas de suppression/recréation du nœud (rebuild d'image, changement de
topologie), le conflit "Duplicate agent name" peut réapparaître
ponctuellement. Procédure de déblocage manuelle, déjà validée :

```bash
# Sur wazuh-stack :
/var/ossec/bin/manage_agents   # option R (remove), ID de suricata-sensor

# Sur suricata-sensor :
agent-auth -m 10.0.30.10 -A suricata-sensor
```
