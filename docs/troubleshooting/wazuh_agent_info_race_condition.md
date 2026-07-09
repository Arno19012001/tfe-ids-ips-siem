# Erreurs (1103) "Could not open file 'queue/sockets/.agent_info'" au démarrage de l'agent

## Symptôme
Au démarrage du conteneur `suricata-sensor`, les daemons `wazuh-agentd`,
`wazuh-syscheckd`, `wazuh-logcollector` et `wazuh-modulesd` affichent
chacun une ou plusieurs erreurs :

```
wazuh-agentd: ERROR: (1103): Could not open file 'queue/sockets/.agent_info'
due to [(2)-(No such file or directory)].
```

## Cause
`wazuh-control start` lance les daemons Wazuh quasi simultanément.
`.agent_info` est créé par `wazuh-agentd` lors de son initialisation ;
les autres daemons tentent de le lire avant que ce fichier n'existe,
d'où l'erreur (2) "No such file or directory". Il s'agit d'une race
condition connue au boot, sans effet sur le fonctionnement de l'agent
une fois l'initialisation terminée.

## Validation empirique (09/07/2026)
- `tail -n 30 /var/ossec/logs/ossec.log` : aucune récurrence de
  l'erreur après le boot ; séquence de démarrage propre (FIM, SCA,
  rootcheck, logcollector surveillant `eve.json`).
- `.agent_info` présent après démarrage :
  `-rw-r--r-- 1 wazuh wazuh 39 Jul 9 12:38 /var/ossec/queue/sockets/.agent_info`
- Statut côté Wazuh Manager (`agent_control -l`) :
  `ID: 007, Name: suricata-sensor, IP: any, Active`

## Conclusion
Comportement bénin et transitoire, sans impact sur la collecte
des logs Suricata ni sur la remontée des alertes vers le Manager.
Aucune action corrective nécessaire. À ignorer si observé de nouveau
lors d'un redémarrage du nœud GNS3.
