# ansible/ — Déploiement automatisé (playbooks à venir)

Automatisation du déploiement prévue mais pas encore implémentée — voir
l'Issue #39. À ce stade, seul l'inventaire est présent ; le déploiement se
fait manuellement (import de la topologie GNS3 + build des images Docker,
voir le README racine du dépôt).

## Contenu

| Fichier | Rôle |
|---|---|
| `inventory/hosts.ini` | Inventaire des hôtes du lab, groupés par zone réseau (`dmz`, `management`, `lan`). |
| `roles/` | Vide pour l'instant (playbooks à venir, Issue #39). |
