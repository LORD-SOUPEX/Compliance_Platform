# Reporting

Deux sorties JSON existent actuellement.

Le module Compliance introduit aussi un Execution Plan autonome `schema_version: 1`, serialisable avec `ConvertTo-Json -Depth 12`. Le rapport Compliance et son verdict ne sont pas encore branches dans ce premier cycle de modele. Voir [compliance-engine.md](compliance-engine.md).

## DiscoveryOnly

`-DiscoveryOnly` ecrit sur stdout un objet `schema_version: 1` contenant repository, technologies, project_roots, ambiguities, capability_matrix, tool_resolution, scan_complete et scan_errors. `-ReportPath` ecrit une copie sous `reports/` de la plateforme, ou au chemin absolu indique. Une erreur de parcours ou lecture ne supprime plus cet inventaire partiel.

## Quality Gate

Quick/Full/Ci produisent un rapport comprenant date, mode, catégorie, technologies, contrôles (`nom`, `statut`, `message`, `duree_ms`), résumé et code de sortie. Les technologies transportent aussi les preuves Discovery, la Capability Matrix et la résolution.

Sans `-ReportPath`, Quick/Full n'écrivent aucun rapport. Ci utilise `quality-report.json` par défaut. Un chemin relatif est résolu sous `reports/` du **dépôt analysé**, contrairement à Discovery qui l'ancre dans la plateforme. Un chemin absolu est utilisé tel quel. Fix peut aussi produire un rapport, avec le mode `Quick après Fix`.

## Codes et limites

- Discovery réussi: code 0, sans verdict de conformité.
- Discovery incomplet par erreur de parcours/lecture: JSON diagnostique et code 2, sans verdict de conformite.
- Gate: code 1 si au moins un FAIL ou ERROR est agrégé, sinon 0; WARN/SKIP seuls ne bloquent pas le gate.
- Exception dans le bloc principal: code 2, sans écriture garantie du rapport final. Une entrée invalide peut échouer avant ce bloc.

Le JSON du gate n'a pas de `schema_version`, de champ de verdict `PASS`/`FAIL`, de versions moteur/politique ni de constats normalisés. Les sorties externes restent dans la console: les avis pip-audit détaillés ne sont pas conservés dans `controles`. Les tests vérifient cohérence du code et du résumé, pas un schéma commun complet.

**Reporting Engine autonome: non implémenté.** Les enveloppes Discovery et Quality Gate restent distinctes. La rétention GitLab de sept jours ne constitue pas une politique de conservation des rapports locaux. Voir [testing.md](testing.md) pour les preuves, et [architecture-current.md](architecture-current.md) pour les limites des intégrations.
