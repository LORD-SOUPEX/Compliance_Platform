# Reporting

Trois sorties JSON existent: Discovery, gate historique et Compliance v1.

## Compliance v1

`-Compliance` produit `compliance-report.json` par defaut sous `reports/` de la plateforme, y compris sur verdict FAIL. `-ReportPath` accepte un chemin relatif dans ce dossier ou un chemin absolu explicite. Le fichier est UTF-8 sans BOM; le meme JSON est emis sur stdout.

Le contrat `schema_version: 1`, `engine_version: 0.1.0` inclut `repository`, `generated_at`, `execution_status`, `discovery`, `matrix`, `resolver`, `execution_plan`, `execution_results`, `summary`, `verdict`, `verdict_reasons`, `coverage` et `advisory: true`.

Le modele de resultat et les regles PASS/FAIL sont decrits dans [compliance-engine.md](compliance-engine.md). `execution_status` vaut `planned`, `completed`, `blocked` (scan incomplet) ou `error` (preparation). Le plan seul ne produit pas de verdict et n'execute pas de controle. Le rapport conserve stdout/stderr, les codes, les versions, les diagnostics et les controles non executes.

`coverage.complete` devient faux en presence de controle requis omis, erreur, resultat manquant ou scan incomplet. Les alternatives ecartes par le resolver ne sont pas des obligations manquantes. La decision porte sur le perimetre effectivement evalue, pas sur une certification.

Les rapports sur disque sont verifies par les integrations, y compris FAIL, capacite manquante et lecture verrouillee. Une erreur d'entree avant le scan ou une impossibilite d'ecrire le fichier ne permet pas de garantir un rapport persistant. Le reporting humain, le masquage general, les limites de taille et la retention locale restent ouverts.

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

Reporting v1 est implemente dans le module Compliance; les enveloppes historiques Discovery et Quality Gate restent distinctes et ne sont pas migrees. La retention GitLab de sept jours ne constitue pas une politique de conservation locale. Voir [testing.md](testing.md) pour les preuves et [architecture-current.md](architecture-current.md) pour les integrations historiques.
