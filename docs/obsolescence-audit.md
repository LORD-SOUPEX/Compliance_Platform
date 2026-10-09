# Audit d'obsolescence

Date: 9 octobre 2026.

## Périmètre et méthode

Audit statique du README, des pages de documentation, des scripts PowerShell/Bash, modules PowerShell, tests, configurations et dépendances déclarées. Les exécutions disponibles utilisées comme preuves récentes sont Bootstrap Offline, Doctor, Quick, Full, `scripts/test.ps1` et les hooks pre-commit. Aucun code, dépendance, configuration ou contrôle n'a été supprimé.

Le scan AST a parcouru 22 fichiers PowerShell, 110 définitions de fonctions et 157 noms de commandes; il n'a trouvé aucune définition sans appel statique. Un second scan n'a relevé aucun paramètre inutilisé de premier niveau dans les scripts. Ces scans ne détectent pas toutes les formes de dispatch dynamique; leurs résultats désignent des candidats, pas une preuve formelle d'absence de code mort.

## Résumé

- Aucune fonction, module ou script de production n'a été confirmé inutilisé.
- Les cinq modules source sont importés par Bootstrap, Doctor, Quality Gate, adaptateur ou les tests.
- Les relais Bash sont référencés par les contrats/tests et sont vérifiés par Doctor; ils relaient PowerShell sous Git Bash Windows, ils ne sont pas des moteurs Linux/macOS.
- Les paramètres de scripts n'ont pas de candidat inutilisé dans le scan AST de premier niveau.
- Aucun doublon de tests fonctionnels n'est démontré. Les suites unitaires de schéma/catalogue et leurs intégrations testent des niveaux de contrat différents.
- Le code Quick/Full historique reste actif et sert les entrées existantes; ce n'est pas du code mort.
- La recherche `TODO|FIXME|HACK|XXX` n'a trouvé aucun marqueur de travail dans les scripts, sources, tests, README et docs.

## Découvertes

| ID | Découverte et preuve | Impact | Risque d'une suppression | Recommandation |
| --- | --- | --- | --- | --- |
| OBS-01 | [runtime.md](runtime.md) et [resolver.md](resolver.md) indiquaient que les wheels Python n'avaient pas de hashes; le Runtime Index contient maintenant 154 provenances de roues et Doctor re-vérifie leurs SHA-256. `runtime.md` indiquait aussi que Doctor ne lisait pas l'index, alors que `scripts/doctor.ps1` le valide. | Guide d'exploitation erroné pouvant faire croire à une absence de vérification d'intégrité ou à une validation insuffisante. | Supprimer ces pages ferait perdre des procédures encore utiles; le défaut porte sur leur texte, pas leur existence. | Corrigé dans la consolidation documentaire du 9 octobre; conserver les preuves historiques datées. |
| OBS-02 | [architecture-current.md](architecture-current.md) et [compliance-engine.md](compliance-engine.md) donnaient des comptes courants de 38 et 45 scénarios, contre 49 scénarios Quality Gate dans la validation du 9 octobre. | Les comptes et dates donnaient une image incohérente de l'état vérifié. | Retirer l'historique effacerait la progression et les conditions sous lesquelles les preuves ont été obtenues. | Résumé courant corrigé; les nombres antérieurs restent uniquement dans leurs passages historiques datés. |
| OBS-03 | [testing.md](testing.md) contenait deux paragraphes successifs répétant les mêmes mesures du corpus Discovery et mêlait résultats courants et historiques. | Lecture coûteuse et possibilité de reprendre un ancien compte sans sa date/contexte. | La suppression du seul paragraphe dupliqué ne retire aucune preuve unique; supprimer tout l'historique ferait perdre la traçabilité. | Le paragraphe répété a été retiré; les résultats historiques restent datés et identifiés comme tels. |
| OBS-04 | [roadmap-status.md](roadmap-status.md) déclarait encore que les overrides/layouts étaient des tâches locales, alors que les racines sont couvertes par tests et que l'override est bloqué par décision de gouvernance dans [roadmap.md](roadmap.md). | Les lecteurs pouvaient lancer un chantier déjà couvert ou croire un arbitrage déjà donné. | Supprimer le résumé casserait le lien de navigation et ferait perdre une vue d'ensemble. | Synthèse corrigée pour refléter le statut détaillé, sans modifier les critères de sortie. |
| OBS-05 | [quality-gate.yml](../.config/quality-gate.yml) n'est lu par aucun moteur; références code trouvées: présence exigée par Doctor et documentation Policy Engine. Les décisions runtime restent dans PowerShell. | Les modifications du YAML peuvent sembler influer sur le comportement alors qu'elles ne le font pas. | Le fichier est exigé par Doctor et matérialise le contrat descriptif; le supprimer serait un changement de comportement du diagnostic et de documentation. | Le traiter explicitement comme descriptif/non autoritaire. Une consommation effective nécessiterait une décision de politique, hors de cet audit. |
| OBS-06 | Les schémas [control-catalog.schema.json](../.config/control-catalog.schema.json) et [compliance-report.schema.json](../.config/compliance-report.schema.json) sont lus par les tests et docs; les chemins runtime emploient des validateurs PowerShell (`Import-ControlCatalog`, `Test-ComplianceReport`) et non un validateur JSON Schema générique. | La règle de validation existe à deux endroits et peut diverger entre schéma publié, validateur runtime et tests. | Supprimer un schéma affaiblirait le contrat pour les consommateurs externes et les tests de compatibilité. | Conserver les schémas comme contrats publics; documenter qu'ils ne sont pas l'implémentation runtime et garder leurs tests de cohérence. |
| OBS-07 | `setuptools==84.0.0` est une dépendance directe dans `requirements-dev.txt` et `.config/tool-versions.yml`. L'examen des métadonnées installées n'a trouvé que des références setuptools derrière des extras optionnels (`dev`, `build`, `mypyc`), pas de dépendance non optionnelle observée dans cet environnement. | Un pin direct possiblement superflu augmente le verrou et la surface de maintenance; une installation depuis source ou un extra futur peut toutefois en dépendre. | Retrait sans reconstruction/validation du lock peut casser des installations ou des flux de build qui ne sont pas exercés par le poste courant. | Candidat à une revue ultérieure contrôlée par `update-lock.ps1 -Update/-Check`; ne pas retirer sur cette seule preuve locale. |
| OBS-08 | Le Resolver et le catalogue sont également testés en unitaires et dans les scénarios end-to-end; la suite intégration Quality Gate utilise des fixtures et des fonctions extraites par AST. Aucun couple de tests identiques n'a été confirmé. | Les tests ont un coût de maintenance, mais leurs portées se complètent; les fixtures sont sensibles à la structure interne. | Dédupliquer à l'aveugle peut retirer la seule couverture d'une frontière ou d'un résultat négatif. | Ne supprimer aucun test sur les preuves actuelles; conserver les cas d'intégrité, rollback, corruption, permissions et rapports. |

## Éléments non obsolètes confirmés

| Élément examiné | Preuve de consommation | Conclusion |
| --- | --- | --- |
| `src/Tool.Provenance.psm1` | Importé par Bootstrap, Doctor et Quality Gate; tests unitaires dédiés. | Actif. |
| `src/Control.Catalog.psm1` | Importé par Quality Gate et Compliance Engine; tests unitaires/intégration. | Actif. |
| `src/Platform.Support.psm1` | Importé au démarrage du Quality Gate; tests de matrice. | Actif. |
| `src/Compliance.Engine.psm1` | Importé par les modes Compliance et rapports historiques; tests unitaires/intégration. | Actif. |
| `src/Compliance.Adapter.psm1` | Importé par le wrapper; tests adaptateurs. | Actif. |
| Scripts Bootstrap, Doctor, Quality Gate, Tests, update-lock, adaptateur Compliance, relais Compliance et contrôle pictogrammes | Appels par tâches VS Code, CI, autres scripts, documentation ou tests; Doctor vérifie une partie des fichiers requis. | Aucun script orphelin confirmé. |
| Dépendances Ruff, Pylint, mypy, pytest, Bandit, Ansible, Checkov et outils associés | Déclarées au catalogue et/ou appelées conditionnellement selon la technologie, les contrôles ou le test du socle. | Leur absence d'invocation sur ce dépôt sans sources Python/IaC ne prouve pas qu'elles sont inutilisées pour les dépôts consommateurs. |

## README

Le README a été structuré comme point d'entrée produit avec capacités, architecture, technologies, plateformes, commandes, modèle de sécurité, résultats datés, blocages externes et liens vers l'index documentaire.

## Décision

Aucune suppression n'est justifiée par cet audit. Le seul candidat de dépendance nécessite une validation du lock; les problèmes confirmés portent sur des incohérences et répétitions documentaires corrigées au cours de la consolidation. Aucun code, dépendance ou contrôle n'a été supprimé ou modifié.
