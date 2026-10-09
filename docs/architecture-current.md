# Architecture actuelle

État observé le 9 octobre 2026. Cette page décrit le comportement implémenté, pas l'architecture cible. La vision et les critères des phases restent dans [la roadmap](roadmap.md).

## Parcours présents

- Le Quality Gate sans `-RepositoryPath` analyse son propre repository.
- `-DiscoveryOnly -RepositoryPath <chemin>` inspecte un repository externe en lecture seule et émet du JSON.
- `-Compliance -RepositoryPath <chemin>` execute le parcours v1 plan/resultats/rapport/verdict; `-PlanOnly` n'execute rien. Les effets reseau/code sont soumis a permission.
- Quick, Full, Ci et Fix conservent leurs anciens contrôles et leur orchestration dans `scripts/quality-gate.ps1`.
- Le Bootstrap installe les dépendances locales, vérifie des outils et inscrit les binaires vérifiés dans `.tools/runtime/index.json`.

## Composants

| Composant | État actuel | Limite principale |
| --- | --- | --- |
| Discovery Engine | Intégré au Quality Gate; technologies, preuves, racines et ambiguïtés en JSON | Heuristiques; précision non mesurée sur des repositories réels |
| Capability Matrix | Générée par technologie et plateforme; capacités et disponibilité des outils | Profils codés dans le script; pas de catalogue ou version de matrice autonome |
| Tool Resolver | Sélectionne les candidats disponibles, déduplique par commande et rapporte les capacités non résolues | N'exécute pas lui-même les contrôles; profils en code |
| Tool Runtime | Index local versionné: cinq binaires Windows x64, Python/packages/wheels et PSScriptAnalyzer avec hashes | `qualified` runtime signifie installation terminée; sécurité produit et autres plateformes non qualifiées |
| Tool Bootstrap | Installe les dépendances, répare le cache déplacé, vérifie les artefacts, provenance et inventaire | Bootstrap Offline local réussi; preuves poste neuf/runner encore absentes |
| Compliance Engine | Module autonome v1: plan, execution bornee, aggregation et verdict | Adapteurs codes, migrations historiques et qualifications avancees ouvertes |
| Control Catalog | `.config/control-catalog.json` v1 validé; profils et métadonnées consommés par Matrix/Plan | 28 contrôles déclarés; exécution historique encore codée, qualifications externes ouvertes |
| Reporting Engine | Rapport Compliance v1 versionné: findings, diagnostics, couverture, limitations, métriques, masquage et rétention locale ciblée | Enveloppes historiques distinctes conservées; gouvernance de partage/rétention externe ouverte |
| Policy Engine | YAML descriptif et décisions dans le script | Le YAML n'est pas la source des décisions effectives |
| Optional Integrations | Contrat commun, wrappers PS/Bash, tâche VS Code, job GitLab opt-in | Runner GitLab distant non exécuté; limites dans [integrations.md](integrations.md) |

## Runtime constaté

L'index `.tools/runtime/index.json` contient cinq outils pour `windows-x64`: Gitleaks 8.30.1, TFLint 0.64.0, Terragrunt 1.1.6, Hadolint 2.15.1 et Trivy 0.75.0, ainsi que le snapshot Python de 154 packages/wheels et PSScriptAnalyzer. Les provenances et empreintes correspondantes sont enregistrées. Bootstrap marque le runtime `qualified` après installation complète; cela ne qualifie pas le produit. Full reste bloqué par pip-audit.

Les dépendances Python résident dans `.venv`; PSScriptAnalyzer est sous `.tools/powershell-modules`. Le resolver sait les retrouver localement, mais elles ne figurent pas toutes dans l'index runtime.

## Validation courante

La dernière validation locale consignée rapporte 49 scénarios Quality Gate, 27 tests unitaires Compliance, 14 tests provenance/runtime, 13 intégrations Compliance, 4 intégrations adaptateur et les autres suites spécialisées au vert. Doctor: 71 PASS; Quick: 10 PASS et un WARN ShellCheck; Full: 11 PASS, seul pip-audit en FAIL. Les détails et preuves historiques sont centralisés dans [testing.md](testing.md).

Linux/macOS/ARM64, qualification d'exécution de tous les contrôles et Policy Engine avancé restent ouverts. Compliance, catalogue et reporting v1 sont livrés; les parcours Quick/Full historiques ne sont pas migrés.

## Écarts avec la cible

`-RepositoryPath` est utilisable pour Discovery; il ne prouve pas la portabilité des contrôles. YAML, Markdownlint, PSScriptAnalyzer et Checkov conservent des chemins ou configurations sous le dépôt analysé. Terraform crée aussi ses caches dans ce dépôt. Les racines découvertes ne pilotent pas les répertoires d'exécution. Voir [compliance-engine.md](compliance-engine.md).

Le gate ne lance aucune opération Git de commit, push ou merge, mais retourne un code non nul sur FAIL/ERROR. Les hooks pre-commit du socle peuvent refuser un commit et le job GitLab n'a pas de `allow_failure`. Leur comportement actuel n'est donc pas celui des adaptateurs consultatifs ciblés par le plan. Aucune configuration n'a été changée pendant cet audit.
