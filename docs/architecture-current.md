# Architecture actuelle

État observé le 6 octobre 2026. Cette page décrit le comportement implémenté, pas l'architecture cible. La vision et les priorités restent dans [plan.md](../plan.md).

## Parcours présents

- Le Quality Gate sans `-RepositoryPath` analyse son propre repository.
- `-DiscoveryOnly -RepositoryPath <chemin>` inspecte un repository externe en lecture seule et émet du JSON.
- Quick, Full, Ci et Fix conservent leurs anciens contrôles et leur orchestration dans `scripts/quality-gate.ps1`.
- Le Bootstrap installe les dépendances locales, vérifie des outils et inscrit les binaires vérifiés dans `.tools/runtime/index.json`.

## Composants

| Composant | État actuel | Limite principale |
| --- | --- | --- |
| Discovery Engine | Intégré au Quality Gate; technologies, preuves, racines et ambiguïtés en JSON | Heuristiques; précision non mesurée sur des repositories réels |
| Capability Matrix | Générée par technologie et plateforme; capacités et disponibilité des outils | Profils codés dans le script; pas de catalogue ou version de matrice autonome |
| Tool Resolver | Sélectionne les candidats disponibles, déduplique par commande et rapporte les capacités non résolues | N'exécute pas lui-même les contrôles; profils en code |
| Tool Runtime | Index local versionne et binaires Windows x64 verifies; marqueur `qualified` apres bootstrap complet | Python et PSScriptAnalyzer hors index; securite et autres plateformes non qualifiees |
| Tool Bootstrap | Installe les dependances, repare le cache deplace, verifie cinq binaires et ecrit l'index | Termine localement; preuves poste neuf/runner encore absentes |
| Compliance Engine | Non autonome; les contrôles restent des fonctions du Quality Gate | Pas de plan générique ni d'agrégateur de conformité séparé |
| Control Catalog | Profils de capacités codés dans PowerShell; configurations existantes | Pas de catalogue indépendant chargé à l'exécution |
| Reporting Engine | JSON Discovery et JSON Quality Gate | Deux formats; pas de moteur de reporting commun |
| Policy Engine | YAML descriptif et décisions dans le script | Le YAML n'est pas la source des décisions effectives |
| Optional Integrations | Scripts, tâches VS Code et job GitLab propres au dépôt | Pas d'adaptateurs portables autonomes |

## Runtime constaté

L'index `.tools/runtime/index.json` contient cinq outils pour `windows-x64`: Gitleaks 8.30.1, TFLint 0.64.0, Terragrunt 1.1.6, Hadolint 2.15.1 et Trivy 0.75.0. Les empreintes SHA-256 sont conservees. Le bootstrap complet marque maintenant la plateforme `qualified`; la securite et le poste neuf restent a qualifier.

Les dépendances Python résident dans `.venv`; PSScriptAnalyzer est sous `.tools/powershell-modules`. Le resolver sait les retrouver localement, mais elles ne figurent pas toutes dans l'index runtime.

## Validation courante

Le cycle courant comprend 38 tests reussis, un bootstrap termine et Quick sans echec. Les avis de dependances et preuves historiques sont centralises dans [testing.md](testing.md).

Linux, macOS, ARM64, exécution de contrôles par plateforme, Control Catalog autonome, Compliance Engine, Reporting Engine et Policy Engine séparé ne sont pas implémentés/qualifiés.

## Écarts avec la cible

`-RepositoryPath` est utilisable pour Discovery; il ne prouve pas la portabilité des contrôles. YAML, Markdownlint, PSScriptAnalyzer et Checkov conservent des chemins ou configurations sous le dépôt analysé. Terraform crée aussi ses caches dans ce dépôt. Les racines découvertes ne pilotent pas les répertoires d'exécution. Voir [compliance-engine.md](compliance-engine.md).

Le gate ne lance aucune opération Git de commit, push ou merge, mais retourne un code non nul sur FAIL/ERROR. Les hooks pre-commit du socle peuvent refuser un commit et le job GitLab n'a pas de `allow_failure`. Leur comportement actuel n'est donc pas celui des adaptateurs consultatifs ciblés par le plan. Aucune configuration n'a été changée pendant cet audit.
