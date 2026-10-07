# Compliance Engine

Etat: v1 de la Phase 4 terminé; qualification consommateur, sandbox et rétention restent suivies en Phase 8. Le module [src/Compliance.Engine.psm1](../src/Compliance.Engine.psm1) sépare planification, exécution, agrégation et verdict sous Windows x64/PowerShell 5.1. Les modes historiques du Quality Gate restent disponibles.

## Lancement

Depuis la racine de Compliance_Platform, remplacer `<chemin-du-depot>` par un chemin local entre guillemets:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Compliance -RepositoryPath <chemin-du-depot> -PlanOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Compliance -RepositoryPath <chemin-du-depot>
```

Le rapport par defaut est `compliance-report.json` sous `reports/` de la plateforme. `-ReportPath` permet un chemin relatif sous ce dossier ou un chemin absolu explicite. Le plan seul expose `execution_plan`, n'execute aucun controle et garde `verdict: null`. Le mode Compliance ne se combine pas avec DiscoveryOnly, Fix ou Category.

Le parcours est Discovery, Matrix, Resolver, `New-CompliancePlan`, `Invoke-CompliancePlan`, `Get-ComplianceVerdict`, puis `New-ComplianceReport`. Le plan et les fonctions du module sont aussi utilisables independamment de la CLI.

## Execution Plan v1

`New-CompliancePlan` recoit Discovery, Capability Matrix, Resolver, racine du depot et timeout. Il exige des contrats coherents par technologie et ne lance aucun outil. Le JSON `schema_version: 1` contient le depot et les controles ordonnes.

Chaque controle expose `id`, `name`, `technology`, `capability`, `tool`, `root`, `applicability`, `execution_order`, `timeout`, `side_effect_level`, `required` et `reason`. Les racines sont relatives et ne peuvent sortir du depot. Les identifiants sont deterministes pour les memes entrees.

Les six etats prealables sont `applicable`, `not_applicable`, `capability_unavailable`, `tool_unavailable`, `technology_absent` et `ambiguous`. La selection suit celle du resolver; un candidat disponible mais non retenu n'est pas execute. Une indisponibilite requise reste explicite, pas une technologie absente.

Les candidats alternatifs ecartes ne sont pas rendus obligatoires lorsque le resolver couvre la capacite. Les outils complementaires gardent leurs obligations distinctes. Les effets non autorises donnent `not_applicable` avec une raison; ces controles requis omis rendent la couverture explicitement partielle.

## Execution et permissions

L'executeur `Invoke-BoundedProcess` du gate est reutilise pour lancer les processus dans la racine du controle, avec capture separee stdout/stderr/code, budget de temps et terminaison de l'arbre Windows au timeout. Les erreurs de lancement et d'integrite sont restituees comme erreurs techniques. Une sonde de version est effectuee lorsque le resolver ne fournit pas la version; elle consomme le budget du controle. La granularite native du timeout reste la seconde.

`-AllowNetwork` autorise les controles reseau. `-AllowCodeExecution` autorise tests, plugins et configurations pouvant charger du code (pytest, Pylint, ansible-lint, pre-commit, TFLint). Checkov exige les deux permissions. Ces flags sont des gardes de selection, pas un sandbox: le code autorise peut ecrire ou acceder au reseau. Aucun apply, destroy, build d'image ou deploiement n'est configure.

Les adaptateurs v1 couvrent les commandes declarees dans les profils du socle: Ruff, Pylint, Bandit, pytest, pip-audit, format Terraform/OpenTofu/Terragrunt, TFLint, ShellCheck, Hadolint, YAML/Ansible, Markdown, PSScriptAnalyzer, Checkov et Trivy. Leur presence dans le code n'est pas une qualification de toutes les plateformes ou technologies. Un adaptateur inconnu produit une erreur explicite.

PowerShell passe d'abord par le parseur natif, puis PSScriptAnalyzer sur les fichiers decouverts. Ruff et Bandit recoivent les sources decouvertes et ignorent les caches exclus. Markdown utilise la configuration et le cache pre-commit de la plateforme, sans installer de hook dans le consommateur. L'audit Python consommateur exige `requirements.txt` et utilise `--no-deps --disable-pip`; il n'audite pas le runtime de la plateforme a sa place. Hadolint ne qualifie pas Compose.

## Resultats et decision

Chaque resultat expose `control_id`, `technology`, `capability`, `root`, `status`, `execution_start`, `execution_end`, `duration_ms`, `tool_version`, `stdout`, `stderr`, `exit_code`, `critical` et `diagnostics`.

- `success`: controle execute, code 0.
- `fail`: controle execute, code non nul.
- `error`: lancement, integrite, timeout, preparation, ambiguite ou capacite/outil requis indisponible.
- `skipped`: technologie absente, candidat non retenu ou execution non autorisee, avec justification.

FAIL signifie au moins un `fail` ou une erreur critique. PASS signifie aucun de ces deux cas; une erreur non critique reste visible sans rendre la decision bloquante. Un scan incomplet empeche toute execution et donne FAIL. Un resultat manquant ou duplique devient une erreur critique de contrat. `coverage` indique les controles requis omis: PASS n'est pas une attestation de couverture complete.

La CLI retourne 0 sur PASS ou plan seul valide, 1 sur verdict FAIL et 2 sur scan/preparation incomplets. Elle n'effectue aucune operation Git de commit, push ou merge. Les adaptateurs CI et hooks historiques gardent leurs propres comportements.

## Preuves et limites

27 tests unitaires Compliance, 6 tests Control Catalog, 13 intégrations Compliance, 4 intégrations adaptateur et 45 scénarios historiques passent. Les tests couvrent le DAG, budgets, schémas, rapports, permissions, parité et audits externes PowerShell/Python/Markdown.

Le DAG catalogue est trié topologiquement; cycles et références absentes sont refusés. Un prérequis non réussi bloque les contrôles dépendants requis. Le moteur applique deadline globale, maximum de contrôles et plafond de sortie conservée par flux. Le résumé humain optionnel s'écrit sur stderr sans polluer stdout JSON.

Le Control Catalog source est [`.config/control-catalog.json`](../.config/control-catalog.json), son schéma est [`.config/control-catalog.schema.json`](../.config/control-catalog.schema.json). Il contient 28 contrôles v1 couvrant 13 technologies, avec objectif, applicabilité, paramètres, outil, dépendances, timeout, coût, sévérité, effets, permissions, plateformes et limites. `Get-CapabilityProfile` ne contient plus de switch de profils; Matrix expose les IDs et métadonnées du catalogue, et le plan les transporte. Les paramètres des adaptateurs Ruff/Pylint/Bandit/pytest, IaC, Checkov, Trivy, Ansible, YAML et Markdown sont lus du catalogue.

Le rapport v1 contient maintenant `findings`, diagnostics aplatis, limitations, metadata, coverage et les durées Discovery/Resolver/Compliance/Reporting; les erreurs de scan produisent un finding critique. `metadata.catalog_sha256` identifie exactement les octets du catalogue chargé; ce champ et les métriques sont facultatifs pour préserver la compatibilité des rapports v1 antérieurs. Le schéma est [`.config/compliance-report.schema.json`](../.config/compliance-report.schema.json) et `Test-ComplianceReport` valide la cohérence avant écriture. Les 6 tests du catalogue vérifient champs inconnus, permissions, références, cycles et empreinte; les intégrations couvrent le flux catalogue → Matrix → Plan → rapport.

Restent ouverts: qualification sur dépôts consommateurs représentatifs, migration des modes Quick/Full historiques, isolation des contrôles pouvant exécuter du code, limites mémoire réelles (les flux sont tronqués après buffering) et gouvernance de confidentialité/rétention. Les sorties du rapport peuvent contenir des données sensibles; aucune publication distante ou rétention automatique n'est configurée. Voir [reporting.md](reporting.md) et [testing.md](testing.md).

## Gate historique

`scripts/quality-gate.ps1` découvre les technologies puis appelle, dans un ordre fixe, les fonctions génériques, sécurité, documentation, Python, PowerShell, Ansible, Terraform, Terragrunt, conteneurs et Shell. Quick, Full, Ci, Fix et `-Category` influencent cette orchestration. Fix modifie des fichiers et constitue un mode explicite distinct du scan en lecture seule.

Discovery, Capability Matrix et Tool Resolver calculent maintenant des structures réutilisables, mais le Quality Gate n'exécute pas encore les contrôles à partir de `tool_resolution.selected_tools`. Les contrôles gardent leurs propres règles d'applicabilité et d'appel d'outils. Pas de DAG, modèle de contrôle, agrégateur générique de résultats ou moteur de décision autonome.

Le mode `-DiscoveryOnly` ne modifie pas les sources et n'appelle pas l'orchestration des contrôles; un rapport est écrit uniquement sur demande. Le gate ne lance aucune opération Git, mais ses codes non nuls sont propagés par les hooks et le job CI du socle. Le verdict consultatif sans blocage reste une cible produit, pas une garantie des intégrations existantes.

## Modes et périmètres actuels

| Mode | Comportement implémenté |
| --- | --- |
| Quick | Contrôles génériques, secrets, Markdown et contrôles technologiques applicables; pas d'audit Python ni de tests par défaut |
| Full / Ci | Ajoute audit des dépendances de la plateforme et tests du socle; autres contrôles approfondis selon les technologies; Ci écrit un rapport par défaut |
| Fix | Formate/corrige Python, formate Terraform si certain, normalise les fichiers, puis exécute Quick; les corrections ne sont pas limitées par `-Category` |
| `-Category` | Limite les contrôles exécutés; une catégorie verte n'atteste pas Full; Tests lance les tests même en Quick |

Les contrôles Terraform incluent `init -backend=false` et créent des caches sous le dépôt analysé; ils ne font ni apply ni destroy. Full peut contacter les bases d'avis, télécharger des plugins ou exécuter du code de test. Aucune gestion générique de consentements, permissions ou budgets réseau n'est livrée.

## Limites sur dépôt externe

L'interpréteur Python et `.tools/bin` sont ancrés dans la plateforme, mais plusieurs contrôles conservent leurs chemins sous le dépôt analysé: YAML, Markdownlint, module/configuration PSScriptAnalyzer et lanceur Checkov. PSScriptAnalyzer n'analyse que `scripts/`, contrairement au parseur qui couvre tous les fichiers PowerShell détectés. Terraform init/validate s'exécutent à la racine, sans suivre les racines Discovery.

Compose est détecté comme conteneur mais passe par les règles Dockerfile et Hadolint, sans validation Compose dédiée. OpenTofu, Kubernetes, Helm, JavaScript et TypeScript n'ont pas de contrôles dédiés dans la séquence actuelle. Full exécute les tests de Compliance_Platform, pas ceux d'un dépôt externe choisi. Ces capacités restent partielles, même si la détection est implémentée.

L'exécuteur borne les processus avec capture stdout/stderr et délai; il utilise `taskkill` sous Windows. Les appels Git, TOML et PSScriptAnalyzer ne passent pas tous par cet exécuteur, et les sorties ne sont pas bornées en taille. Voir [reporting.md](reporting.md) et [testing.md](testing.md).
