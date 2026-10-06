# Compliance Engine

Etat: **PHASE EN COURS**. Le module [src/Compliance.Engine.psm1](../src/Compliance.Engine.psm1) fournit le premier planificateur autonome. Les modes historiques du Quality Gate restent inchanges pendant son integration.

## Execution Plan v1

`New-CompliancePlan` recoit Discovery, Capability Matrix, Resolver, racine du depot et timeout. Il exige des contrats coherents par technologie et ne lance aucun outil. Le JSON `schema_version: 1` contient le depot et les controles ordonnes.

Chaque controle expose `id`, `name`, `technology`, `capability`, `tool`, `root`, `applicability`, `execution_order`, `timeout`, `side_effect_level`, `required` et `reason`. Les racines sont relatives et ne peuvent sortir du depot. Les identifiants sont deterministes pour les memes entrees.

Les six etats prealables sont `applicable`, `not_applicable`, `capability_unavailable`, `tool_unavailable`, `technology_absent` et `ambiguous`. La selection suit celle du resolver; un candidat disponible mais non retenu n'est pas execute. Une indisponibilite requise reste explicite, pas une technologie absente.

Huit tests unitaires couvrent ces etats, les deux racines d'un meme projet, la serialisation, l'ordre et le rejet d'une racine externe. Execution, aggregation et verdict sont les prochaines etapes de ce meme module.

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
