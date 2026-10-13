# Rapport d'Exécution - Phase 3 (Portage des 28 Contrôles & Parité Canonique)

> **Date** : 13 Octobre 2026  
> **Statut global** : Phase 3 réalisée, vérifiée et attestée par 32 tests automatisés (100 % PASS).

---

## 1. Objectifs et Livrables de la Phase 3

La Phase 3 réalise le portage intégral des contrôles de conformité et l'alignement canonique strict entre l'ancien moteur PowerShell et le nouveau moteur Go (`core/`) :
1. **Exécuteur de contrôles borné & Masquage regex** ([runner.go](file:///m:/Git/Compliance_Platform/core/internal/engine/runner.go)) :
   - Confinement des processus sous Windows Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) et PGID POSIX sans orphelin.
   - Capture streaming avec plafond mémoire (`max_output_bytes`) et indicateur `output_truncated`.
   - Masquage regex des secrets (tokens GitHub/GitLab, clés AWS, clés privées, mots de passe) avant émission des sorties.
   - Sonde de qualification et de version des outils.
2. **Catalogue des 28 contrôles en Go** ([catalog.go](file:///m:/Git/Compliance_Platform/core/internal/catalog/catalog.go)) :
   - Modélisation typée et chargement cryptographiquement vérifié (SHA-256) de [.config/control-catalog.json](file:///m:/Git/Compliance_Platform/.config/control-catalog.json).
   - Profils de capacités regroupant les 28 contrôles sur les 13 technologies.
   - Gestion stricte de tous les statuts d'indisponibilité : `tool_unavailable`, `capability_unavailable`, `technology_absent`, `ambiguous`, `permission_denied`, `skipped`, `error`.
3. **Peuplement dynamique de la Capability Matrix et de la Tool Resolution** ([matrix.go](file:///m:/Git/Compliance_Platform/core/internal/matrix/matrix.go)) :
   - Construction dynamique de `capability_matrix` et `tool_resolution` pour toutes les technologies découvertes.
   - Prise en compte des politiques de sélection (`all` vs `alternative`).
   - Calcul des statuts (`ready`, `partial`, `unavailable`, `absent`, `ambiguous`) et des métriques de résolution.
4. **Moteur d'ordonnancement de plan & Génération du rapport canonique v1** ([plan.go](file:///m:/Git/Compliance_Platform/core/internal/engine/plan.go), [executor.go](file:///m:/Git/Compliance_Platform/core/internal/engine/executor.go), [report.go](file:///m:/Git/Compliance_Platform/core/internal/report/report.go)) :
   - Résolution des dépendances du catalogue (`catalog_dependencies`) et tri topologique déterministe (Kahn).
   - Émission du rapport JSON v1 canonique validé par [.config/compliance-report.schema.json](file:///m:/Git/Compliance_Platform/.config/compliance-report.schema.json) et par les règles de `Test-ComplianceReport`.
   - Démonstration de la parité canonique à 100 % avec `quality-gate.ps1`.

---

## 2. Inventaire des 28 Contrôles du Catalogue

| # | Identifiant du contrôle | Technologie | Capacité | Commande d'outil | Effet de bord | Permissions requises |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `terraform.format.terraform` | `terraform` | formatting | `terraform` | `read_only` | Aucune |
| 2 | `terraform.lint.tflint` | `terraform` | linting | `tflint` | `code_execution` | `code_execution` |
| 3 | `terraform.security.checkov` | `terraform` | security | `checkov` | `network_code_execution` | `network,code_execution` |
| 4 | `opentofu.format.tofu` | `opentofu` | formatting | `tofu` | `read_only` | Aucune |
| 5 | `opentofu.lint.tflint` | `opentofu` | linting | `tflint` | `code_execution` | `code_execution` |
| 6 | `opentofu.security.checkov` | `opentofu` | security | `checkov` | `network_code_execution` | `network,code_execution` |
| 7 | `terragrunt.format.terragrunt` | `terragrunt` | formatting | `terragrunt` | `read_only` | Aucune |
| 8 | `ansible.lint.ansible-lint` | `ansible` | linting | `ansible-lint` | `code_execution` | `code_execution` |
| 9 | `ansible.lint.yamllint` | `ansible` | linting | `yamllint` | `read_only` | Aucune |
| 10 | `python.format.ruff` | `python` | formatting | `ruff` | `read_only` | Aucune |
| 11 | `python.lint.ruff` | `python` | linting | `ruff` | `read_only` | Aucune |
| 12 | `python.lint.pylint` | `python` | linting | `pylint` | `code_execution` | `code_execution` |
| 13 | `python.test.pytest` | `python` | testing | `pytest` | `code_execution` | `code_execution` |
| 14 | `python.security.bandit` | `python` | security | `bandit` | `read_only` | Aucune |
| 15 | `python.dependencies.pip-audit` | `python` | dependency audit | `pip-audit` | `network` | `network` |
| 16 | `powershell.lint.psscriptanalyzer` | `powershell` | linting | `Invoke-ScriptAnalyzer` | `read_only` | Aucune |
| 17 | `docker.lint.hadolint` | `docker` | linting | `hadolint` | `read_only` | Aucune |
| 18 | `docker.security.trivy` | `docker` | security | `trivy` | `network` | `network` |
| 19 | `kubernetes.security.checkov` | `kubernetes` | security | `checkov` | `network_code_execution` | `network,code_execution` |
| 20 | `kubernetes.security.trivy` | `kubernetes` | security | `trivy` | `network` | `network` |
| 21 | `kubernetes.policy.checkov` | `kubernetes` | policy validation | `checkov` | `network_code_execution` | `network,code_execution` |
| 22 | `helm.security.checkov` | `helm` | security | `checkov` | `network_code_execution` | `network,code_execution` |
| 23 | `helm.security.trivy` | `helm` | security | `trivy` | `network` | `network` |
| 24 | `helm.policy.checkov` | `helm` | policy validation | `checkov` | `network_code_execution` | `network,code_execution` |
| 25 | `shell.lint.shellcheck` | `shell` | linting | `shellcheck` | `read_only` | Aucune |
| 26 | `javascript.lint.unconfigured` | `javascript` | linting | *(aucun)* | `read_only` | Aucune |
| 27 | `typescript.lint.unconfigured` | `typescript` | linting | *(aucun)* | `read_only` | Aucune |
| 28 | `markdown.documentation.markdownlint` | `markdown` | documentation | `pre-commit` | `code_execution` | `code_execution` |

---

## 3. Résultats Mesurés & Validation de Parité

### 3.1 Parité Canonique du Plan et des Contrôles (TASK-07 / TASK-08)

- **Test automatisé** : `TestPowerShellComplianceParity` dans [parity_test.go](file:///m:/Git/Compliance_Platform/core/internal/engine/parity_test.go).
- **Protocole** : Exécution conjointe de `RunCompliance(..., PlanOnly: true)` en Go et de `quality-gate.ps1 -Compliance -PlanOnly -NoColor` via l'interpréteur PowerShell sur le même dépôt fixture (`core/testdata/python_project`).
- **Résultats mesurés** :
  - **Parité du plan d'exécution** : **28 / 28 contrôles ordonnancés identiquement**.
  - **Parité stricte des statuts d'applicabilité** : **28 / 28 contrôles strictement identiques (100 %)**.
  - **Alignement des métadonnées** : `schema_version = 1`, `execution_status = "planned"`, `verdict = null`, `advisory = true`, `catalog_schema_version = 1`.

### 3.2 Gestion des Statuts d'Indisponibilité

1. **Outil indisponible / échec de qualification** :
   - Quand la commande de version échoue (`runtime_error`), le Tool Resolver remonte l'erreur et le plan marque le contrôle comme `tool_unavailable` (ex: `pylint`) ou `capability_unavailable` (ex: `bandit`, `pytest`, `pip-audit`).
2. **Technologie absente** :
   - Tous les contrôles des technologies non détectées sortent en `technology_absent` avec statut `skipped` non bloquant.
3. **Contrôles sans outil configuré** :
   - `javascript.lint.unconfigured` et `typescript.lint.unconfigured` sont planifiés en `capability_unavailable` avec limitation documentée.
4. **Refus de permissions** :
   - Les contrôles exigeant `network` ou `code_execution` sont automatiquement basculés en `not_applicable` avec le code `permission_denied` lorsque les options correspondantes sont désactivées.

### 3.3 Masquage Regex (Redaction)

- Testé unitairement dans `TestRunCompliance_RedactionAndVerdict` :
  - Les jetons sensibles (`ghp_*`, `glpat-*`, clés AWS, clés privées PEM, secrets arbitraires) sont remplacés par `[REDACTED]`.
  - La métadonnée `redaction_applied` est positionnée à `true` dans le rapport.

---

## 4. Matrice Complète des Tests Automatisés (32 tests, 100 % PASS)

| Package Go | Fichier de test | Tests unitaires exécutés | Statut |
| :--- | :--- | :--- | :-: |
| `internal/catalog` | `catalog_test.go` | `TestLoadCatalogOfficial` | **PASS** |
| `internal/discovery` | `discovery_test.go`<br>`parity_test.go` | `TestDiscoveryAllTechnologies`<br>`TestTerraformAndOpenTofuDetection`<br>`TestKubernetesAndAnsibleDetection`<br>`TestPowerShellDiscoveryParity` | **PASS** |
| `internal/distribution` | `distribution_test.go`<br>`manifest_v2_test.go`<br>`sync_test.go` | `TestSignatureVerification`<br>`TestSyncWithHashVerification`<br>`TestPhase1ManifestAndSignature`<br>`TestManifestHashesUniqueness`<br>`TestExtractedBinaryHashesFromArchives`<br>`TestRealRuntimeSyncEndToEnd`<br>`TestSyncRepoManifestWithEmbeddedKey` | **PASS** |
| `internal/engine` | `dag_test.go`<br>`plan_test.go`<br>`engine_test.go`<br>`parity_test.go` | `TestLinearAndBranchingDAG`<br>`TestCycleDetection`<br>`TestSelfCycleAndMissingDep`<br>`TestGuardrailsOnApplyDestroy`<br>`TestLoadAllRepoPipelines`<br>`TestBuildCompliancePlan_All28Controls`<br>`TestRunCompliance_PlanOnly`<br>`TestRunCompliance_RedactionAndVerdict`<br>`TestRunCompliance_PermissionsDenied`<br>`TestPowerShellComplianceParity` | **PASS** |
| `internal/matrix` | `matrix_test.go` | `TestBuildCapabilityMatrixAndResolution` | **PASS** |
| `internal/osutil` | `process_test.go` | `TestStreamingMemoryCap`<br>`TestLarge500MBMemoryCap`<br>`TestOrphanProcessTermination` | **PASS** |
| `internal/report` | `report_test.go` | `TestReportParityAndNormalization` | **PASS** |
| `internal/toolchain` | `resolver_test.go` | `TestToolResolverLocalBin`<br>`TestToolResolverOnDemandExtraction`<br>`TestToolResolverTamperedBinaryRejection`<br>`TestToolResolverUnknownTool`<br>`TestToolResolverAutonomousMock` | **PASS** |

---

## 5. Conclusion & Transition vers la Phase 4

Tous les objectifs de la **Phase 3** sont atteints :
- Les 28 contrôles sont portés en Go avec leur modèle de permissions et de budget.
- L'exécuteur de processus borné avec streaming et masquage regex est opérationnel.
- La capability matrix et la tool resolution sont dynamiquement peuplées.
- La parité canonique du rapport JSON v1 avec `quality-gate.ps1` est démontrée à **100 %**.

Le socle est prêt pour la **Phase 4** : Développement du démon local HTTP/SSE avec protection DNS Rebinding et adaptation de l'extension VS Code.
