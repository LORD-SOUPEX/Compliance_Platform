# Rapport d'Exécution - Phase 2 (Discovery Multi-technologies, DAG & Toolchain)

> **Date** : 13 Octobre 2026  
> **Statut global** : Phase 2 réalisée, vérifiée et attestée par tests automatisés.

---

## 1. Objectifs et Périmètre de la Phase 2

La Phase 2 visait à consolider et étendre le moteur Go (`core/`) en franchissant trois étapes clés avant le portage des contrôles unitaires (Phase 3) :
1. **Discovery multi-technologies** : Porter l'intégralité des 13 technologies analysées par `quality-gate.ps1`, avec extraction des racines de projets, gestion des ambiguïtés et détection des erreurs.
2. **Moteur de DAG déclaratif & Garde-fous** : Exécuter l'ordonnancement topologique des pipelines au format [.config/pipeline.schema.json](file:///m:/Git/Compliance_Platform/.config/pipeline.schema.json), détecter les cycles de dépendances et appliquer les garde-fous stricts sur les étapes `apply_destroy`.
3. **Tool Resolver unifié** : Assurer la résolution et le cache local des binaires d'outils avec synchronisation ciblée outil par outil, mode hors-ligne garanti et écriture atomique sur le disque.

---

## 2. Résultats Mesurés et Vérifications

### 2.1 Parité Dynamique de la Discovery (TASK-05)

- **Test automatisé** : `TestPowerShellDiscoveryParity` dans [parity_test.go](file:///m:/Git/Compliance_Platform/core/internal/discovery/parity_test.go).
- **Protocole de test** : Génération de fixtures mixtes reproduisant les cas historiques de `quality-gate.Tests.ps1` (projets imbriqués, exclusions de répertoires, détection Python/PowerShell), exécution conjointe de `DiscoverAll()` en Go et de `quality-gate.ps1 -RepositoryPath <tempDir> -DiscoveryOnly -NoColor` via l'interpréteur système.
- **Résultat mesuré** : **100% de parité** sur les 13 technologies :
  - `ansible` -> `absent`
  - `docker` -> `absent`
  - `helm` -> `absent`
  - `javascript` -> `absent`
  - `kubernetes` -> `absent`
  - `markdown` -> `absent`
  - `opentofu` -> `absent`
  - `powershell` -> `detected` (racine: `nested/project`)
  - `python` -> `detected` (racine: `pkg`)
  - `shell` -> `absent` (répertoire `reports/` exclu)
  - `terraform` -> `absent` (répertoire `.venv/` exclu)
  - `terragrunt` -> `absent`
  - `typescript` -> `absent`
- **Conformité JSON** :
  - Zéro tableau `null` : `evidence`, `roots`, `ambiguities`, `scan_errors`, `project_roots` sont strictement sérialisés en tableaux vides `[]` en l'absence d'éléments.
  - Remontée explicite des erreurs d'énumération ou de lecture sous forme d'objets `ScanError` dans `scan_errors`, avec `scan_complete = false` si une erreur survient.
- **Arbitrage méthodologique** : L'expansion dynamique de la matrice de capacités (`capability_matrix`) et du `tool_resolution` associés aux 28 contrôles d'audit est expressément rattachée à la **Phase 3** (Portage des contrôles & Parité canonique), évitant un doublon prématuré avant l'implémentation des exécuteurs de contrôles.

### 2.2 Moteur de DAG & Garde-fous (TASK-06)

- **Module** : [dag.go](file:///m:/Git/Compliance_Platform/core/internal/engine/dag.go) et tests dans [dag_test.go](file:///m:/Git/Compliance_Platform/core/internal/engine/dag_test.go).
- **Capacités validées** :
  - **Tri topologique déterministe (Kahn)** : Ordonnancement stable respectant les dépendances (`depends_on`).
  - **Détection stricte des cycles** : Rejet immédiat avec `ErrCycleDetected` en cas de cycle direct (A -> A) ou indirect (A -> B -> C -> A).
  - **Contrôle d'intégrité de schéma** : Utilisation de `DisallowUnknownFields()` pour interdire les clés mal orthographiées (ex: `depend_on`).
  - **Confinement d'effet de bord** : Interdiction bloquante pour toute étape de dépasser le niveau global déclaré par le pipeline (`side_effect_level`).
  - **Verrouillage `apply_destroy`** :
    - Rejet absolu en mode « Run All » (`ErrRunAllForbidden`).
    - Présence obligatoire d'une section `guardrails` dès qu'une étape est de classe `apply_destroy`.
    - Filtrage précis des environnements interdits (exclut `production`, `prod`, `staging`, `shared` et leurs dérivés de token, sans bloquer accidentellement des noms légitimes comme `unshared-dev`).
    - Validation des motifs autorisés (`sandbox`, `dev-local`, `ephemeral-*`).
    - Exigence bloquante d'une prévisualisation réussie (`require_plan_preview`) et d'une confirmation utilisateur (`require_explicit_confirmation`).
    - Validation des restrictions de backend d'état (`state_backend_restrictions`).

### 2.3 Tool Resolver (TASK-04)

- **Module** : [resolver.go](file:///m:/Git/Compliance_Platform/core/internal/toolchain/resolver.go) et tests dans [resolver_test.go](file:///m:/Git/Compliance_Platform/core/internal/toolchain/resolver_test.go).
- **Capacités validées** :
  - **Résolution ciblée** : `SyncRuntime` et `ResolveTool` acceptent un filtre `ToolName` pour ne télécharger et n'extraire **que l'outil requis**, sans charger inutilement les 176 Mo des autres outils.
  - **Mode hors-ligne garanti** : `OfflineOnly: true` bloque catégoriquement toute tentative d'appel réseau et renvoie une erreur explicite si l'archive est absente localement.
  - **Écriture atomique** : Tout binaire est écrit dans un fichier temporaire (`.tmp.<pid>`) avant d'être renommé atomiquement (`os.Rename`), prévenant tout état corrompu en cas de concurrence.
  - **Autonomie CI totale** : Le test `TestToolResolverAutonomousMock` simule une distribution complète en mémoire avec serveur mock HTTP et clé Ed25519 jetable, garantissant une suite de tests verte en CI sans aucun prérequis de fichiers résidents sur disque.

---

## 3. Matrice de Tests Automatisés (25 tests, 100% PASS)

| Package | Fichier | Tests unitaires exécutés | Statut |
| :--- | :--- | :--- | :-: |
| `internal/discovery` | `discovery_test.go`, `parity_test.go` | `TestDiscoveryAllTechnologies`<br>`TestTerraformAndOpenTofuDetection`<br>`TestKubernetesAndAnsibleDetection`<br>`TestPowerShellDiscoveryParity` | **PASS** |
| `internal/distribution` | `distribution_test.go`, `manifest_v2_test.go`, `sync_test.go` | `TestSignatureVerification`<br>`TestSyncWithHashVerification`<br>`TestPhase1ManifestAndSignature`<br>`TestManifestHashesUniqueness`<br>`TestExtractedBinaryHashesFromArchives`<br>`TestRealRuntimeSyncEndToEnd`<br>`TestSyncRepoManifestWithEmbeddedKey` | **PASS** |
| `internal/engine` | `dag_test.go` | `TestLinearAndBranchingDAG`<br>`TestCycleDetection`<br>`TestSelfCycleAndMissingDep`<br>`TestGuardrailsOnApplyDestroy`<br>`TestLoadAllRepoPipelines` | **PASS** |
| `internal/osutil` | `process_test.go` | `TestStreamingMemoryCap`<br>`TestLarge500MBMemoryCap`<br>`TestOrphanProcessTermination` | **PASS** |
| `internal/report` | `report_test.go` | `TestReportParityAndNormalization` | **PASS** |
| `internal/toolchain` | `resolver_test.go` | `TestToolResolverLocalBin`<br>`TestToolResolverOnDemandExtraction`<br>`TestToolResolverTamperedBinaryRejection`<br>`TestToolResolverUnknownTool`<br>`TestToolResolverAutonomousMock` | **PASS** |

---

## 4. Conclusion & Transition vers la Phase 3

Tous les critères techniques de la Phase 2 sont validés et testés :
- La parité de discovery avec l'ancien moteur PowerShell est formellement démontrée par test dynamique.
- Le format JSON v1 est rigoureusement conforme (zéro `null`).
- Le moteur de DAG est robuste, typé et protégé par des garde-fous non contournables.
- Le Tool Resolver est granulaire, atomique et testable en CI autonome.

**Recommandation** : Le socle est prêt pour engager la **Phase 3** (Portage des 28 contrôles du catalogue en Go et parité canonique du rapport d'audit).
