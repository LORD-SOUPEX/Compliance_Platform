# Audit du dépôt et feuille de route des travaux restants

> **Nature du document** : audit en lecture seule après la Phase 5. Aucun code n'a été modifié, aucun test ni build lancé pendant cet audit.
> **Remplace** l'ancien `plan.md` (« Plan d'évolution et de migration », v1.1), à la demande explicite du lead. L'ancien contenu est récupérable via `git show HEAD:plan.md` (le fichier est suivi par Git et apparaît comme modifié).
> **Légende de rigueur** : **CONSTATÉ** (lu dans le dépôt pendant cet audit) · **NON VÉRIFIÉ** (non contrôlé, à confirmer) · **HYPOTHÈSE** · **À DÉCIDER**.

---

## 0. Constats bloquants (à lire avant tout le reste)

1. **PowerShell n'est pas « déprécié » dans les faits.** **CONSTATÉ** : aucun marqueur de dépréciation (`deprecat`, `obsol`) dans `scripts/` ; `README.md` présente toujours `bootstrap.ps1`, `doctor.ps1` et `quality-gate.ps1` comme commandes principales (lignes 46 à 100). Le « statut DEPRECATED » affiché dans `docs/phase5-report.md` (§ 8) est une déclaration, pas un état du dépôt.
2. **Le cœur Go dépend encore de PowerShell.** **CONSTATÉ** : `core/internal/engine/runner.go` (≈ l. 246-258) lance `powershell.exe` et `scripts/invoke-compliance-powershell.ps1` pour le contrôle `powershell.lint.psscriptanalyzer`. Supprimer `scripts/` casserait ce contrôle.
3. **L'extension conserve des replis PowerShell.** **CONSTATÉ** : `backend.ts` (l. 39-40, 101-109), `auditBackend.ts` (l. 15, 35-44, 110-130) et `reportReader.ts` (l. 139-160) appellent encore `powershell.exe` / `compliance-adapter.ps1` / `taskkill.exe`. Le verrou « Windows x64 uniquement » est toujours présent dans `backend.ts` et `auditBackend.ts`. Le lecteur de rapports contient en outre une **branche de production spécifique aux tests** (`runner !== runProcess`).
4. **Tout le travail des Phases 4bis et 5 est non commité.** **CONSTATÉ** (`git status`) : `core/internal/server/`, `core/internal/selftest/`, `daemonClient.ts`, `package_vsix.py`, fixtures, etc. sont `??` ou `M`. Risque de perte majeur ; à traiter avant toute purge.
5. **Qualification Windows incohérente entre sources.** **CONSTATÉ** : `compliance selftest` affiche « Windows x64 Qualifié » alors que `.config/platform-support.json` déclare toujours `windows-x64` = `experimental` avec des preuves PowerShell (« Local PowerShell test suites pass »).
6. **`docs/phase5-report.md` contient des affirmations à re-vérifier.** **NON VÉRIFIÉ** dans cet audit : versions précises des outils (§ 4.1), explication de la divergence « 1 sur 10 » (§ 2, trivy), et la mention « Windows 11 ». Elles doivent être confrontées à `.config/runtime-manifest.json` et à `docs/phase4bis-addendum.md` avant d'être citées comme références.

---

## 1. État des lieux synthétique

| Composant | Statut | Remarque |
| :--- | :--- | :--- |
| `core/` (Go) : discovery, matrix, engine, report, distribution, server, selftest, osutil, toolchain, catalog | **Actif** | Selftest 20/20 mesuré sur Windows x64 ; Linux/macOS non exécutés |
| Démon HTTP/SSE (`core/internal/server`) | **Actif** | Sécurité (jeton, Host, Origin) couverte par `server_test.go` et le selftest |
| `vscode-extension/src/daemonClient.ts` | **Actif** | Cible principale de l'extension |
| `vscode-extension/src/backend.ts`, `auditBackend.ts`, `reportReader.ts` | **Mixte** | Chemin démon + replis PowerShell encore câblés |
| `vscode-extension/bin/` + `dist/*.vsix` | **Actif (artefacts)** | Binaires versionnés dans l'arbre de travail ; politique Git à fixer |
| `.config/` : schémas, `control-catalog.json`, `runtime-manifest.json(.sig)` | **Actif** | Contrats partagés Go/TS |
| `.config/tool-versions.yml`, `tool-versions-multiarch.json`, `quality-gate.yml`, `PSScriptAnalyzerSettings.psd1` | **Hérité** | Alimentent bootstrap/doctor/quality-gate PowerShell |
| `scripts/*.ps1`, `scripts/*.sh` (shims) | **Obsolète (sous condition)** | Voir § 2 |
| `src/*.psm1` | **Obsolète (sous condition)** | Référence de parité encore utilisée par des tests Go |
| `tests/**/*.Tests.ps1` | **Obsolète (sous condition)** | Parité à transférer avant suppression |
| `.gitlab-ci.yml` | **Hérité** | Job Windows PowerShell ; contradictoire avec « pipelines locaux » |
| `.venv/`, `requirements-*.txt|lock`, `pyproject.toml` | **Hérité** | Plus requis par le résolveur (repli seulement) |

---

## 2. Inventaire du code mort à purger (matrice de nettoyage)

Règle : « Immédiat » = aucune dépendance constatée ; « Sous condition » = dépendance constatée, condition listée.

### 2.1 Scripts (`scripts/`)

| Chemin | Rôle historique | Remplacé par | Risque de suppression | Action |
| :--- | :--- | :--- | :--- | :--- |
| `scripts/quality-gate.ps1` (101 Ko) | Discovery, matrice, moteur, modes Quick/Full/Ci/Fix | `compliance run`, `compliance discovery`, démon | Sous condition : référencé par `parity_test.go`, `parity_defect_test.go`, `discovery/parity_test.go`, README, `.gitlab-ci.yml` ; **les modes Quick/Full/Ci/Fix n'ont pas d'équivalent Go constaté** | Conserver comme shim jusqu'à décision n° 2, puis archiver |
| `scripts/bootstrap.ps1` (56 Ko) | Installation du runtime Windows | `compliance runtime sync` + manifeste signé | Sous condition : le runtime **PSScriptAnalyzer** (`.tools/powershell-modules`) n'a pas d'équivalent Go constaté | Archiver après décision n° 4 |
| `scripts/doctor.ps1` | Vérification d'index runtime | `compliance selftest` (périmètre différent : démon, pas intégrité des outils) | Sous condition : pas de commande Go équivalente à la vérification d'intégrité des hashes | Conserver jusqu'à ajout d'un `compliance doctor` ou équivalent |
| `scripts/compliance-adapter.ps1` | Adaptateur PowerShell/Bash/VSCode/GitLab, `-ValidateReportPath` | Démon + `POST /api/v1/reports/validate` | Sous condition : replis de l'extension et tests PS | Conserver comme shim jusqu'au retrait des replis TS |
| `scripts/invoke-compliance-powershell.ps1` | Hôte d'exécution de PSScriptAnalyzer | **Aucun** | **Non supprimable** : appelé par `runner.go` | Conserver ; voir décision n° 3 |
| `scripts/update-lock.ps1` | Mise à jour des lock Python / manifestes | Aucun constaté (`build_and_sign_manifest` n'est pas versionné) | Sous condition | Conserver ; formaliser un outil Go ou Python versionné de signature de manifeste |
| `scripts/check-emoji.ps1` | Garde « pas d'emoji » (utilisé par quality-gate, pre-commit) | Aucun | Sous condition | Conserver ou porter en Go |
| `scripts/test.ps1` | Lance les `.Tests.ps1` | `go test ./...` + `node --test` | Sous condition : tant que les `.Tests.ps1` existent | Supprimer avec les tests PS |
| `scripts/vscode-extension.ps1` | Install/Build/Test/Package de l'extension | Aucun (outillage actif, désormais avec `-Action Package`) | Risque élevé | **Conserver** (non obsolète) ; prévoir un équivalent POSIX |
| `scripts/package_vsix.py` | Packaging OPC du VSIX | — | — | **Conserver** ; noter qu'il produit un VSIX « universal » contenant 5 binaires (taille 17 Mo) |
| `scripts/bootstrap.sh`, `doctor.sh`, `compliance.sh`, `quality-gate.sh`, `test.sh` | Shims Git Bash qui relaient vers PowerShell | `compliance` (binaire Go) | **Immédiat** une fois le binaire Go supporté en distribution | Supprimer (ou réécrire en appel direct du binaire Go) |

### 2.2 Modules (`src/`)

| Chemin | Rôle historique | Remplacé par | Risque | Action |
| :--- | :--- | :--- | :--- | :--- |
| `src/Compliance.Engine.psm1` (51 Ko) | Plan, exécution, verdict, rapport | `core/internal/engine`, `report` | Sous condition : référence des tests de parité | Archiver après gel du contrat v1 par golden files |
| `src/Compliance.Session.psm1` | Sessions, événements NDJSON, annulation | `core/internal/server/session.go` | Sous condition : `quality-gate.ps1` | Archiver avec quality-gate |
| `src/Control.Catalog.psm1` | Chargement du catalogue | `core/internal/catalog` | Sous condition | Archiver |
| `src/Tool.Provenance.psm1` | Hashes, intégrité d'arbre | `core/internal/distribution`, `toolchain` | Sous condition : intégrité d'arbre de PSScriptAnalyzer | Archiver après décision n° 3 |
| `src/Platform.Support.psm1` | Lecture de `platform-support.json` | Aucun équivalent Go **constaté** | **NON VÉRIFIÉ** (grep Go incomplet) | Vérifier avant toute action |
| `src/Compliance.Adapter.psm1` | Fabrique d'invocations par contrôle | `core/internal/engine/runner.go` | Sous condition | Archiver |

### 2.3 Tests (`tests/`)

| Chemin | Rôle | Équivalent actuel | Risque | Action |
| :--- | :--- | :--- | :--- | :--- |
| `tests/integration/quality-gate.Tests.ps1` (73 Ko, plus gros test du dépôt) | Discovery, matrice, Quick/Full, extraction d'AST | `discovery_test.go`, `matrix_test.go` (partiel) | **Élevé** : couverture non transférée | Transférer (Lot 3) puis supprimer |
| `tests/unit/compliance-engine.Tests.ps1` (30 Ko) et `tests/integration/compliance-engine.Tests.ps1` | Verdict, couverture, schéma, timeouts, dépendances, redaction | `engine_test.go` (3 tests), `dag_test.go`, `plan_test.go`, `report_test.go` | **Élevé** : voir § 5 | Transférer puis supprimer |
| `tests/integration/compliance-session.Tests.ps1`, `compliance-report-reader.Tests.ps1`, `compliance-adapters.Tests.ps1` | Sessions, lecteur, adaptateurs | `server_test.go`, `selftest`, `report-reader.test.ts` | Moyen | Transférer puis supprimer |
| `tests/unit/tool-provenance.Tests.ps1`, `reproducibility.Tests.ps1`, `control-catalog.Tests.ps1`, `platform-support.Tests.ps1`, `compliance-adapter.Tests.ps1` | Provenance, reproductibilité, catalogue, plateformes | `distribution/*_test.go`, `catalog_test.go` | Moyen (reproductibilité et plateformes : **NON VÉRIFIÉ**) | Transférer puis supprimer |

### 2.4 Code mort ou résiduel côté Go et TypeScript

| Chemin | Constat | Action |
| :--- | :--- | :--- |
| `vscode-extension/src/backend.ts` : `planInvocation`, `runProcess`, `taskkill` (l. 39-57) | Chemin PowerShell de repli | Supprimer avec les replis |
| `vscode-extension/src/auditBackend.ts` : validation `runtime.powershell_modules`, `index.platforms['windows-x64']` (l. 15-44) | Vérification d'un index runtime **PowerShell** que le démon Go ne produit pas | Remplacer par une vérification via `/api/v1/health` ou supprimer |
| `vscode-extension/src/reportReader.ts` : branche `runner !== runProcess` | Code de production piloté par les tests | Remplacer par une injection du `DaemonClient` |
| `vscode-extension/src/reportPanel.ts` l. 102 | Message « validation PowerShell » | Corriger le libellé |
| `core/internal/matrix/matrix.go` (repli `.venv`, modules PowerShell) et `core/cmd/compliance/main.go` (`resolveBanditPythonModule`, `.venv/Scripts`) | Résolution héritée | Retirer le repli `.venv` après qualification du runtime autonome |
| `core/internal/report/report.go` l. 341 | `adapter = "PowerShell"` par défaut | Décider du nom d'adaptateur (voir § 5) |
| `core/internal/engine/parity_test.go`, `parity_defect_test.go`, `discovery/parity_test.go` | Exécutent `quality-gate.ps1` ; se **skippent silencieusement** si PowerShell échoue | Convertir en tests golden figés (voir Lot 3) |

### 2.5 Artefacts, caches et configurations orphelines

| Chemin | Constat | Action |
| :--- | :--- | :--- |
| `.scratch_daemon_test/` (racine) | Dossier créé par un script de diagnostic de la session précédente (**artefact de l'assistant**) | Supprimer, ajouter à `.gitignore` si récurrent |
| `core/compliance.exe` (non suivi) | Binaire de build à l'intérieur de l'arbre source | Supprimer ; compiler vers `.tools/bin/` |
| `core/testdata/ps_defect_report.json`, `ps_exec_test.json`, `go_defect_report.json`, `analyze_parity.py`, `inspect_matrix.py` | Sorties et scripts de la comparaison de parité, non versionnés | Soit figer en golden files documentés, soit supprimer |
| `.ruff_cache/`, `.venv/`, `reports/` | Caches / environnement local | Vérifier qu'ils sont dans `.gitignore` (**NON VÉRIFIÉ**) |
| `vscode-extension/node_modules/`, `.vscode-test/`, `dist/`, `bin/` | Non suivis ; `node_modules` existe en double (`.tools/vscode-extension/node_modules`) | Fixer la politique : `bin/` et `dist/` ignorés et produits par build, ou publiés hors Git |
| `.config/tool-versions.yml`, `tool-versions-multiarch.json` | Anciens manifestes d'outils, distincts du `runtime-manifest.json` signé | Fusionner ou supprimer après retrait de bootstrap/doctor |
| `.gitlab-ci.yml` | Exécute bootstrap/doctor/quality-gate sur `tags: [windows]` | À décider (n° 5) ; ne figure pas dans les critères d'acceptation |
| `.github/workflows/ci.yml` | **CONSTATÉ** absent (le répertoire `.github` n'existe pas) | Aucune action |
| `requirements-dev.lock` (33 Ko), `requirements-dev.txt`, `requirements-lock-tools.txt`, `pyproject.toml` | Pilotent le `.venv` historique | Conserver tant que `quality-gate.ps1` existe, puis supprimer |

---

## 3. Mise à jour documentaire requise

| Fichier | Sections ciblées | Correction attendue |
| :--- | :--- | :--- |
| `README.md` | « Fonctionnalités clés » (l. 9, 13, 14) ; « Préparation dans VS Code » (l. 34, *« Le moteur PowerShell reste responsable du contrat et du verdict »*) ; périmètre (l. 42, 46) ; Bootstrap (l. 52-60) ; Doctor (l. 62-68) ; Discovery/Compliance/Quick/Full (l. 72-100) ; runtime (l. 105) ; résultats (l. 121-122, *Doctor 71 PASS*) | Réécrire autour de `compliance selftest`, `compliance daemon`, `compliance runtime sync`, `compliance run`. Marquer PowerShell comme legacy. Corriger la phrase l. 34 (fausse depuis la Phase 5) |
| `docs/architecture-current.md` | Runtime et intégrité ; Discovery et capacités ; flux moteur | Décrire le démon, le Tool Resolver réel (`.tools/bin`, Python autonome, cache runtime, PATH) et le manifeste signé v2 |
| `docs/utilisation.md` | « Audit VS Code (MVP local) » et tutoriels CLI | Remplacer les commandes PowerShell ; documenter l'installation du VSIX et le démon |
| `docs/maintenance.md` | l. 63 : *« Linux/macOS … hors périmètre … Aucun VSIX n'est produit à cette étape »* | **Contredit l'état actuel** (VSIX produit, binaires multi-OS) ; réécrire |
| `.config/platform-support.json` | `windows-x64` : `experimental` + preuves PowerShell | Remplacer les preuves par le selftest, et trancher le statut (décision n° 6). Conserver `targeted` pour Linux/macOS tant que le selftest n'y est pas exécuté |
| `.config/compliance-report.schema.json` | `source_adapter` : enum `PowerShell, Bash, VSCode, GitLab, Legacy` | Ajouter une valeur Go (ex. `Go`/`Daemon`) via une évolution **compatible v1**, à décider |
| `docs/phase4-report.md`, `phase4bis-report.md`, `phase5-report.md` | Statuts et chiffres | Réconcilier les chiffres entre rapports ; supprimer toute mention non mesurée (cf. § 0, point 6) |
| `vscode-extension/README.md` | Créé en Phase 5 | Compléter : prérequis, plateformes réellement testées, politique de binaires |

---

## 4. Chantiers techniques non finalisés

### 4.1 Qualification multi-OS

| Plateforme | Statut effectif | Preuve | Reste à faire |
| :--- | :--- | :--- | :--- |
| windows-x64 | Selftest 20/20 **mesuré** | Exécution locale | Statut produit à trancher ; exécuter la suite sur un poste vierge (sans `.venv` ni `.tools` préremplis) — **NON TESTÉ** |
| linux-x64 | `targeted` | Binaire cross-compilé uniquement | Exécuter `compliance selftest` sur un hôte Linux réel |
| linux-arm64, macos-x64, macos-arm64, windows-arm64 | `targeted` | Aucune ; le manifeste ne couvre que `windows-x64` et `linux-x64` | Binaires et manifeste pour ces cibles, puis selftest |
| macOS (binaires `darwin-amd64/arm64` dans le VSIX) | Compilés, **jamais exécutés** | — | Exécution réelle ; sinon les retirer du VSIX ou les signaler « non testés » |

**Point d'attention** : le code POSIX n'a été que compilé. **HYPOTHÈSE** : le confinement des processus (`Setpgid`, `kill(-pgid)`), les permissions `0600` du jeton et le verrou d'instance (`lock_posix.go`) fonctionnent comme sur Windows. Le « zéro orphelin » n'est **mesuré que sous Windows (Job Objects)**.

### 4.2 Cas limites d'outils

| Outil / contrôle | Constat | Piste |
| :--- | :--- | :--- |
| `ansible-lint` | Déclaré `linux-x64` / `macos-arm64` uniquement dans le catalogue ; absent du manifeste (qui ne contient pas ansible) | Ajouter la roue au runtime Python autonome Linux, ou assumer « non disponible sur Windows natif » dans le plan |
| `markdownlint` | Dépend de Node ; le Node utilisé par `vscode-extension.ps1` est cherché dans `.tools/pre-commit/…node_env-26.10.0` (installé par **Bootstrap PowerShell**) | Ajouter Node au manifeste signé ou supprimer la dépendance ; sinon `scripts/vscode-extension.ps1` ne fonctionne plus après retrait de bootstrap |
| `powershell.lint.psscriptanalyzer` | Exécuté via `powershell.exe` hôte (Windows PowerShell 5.1) | Décision n° 3 : conserver comme dépendance optionnelle, ou abandonner le contrôle |
| `javascript/typescript.lint.unconfigured` | Contrôles sans outil (`capability_unavailable`) | Choisir un outil (ESLint/Biome) ou assumer le blocage |
| `checkov`, `pip-audit` | Exigent réseau / exécution de code ; wrapper `.cmd` Windows corrigé en Phase 5 | Valider sur Linux |
| Terraform/OpenTofu | Précédemment `ambiguous` en parité de poste dégradé ; fixtures dédiées ajoutées | Étendre les fixtures IaC (**NON VÉRIFIÉ** sur un poste vierge) |

### 4.3 Maintenabilité de Go (décision n° 1)

**CONSTATÉ** : le dépôt contient désormais ≈ 10 paquets Go internes, un démon, un selftest et un client TS. **À DÉCIDER** : propriétaires, revue, mise à jour du toolchain Go (`.tools/go` n'est pas piloté par le manifeste signé), politique de mise à jour des outils épinglés.

### 4.4 CI/CD distante

Le périmètre produit exclut la CI distante comme critère d'acceptation (consigne de la Phase 5). Le brief de cet audit demande néanmoins d'évaluer son intégration. **Position** : traiter la CI comme **optionnelle** ; la qualification Linux/macOS peut se faire sur machines physiques ou VM locales. Si une CI est retenue, `.gitlab-ci.yml` doit être réécrit (`compliance selftest` sur runners Windows/Linux/macOS) ; l'état actuel appelle encore bootstrap/doctor/quality-gate.

---

## 5. Robustesse et couverture de tests

**CONSTATÉ** (structure des fichiers) : suites PowerShell ≈ 11 fichiers dont `quality-gate.Tests.ps1` (73 Ko), `compliance-engine.Tests.ps1` unit (30 Ko) et integration (14 Ko) ; côté Go, `engine/` ne contient que ≈ 11 fonctions `Test*` (`engine_test.go` : 3, `dag_test.go` : 5, `plan_test.go` : 1, 2 tests de parité). Les nombres exacts d'assertions **n'ont pas pu être comptés** (limitation d'outillage) ; l'écart de volume est un **indice**, pas une mesure.

Scénarios PowerShell dont **aucun équivalent Go n'a été constaté** (à vérifier un par un dans `engine_test.go`, `report_test.go`, `matrix_test.go`) :

| Scénario (source : `compliance-engine.Tests.ps1`) | Équivalent Go constaté |
| :--- | :--- |
| Verdict : succès, échec, erreur critique/non critique, scan incomplet | Partiel (`RedactionAndVerdict`) |
| Outil requis absent → `error`/critique ; technologie absente → `skipped` | **Non constaté** |
| Rapport : traçabilité `catalog_sha256`, `platform_qualification_status`, métriques non négatives, rétrocompatibilité v1 sans `metrics` | **Non constaté** |
| Validation de schéma : verdict non canonique, résumé incohérent, empreinte invalide, statut inconnu | **Non constaté** |
| Redaction configurable + motif regex invalide rejeté | Partiel |
| Plan seul sans verdict ; effets non autorisés ; Checkov refusé avec réseau seul | Partiel (`PermissionsDenied`) |
| Couverture partielle (`omitted_required_controls`) ; résultat manquant/dupliqué → FAIL | **Non constaté** |
| Timeout de sonde ; budget global ; dépendance échouée → `dependency_failed` | **Non constaté** |
| Alternative satisfaite / écartée ; contrôle de catalogue scalaire | **Non constaté** |
| Annulation entre contrôles (`cancelled_before_start`), rapport interrompu non fiable | Couvert côté selftest/serveur pour l'annulation ; **rapport interrompu** non constaté |
| `quality-gate.Tests.ps1` : marqueurs de fichiers, ambiguïtés, exclusions, scan incomplet | `discovery_test.go` (étendue à vérifier) |
| Reproductibilité des builds / lock | **Non constaté** |

Côté TypeScript (`vscode-extension/tests/`, et non `test/`) : 3 suites (`daemonClient`, `preparation`, `report-reader`) + `host.ts`/`run-host.ts` (tests Extension Host, **NON VÉRIFIÉ** depuis la Phase 5). Le test `Backend reel externe` s'est révélé **dépendant de l'ordre d'exécution** (échec en parallèle, succès avec `--test-concurrency=1`) : cause non identifiée, contournée par une option du script.

Autres fragilités constatées :

- Les tests de parité Go↔PowerShell **se skippent** en cas d'échec de PowerShell : ils peuvent passer au vert en ne testant rien.
- Les tests TS de l'extension partagent le démon et son état `~/.compliance` (verrou global) : pas d'isolation.
- Le test `DaemonClient` attend `controls.length == 28` : couplage au catalogue.

---

## 6. Feuille de route priorisée

### Lot 0 : Sécuriser l'existant (préalable)

- [x] Commiter (par commits logiques) tout le travail Phase 4bis/5 non suivi (`core/internal/server/`, `selftest/`, `daemonClient.ts`, `package_vsix.py`, tests). (Tag v1 posé)
- [x] Définir `.gitignore` : `core/*.exe`, `.scratch_daemon_test/`, `vscode-extension/{dist,node_modules,.vscode-test}`.
- [x] Supprimer `.scratch_daemon_test/` et `core/compliance.exe`.

### Lot 1 : Purge et décommissionnement

- [x] Retirer les replis PowerShell de `backend.ts`, `auditBackend.ts`, `reportReader.ts` ; injecter un `DaemonClient` dans les tests au lieu de la branche `runner !== runProcess`.
- [x] Remplacer la vérification d'index runtime PowerShell de `auditBackend.ts` par une vérification via le démon.
- [x] Supprimer les 5 shims `scripts/*.sh`.
- [x] Ajouter des bannières de dépréciation réelles en tête de `quality-gate.ps1`, `bootstrap.ps1`, `doctor.ps1`, `compliance-adapter.ps1`, `src/*.psm1`.
- [ ] Archiver (déplacer vers `legacy/powershell/` ou tag Git `powershell-final`) une fois le Lot 3 clos et les décisions n° 2 à 4 prises.
- [x] Retirer le repli `.venv` du résolveur et de `main.go`.

### Lot 2 : Réalignement documentaire et contrats

- [ ] Réécrire `README.md`, `docs/architecture-current.md`, `docs/utilisation.md`, `docs/maintenance.md` (§ 3).
- [ ] Mettre à jour `platform-support.json` après arbitrage ; faire évoluer `source_adapter` de façon compatible v1.
- [ ] Réconcilier `phase4-report`, `phase4bis-report`, `phase5-report` ; marquer chaque chiffre « mesuré / non testé / hypothèse ».
- [ ] Documenter le protocole du démon (endpoints, jeton, SSE) dans `docs/`.

### Lot 3 : Parité des tests et couverture Go

- [ ] Établir la matrice scénario PowerShell → test Go (§ 5) ; implémenter les scénarios « non constatés », en priorité : couverture partielle, résultat manquant/dupliqué, timeouts, `dependency_failed`, validation de schéma, rétrocompatibilité v1.
- [ ] Figer des **golden files** issus du moteur PowerShell (`ps_defect_report.json`, plan à 28 contrôles) avant archivage, et convertir les tests de parité (suppression du `t.Skip` silencieux).
- [ ] Ajouter des tests Go pour `selftest`, `lock_*`, `process_*` sous les deux familles d'OS (build tags).
- [ ] Isoler les tests TS (répertoire d'état temporaire, port éphémère) ; identifier la cause de la dépendance d'ordre.
- [ ] Exécuter les tests Extension Host (`-Action TestHost`) et consigner le résultat.

### Lot 4 : Qualification multi-OS (et CI optionnelle)

- [ ] Exécuter `compliance selftest` sur Linux x64 réel ; si PASS, passer `linux-x64` à `qualified`, sinon rester `targeted`.
- [ ] Même démarche pour macOS ; sinon retirer les binaires `darwin` du VSIX ou les documenter « non testés ».
- [ ] Compléter le manifeste signé pour `linux-arm64`, `macos-*`, `windows-arm64` si ces cibles sont conservées.
- [ ] Qualifier Windows x64 **sur poste vierge** (sans `.venv`, `.tools` vide) et en mesurer le temps de provisioning.
- [ ] Traiter Node (markdownlint) et PSScriptAnalyzer dans le runtime (décisions n° 3 et 4).
- [ ] CI : décider (n° 5) ; si oui, réécrire `.gitlab-ci.yml` sur `compliance selftest`.

---

## 7. Points d'arbitrage restants

| N° | Décision | Options | Conséquence |
| :--- | :--- | :--- | :--- |
| 1 | Pérennité de la maintenance Go | Équipe propriétaire désignée / périmètre réduit | Conditionne la suppression définitive de PowerShell |
| 2 | Sort des modes Quick/Full/Ci/Fix de `quality-gate.ps1` | Porter en Go / abandonner / conserver legacy | Sans décision, `quality-gate.ps1` ne peut pas être supprimé |
| 3 | `powershell.lint.psscriptanalyzer` | Conserver (dépendance hôte optionnelle) / porter / abandonner | Détermine si `invoke-compliance-powershell.ps1` et `src/Tool.Provenance.psm1` survivent |
| 4 | Distribution de Node et du module PSScriptAnalyzer dans le manifeste signé | Ajouter / retirer markdownlint | Détermine l'avenir de `bootstrap.ps1` et de `scripts/vscode-extension.ps1` |
| 5 | CI distante | Aucune / GitLab / GitHub | Hors critères d'acceptation ; impacte la qualification automatisée |
| 6 | Statut `windows-x64` | Rester `experimental` / passer `qualified` | Doit refléter le selftest **et** une exécution sur poste vierge |
| 7 | Nom de l'adaptateur dans le rapport v1 (`PowerShell` par défaut dans `report.go`) | Nouvelle valeur d'enum / conserver | Évolution compatible du schéma |
| 8 | Politique de distribution des binaires | Binaires dans le VSIX universel / un VSIX par plateforme / téléchargement via le manifeste | Taille (17 Mo), surface de confiance, signature |
| 9 | Cibles supportées | Windows+Linux x64 seulement / ajouter ARM64 et macOS | Effort de qualification |
| 10 | Valeur des fixtures `core/testdata` | Golden versionnés / jetables | Fiabilité de la parité après archivage |

---

## 8. Limites de cet audit

- Les comptes précis d'assertions et de tests n'ont **pas** pu être établis : les recherches par motif sur ces fichiers ont renvoyé des résultats vides ou erronés avec l'outillage disponible. Les écarts de couverture du § 5 sont donc des **indices à confirmer**, pas des mesures.
- Aucun test, build ni commande de qualification n'a été lancé : l'état « vert » de la Phase 5 est repris du travail précédent, non revérifié ici.
- La liste des fichiers ignorés par Git (`.gitignore`) n'a pas été lue en détail.
- Les chemins de lignes cités proviennent de lectures faites pendant la session ; ils peuvent dériver après modification.
