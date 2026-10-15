# Plan 2.0.15 — Registre d'outils auto-hébergé

Version cible : 2.0.15. Ce document spécifie et encadre le remplacement complet des téléchargements tiers (GitHub d'éditeurs, HashiCorp, PyPI, npm, PowerShell Gallery) par un registre d'archives prêtes à l'emploi publiées sur `https://github.com/LORD-SOUPEX/Compliance_Platform/releases/tag/tools-v1`.

Les identifiants de plateforme restent ceux du manifeste : `windows-x64`, `linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`, `windows-arm64`. On ne renomme pas `macos-*` en `darwin-*`.

## Décision architecturale

Les archives sont publiées en **GitHub Release** du dépôt, tag `tools-v1`, et non dans l'arbre Git.

| Critère | Option A — Fichiers dans Git (`tools-registry`) | Option B — Release GitHub `tools-v1` (Retenue) |
| --- | --- | --- |
| Limite de taille | Git refuse un blob > 100 Mo. GitHub alerte dès 50 Mo. | 2 Go max par asset. |
| Impact clone / VSIX | Chaque `git clone` et chaque VSIX embarquerait toutes les archives. | Le clone du code et le VSIX ne contiennent aucune archive d'outil. |
| Bundle Python / Node | Le bundle CPython autonome dépasse 100 Mo compressés. | Une archive unitaire par plateforme, sans découpage complexe. |
| URL d'accès | Dépend d'une branche et de l'historique Git. | `https://github.com/LORD-SOUPEX/Compliance_Platform/releases/download/tools-v1/<asset>` |
| Transposition entreprise | Miroir Git complexe avec quotas et LFS. | Compatible GitHub Enterprise, GitLab (Package Registry) ou simple serveur HTTPS statique. |

Git LFS n'est pas retenu. Le VSIX continue d'embarquer le manifeste JSON validé, mais jamais les archives d'outils.

Le dépôt étant public, les téléchargements de release s'effectuent sans jeton d'authentification par défaut. Pour un registre d'entreprise privé, le jeton optionnel `COMPLIANCE_REGISTRY_TOKEN` est transmis via le header `Authorization: Bearer`.

---

## 1. Inventaire et formats d'archives

30 contrôles du catalogue sont couverts par 20 commandes distinctes : `terraform`, `tofu`, `tflint`, `terragrunt`, `checkov`, `ansible-lint`, `yamllint`, `ruff`, `pylint`, `pytest`, `bandit`, `pip-audit`, `hadolint`, `trivy`, `shellcheck`, `gitleaks`, `eslint`, `tsc`, `rumdl`, `Invoke-ScriptAnalyzer`.

### Règle d'aplatissement des assets (Correction critique GitHub Release)
GitHub Releases interdit les slashs `/` dans les noms d'assets (ex. `windows-x64/terraform-1.8.5.zip` échoue ou est corrompu). **Tous les fichiers d'assets sont strictement nommés à plat avec le préfixe de plateforme :**
`<platform>-<tool>-<version>.<ext>` (ex. `windows-x64-terraform-1.8.5.zip`, `windows-x64-python-tools-3.11.9.tar.gz`).

### Formats d'archives uniformes et multi-OS
Les archives utilisent exclusivement `.zip` ou `.tar.gz`, supportés nativement par le moteur Go (`archive/zip`, `archive/tar`, `compress/gzip`) sans aucun outil système externe. Les binaires nus amont (hadolint, terragrunt) sont reconditionnés sous zip/tar.gz avec un chemin interne stable.

### A. Binaires natifs (10 outils x 5 plateformes)
Plateformes cibles : `windows-x64`, `linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`.

| Outil | Version épinglée | Archive générée | Binaire interne |
| --- | --- | --- | --- |
| ruff | 0.16.10 | `<platform>-ruff-0.16.10.<ext>` | `ruff` (ou `ruff.exe`) |
| gitleaks | 8.30.1 | `<platform>-gitleaks-8.30.1.<ext>` | `gitleaks` (ou `gitleaks.exe`) |
| tflint | 0.64.0 | `<platform>-tflint-0.64.0.<ext>` | `tflint` (ou `tflint.exe`) |
| terraform | 1.8.5 | `<platform>-terraform-1.8.5.<ext>` | `terraform` (ou `terraform.exe`) |
| tofu | 1.8.2 | `<platform>-tofu-1.8.2.<ext>` | `tofu` (ou `tofu.exe`) |
| hadolint | 2.15.1 | `<platform>-hadolint-2.15.1.<ext>` | `hadolint` (ou `hadolint.exe`) |
| terragrunt | 1.1.6 | `<platform>-terragrunt-1.1.6.<ext>` | `terragrunt` (ou `terragrunt.exe`) |
| shellcheck | 0.10.0 | `<platform>-shellcheck-0.10.0.<ext>` | `shellcheck` (ou `shellcheck.exe`) |
| rumdl | 0.2.79 | `<platform>-rumdl-0.2.79.<ext>` | `rumdl` (ou `rumdl.exe`) |
| trivy | 0.75.0 | `<platform>-trivy-0.75.0.<ext>` | `trivy` (ou `trivy.exe`) |

*Note Windows ARM64* : statut maintenu à `targeted` avec `tools: {}` jusqu'à disponibilité d'un jeu complet.

### B. Bundle Python 100 % relocalisable (Zéro venv à chemins absolus)
**Correction technique critique** : Un `venv` Python standard fige le chemin absolu de la machine de build dans les shebangs POSIX et les en-têtes des `.exe` Windows. Il devient inopérant lorsqu'il est extrait dans un dossier différent chez le client.
**Solution validée et imposée** :
1. Les paquets (`checkov 3.3.23`, `bandit 1.9.4`, `pylint 4.1.2`, `pytest 9.1.1`, `pip-audit 2.10.1`, `yamllint 1.35.1`, et `ansible-lint 25.8.2` sur POSIX) sont installés directement dans le préfixe CPython autonome (`python-build-standalone` 3.11.9 extrait sous `python/`) via `pip install --no-cache-dir --no-warn-script-location`.
2. Les shebangs absolus des scripts sous `python/bin` et `python/Scripts` sont nettoyés/réécrits.
3. Côté Go (`matrix.go`, `engine.go`), l'exécution des outils Python passe par l'interpréteur relatif du bundle :
   - Mode module autonome : `python -m <module>` (ex. `python -m checkov.main`, `python -m bandit`, `python -m pylint`, `python -m pytest`, `python -m pip_audit`, `python -m yamllint`),
   - Ou lanceur direct script : `python.exe Scripts/checkov.cmd` / `python.exe -x Scripts/<script>`.
   Aucun binaire client ne dépend ainsi d'un chemin codé en dur lors de la construction.
4. Layout de l'archive `windows-x64-python-tools-3.11.9.tar.gz` :
   Racine `python/` contenant `python.exe`, `python311.dll`, `Lib/site-packages/` et `Scripts/`.

### C. Bundle Node (Zéro npm chez le client)
- Binaire autonome `node` de la plateforme (Node 22 LTS).
- `eslint` et `typescript` (`tsc`) installés sous `node/node_modules/` avec les lanceurs sous `node/node_modules/.bin/`.
- Côté moteur, `nodeBinScript` invoque directement le `node` du bundle avec `eslint.js` ou `tsc`, sans passer par le `PATH` ni par des scripts shell intermédiaires.
- Archive : `<platform>-node-tools-22.14.0.zip` (ou `.tar.gz`).

### D. Module PowerShell PSScriptAnalyzer
- Module `PSScriptAnalyzer 1.23.0` packagé sous l'archive aplatie `windows-x64-powershell-modules-PSScriptAnalyzer-1.23.0.zip`.
- Layout interne : `powershell-modules/PSScriptAnalyzer/PSScriptAnalyzer.psd1`, DLLs et fichiers de métadonnées.
- Extrait sous `~/.compliance/tools/powershell-modules/PSScriptAnalyzer`.

---

## 2. Manifeste Runtime Schéma 3 et Résolution d'URL

Le schéma du manifeste passe à **3** (`manifest_version`: "2.0.15").

### Structure JSON

```json
{
  "schema_version": 3,
  "manifest_version": "2.0.15",
  "registry_base_url": "https://github.com/LORD-SOUPEX/Compliance_Platform/releases/download/tools-v1",
  "platforms": {
    "windows-x64": {
      "status": "qualified",
      "tools": {
        "terraform": {
          "name": "terraform",
          "version": "1.8.5",
          "install": "archive",
          "archive": "windows-x64-terraform-1.8.5.zip",
          "archive_sha256": "17f93df5a4021a415f3fd50d2b55c0d093b42c64ea9957ceda55be3aaa91b0e5",
          "binary_in_archive": "terraform.exe",
          "binary_sha256": "e8d09543b436e84db70aa12ce42f1af1729b3b0489b424d29933a207034be2b1",
          "version_args": ["version"]
        },
        "python": {
          "name": "python",
          "version": "3.11.9",
          "install": "bundle",
          "archive": "windows-x64-python-tools-3.11.9.tar.gz",
          "archive_sha256": "...",
          "binary_in_archive": "python/python.exe",
          "binary_sha256": "",
          "version_args": ["--version"]
        },
        "node": {
          "name": "node",
          "version": "22.14.0",
          "install": "bundle",
          "archive": "windows-x64-node-tools-22.14.0.zip",
          "archive_sha256": "...",
          "binary_in_archive": "node/node.exe",
          "binary_sha256": "",
          "version_args": ["-v"]
        },
        "PSScriptAnalyzer": {
          "name": "PSScriptAnalyzer",
          "version": "1.23.0",
          "install": "bundle",
          "archive": "windows-x64-powershell-modules-PSScriptAnalyzer-1.23.0.zip",
          "archive_sha256": "...",
          "binary_in_archive": "powershell-modules/PSScriptAnalyzer/PSScriptAnalyzer.psd1",
          "binary_sha256": "",
          "version_args": []
        }
      }
    }
  }
}
```

### Ordre de résolution de l'URL du registre
1. Variable d'environnement `COMPLIANCE_REGISTRY_URL`.
2. Réglage VS Code `compliance.registryUrl` transmis par le client.
3. `registry_base_url` défini dans le manifeste.
4. Constante Go par défaut : `https://github.com/LORD-SOUPEX/Compliance_Platform/releases/download/tools-v1`.

### Gestion des anciens manifestes (Schéma 2)
Tout manifeste schéma 2 (`install: pip`, `install: runtime`, `archive_url` directe) rencontré en 2.0.15+ retourne une erreur explicite invitant à utiliser le manifeste schéma 3 et le registre `tools-v1`.

---

## 3. Ordre strict de résolution des outils (`matrix.go` et `engine.go`)

La découverte et qualification des outils respecte l'ordre strict suivant :

1. **Outils JavaScript/TypeScript (`eslint`, `tsc`)** :
   - `node_modules/.bin` du dépôt cible audité (Target Repo) en priorité absolue,
   - Sinon, bundle Node managé : `~/.compliance/tools/node/node_modules/.bin/` via `node` du bundle,
   - Sinon, `PATH` système.

2. **Tous les autres outils** :
   - `.tools/bin` (outils de développement local de la plateforme),
   - `~/.compliance/tools/bin/<platform>` (binaires natifs installés par le registre),
   - `~/.compliance/tools/python` (outils Python exécutés via `python -m <module>` ou `python Scripts/<script>`),
   - `~/.compliance/tools/powershell-modules/PSScriptAnalyzer` (module PowerShell managé),
   - `PATH` système de la machine hôte.

---

## 4. Script de construction et publication (`scripts/build_and_publish_tools.py`)

Le script `scripts/build_and_publish_tools.py` assure :
1. Le téléchargement et reconditionnement des 10 binaires natifs pour les 5 plateformes en noms d'assets aplatis (`<platform>-<tool>-<version>.<ext>`),
2. L'assemblage du bundle Python relocalisable pour Windows x64 (et documentation de build pour POSIX),
3. L'assemblage du bundle Node pour Windows x64 avec `eslint` et `typescript`,
4. L'assemblage du bundle `PSScriptAnalyzer 1.23.0`,
5. Le calcul rigoureux des sommes SHA-256 et des tailles réelles,
6. La mise à jour atomique de `.config/runtime-manifest.json` et de sa copie embarquée `core/internal/embedded/assets/runtime-manifest.json`,
7. La publication sur GitHub Release `tools-v1` via `gh release` ou l'API REST GitHub avec token d'authentification,
8. Un mode `--dry-run` permettant de valider les tailles et sommes sans publication réseau.

---

## 5. Ordre d'exécution séquentiel (Étapes 1 à 5)

1. **Mesurer et assembler** : Exécution de `build_and_publish_tools.py` en dry-run. Vérification des tailles, calcul des SHA-256 réels.
2. **Publier `tools-v1`** : Création du tag/release `tools-v1` sur `LORD-SOUPEX/Compliance_Platform`, upload des assets aplatis, mise à jour des manifestes.
3. **Mettre à jour le code moteur et extension** :
   - `distribution` : gestion de `archive` et `bundle`, suppression de pip/npm dynamiques,
   - `matrix` & `engine` : ordre strict de résolution et support de l'exécution relative Python/Node/PowerShell,
   - `package_vsix.py` : synchronisation du manifeste avant compilation des démons,
   - Extension VS Code : ajout du paramètre `compliance.registryUrl` et incrément version 2.0.15.
4. **Validation et tests complets** :
   - Provisionnement réel depuis `tools-v1` dans un cache propre,
   - `go test ./...`,
   - `npm test`,
   - `npm run test:webview`,
   - `compliance selftest`.
5. **Livraison 2.0.15** :
   - Mise à jour de toute la documentation (`README.md`, `docs/*`),
   - Génération du VSIX `compliance-local-pipelines-2.0.15.vsix`,
   - Commit et push sur `origin/main`.
