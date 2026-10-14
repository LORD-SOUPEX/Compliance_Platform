# Outils du catalogue et manifeste

Version courante : 2.0.14. Le manifeste est `.config/runtime-manifest.json`. `compliance runtime sync` télécharge l'archive HTTPS déclarée et extrait le binaire dans `~/.compliance/tools`. Une entrée est installable dès qu'elle figure dans le manifeste pour la plateforme. Une signature absente ou différente, ou une somme SHA-256 différente, ne bloque pas l'installation.

## Présents dans le manifeste

Présents pour **windows-x64**, **linux-x64**, **linux-arm64**, **macos-x64** et **macos-arm64** : `ruff`, `gitleaks`, `tflint`, `trivy`, `terraform`, `tofu`, `hadolint`, `terragrunt`, `shellcheck`, `rumdl`, `python`, `bandit`, `pylint`, `pytest`, `pip-audit`, `checkov`, `yamllint`, `ansible-lint`. Les paquets Python s'installent dans `~/.compliance/tools/venv` après le runtime CPython du manifeste. Sur Windows, `checkov` est `Scripts/checkov.cmd` et le moteur l'exécute avec le `python.exe` de ce venv.

`rumdl` 0.2.79 est déclaré là où un binaire officiel existe. **windows-arm64** n'a pas de binaire rumdl. Sans configuration Markdown du dépôt audité, l'appel ajoute `--disable MD013`.

`gitleaks` est lancé avec `--no-git`. Son allowlist reprend les dossiers ignorés par la découverte et les extensions `.vsix`, `.exe`, `.dll`, `.pdb`, `.pyc`, `.zip`. `pytest` qui ne collecte aucun test (code 5) n'est pas un échec de conformité. `pylint` reçoit `--rcfile` lorsque le dépôt contient `.pylintrc`, `pylintrc`, `.pylintrc.toml`, ou un `pyproject.toml` / `setup.cfg` qui mentionne pylint.

`eslint` et `tsc` viennent d'abord de `node_modules/.bin` de la cible. S'ils n'y sont pas, le moteur utilise `~/.compliance/tools/node`, peuplé par `compliance runtime node` (npm installe `eslint` et `typescript` après accord dans l'extension).

## Absents du manifeste

| Outil du catalogue | Pourquoi |
| --- | --- |
| `eslint`, `tsc` | Binaires du dépôt cible (`node_modules`). |
| `Invoke-ScriptAnalyzer` | Module PowerShell, pas une archive du manifeste. |

## Plateformes incomplètes

Windows ARM64 reste incomplet tant que l'éditeur ne publie pas de binaire (rumdl 0.2.79 n'en a pas). Sur Windows, le résolveur marque `ansible`, `ansible-lint` et `molecule` incompatibles avant de chercher le venv. `ansible-lint` n'est pas proposé comme outil installable : il est réservé à Linux et macOS. `yamllint` reste le contrôle Ansible disponible sur Windows.

ShellCheck, Hadolint, Ruff, Pylint et Bandit reçoivent leurs fichiers par lots, sous la limite de ligne de commande Windows. Ruff check, Pylint, Bandit et pip-audit sont lancés en JSON. yamllint est lancé en format `parsable`. Leurs findings portent le fichier, la ligne, la règle et le message. La découverte Docker inclut `Dockerfile`, `Dockerfile.*`, `Containerfile` et `*.Dockerfile`, dans n'importe quel sous-dossier.

Commande de signature, une fois le fragment fusionné dans le manifeste :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```
