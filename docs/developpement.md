# Développement

Version courante : 2.0.15.

Sessions Windows x64 exécutées pour cette version :

| Technologie | Contrôles exécutés | Limite connue |
| --- | --- | --- |
| Terraform | `content` non concerné. `cloud-foundation-toolkit` : terraform, tflint et checkov sur 8 racines. Fixture : terraform, tflint, checkov. | |
| Kubernetes | checkov politique et sécurité sur `cloud-foundation-toolkit` et la fixture. | Trivy sécurité n'est pas lancé quand checkov est retenu. |
| Shell | ShellCheck par lots sur `content` et la fixture. | |
| Markdown | rumdl sur `content`, `cloud-foundation-toolkit` et la fixture. | |
| Ansible | yamllint sur `content` et la fixture. | `ansible-lint` est réservé à Linux et macOS. |
| Docker | Hadolint et Trivy sur `content` et la fixture, y compris `.gitpod.Dockerfile` et `*.Dockerfile`. | |
| Helm | checkov politique et sécurité sur la fixture. | Trivy sécurité n'est pas lancé quand checkov est retenu. |
| JavaScript | ESLint et gitleaks sur la fixture. | |
| TypeScript | `tsc` sur la fixture. | ESLint TypeScript dépend du parseur configuré dans le dépôt. |
| OpenTofu | tofu, tflint et checkov sur la fixture. | |
| Python | Ruff, Pylint, Bandit, pytest et pip-audit sur la fixture. Pylint, Bandit et Ruff aussi sur `content`. | Une racine Python très grande peut tronquer la sortie capturée. |
| Terragrunt | terragrunt hcl fmt sur la fixture. | |
| PowerShell | Invoke-ScriptAnalyzer sur la fixture. | Téléchargeable en 1 clic via le bundle `PSScriptAnalyzer-1.23.0.zip` du registre. |

## Construction et validation

Les commandes ci-dessous construisent et vérifient le dépôt. Elles ne font pas partie de la page Marketplace.

```bash
cd vscode-extension
npm install
npm test
npm run package
```

`npm test` compile le TypeScript, compare la version du moteur à `package.json`, lance les tests Go (découverte, moteur, rapport, distribution, sessions, matrice), vérifie le VSIX et exécute `compliance selftest`.

Go utilisé par ces scripts : `.tools/go/bin/go`. Python : `py -3` sur Windows.

## Publication du registre d'outils (`tools-v1`)

Le script `scripts/build_and_publish_tools.py` automatise :
1. Le téléchargement et le reconditionnement uniforme (.zip / .tar.gz) des 10 binaires natifs pour les 5 plateformes cibles (`windows-x64`, `linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`).
2. L'assemblage du bundle Python relocalisable (CPython autonome + paquets sans venv statique) avec shebangs nettoyés et point d'entrée `checkov/__main__.py`.
3. L'assemblage du bundle Node (`node-tools-22`) et du module `PSScriptAnalyzer`.
4. Le calcul des tailles et des SHA-256 réels.
5. La génération et la signature du manifeste schéma 3 `.config/runtime-manifest.json`.
6. La publication aplatie des 57 assets sur la release GitHub `tools-v1` via GitHub CLI (`gh release`).

```bash
py scripts/build_and_publish_tools.py --repo LORD-SOUPEX/Compliance_Platform --tag tools-v1
```

### Procédure de construction et publication des bundles Linux et macOS

Sur une machine ou un runner Linux (x64 ou arm64) ou macOS (Intel ou Apple Silicon) disposant de Python 3.10+, Go et de GitHub CLI (`gh`) authentifié avec les droits sur le dépôt :

1. **Cloner le dépôt et se placer à la racine** :
   ```bash
   git clone https://github.com/LORD-SOUPEX/Compliance_Platform.git
   cd Compliance_Platform
   ```

2. **Exécuter le script de build du registre** :
   Le script détecte la plateforme POSIX hôte (`linux-x64`, `linux-arm64`, `macos-x64` ou `macos-arm64`), extrait le runtime CPython autonome `python-build-standalone` 3.11.9, installe l'ensemble des paquets requis (`checkov==3.3.23`, `bandit==1.9.4`, `pylint==4.1.2`, `pytest==9.1.1`, `pip-audit==2.10.1`, `yamllint==1.35.1`, ainsi que `ansible-lint==25.8.2` sous POSIX), réécrit les shebangs en `#!/usr/bin/env python3`, injecte `checkov/__main__.py`, calcule les SHA-256 réels et publie l'archive sur la release GitHub :
   ```bash
   python3 scripts/build_and_publish_tools.py --repo LORD-SOUPEX/Compliance_Platform --tag tools-v1
   ```

3. **Mode validation préalable sans téléversement (dry-run)** :
   ```bash
   python3 scripts/build_and_publish_tools.py --dry-run
   ```

4. **Assets produits et mis à jour** :
   - Archive produite : `<platform>-python-tools-3.11.9.tar.gz`
   - Le manifeste `.config/runtime-manifest.json` est mis à jour avec les SHA-256 réels et re-signé par la clé Ed25519.
   - Les archives sont uploadées sur la release GitHub `tools-v1` avec remplacement automatique (`--clobber`).


## Réinstallation locale du VSIX

Réinstaller l'extension de test, sans script PowerShell :

```bash
cd vscode-extension
npm run reinstall -- dist/compliance-local-pipelines-2.0.15.vsix
```

Cela arrête le démon, désinstalle l'extension, supprime les dossiers résiduels de l'extension et installe le VSIX. Les sessions restent dans le dossier utilisateur.

## Signature du manifeste

La signature du manifeste est facultative. L'installation des outils et `npm run package` ne s'arrêtent pas si elle est absente ou différente. Pour la produire malgré tout, avec la clé privée hors dépôt :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```

La clé est une seed Ed25519 de 32 octets ou une clé privée de 64 octets, en hexadécimal. Le dépôt ne la contient pas.
