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
