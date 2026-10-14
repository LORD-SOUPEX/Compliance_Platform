# Développement

Version courante : 2.0.14.

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
| PowerShell | Aucun. | PSScriptAnalyzer n'était pas installé sur la machine de qualification. |

Les commandes ci-dessous construisent et vérifient le dépôt. Elles ne font pas partie de la page Marketplace.

```bash
cd vscode-extension
npm install
npm test
npm run package
```

`npm test` compile le TypeScript, compare la version du moteur à `package.json`, lance les tests Go (découverte, moteur, rapport, distribution, sessions, matrice), vérifie le VSIX et exécute `compliance selftest`.

Go utilisé par ces scripts : `.tools/go/bin/go`. Python : `py -3` sur Windows.

Réinstaller l'extension de test, sans script PowerShell :

```bash
cd vscode-extension
npm run reinstall -- dist/compliance-local-pipelines-2.0.14.vsix
```

Cela arrête le démon, désinstalle l'extension, supprime les dossiers résiduels de l'extension et installe le VSIX. Les sessions restent dans le dossier utilisateur.

La signature du manifeste est facultative. L'installation des outils et `npm run package` ne s'arrêtent pas si elle est absente ou différente. Pour la produire malgré tout, avec la clé privée hors dépôt :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```

La clé est une seed Ed25519 de 32 octets ou une clé privée de 64 octets, en hexadécimal. Le dépôt ne la contient pas.
