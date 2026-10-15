# Outils du catalogue et manifeste

Version courante : 2.0.15. Le manifeste est `.config/runtime-manifest.json` (schéma 3).

Depuis la version 2.0.15, l'intégralité des outils requis par le catalogue est centralisée et pré-packagée dans un **registre d'outils auto-hébergé** publié sur la GitHub Release `tools-v1` (`https://github.com/LORD-SOUPEX/Compliance_Platform/releases/tag/tools-v1`). Plus aucun appel réseau vers des forges tierces (éditeurs, HashiCorp, PyPI, npm, PowerShell Gallery) n'a lieu lors de la synchronisation ou de l'exécution.

## Ordre strict de résolution des outils

1. **Pour `eslint` et `tsc`** :
   - Priorité 1 : `node_modules/.bin` de la cible auditée (Target).
   - Priorité 2 : bundle autonome `~/.compliance/tools/node` issu du registre.
2. **Pour tous les autres outils** :
   - Priorité 1 : `.tools/bin/` du dépôt local (mode développement).
   - Priorité 2 : Registre installé `~/.compliance/tools/{bin,python,node,powershell-modules}`.
   - Priorité 3 : `PATH` système.

## Présents dans le manifeste et le registre `tools-v1`

### 1. Binaires natifs (10 outils x 5 plateformes)
Présents pour **windows-x64**, **linux-x64**, **linux-arm64**, **macos-x64** et **macos-arm64** :
- `ruff` (0.16.10)
- `gitleaks` (8.30.1)
- `tflint` (0.64.0)
- `trivy` (0.75.0)
- `terraform` (1.8.5)
- `tofu` (1.8.2)
- `hadolint` (2.15.1)
- `terragrunt` (1.1.6)
- `shellcheck` (0.10.0)
- `rumdl` (0.2.79)

Tous les assets sont publiés sous un format à plat `<platform>-<tool>-<version>.<ext>` pour respecter les contraintes de GitHub Releases (absence de slashs).

### 2. Bundle Python 100 % relocalisable (Zéro venv à chemins absolus)
Les outils Python (`checkov` 3.3.23, `bandit` 1.9.4, `pylint` 4.1.2, `pytest` 9.1.1, `pip-audit` 2.10.1, `yamllint` 1.35.1, et `ansible-lint` 25.8.2 sur POSIX) sont installés directement dans l'arborescence de CPython autonome (`python-build-standalone` 3.11.9 sous `~/.compliance/tools/python`).
- Les shebangs et chemins absolus codés en dur dans les scripts sont supprimés.
- Le moteur Go exécute systématiquement les outils Python via l'interpréteur autonome du bundle (`python -m <module>`), garantissant une relocalisation parfaite quel que soit l'emplacement du dossier utilisateur.

### 3. Bundle Node (JavaScript / TypeScript)
Le bundle `windows-x64-node-tools-22.14.0.zip` fournit un environnement autonome contenant Node.js 22.14.0, `eslint` 9.21.0 et `typescript` 5.7.3 dans `~/.compliance/tools/node`, servant de repli transparent si la cible auditée ne possède pas de `node_modules/.bin`.

### 4. Module PowerShell `PSScriptAnalyzer`
L'archive `windows-x64-powershell-modules-PSScriptAnalyzer-1.23.0.zip` est hébergée sur le registre et extraite dans `~/.compliance/tools/powershell-modules/PSScriptAnalyzer`. Même sur un poste Windows vierge sans accès à la PowerShell Gallery, `Invoke-ScriptAnalyzer` s'installe et s'exécute en 1 clic.

## Miroirs d'entreprise et jetons d'authentification

Pour les environnements d'entreprise fermés (Artifactory, Nexus, GitLab Package Registry, miroir HTTPS interne) :
- **URL du registre** : configurable via le paramètre VS Code `compliance.registryUrl`, l'option CLI `-registry-url`, ou la variable d'environnement `COMPLIANCE_REGISTRY_URL`.
- **Authentification** : jeton Bearer configurable via `compliance.registryToken`, l'option CLI `-registry-token`, ou la variable `COMPLIANCE_REGISTRY_TOKEN`.

## Signature du manifeste

Le manifeste `.config/runtime-manifest.json` est signé avec une clé Ed25519 d'entreprise :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```
