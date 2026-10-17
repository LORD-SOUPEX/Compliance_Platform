# Développement

Version courante : 2.1.3. Le fonctionnement du moteur, du registre et des compteurs est dans [architecture](architecture.md).

## Validation

```bash
cd core
gofmt -l .
go vet ./...
go test -count=1 ./...
cd ../vscode-extension
npx tsc --noEmit
npm test
npm run test:webview
```

Puis, avec le binaire construit :

```bash
compliance selftest
```

Go utilisé par les scripts de l'extension : `.tools/go/bin/go`. Python : `py -3` sur Windows.

`npm test` compile le TypeScript, compare la version du moteur à `package.json`, relance une partie des tests Go, vérifie le VSIX et exécute `compliance selftest`. `npm run package` produit `dist/compliance-pipelines-<version>.vsix`.

## Registre `tools-v1`

`scripts/build_and_publish_tools.py` reconditionne les 10 binaires natifs pour les cinq plateformes, assemble les bundles Python, Node et `PSScriptAnalyzer`, calcule les SHA-256, met à jour `.config/runtime-manifest.json` et publie les assets aplatis sur la release GitHub `tools-v1`, y compris `runtime-manifest.json`, `runtime-manifest.json.sig` et `control-catalog.json`.

Les versions sont dans `.config/tools-lock.json`. Pour publier un seul linter sans reconstruire les autres archives :

```bash
py scripts/build_and_publish_tools.py --only ruff
```

Pour republier uniquement le manifeste et le catalogue déjà signés :

```bash
py scripts/build_and_publish_tools.py --publish-registry
```

```bash
py scripts/build_and_publish_tools.py --repo LORD-SOUPEX/Compliance_Platform --tag tools-v1
```

Sur un hôte Linux ou macOS, le même script détecte la plateforme, construit le bundle Python POSIX (y compris `ansible-lint`) et publie `<plateforme>-python-tools-3.11.9.tar.gz`. Un essai sans téléversement :

```bash
python3 scripts/build_and_publish_tools.py --dry-run
```

Le détail des paquets et de l'ordre de résolution est dans [architecture](architecture.md).

## VSIX local

```bash
cd vscode-extension
npm run reinstall -- dist/compliance-pipelines-2.1.3.vsix
```

La commande arrête le démon, retire l'extension précédente et installe le VSIX. Les sessions restent dans le dossier utilisateur.

## Signature du manifeste

La signature est facultative. L'installation des outils et `npm run package` continuent si elle est absente ou différente. Pour la produire avec la clé privée hors dépôt :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```

La clé est une seed Ed25519 de 32 octets ou une clé privée de 64 octets, en hexadécimal. Elle n'est pas dans le dépôt. La copie embarquée est `core/internal/embedded/assets/runtime-manifest.json.sig`.
