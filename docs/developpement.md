# Développement

Version courante : 2.2.0. Le fonctionnement du moteur, du registre et des compteurs est dans [architecture](architecture.md).

## Validation

```bash
cd core
gofmt -l .
go vet ./...
go test -count=1 ./...
golangci-lint run ./...
cd ../vscode-extension
npm run lint
npm run test:unit
npm test
npm run test:webview
```

`npm run lint` applique ESLint (`eslint.config.mjs`, règles typées strictes) à l'extension. `npm run test:unit` compile puis lance les tests `node:test` de `src/test/unit` (analyseur SSE, journal, client du démon), sans VS Code ni binaire. `golangci-lint` lit `core/.golangci.yml`.

Les fichiers Go sont en fin de ligne LF sur tous les OS (`.gitattributes`), ce que `gofmt` exige. Le JavaScript, le TypeScript, le CSS et le JSON suivent `biome.json` (`biome format --write`) ; les scripts Python passent `ruff format`, `ruff check`, `pylint --rcfile .pylintrc` et `bandit`.

Le dépôt s'audite lui-même avec le moteur (`compliance run -repo . -allow-code -allow-network`) : chaque contrôle exécuté doit réussir.

## Démo multi-technologies

Le dossier local `devsecops-compliance-benchmark`, cloné à côté de ce dépôt, couvre toutes les technologies du catalogue. Pour l'auditer avec tous les outils du registre sans toucher au dossier `~/.compliance/tools` du poste :

```bash
export COMPLIANCE_TOOLS_DIR="$PWD/.tools/registry"
.tools/bin/compliance runtime sync -manifest .config/runtime-manifest.json -sig .config/runtime-manifest.json.sig
.tools/bin/compliance run -repo ../devsecops-compliance-benchmark -allow-code -allow-network -report benchmark.json
python scripts/check_benchmark.py benchmark.json --min-executed 25
```

Le vérificateur exige les 19 technologies, aucune erreur d'exécution, une anomalie localisée pour chaque contrôle en échec et un processus enregistré pour chaque contrôle exécuté.

## Registre `tools-v1`

`scripts/build_and_publish_tools.py` reconditionne les 15 binaires natifs pour les cinq plateformes, assemble le bundle Node des cinq plateformes depuis n'importe quel hôte, les bundles Python (hôte natif) et `PSScriptAnalyzer`, calcule les SHA-256, met à jour `.config/runtime-manifest.json` et publie les assets aplatis sur la release GitHub `tools-v1`, y compris `runtime-manifest.json`, `runtime-manifest.json.sig` et `control-catalog.json`.

Les versions sont dans `.config/tools-lock.json`. Pour publier un seul linter sans reconstruire les autres archives :

```bash
py scripts/build_and_publish_tools.py --only ruff
```

`--only stylelint` (ou `eslint`, `tsc`, `htmlhint`, `node`) reconstruit le bundle Node des cinq plateformes.

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
npm run package
npm run reinstall -- dist/compliance-pipelines-<version>.vsix
```

La commande arrête le démon, retire l'extension précédente et installe le VSIX. Les sessions restent dans le dossier utilisateur.

## Signature du manifeste

La signature est facultative. L'installation des outils et `npm run package` continuent si elle est absente ou différente. Pour la produire avec la clé privée hors dépôt :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```

La clé est une seed Ed25519 de 32 octets ou une clé privée de 64 octets, en hexadécimal. Elle n'est pas dans le dépôt. `scripts/build_and_publish_tools.py` signe avec la seed brute de 32 octets `.tools/cache/distribution_ed25519.key` (ignorée par Git). Cette clé, créée pour la 2.2.0, correspond à `DefaultPhase0PublicKeyHex` dans `core/internal/distribution/distribution.go` : en conserver une copie hors du poste, car sa perte impose une nouvelle rotation. La copie embarquée est `core/internal/embedded/assets/runtime-manifest.json.sig`.
