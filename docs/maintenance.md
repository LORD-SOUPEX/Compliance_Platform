# Maintenance et qualification

Ce guide regroupe les procédures d'installation, de packaging, de mise à jour, de qualification multi-OS et de gouvernance du socle Compliance Platform.

---

## 1. Architecture du Runtime et Packaging

### Tool Resolver Découplé & Mode Hors-Ligne

Le moteur Go (`core/`) s'appuie sur une hiérarchie de résolution stricte pour exécuter les outils d'audit sans altérer l'environnement de l'hôte :

1. **Binaires locaux dédiés (`.tools/bin/`)** : Emplacement prioritaire contenant les exécutables natifs épinglés et vérifiés.
2. **Environnement Python autonome (`.tools/python/`)** : Python portable indépendant de l'hôte pour l'exécution des modules d'analyse (ex. Ruff, Checkov, pip-audit).
3. **Cache de distribution** : `compliance runtime sync` installe les binaires vérifiés dans `~/.compliance/tools/bin/<plateforme>/` (`macos-x64`, `macos-arm64`, etc.). Le miroir `.tools/runtime/<plateforme>/` reste consulté en secours. La signature Ed25519 est `.config/runtime-manifest.json.sig`.
4. **Préfixes macOS** : `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/Library/Python/*/bin` et `~/.pyenv/shims`, y compris lorsque le PATH GUI de VS Code ne contient pas Homebrew.
5. **PATH du processus** : dernier recours (`exec.LookPath`), après les emplacements ci-dessus.

En mode déconnecté / hors-ligne, le moteur utilise exclusivement les artefacts et caches locaux validés par leurs sommes de contrôle SHA-256.

### Injection des Certificats d'Entreprise (`ca-bundle.pem`)

Pour les environnements sécurisés d'entreprise soumis à une inspection SSL/TLS :
- La plateforme détecte et utilise automatiquement le trousseau de certificats d'autorité racine placé sous `.tools/certs/ca-bundle.pem` ou via la variable d'environnement `COMPLIANCE_CA_BUNDLE`.
- Ce trousseau est transmis aux outils d'audit (ex. requêtes d'inspection réseau ou scans d'intégrité) afin d'éviter les ruptures de confiance TLS.

### Packaging de l'Extension VS Code (VSIX Universel)

Un package VSIX multi-OS complet est produit sans dépendre d'outils propriétaires externes via des scripts multi-OS standards :

```bash
cd vscode-extension
npm run package
```

Sous le capot, `vscode-extension/package_vsix.py` génère un conteneur conforme à la norme **Open Packaging Conventions (OPC)** :
- Il recopie `.config/` dans `core/internal/embedded/assets/` avant `go build`, pour que `//go:embed` (qui ne peut pas remonter au-dessus du module `core`) reste aligné sur le catalogue.
- Il embarque ces mêmes fichiers dans `extension/.config/` du VSIX. Une extension installée hors dépôt trouve son catalogue sans clone Git. Les sessions sont alors écrites dans `~/.compliance/sessions`, pas dans le dossier de l'extension.
- Les binaires POSIX du ZIP portent le mode Unix `0755` (`external_attr`). Au lancement, l'extension réapplique `chmod 0755` et, sur macOS, retire `com.apple.quarantine` si l'attribut est présent.
- Il compile et intègre les binaires natifs Go pour l'ensemble des 6 cibles :
  - `bin/compliance-windows-amd64.exe`
  - `bin/compliance-windows-arm64.exe`
  - `bin/compliance-linux-amd64`
  - `bin/compliance-linux-arm64`
  - `bin/compliance-darwin-amd64`
  - `bin/compliance-darwin-arm64`
- Le VSIX produit (`vscode-extension/dist/compliance-local-pipelines-2.0.0.vsix`) est immédiatement installable sur n'importe quel système d'exploitation sans nécessiter de recompilation sur le poste utilisateur.

---

## 2. Validation Reproductible et Qualification

### Validation Complète du Moteur Go

Depuis la racine du projet :

```bash
# Selftest de bout en bout (20 contrôles de sécurité et d'API)
compliance selftest

# Suite complète de tests unitaires et d'intégration Go
cd core
go test -count=1 ./...
```

### Validation de l'Extension VS Code

Depuis le dossier `vscode-extension/` :

```bash
# Vérification TypeScript (tsc --noEmit) et validation autonome (compliance selftest)
npm test

# Compilation TypeScript seule
npm run compile
```

### Matrice de Qualification Multi-OS

Conformément à `.config/platform-support.json` :

| Plateforme | Statut | Preuves Actuelles |
| :--- | :--- | :--- |
| **windows-x64** | **Qualified** | Selftest Go 20/20 PASS, extension VS Code qualifiée. Confinement Job Objects validé. |
| **windows-arm64** | **Targeted** | Binaire natif `compliance-windows-arm64.exe` cross-compilé et embarqué dans le VSIX universel. |
| **linux-x64** | **Targeted** | Binaire natif `compliance-linux-amd64` cross-compilé (`GOOS=linux GOARCH=amd64`). Confinement POSIX validé. |
| **linux-arm64** | **Targeted** | Binaire natif `compliance-linux-arm64` cross-compilé (`GOOS=linux GOARCH=arm64`) embarqué dans le VSIX. |
| **macos-x64** | **Targeted** | Binaire `compliance-darwin-amd64` embarqué. Identifiant catalogue `macos-x64`. Selftest physique Intel encore requis pour `qualified`. |
| **macos-arm64** | **Targeted** | Binaire `compliance-darwin-arm64` embarqué. Identifiant catalogue `macos-arm64`. Selftest physique Apple Silicon encore requis pour `qualified`. |

---

## 3. Mise à Jour Contrôlée des Outils et Manifestes

1. **Manifeste des Outils (`.config/runtime-manifest.json`)** :
   - Définit les versions exactes, URLs de téléchargement et condensats SHA-256 de chaque binaire et archive.
   - Doit être signé cryptographiquement via la clé privée du projet (`runtime-manifest.json.sig`).
2. **Synchronisation du Runtime** :
   ```bash
   compliance runtime sync
   ```
   Cette commande vérifie l'intégrité de la signature et télécharge ou vérifie les outils dans le cache local.
