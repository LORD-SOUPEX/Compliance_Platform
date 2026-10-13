# Maintenance et qualification

Ce guide regroupe les procédures d'installation, de packaging, de mise à jour, de qualification multi-OS et de gouvernance du socle Compliance Platform.

---

## 1. Architecture du Runtime et Packaging

### Tool Resolver Découplé & Mode Hors-Ligne

Le moteur Go (`core/`) s'appuie sur une hiérarchie de résolution stricte pour exécuter les outils d'audit sans altérer l'environnement de l'hôte :

1. **Binaires locaux dédiés (`.tools/bin/`)** : Emplacement prioritaire contenant les exécutables natifs épinglés et vérifiés.
2. **Environnement Python autonome (`.tools/python/`)** : Python portable indépendant de l'hôte pour l'exécution des modules d'analyse (ex. Ruff, Checkov, pip-audit).
3. **Cache de distribution & Index (`.tools/runtime/`)** : Miroir local vérifié par signature cryptographique Ed25519 (`.config/runtime-manifest.json.sig`).
4. **PATH système contrôlé** : Utilisé uniquement pour les outils système non redistribuables si explicitement configurés.

En mode déconnecté / hors-ligne, le moteur utilise exclusivement les artefacts et caches locaux validés par leurs sommes de contrôle SHA-256.

### Injection des Certificats d'Entreprise (`ca-bundle.pem`)

Pour les environnements sécurisés d'entreprise soumis à une inspection SSL/TLS :
- La plateforme détecte et utilise automatiquement le trousseau de certificats d'autorité racine placé sous `.tools/certs/ca-bundle.pem` ou via la variable d'environnement `COMPLIANCE_CA_BUNDLE`.
- Ce trousseau est transmis aux outils d'audit (ex. requêtes d'inspection réseau ou scans d'intégrité) afin d'éviter les ruptures de confiance TLS.

### Packaging de l'Extension VS Code (VSIX Universel)

Contrairement aux versions préliminaires, un package VSIX multi-OS complet est produit sans dépendre d'outils propriétaires externes :

```powershell
# Packaging officiel via le script de maintenance
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Package
```

Sous le capot, le script `scripts/package_vsix.py` génère un conteneur conforme à la norme **Open Packaging Conventions (OPC)** :
- Il compile et intègre les binaires natifs Go pour l'ensemble des cibles ciblées :
  - `bin/compliance-windows-amd64.exe`
  - `bin/compliance-linux-amd64`
  - `bin/compliance-darwin-arm64`
  - `bin/compliance-darwin-amd64`
- Le VSIX produit (dans `vscode-extension/dist/compliance-pipelines-1.0.0.vsix`) est immédiatement installable sur n'importe quel système d'exploitation sans nécessiter de recompilation sur le poste utilisateur.

---

## 2. Validation Reproductible et Qualification

### Validation Complète du Moteur Go

Depuis la racine du projet :

```bash
# Selftest de bout en bout (20 contrôles de sécurité et d'API)
.tools/bin/compliance.exe selftest

# Suite complète de tests unitaires et d'intégration Go
cd core
go test ./...
```

### Validation de l'Extension VS Code

```powershell
# Compilation et suite de tests unitaires/intégration TypeScript (34 scénarios)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Test

# Test d'intégration dans une instance réelle VS Code (Host isolé)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action TestHost
```

### Matrice de Qualification Multi-OS

Conformément à `.config/platform-support.json` :

| Plateforme | Statut | Preuves Actuelles |
| :--- | :--- | :--- |
| **windows-x64** | **Qualified** | Selftest Go 20/20 PASS, suite Go `core/` OK, extension VS Code 34/34 PASS. Confinement Job Objects validé. |
| **linux-x64** | **Targeted** | Binaires cross-compilés validés. Nécessite l'exécution de `compliance selftest` sur une machine hôte Linux physique avant qualification. |
| **darwin-arm64** | **Targeted** | Binaires cross-compilés embarqués dans le package VSIX. |
| **darwin-amd64** | **Targeted** | Binaires cross-compilés embarqués dans le package VSIX. |

---

## 3. Mise à Jour Contrôlée des Outils et Manifestes

1. **Manifeste des Outils (`.config/runtime-manifest.json`)** :
   - Définit les versions exactes, URLs de téléchargement et condensats SHA-256 de chaque binaire et archive.
   - Doit être signé cryptographiquement via la clé privée du projet (`runtime-manifest.json.sig`).
2. **Synchronisation du Runtime** :
   ```bash
   compliance runtime sync
   ```
   Cette commande vérifie l'intégrité de la signature et télécharge ou vérifie les outils dans `.tools/runtime/`.

---

## 4. Outils et Commandes Historiques (Obsolètes)

Les scripts historiques sous `scripts/` (`quality-gate.ps1`, `bootstrap.ps1`, `doctor.ps1`) sont conservés pour des besoins de rétrocompatibilité et de référence d'archivage. Ils ne doivent plus être utilisés pour les opérations courantes :

```powershell
# [OBSOLÈTE] Ancien bootstrap du runtime PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1

# [OBSOLÈTE] Ancien contrôle d'intégrité PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
```
