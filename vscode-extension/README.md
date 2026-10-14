# Compliance Local Pipelines

Audit local de conformité pour une cible de votre choix. L'extension pilote un démon Go sur `127.0.0.1`, sans forge distante et sans compte cloud.

Le catalogue couvre Python (`ruff`, `pylint`, `pytest`, `bandit`, `pip-audit`), Terraform et OpenTofu (`terraform fmt`, `tofu fmt`, `tflint`, `checkov`), Terragrunt, conteneurs (`hadolint`, `trivy`), Kubernetes et Helm (`checkov`, `trivy`), Ansible (`ansible-lint`, `yamllint`), Shell (`shellcheck`), Markdown (`markdownlint` via `pre-commit`) et PowerShell (`PSScriptAnalyzer`). JavaScript et TypeScript sont détectés ; aucun linter n'est configuré pour eux.

## Installation

Installez l'extension depuis le Marketplace, puis ouvrez la vue **Compliance Pipelines**. Choisissez une Target externe au dossier de l'extension. Le catalogue est embarqué dans le VSIX : un clone du dépôt n'est pas nécessaire. Les sessions sont écrites dans `~/.compliance/sessions`.

Les binaires du démon (`windows`, `linux`, `darwin`, architectures `amd64` et `arm64`) sont inclus. Sur macOS, l'extension rend le binaire exécutable et retire l'attribut de quarantaine lorsqu'il est présent.

## Architecture et Principes Clés

L'extension fonctionne selon une architecture découplée sans aucune exécution de script PowerShell sous le capot. Elle pilote un démon HTTP/SSE local ultra-rapide et sécurisé :

- **Démon local autonome en Go** :
  - Démarré dynamiquement sur un port éphémère (`127.0.0.1:0`).
  - Protégé par un jeton Bearer cryptographique 256 bits généré à chaque lancement.
  - Protection stricte contre le piratage inter-origine (vérification des en-têtes `Host` et `Origin`).
  - Détection de terminaison de l'éditeur hôte et arrêt automatique sans laisser aucun processus orphelin (gestion par Job Objects sous Windows).
- **Orchestration par le binaire Go** :
  - La découverte, le plan et l'exécution passent par le démon. Le contrôle PowerShell, lorsqu'il est applicable, appelle `pwsh` ou Windows PowerShell ; l'extension elle-même ne s'appuie pas sur un script PowerShell.
- **Support Multi-OS Natif** :
  - Les 6 binaires natifs du moteur Go sont directement compilés et embarqués dans le package VSIX universel :
    - `bin/compliance-windows-amd64.exe`
    - `bin/compliance-windows-arm64.exe`
    - `bin/compliance-linux-amd64`
    - `bin/compliance-linux-arm64`
    - `bin/compliance-darwin-amd64`
    - `bin/compliance-darwin-arm64`
  - Aucun téléchargement additionnel n'est requis à l'installation.
  - Le VSIX contient aussi `extension/.config/` (catalogue, schémas, manifeste). Installée hors d'un clone Git, l'extension utilise ce catalogue et écrit les sessions dans `~/.compliance/sessions`.
  - Avant de lancer le démon, l'extension pose le mode `0755` sur le binaire POSIX et, sur macOS, retire l'attribut `com.apple.quarantine` lorsqu'il est présent. Un refus `EACCES` ou un `SIGKILL` (signal 9, Gatekeeper) est signalé explicitement.

---

## Fonctionnalités de l'Extension

1. **Explorateur de Pipelines de Conformité** :
   - Sélection d'un répertoire cible (Target) de confiance.
   - Découverte automatique des technologies, cadres et racines analysées.
   - Visualisation de l'arborescence des contrôles applicables avec statut en temps réel (`Pending`, `Running`, `Succeeded`, `Failed`, `Error`, `Skipped`).
2. **Gestion Granulaire des Permissions** :
   - Consentement interactif requis pour les contrôles nécessitant un accès réseau ou une exécution de code arbitraire.
3. **Lecteur de Rapport Haute Fidélité** :
   - Restitution du verdict final (`PASS` / `FAIL`), de la couverture et des constats détaillés (*findings*).
   - Navigation directe au clic vers la ligne incriminée dans l'éditeur.
   - Consultation des logs d'exécution (stdout, stderr) et du document JSON canonique conforme au contrat v1.

---

## Commandes VS Code Disponibles

| Commande | Action |
| :--- | :--- |
| `Compliance: Selectionner une Target` | Choisit le dossier du projet à auditer et lance la découverte |
| `Compliance: Lancer l'audit` | Exécute le plan d'audit avec suivi de progression en direct |
| `Compliance: Annuler l'audit` | Interrompt immédiatement l'audit en cours sans laisser de processus actif |
| `Compliance: Actualiser la preparation` | Recalcule la découverte et le graphe des contrôles |
| `Compliance: Ouvrir le rapport de la derniere session` | Affiche le lecteur interactif pour le dernier audit |
| `Compliance: Ouvrir un rapport existant` | Charge et valide un fichier JSON de rapport externe |
| `Compliance: Ouvrir les sorties du controle` | Affiche stdout, stderr et diagnostics du contrôle sélectionné |
| `Compliance: Ouvrir le JSON brut` | Affiche le document JSON canonique validé par le moteur |

---

## Développement et Tests Locaux

Depuis le dossier `vscode-extension/` :

```bash
# Installation des dépendances npm
npm install

# Compilation TypeScript
npm run compile

# Selftest du moteur Go (20/20) après compilation TypeScript
npm test

# Packaging du VSIX universel (compilation automatique des 6 binaires multi-OS Go)
npm run package
```
