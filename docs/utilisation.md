# Tutoriel : auditer et corriger un projet externe

Ce guide s'adresse à un développeur qui crée son projet dans un répertoire local puis appelle Compliance Platform depuis son installation ou via son extension VS Code. La plateforme audite la conformité du code, identifie les non-conformités, et vous permet d'itérer jusqu'à l'obtention d'un verdict conforme. Elle ne réécrit pas automatiquement vos fichiers métier.

---

## 1. Audit dans VS Code (Recommandé)

L'extension VS Code pilote l'audit au moyen du démon local autonome Go, garantissant une réactivité immédiate sans latence de démarrage et sans exécution de scripts PowerShell sous le capot.

### Installation et Démarrage de l'Extension

Depuis la racine de la plateforme (ou en installant le package VSIX) :

```bash
# Installation des dépendances et compilation
cd vscode-extension
npm install
npm run compile

# Lancement de VS Code en mode développement
code --new-window --extensionDevelopmentPath="./vscode-extension" .
```

*Alternative avec le VSIX autonome packagé :*
```bash
npm run package
code --install-extension dist/compliance-local-pipelines-0.1.0.vsix
```

### Parcours utilisateur dans l'éditeur

1. **Approbation de l'Espace de Travail** :
   - Au démarrage, VS Code ou l'extension peut vous demander d'approuver le workspace. Le démon local exige cette confirmation pour garantir qu'aucune opération n'est initiée sur un dossier non maîtrisé.
2. **Sélection de la Cible (Target)** :
   - Ouvrez la palette de commandes (`Ctrl+Shift+P` ou `F1`) et exécutez :  
     `Compliance: Selectionner une Target`
   - Sélectionnez le répertoire du projet à auditer.
3. **Préparation & Découverte** :
   - L'extension invoque le démon local (`POST /api/v1/discovery` puis `POST /api/v1/plans`).
   - La vue **Compliance Pipelines** dans l'Explorateur affiche la cible, les technologies détectées, les racines analysées et les contrôles applicables ordonnés par le plan d'exécution.
   - Les contrôles `Pending` attendent le lancement ; les étapes indisponibles ou non applicables explicitent leur motif dans une infobulle dédiée.
4. **Lancement de l'Audit** :
   - Cliquez sur l'icône de lecture dans la vue ou lancez `Compliance: Lancer l'audit`.
   - Si certains contrôles nécessitent un accès réseau ou une exécution de code (ex. tests unitaires ou Checkov), une boîte de dialogue modale sollicite explicitement votre accord. Un refus place ces contrôles dans l'état `Skipped` (`permission_denied`) sans bloquer le reste de l'audit.
   - La progression s'affiche en temps réel via Server-Sent Events (SSE) : passage de `Pending` à `Running`, puis aux états terminaux (`Succeeded`, `Failed`, `Error`, `Skipped`).
5. **Exploration du Rapport et Navigation dans les Findings** :
   - À l'issue de l'audit, le lecteur de rapport interactif s'ouvre automatiquement.
   - Vous disposez d'une synthèse du verdict (`PASS`, `FAIL`), du taux de couverture, et de la liste détaillée des constats (*findings*).
   - Cliquer sur un finding contenant un chemin et une position ouvre directement le fichier incriminé à la bonne ligne.
   - Vous pouvez également afficher les sorties brutes (`Compliance: Ouvrir les sorties du controle`) ou le document JSON canonique (`Compliance: Ouvrir le JSON brut`).

---

## 2. Audit en Ligne de Commande (CLI Go autonome)

Le moteur Go autonome peut être invoqué directement depuis n'importe quel shell (PowerShell, Command Prompt, Bash) sans nécessiter VS Code.

### Commandes Fondamentales

Assurez-vous que l'exécutable `compliance` est disponible (dans `.tools/bin/compliance.exe` ou dans votre `PATH`) :

```bash
# Vérifier la validité de l'installation et du démon
compliance selftest
```

### Étape 1 : Découverte des technologies

Identifie les technologies, les cadres applicatifs et les répertoires d'intérêt de votre projet cible :

```bash
compliance discovery -repo "/chemin/du/projet"
```
*Sortie : JSON structuré listant les langages, outils préconisés et erreurs éventuelles de scan.*

### Étape 2 : Prévisualisation du plan d'audit

Affiche les contrôles ordonnancés (graphe acyclique orienté / DAG) sans rien exécuter :

```bash
compliance run -repo "/chemin/du/projet" -plan-only
```
*Le rapport généré contient les contrôles applicables, les motifs d'omission et les permissions requises, sans verdict d'audit.*

### Étape 3 : Exécution complète de l'audit

Lancer l'audit de conformité :

```bash
# Audit standard (sans autorisations spéciales)
compliance run -repo "/chemin/du/projet" -report "reports/mon-projet-audit.json"
```

Pour les projets nécessitant des contrôles dynamiques ou des vérifications d'infrastructures étendues (ex: Checkov, tests Python) :

```bash
# Audit avec autorisation explicite d'exécution de code et d'accès réseau
compliance run -repo "/chemin/du/projet" -allow-code -allow-network -report "reports/mon-projet-audit.json"
```

---

## 3. Analyse du Rapport et Traitement des Écarts

Le rapport généré est strictement conforme au schéma JSON v1 (`.config/compliance-report.schema.json`).

### Structure du Rapport

```json
{
  "version": "1.0.0",
  "source_adapter": "Go",
  "verdict": "fail",
  "summary": { "passed": 18, "failed": 2, "skipped": 4, "error": 0 },
  "coverage": { "percentage": 90.0, "complete": false },
  "findings": [
    {
      "control_id": "python.lint.ruff",
      "severity": "medium",
      "status": "fail",
      "message": "F401 'os' imported but unused",
      "file_path": "src/app.py",
      "line": 3
    }
  ]
}
```

### Guide de Décision

| Statut du Contrôle | Signification | Action Requise |
| :--- | :--- | :--- |
| `fail` | Non-conformité détectée dans le projet. | Corriger le fichier selon les indications du diagnostic ou finding. |
| `error` | Échec technique (ex. binaire défaillant, timeout, corruption). | Analyser les logs d'exécution du contrôle avant de modifier le code cible. |
| `skipped` | Contrôle ignoré (technologie absente ou permission refusée). | Vérifier si l'omission est normale ou si une autorisation manquait (`-allow-code`). |
| `PASS` avec couverture partielle | Les contrôles exécutés ont réussi, mais certains contrôles applicables ont été omis. | Ne pas considérer le projet comme 100 % conforme ; réexaminer les contrôles omis. |

### Codes de Sortie CLI

- `0` : Succès (`verdict: pass`) ou plan simulé valide.
- `1` : Non-conformité (`verdict: fail`).
- `2` : Erreur d'initialisation, scan incomplet ou défaillance critique.

---

## 4. Cycle d'Itération et Correction

1. **Isolation des modifications** : Travaillez sur une branche Git dédiée.
2. **Correction chirurgicale** : Corrigez précisément les écarts identifiés par les linters et scanners sans relâcher les règles de sécurité.
3. **Ré-audit immédiat** :
   ```bash
   compliance run -repo "/chemin/du/projet" -report "reports/mon-projet-post-fix.json"
   ```
4. **Comparaison** : Vérifiez que le nombre de `failed` diminue sans apparition d'`error`. Le verdict final doit atteindre `pass` avec une couverture complète.
