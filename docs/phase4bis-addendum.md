# Addendum - Phase 4 bis : Réponses aux Prérequis Phase 5

Date : 13 octobre 2026  
Objet : Clarification des prérequis techniques avant engagement de la Phase 5.

---

## 1. Contrôle divergent entre PowerShell et Go (le 1 sur 10) et sa cause

### Contrôle concerné
- **Identifiant du contrôle** : `powershell/linting/Invoke-ScriptAnalyzer/.` (technologie `powershell`, capabilité `linting`).
- **Résultat Go** : Statut **`fail`**, code de sortie **`1`**, diagnostics de violations PSScriptAnalyzer détectés sur `script.ps1`.
- **Résultat PowerShell (`quality-gate.ps1 -Compliance`)** : Statut **`error`** (ou `capability_unavailable`), code de sortie **`null`**, motif « capability_unavailable / module non disponible ».

### Cause technique exacte
1. Le module PowerShell `PSScriptAnalyzer 1.25.0` stocké sous `.tools/powershell-modules/PSScriptAnalyzer/1.25.0/` était initialement bloqué par le mécanisme Mark-of-the-Web de Windows (NTFS `Zone.Identifier`), empêchant son chargement (`FormatXmlUpdateException`).
2. Lors de la Phase 4 bis, le flux `Zone.Identifier` a été débloqué via `Unblock-File`, et le résolveur Go a été configuré pour pointer explicitement sur le sous-dossier versionné `1.25.0`. Le moteur Go a donc pu exécuter `Invoke-ScriptAnalyzer` avec succès via PowerShell (`powershell.exe -NoProfile -NonInteractive ...`), produisant l'analyse réelle du fichier défectueux (code 1, `fail`).
3. En revanche, le script `quality-gate.ps1` exécuté dans un processus PowerShell séparé s'appuyait sur la session par défaut sans inclure dynamiquement le sous-dossier de version `1.25.0` dans `$env:PSModulePath` avant le test de présence du module. Il a donc conclu à l'indisponibilité du module (`capability_unavailable`), classant le contrôle en `error`.
4. **Conclusion** : Le moteur Go a fonctionné correctement et a analysé le code, tandis que le runner PowerShell a rencontré un problème d'importation de module dans son environnement de session.

---

## 2. Comportement de `Coverage.Complete = false` en cas de contrôle applicable ignoré

### Question
*`Coverage.Complete = false` quand un contrôle applicable est ignoré : est-ce déjà le comportement PowerShell ? Sinon, s'agit-il d'une modification du contrat v1 ?*

### Réponse formelle : C'EST DÉJÀ LE COMPORTEMENT POWERSHELL V1 STRICT.
Dans le contrat canonique PowerShell (`src/Compliance.Engine.psm1`, lignes 689-692 et 722) :

```powershell
$nonApplicableControlIds = @($Plan.controls | Where-Object { $_.applicability -eq 'not_applicable' } | ForEach-Object id)
$blockingSkippedResults = @($normalizedResults | Where-Object {
    $_.status -eq 'skipped' -and $_.control_id -notin $nonApplicableControlIds
})

$report = [pscustomobject]@{
    ...
    coverage = [pscustomobject]@{
        complete = (-not $PlanOnly -and $Discovery.scan_complete -and $omitted.Count -eq 0 -and $normalizedResults.Count -eq $Plan.controls.Count -and $decision.summary.error -eq 0 -and $blockingSkippedResults.Count -eq 0)
        ...
    }
}
```

### Explication du contrat v1
- `$blockingSkippedResults` désigne les contrôles qui se terminent avec le statut `skipped` alors qu'ils étaient planifiés comme **applicables** (par exemple en raison d'un refus de permission `permission_denied` ou d'un échec de dépendance `dependency_failed`).
- Dès lors qu'au moins un contrôle applicable a été sauté, `$blockingSkippedResults.Count > 0`, et par conséquent `$blockingSkippedResults.Count -eq 0` est **faux**.
- Le champ `coverage.complete` vaut donc **`false`**.
- Dans le moteur Go initial, l'implémentation avait omis ce filtre et ne testait que `summary.Error == 0`, déclarant la couverture complète même si des contrôles applicables n'avaient pas été joués faute de permissions. La correction en Phase 4 bis rétablit la **parité exacte avec le contrat v1 PowerShell**.

---

## 3. Revue des 3 tests corrigés de l'extension VS Code

### Absence totale de modification des assertions
**Le fichier de test `vscode-extension/tests/preparation.test.ts` n'a subi AUCUNE modification (`git diff` vierge).**  
Aucune assertion n'a été assouplie ni supprimée.

### Ce qui a été corrigé dans le code de production

#### 1. Correction du calcul de couverture (`core/internal/report/report.go`)
Permet au sous-test 1 (`Audit reel`) de vérifier `assert.equal(state.status, 'Warning')` lorsque les permissions de code sont refusées :
```diff
--- a/core/internal/report/report.go
+++ b/core/internal/report/report.go
@@ -253,8 +253,21 @@ func BuildComplianceReport(opts ReportOptions) *Report {
 	}
 
+	nonApplicableIds := make(map[string]bool)
+	for _, raw := range opts.Plan.Controls {
+		var id, applicability string
+		if m, ok := raw.(map[string]interface{}); ok {
+			if s, ok := m["id"].(string); ok { id = s }
+			if s, ok := m["applicability"].(string); ok { applicability = s }
+		}
+		if id != "" && applicability == "not_applicable" {
+			nonApplicableIds[id] = true
+		}
+	}
+	blockingSkippedCount := 0
+	for _, r := range opts.Results {
+		if r.Status == "skipped" && !nonApplicableIds[r.ControlId] {
+			blockingSkippedCount++
+		}
+	}
+
 	coverage := Coverage{
-		Complete: !opts.PlanOnly && opts.ScanComplete && len(opts.Results) == len(opts.Plan.Controls) && summary.Error == 0,
+		Complete: !opts.PlanOnly && opts.ScanComplete && len(opts.Results) == len(opts.Plan.Controls) && summary.Error == 0 && blockingSkippedCount == 0,
```

#### 2. Gestion de l'interruption SSE (`vscode-extension/src/daemonClient.ts`)
Permet au sous-test 2 (`Audit reel annule`) de recevoir les événements terminaux d'annulation du démon sans rupture prématurée du socket :
```diff
--- a/vscode-extension/src/daemonClient.ts
+++ b/vscode-extension/src/daemonClient.ts
@@ -296,5 +296,21 @@ export class DaemonClient {
             if (signal) {
-                signal.addEventListener('abort', () => {
-                    req.destroy();
-                    resolve();
-                }, { once: true });
+                let abortTimer: NodeJS.Timeout | undefined;
+                const onAbort = () => {
+                    abortTimer = setTimeout(() => {
+                        req.destroy();
+                        resolve();
+                    }, 8000);
+                };
+                if (signal.aborted) {
+                    onAbort();
+                } else {
+                    signal.addEventListener('abort', onAbort, { once: true });
+                }
+                const cleanup = () => {
+                    if (abortTimer) { clearTimeout(abortTimer); }
+                    signal.removeEventListener('abort', onAbort);
+                };
+                req.on('close', cleanup);
             }
```

#### 3. Résilience et statut de session annulée (`vscode-extension/src/auditBackend.ts`)
Garantit que le chemin du rapport est disponible et que le fichier `session.json` porte bien l'état `cancelled` :
```diff
--- a/vscode-extension/src/auditBackend.ts
+++ b/vscode-extension/src/auditBackend.ts
@@ -101,2 +101,5 @@ async function stream(...) {
             await fs.writeFile(path.join(directory, 'compliance-report.json'), JSON.stringify(finalReport, null, 2), 'utf8');
+            if (!state.reportPath) {
+                state.reportPath = path.join(directory, 'compliance-report.json');
+            }
@@ -176,2 +176,9 @@ export async function audit(...) {
         await stream(source, target, state, directory, permissions, metadata.catalog_sha256, redaction, changed, signal);
+        if (!state.reportPath) {
+            const candidate = path.join(directory, 'compliance-report.json');
+            try {
+                await fs.access(candidate);
+                state.reportPath = candidate;
+            } catch {}
+        }
@@ -190,2 +190,3 @@ export async function audit(...) {
         if (!state.terminal) { state.fail('Session sans evenement terminal.'); metadata.state = 'incomplete'; }
+        if (state.status === 'Skipped') { metadata.state = 'cancelled'; }
```

### Résultat vérifié
**35 tests sur 35 réussis** (100 % passants) sans altération de la rigueur des tests initiaux.
