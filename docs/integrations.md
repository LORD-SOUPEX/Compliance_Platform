# Integrations optionnelles

## Contrat commun v1

Les lanceurs PowerShell, Bash, VS Code et GitLab utilisent `scripts/compliance-adapter.ps1`; Bash appelle le même wrapper. `src/Compliance.Adapter.psm1` construit le contrat local:

```json
{
  "schema_version": 1,
  "adapter": "VSCode",
  "repository": "<chemin local>",
  "report_path": null,
  "mode": "Compliance",
  "plan_only": false,
  "permissions": { "network": false, "code_execution": false },
  "presentation": { "human_summary": false },
  "source_transmitted": false,
  "secrets_transmitted": false
}
```

Le contrat exige un dossier local existant; il refuse les URI de rapport distantes. Les chemins source et secrets ne sont pas envoyés à un service central. Les outils peuvent toutefois accéder aux données du dépôt selon les permissions explicites. La sortie et les diagnostics sont écrits localement dans `reports/compliance-report.json` par défaut.

## Lanceurs

| Adaptateur | Lancement | Compatibilité vérifiée | Résultat |
| --- | --- | --- | --- |
| PowerShell | `scripts/compliance-adapter.ps1 -Adapter PowerShell -RepositoryPath <chemin>` | Windows x64, PowerShell 5.1; statut produit experimental | Code moteur et rapport v1 |
| Bash | `scripts/compliance.sh -RepositoryPath <chemin>` | Git Bash sous Windows avec `powershell.exe` | Relais vers PowerShell, rapport v1 |
| VS Code | Tâche `Compliance v1` | Tâche locale invoquée en fixture Windows; expérience UI non qualifiée | Même contrat; résumé humain sur stderr |
| GitLab | Job `compliance-report` | Configuration YAML validée; runner distant non exécuté | Rapport artifact, verdict non bloquant |

Le script Bash peut trouver `pwsh`, mais cela ne qualifie pas le moteur natif Linux/macOS: chemins d'outils, runtime, intégrité et contrôles ne sont pas vérifiés sur ces systèmes. Windows x64 reste experimental dans la matrice de qualification produit.

## Permissions GitLab

Le job GitLab informatif ne s'exécute que si `COMPLIANCE_ADAPTER_ENABLED` vaut exactement `true`. Il a `allow_failure: true`; un verdict `FAIL` est aussi converti en code de succès par l'adaptateur GitLab. Les erreurs techniques restent visibles dans le rapport et gardent un code distinct, mais ne bloquent pas le pipeline par ce job optionnel.

Par défaut, réseau et exécution de code sont refusés. Pour autoriser les capacités correspondantes dans ce job, configurer explicitement `COMPLIANCE_ALLOW_NETWORK=true` ou `COMPLIANCE_ALLOW_CODE_EXECUTION=true`. Checkov exige les deux. Ces variables ne sont pas des secrets. Le job bootstrappe son propre runner et conserve `reports/compliance-report.json` comme artifact sept jours. Cette rétention CI n'est pas une politique de rétention locale.

Le job historique `quality-gate` conserve son comportement et peut échouer indépendamment; l'adaptateur facultatif n'en modifie ni les règles, ni les protections de branche, ni les opérations Git.

## Limites

Les quatre contrats et wrappers sont testés en fixtures; Git Bash a été exécuté sur Windows. Aucun pipeline GitLab distant, véritable workspace UI VS Code ni dépôt consommateur autorisé n'a été qualifié. Les mesures faites sur fixtures ne démontrent pas le comportement de dépôts réels. L'adaptateur n'envoie ni sources ni secrets à une API, et ne publie que l'artifact local configuré par GitLab. Les permissions autorisent des processus dans le dépôt sans sandbox; les contributions non fiables exigent un runner isolé. Toute extension à une nouvelle plateforme ou forge demande une qualification propre.
