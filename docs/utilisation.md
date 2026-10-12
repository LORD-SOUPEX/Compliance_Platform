# Tutoriel : auditer et corriger un projet externe

Ce guide s'adresse à un développeur qui crée son projet dans un dossier puis appelle Compliance Platform depuis une installation séparée. La plateforme identifie des problèmes; vous appliquez les corrections et relancez l'audit. Elle ne réécrit pas automatiquement un projet en mode Compliance.

## Audit VS Code (MVP local)

Après Bootstrap de la plateforme, depuis sa racine sous Windows x64 :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Install
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Build
code --new-window --extensionDevelopmentPath="$((Resolve-Path .\vscode-extension).Path)" "$PWD"
```

Dans le nouveau host, traiter d'abord l'écran d'initiation s'il apparaît : choisir ou conserver le thème, puis fermer l'onglet de prise en main. Approuver ensuite le workspace, sans confondre cette approbation avec les permissions d'audit. Lancer `Compliance: Selectionner une Target` dans la palette de commandes. Choisir un dossier externe de confiance et confirmer sa préparation. La vue `Compliance Pipelines` de l'Explorateur affiche séparément Target, Pipeline source, technologies, racines et contrôles proposés. `Pending` ne signifie pas qu'un contrôle a été exécuté ; les étapes indisponibles ou non applicables portent leur motif dans l'infobulle. Les ambiguïtés et scans incomplets restent bloqués.

Lancer `Compliance: Lancer l'audit` depuis la palette ou le bouton de la vue. La commande exige une préparation complète, un runtime valide, un workspace approuvé et la Target confirmée ; une seule session peut être active. Le lancement revalide les dossiers, refait la préparation et propose uniquement les permissions nécessaires au plan : réseau et exécution de code sont indépendants, refusés par défaut et limités à cette session. Chaque dialogue liste les contrôles, technologies, racines et effets ; ces autorisations ne constituent pas un sandbox. Un refus donne `Skipped` avec le motif `permission_denied`, sans exécuter le contrôle protégé. Checkov conserve les exigences du catalogue.

La TreeView affiche les contrôles `Pending`, puis `Running` avec durée écoulée, et les états terminaux `Succeeded`, `Failed`, `Error`, `Warning`, `Skipped`, `Blocked` ou `Not applicable`. `Failed` signifie un défaut détecté ; `Error` signifie un résultat techniquement non fiable. Les états d'omission, blocage et avertissement portent un motif structuré dans l'infobulle. La durée finale provient du moteur ; l'affichage du temps en cours est rafraîchi au maximum une fois par seconde. Une couverture partielle n'est pas présentée comme un succès complet.

Cliquer sur la session finalisée, une pipeline ou un contrôle terminé ouvre ou focalise sa section du lecteur. L'action `Compliance: Ouvrir les sorties du controle` reste disponible : stdout, stderr et diagnostics s'ouvrent en texte brut, identifiés par session et contrôle. Les sorties deviennent accessibles à la fin du contrôle ; le streaming ligne par ligne n'est pas garanti. `Compliance: Ouvrir les messages de session` affiche le canal général et `Compliance: Ouvrir le dossier de la session` révèle les fichiers locaux. Le paramètre VS Code `compliance.reportRedactionPatterns` transmet des motifs de masquage au backend ; les rapports restent à relire avant partage.

Le lecteur s'ouvre automatiquement après validation du rapport final. Son en-tête identifie session, Target, source, dates et catalogue ; résumé, verdict, couverture, omissions et limitations restent distincts. Les contrôles sont regroupés génériquement par technologie et racine, avec statut, durée, outil, diagnostics, findings et sorties. PASS avec couverture partielle garde un avertissement explicite ; `Failed` reste un défaut détecté, `Error` un résultat techniquement non fiable. Une session annulée reste incomplète. Les longs textes sont bornés à l'affichage ; les actions de sorties et de JSON brut donnent accès aux données validées.

`Compliance: Ouvrir le rapport de la derniere session` n'utilise que la référence connue, jamais le fichier le plus récent d'un dossier. `Compliance: Ouvrir un rapport existant` demande un JSON explicitement choisi, validé par le backend et présenté comme « Rapport historique : aucune session active associée ». Les v1 sans métriques ou hash modernes restent acceptés. `Compliance: Actualiser le rapport` recharge et revalide ; `Compliance: Ouvrir le JSON brut` affiche les octets validés dans un document JSON, sans rapport Markdown parallèle. Un rapport absent, vide, modifié, incohérent ou non pris en charge produit une erreur, pas une page vide ni un ancien résultat.

Après redémarrage, seule la référence de la dernière session valide est restaurée, comme historique ; aucune Target active, permission ou autorisation d'exécution n'est restaurée. Pour les findings, un bouton de navigation apparaît seulement si le backend fournit un fichier explicite, avec ligne/colonne uniquement si elles existent. Le chemin et ses liens de réanalyse sont vérifiés ; une sortie de la Target est refusée et aucune position n'est inventée. La navigation depuis un rapport historique exige une confirmation distincte, sans lancer de contrôle.

Les audits créent `.tools/state/runs/<run_id>/session.json`, `execution-plan.json`, `compliance-report.json`, `events.ndjson` et `logs/` dans la Pipeline source, ignorés par Git et Discovery. Le même `run_id` identifie la session, le snapshot, les événements et le rapport. Le snapshot est reconstruit par le backend avec les permissions accordées ; un catalogue modifié après consentement est refusé. Le rapport final est validé contre la session et ses résultats ; aucun ancien rapport n'est réutilisé. Les préparations seules conservent leur dossier technique propre sans verdict.

`Compliance: Annuler l'audit` demande l'arrêt coopératif au backend, termine l'arbre du contrôle actif et empêche les suivants. Les résultats déjà obtenus sont conservés ; les contrôles restants portent un motif d'annulation et le rapport reste incomplet avec FAIL, jamais PASS complet. La fermeture du host est détectée par absence de battement de vie après 15 secondes ; un délai de secours de 10 secondes termine l'arbre backend si une annulation explicite reste sans réponse. Une disparition ou erreur de transport laisse une session `incomplete` et des preuves locales, sans promettre un rapport final exploitable.

`Compliance: Actualiser la preparation` invalide le plan précédent. Un changement de Target ou de catalogue/runtime invalide aussi préparation et consentements ; une sélection annulée conserve la Target. Les dossiers internes à la plateforme ou contenant celle-ci sont refusés. La préparation est limitée à 120 secondes et 32 Mio de sorties capturées ; les événements sont limités à 16 Mio et les contrôles conservent les budgets du moteur. Le lecteur refuse les rapports dépassant 32 Mio ou 5 000 contrôles planifiés, et les fichiers traversant des liens de réanalyse. Réseau et code autorisés ne garantissent pas l'absence d'effets de bord des outils. Les lancements par technologie/racine/étape, le streaming ligne par ligne et la publication Marketplace restent hors périmètre.

## 1. Préparer la plateforme une fois

Utiliser Windows x64 et Windows PowerShell 5.1. Les exemples emploient des chemins fictifs: remplacer les deux chemins suivants par les dossiers réels, en gardant les guillemets.

```powershell
$plateforme = (Resolve-Path "C:\outils\Compliance_Platform").Path
$projet = (Resolve-Path "C:\projets\mon-projet").Path
$gate = Join-Path $plateforme 'scripts\quality-gate.ps1'
```

Le dossier projet doit déjà exister et contenir vos fichiers. Il n'a pas besoin d'intégrer la plateforme, ses outils ou ses hooks. Ces variables restent disponibles dans le terminal PowerShell courant; les redéfinir si vous ouvrez un nouveau terminal.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $plateforme 'scripts\bootstrap.ps1')
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $plateforme 'scripts\doctor.ps1') -NoColor
```

Bootstrap est réservé à l'installation/mise à jour, pas à chaque audit. Il installe les hooks dans le dépôt plateforme uniquement. `-Offline` ne fonctionne qu'avec les artefacts requis déjà en cache. En cas d'échec Doctor, résoudre l'installation avant d'interpréter les résultats du projet; voir [Maintenance](maintenance.md).

## 2. Détecter les technologies du projet

Les commandes suivantes peuvent être lancées depuis n'importe quel dossier: `$gate` et `$projet` sont des chemins absolus.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -DiscoveryOnly -RepositoryPath $projet -ReportPath 'mon-projet-discovery.json'
$codeDiscovery = $LASTEXITCODE
```

Le JSON est affiché dans le terminal et enregistré dans `reports/mon-projet-discovery.json` sous la plateforme. Examiner les technologies, preuves et racines. Une ambiguïté `.tf` Terraform/OpenTofu ou `hosts:` Ansible ne doit pas être interprétée comme un outil absent ni comme une conformité. Un projet vide ne donne aucune couverture utile. Les fichiers générés/caches sont exclus.

Discovery ne lance pas les contrôles, mais peut vérifier la disponibilité des outils avec des sondes de version. Code 2 signifie que le scan est incomplet ou qu'une erreur de préparation est survenue; lire `scan_errors` lorsqu'ils sont présents.

## 3. Examiner le plan avant l'audit

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -Compliance -PlanOnly -RepositoryPath $projet -ReportPath 'mon-projet-plan.json' -HumanSummary
```

Le rapport est sous `reports/mon-projet-plan.json`. Aucun contrôle n'est exécuté et `verdict` reste nul. Examiner `execution_plan.controls`, leurs racines, applicabilité et motifs d'omission. Certaines technologies détectées n'ont pas d'outil configuré (JavaScript/TypeScript), et ShellCheck n'est pas fourni sous Windows.

Si vous envisagez un audit avec permissions, vous pouvez prévisualiser le même plan en ajoutant `-AllowCodeExecution` et/ou `-AllowNetwork` avec `-PlanOnly`, sans exécuter les contrôles.

## 4. Lancer un premier audit

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -Compliance -RepositoryPath $projet -ReportPath 'mon-projet-audit.json' -HumanSummary
$codeAudit = $LASTEXITCODE
```

Les contrôles soumis à une permission sont omis par défaut; vérifier la couverture, même en cas de PASS. Pour un projet de confiance, autoriser ensuite explicitement les contrôles nécessaires:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -Compliance -RepositoryPath $projet -AllowCodeExecution -ReportPath 'mon-projet-audit.json' -HumanSummary
$codeAudit = $LASTEXITCODE
```

`-AllowCodeExecution` autorise notamment tests, Pylint, plugins/configurations chargées et Markdown via pre-commit. Ces processus ne sont pas isolés et peuvent avoir des effets de bord. Si l'audit exige aussi un accès réseau et que vous l'approuvez, utiliser:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -Compliance -RepositoryPath $projet -AllowCodeExecution -AllowNetwork -ReportPath 'mon-projet-audit.json' -HumanSummary
$codeAudit = $LASTEXITCODE
```

Checkov demande les deux autorisations. Ne les accorder ni automatiquement ni pour un dépôt inconnu. Aucun consentement ne rend disponibles des outils absents ou incompatibles.

## 5. Lire le rapport et prioriser les corrections

```powershell
$rapportPath = Join-Path $plateforme 'reports\mon-projet-audit.json'
$rapport = Get-Content -LiteralPath $rapportPath -Raw -Encoding UTF8 | ConvertFrom-Json
$rapport.verdict
$rapport.summary
$rapport.coverage
$rapport.findings | Select-Object control_id, severity, status, root
$rapport.execution_results | Select-Object control_id, status, exit_code, stderr
```

Dans VS Code, ouvrir le fichier JSON puis rechercher le `control_id` concerné pour lire stdout, stderr et diagnostics. Les rapports peuvent contenir des chemins ou données sensibles; les relire avant partage.

| Résultat | Action |
| --- | --- |
| `fail` | Un contrôle exécuté a relevé un problème; corriger les fichiers selon son diagnostic. |
| `error` | Examiner outil manquant, incompatibilité, timeout, intégrité ou scan incomplet avant de modifier le code du projet. |
| `skipped` | Lire le motif: technologie absente, alternative non retenue ou permission non accordée; ce n'est pas une réussite du contrôle. |
| PASS avec couverture partielle | Ne pas conclure que tout le projet est conforme; examiner les contrôles requis omis. |

Le code Compliance vaut 0 pour PASS ou plan seul valide, 1 pour FAIL et 2 pour scan/préparation incomplets. Une entrée invalide ou une impossibilité d'écrire peut empêcher la création du rapport: vérifier aussi le terminal et son code de sortie.

## 6. Corriger puis refaire exactement le même audit

Conserver vos changements dans Git ou une sauvegarde avant toute correction. Par exemple, corriger les espaces/formatages indiqués par Ruff dans un fichier Python, la syntaxe d'un script PowerShell ou un défaut documentaire signalé. Un diagnostic doit déterminer la modification, pas seulement le verdict global.

Demander éventuellement à votre assistant de développement: « Corrige le finding de ce contrôle dans ce fichier, sans désactiver la règle ni supprimer le test, puis relance le même audit ». Ne lui transmettre que les extraits nécessaires, expurgés de secrets.

Après correction, reprendre la commande de l'étape 4 avec les mêmes permissions et une autre destination pour conserver la comparaison:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $gate -Compliance -RepositoryPath $projet -ReportPath 'mon-projet-apres-corrections.json' -HumanSummary
$codeApres = $LASTEXITCODE
```

Si le premier audit utilisait des permissions, les ajouter également à cette commande. Comparer findings et couverture, pas seulement le nombre de PASS. Le moteur ne bloque ni commit ni push ni merge.

## Ce qu'il ne faut pas confondre

- `Quick`/`Full` servent les contrôles historiques du socle; Full audite les dépendances de la plateforme et lance ses tests, pas un audit complet de votre projet.
- `-Mode Fix` est un mode historique à effets de bord, incompatible avec `-Compliance`. Il n'est pas recommandé comme correcteur générique d'un projet externe.
- Un formatage ou une correction métier nécessite une modification ciblée de votre code; Compliance ne dispose pas d'un bouton « tout corriger ».
- Python: l'audit consommateur des dépendances exige `requirements.txt`; la présence d'un pyproject seul ne suffit pas à ce contrôle.
- Terraform/OpenTofu: un `.tf` seul est ambigu. Utiliser les marqueurs réellement appropriés au projet; ne pas en ajouter uniquement pour obtenir PASS.
- La tâche VS Code `Compliance v1` fournie dans la plateforme cible son propre workspace. Pour votre projet externe, les commandes ci-dessus sont le point d'entrée explicite.

## Où aller ensuite

- [Architecture et contrats](architecture-current.md): technologies, résultats, permissions et limites.
- [Maintenance et qualification](maintenance.md): installation, mises à jour, tests et sécurité du runtime.
