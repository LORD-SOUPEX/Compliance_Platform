# Tutoriel : auditer et corriger un projet externe

Ce guide s'adresse à un développeur qui crée son projet dans un dossier puis appelle Compliance Platform depuis une installation séparée. La plateforme identifie des problèmes; vous appliquez les corrections et relancez l'audit. Elle ne réécrit pas automatiquement un projet en mode Compliance.

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
