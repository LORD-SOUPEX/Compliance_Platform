# ICP - IaC Compliance Platform

Audit local d'un dépôt. L'extension parle à un démon Go sur `127.0.0.1`. Aucun compte, aucune forge et aucun envoi du code. Version courante : 2.0.14.

## Architecture de la plateforme

| Étape | Rôle |
| --- | --- |
| Target | Dossier local à auditer |
| Discovery | Technologies, racines et preuves |
| Matrix | Contrôles du catalogue qui s'appliquent |
| Resolver | Outils déjà présents sur la machine |
| Plan | Ordre d'exécution et autorisations |
| Engine | Exécution locale des contrôles |
| Report | Rapport JSON, verdict et findings |

- Le démon écoute sur `127.0.0.1`, port éphémère, jeton Bearer.
- L'extension parle au démon en HTTP et en SSE.
- Le schéma Mermaid du même parcours est dans le README du dépôt et dans `docs/architecture.md`. La page Détails de VS Code ne l'affiche pas.

## À quoi elle sert

Elle détecte les technologies d'un dossier cible, exécute les contrôles du catalogue qui s'appliquent, et affiche un rapport : verdict, couverture par technologie, findings, outils manquants. Le verdict est consultatif.

## Pour qui

Développeurs et évaluateurs qui veulent un contrôle local sur un projet Terraform, conteneur, Python, JavaScript, TypeScript, Markdown ou un mélange de ces piles, sans installer une chaîne CI.

## Comment c'est fait

- Démon Go local, port éphémère, jeton Bearer. L'extension le démarre et le compare à sa version ; un démon plus ancien est arrêté.
- Catalogue embarqué (`.config/control-catalog.json`) et manifeste d'outils (`.config/runtime-manifest.json`). Une signature absente ou différente n'empêche pas l'installation.
- Le code de la cible n'est pas transmis. Les outils s'exécutent sur la machine, dans la limite des autorisations données pour la session.

## Contrôles

ESLint et `tsc` viennent du `node_modules` de la cible. Sans `npm install` ou sans configuration ESLint, le contrôle n'est pas un succès. Terraform et les autres outils de répertoire restent un contrôle par racine. Le rapport les présente dans une carte par outil : chaque sous-dossier a son statut, sa durée et son nombre d'anomalies, puis se déroule vers les fichiers et leurs lignes. Checkov, TFLint, ShellCheck, Trivy et `terraform fmt` exposent la règle, le fichier, la ligne et le message. Une technologie exécutée sur au moins une racine n'est pas répétée dans les contrôles non applicables. `rumdl check` lint le Markdown. Sans fichier de configuration Markdown dans le dépôt, MD013 (longueur de ligne) est désactivée. Si `.rumdl.toml`, `.markdownlint.json` ou un équivalent est présent, cette règle reste active. `pytest` qui se termine avec le code 5 (aucun test collecté) est un succès, avec le diagnostic `no_tests_collected`. Pylint reçoit le `.pylintrc` ou le `pyproject.toml` à la racine du dépôt lorsqu'il en existe un. Ruff, Pylint, Bandit, pytest, pip-audit et yamllint produisent aussi un fichier, une ligne, une règle et un message. Un chemin d'anomalie qui commence par `/` ou `\` est rattaché au dossier du contrôle, puis à la racine de la Target. Sur Windows, `ansible-lint` n'est pas proposé à l'installation : il reste réservé à Linux et macOS, et `yamllint` couvre les playbooks. Les listes de fichiers (ShellCheck, Hadolint, Ruff, Pylint, Bandit) sont découpées pour rester sous la limite de ligne de commande. La découverte Docker reconnaît `Dockerfile`, `Dockerfile.*`, `Containerfile` et les noms `*.Dockerfile`, y compris dans un sous-dossier. Ces noms restent une preuve pour Hadolint et Trivy lorsque l'échantillon de fichiers est tronqué. Le canal Output ne remet pas une technologie dans `ignorés (technologie absente)` si un contrôle de cette technologie vient de s'exécuter, et il n'inscrit `indisponible` que pour les mêmes codes que le compteur du rapport. Un plan rejeté au lancement nomme le contrôle, la racine et la raison.

<!-- catalog-controls:start -->
| Identifiant | Technologie | Outil |
| --- | --- | --- |
| terraform.format.terraform | terraform | terraform |
| terraform.lint.tflint | terraform | tflint |
| terraform.security.checkov | terraform | checkov |
| opentofu.format.tofu | opentofu | tofu |
| opentofu.lint.tflint | opentofu | tflint |
| opentofu.security.checkov | opentofu | checkov |
| terragrunt.format.terragrunt | terragrunt | terragrunt |
| ansible.lint.ansible-lint | ansible | ansible-lint |
| ansible.lint.yamllint | ansible | yamllint |
| python.format.ruff | python | ruff |
| python.lint.ruff | python | ruff |
| python.lint.pylint | python | pylint |
| python.test.pytest | python | pytest |
| python.security.bandit | python | bandit |
| python.dependencies.pip-audit | python | pip-audit |
| powershell.lint.psscriptanalyzer | powershell | Invoke-ScriptAnalyzer |
| docker.lint.hadolint | docker | hadolint |
| docker.security.trivy | docker | trivy |
| kubernetes.security.checkov | kubernetes | checkov |
| kubernetes.security.trivy | kubernetes | trivy |
| kubernetes.policy.checkov | kubernetes | checkov |
| helm.security.checkov | helm | checkov |
| helm.security.trivy | helm | trivy |
| helm.policy.checkov | helm | checkov |
| shell.lint.shellcheck | shell | shellcheck |
| javascript.lint.eslint | javascript | eslint |
| javascript.security.gitleaks | javascript | gitleaks |
| typescript.lint.eslint | typescript | eslint |
| typescript.check.tsc | typescript | tsc |
| markdown.lint.rumdl | markdown | rumdl |
<!-- catalog-controls:end -->

## Démarrage

1. Installez le VSIX. Le catalogue est dedans ; un clone Git n'est pas nécessaire.
2. Ouvrez la vue **Compliance Pipelines**.
3. **ICP: Sélectionner la cible à auditer**. La cible doit être un dossier distinct de l'extension.
4. **ICP: Lancer l'audit de la cible**. Le rapport s'ouvre à la fin.

La découverte ignore `.git`, `.vscode`, `.vscode-test`, `.rumdl_cache`, `node_modules`, `.terraform`, `venv`, `.venv`, `.tools`, `dist`, `build`, `vendor`, `__pycache__`, `testdata`, `fixtures`, `__snapshots__`, plus `.gitignore`, `.complianceignore` et `COMPLIANCE_DISCOVERY_EXCLUDE`. Ces dossiers ne deviennent pas des racines. Gitleaks, lancé avec `--no-git`, reprend la même liste et ignore aussi les fichiers `.vsix`, `.exe`, `.dll`, `.pdb`, `.pyc` et `.zip`.

## Commandes

| Commande | Effet |
| --- | --- |
| ICP: Sélectionner la cible à auditer | Choisit le dossier à auditer et lance la préparation. |
| ICP: Recalculer la découverte et le plan | Relit la cible sans exécuter les contrôles. |
| ICP: Lancer l'audit de la cible | Demande les autorisations manquantes, exécute le plan, ouvre le rapport. |
| ICP: Annuler l'audit en cours | Arrête le run et les processus du contrôle en cours. |
| ICP: Ouvrir le rapport de la dernière session | Rouvre le rapport de la session courante ou de la dernière session connue. |
| ICP: Ouvrir un rapport JSON existant | Charge un `compliance-report.json` local. |
| ICP: Recharger le rapport affiché | Relit le rapport de la session ouverte. |
| ICP: Ouvrir compliance-report.json | Ouvre le fichier de rapport dans l'éditeur. |
| ICP: Ouvrir les sorties du contrôle | Montre stdout et stderr du contrôle sélectionné dans l'arbre. |
| ICP: Ouvrir le dossier de session | Ouvre le dossier de la session dans l'explorateur du système. |
| ICP: Ouvrir le journal Output | Affiche le canal **Compliance** (durées, purge, contrôles). |

Dans le rapport : **Ouvrir un rapport…** choisit un `compliance-report.json` dans le dossier des sessions, **JSON brut** ouvre le fichier, **Dossier de session** ouvre le dossier. **Installer depuis le manifeste** télécharge les outils listés dans le manifeste. Chaque contrôle exécuté (réussi, échec ou erreur) a **Ouvrir les sorties**. **Ouvrir à la ligne** ouvre le fichier de l'anomalie, reconstitué depuis la racine du contrôle, à la ligne indiquée. Le bandeau utilise le logo `media/icon.png` et des icônes SVG, sans emoji.

## Autorisations

Réseau et exécution de code sont refusés tant que vous ne les accordez pas pour la session. Les contrôles qui en ont besoin restent non exécutés et apparaissent comme une lacune, pas comme un succès. Ce n'est pas un bac à sable.

## Outils

L'installation du VSIX ne télécharge pas les outils d'audit. Après un audit, si un outil figure dans le manifeste, l'extension peut le télécharger en HTTPS une fois que vous acceptez la liste (version et URL). L'archive est extraite sous `~/.compliance/tools`, sans droits administrateur. Une signature ou une somme SHA-256 différente ne bloque pas ce téléchargement. Un refus n'est pas redemandé tout seul. Une coupure réseau ou un proxy (`HTTP_PROXY` / `HTTPS_PROXY`) n'installe rien.

ESLint et `tsc` ne sont pas dans le manifeste : ils viennent du dépôt cible. `Invoke-ScriptAnalyzer` est un module PowerShell, pas une archive. `ansible-lint`, `yamllint`, `checkov` et les autres paquets Python s'installent dans `~/.compliance/tools/venv`. `rumdl` est le linter Markdown (MIT, binaires officiels) et s'installe depuis le manifeste sur les plateformes où l'éditeur publie un binaire. Pas de binaire Windows ARM64. Détail : `docs/outils.md`.

## Rapports et sessions

La couverture compte les technologies détectées, pas la taille du catalogue. Exemple : `Couverture partielle : 2 technologie(s) couverte(s) sur 3 détectée(s).` Les lacunes sont listées. Les contrôles des technologies absentes sont une liste statique, pas un bouton.

Le réglage d'application `compliance.maxSessions` conserve de 1 à 1000 sessions, 5 par défaut. Le moteur applique la valeur choisie dans cette plage. La purge tourne au début et à la fin d'un audit, journalisée dans le canal **Compliance**. Elle ne suit pas les liens, ne sort pas du dossier des runs, et ne supprime ni la session en cours ni le rapport ouvert.

- Extension installée : `~/.compliance/sessions/runs` (profil utilisateur Windows, `$HOME` sur Linux et macOS).
- Clone de développement : `<dépôt>/.tools/state/runs`.
- Remplacement : variable `COMPLIANCE_SESSIONS_DIR`.

## Plateformes

Seul **Windows x64** est qualifié (selftest exécuté ici). Les binaires Linux x64/arm64, Windows ARM64 et macOS Intel/Apple Silicon sont dans le VSIX ; leur statut est ciblé, pas qualifié, tant qu'un selftest n'a pas tourné sur la machine. `rumdl` 0.2.79 ne publie pas de binaire Windows ARM64.

## Confidentialité

Découverte, exécution et rapports restent sur la machine. Le seul téléchargement possible est celui d'un outil du manifeste, après accord, en HTTPS depuis l'URL déclarée. Le code audité n'est pas envoyé.
