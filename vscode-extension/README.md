# ICP - IaC Compliance Platform

Audit local d'un dépôt, depuis VS Code. Un démon Go sur la machine prépare le plan et exécute les contrôles. Aucun compte, aucun envoi du code.

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
- Le schéma Mermaid du même parcours est dans le README du dépôt.

## À quoi elle sert

Elle reconnaît les technologies d'un dossier, lance les contrôles qui s'appliquent et affiche un rapport : verdict, couverture, findings et outils manquants.

## Pour qui

Développeurs et évaluateurs qui veulent contrôler un projet Terraform, conteneur, Python, JavaScript, TypeScript ou Markdown, sans chaîne CI.

## Fonctionnalités clés

- 100 % local : découverte, exécution et rapport restent sur la machine.
- Démon Go lancé à la demande, arrêté avec l'extension.
- Couverture des technologies détectées, pas de la taille du catalogue.
- Le code audité n'est pas transmis. Un outil ne se télécharge qu'après accord.

## Stack et outils

**IaC & Cloud** — Terraform, OpenTofu, Terragrunt, TFLint, Checkov

**Conteneurs & orchestration** — Docker (Hadolint, Trivy) ; Kubernetes & Helm (Checkov, Trivy)

**Configuration & scripts** — Ansible (ansible-lint, yamllint) ; Shell (ShellCheck) ; PowerShell (PSScriptAnalyzer)

**Code & documentation** — Python (Ruff, Pylint, Bandit, Pytest, pip-audit) ; JS / TS (ESLint, tsc) ; Markdown (rumdl)

**Sécurité transverse** — Gitleaks, détection de secrets sans fuite en clair

## Démarrage rapide

1. Installez le VSIX et ouvrez la vue **Compliance Pipelines**.
2. **ICP: Sélectionner la cible à auditer**.
3. **ICP: Lancer l'audit de la cible**.
4. Lisez le rapport. **Ouvrir un rapport…** recharge un `compliance-report.json` déjà produit.

## Confidentialité et sécurité

Le démon n'écoute que sur `127.0.0.1`. Réseau et exécution de code restent refusés tant que vous ne les accordez pas pour la session. Les rapports restent dans le dossier de sessions de la machine.
