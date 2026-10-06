# Capability Matrix

La Capability Matrix est calculée dans `scripts/quality-gate.ps1` pour chaque technologie Discovery et la plateforme locale. Elle relie capacités, outils candidats et état de disponibilité; elle n'exécute aucun outil.

## Capacités actuelles

Les profils sont intégrés dans le script. Exemples de mappings présents:

| Technologie | Capacités déclarées | Outils candidats |
| --- | --- | --- |
| Terraform | formatting, linting, security | terraform, tflint, checkov |
| OpenTofu | formatting, linting, security | tofu, tflint, checkov |
| Terragrunt | formatting | terragrunt |
| Ansible | linting | ansible-lint, yamllint |
| Python | formatting, linting, testing, security, dependency audit | ruff, pylint, pytest, bandit, pip-audit |
| PowerShell | linting | PSScriptAnalyzer |
| Docker | linting, security | Hadolint, Trivy |
| Kubernetes/Helm | security, policy validation | Checkov, Trivy |
| Shell | linting | ShellCheck |
| JavaScript/TypeScript | linting | Aucun outil configuré; capacité `unconfigured` |
| Markdown | documentation | pre-commit, candidat nommé markdownlint |

## États

Les technologies restent `detected`, `ambiguous` ou `absent`. Chaque capacité expose `required`, `availability`, `candidate_tools`, `available_tools` et `reasons`. Disponibilités actuelles: `available`, `partially_available`, `unavailable`, `unconfigured`, `not_applicable`, `ambiguous`.

Chaque outil candidat porte notamment `status`, `source`, `version`, `runtime_managed`, `platform` et `reason`. Les etats observes comprennent `available`, `not_installed`, `incompatible`, `runtime_error` et `integrity_error`.

Une technologie absente rend ses capacités non applicables. Une technologie ambiguë n'a pas de capacités requises résolues. Une technologie détectée ne devient jamais absente parce que ses outils manquent.

La matrice ne possède pas encore son propre numéro de version, schéma publié ou fichier catalogue; elle est générée à partir de profils PowerShell.

## Limites d'interprétation

`available` signifie que tous les candidats sont résolus; si un seul manque, la capacité devient `partially_available`, même si une alternative existe. La matrice ne choisit donc pas une alternative qualifiée au sens du contrat cible. `required` découle uniquement de `technology_status: detected`, sans profil utilisateur ni mode Quick/Full.

La présence d'un lanceur ansible-lint dans `.venv` peut apparaître disponible sous Windows sans démontrer une exécution native supportée. De même, pre-commit présent ne prouve pas que le hook Markdownlint fonctionne. Les profils Kubernetes/Helm sont déclarés mais aucun contrôle dédié n'est appelé par l'orchestration du gate; JavaScript et TypeScript sont détectés mais sans linter configuré. Voir [resolver.md](resolver.md) et [testing.md](testing.md).
