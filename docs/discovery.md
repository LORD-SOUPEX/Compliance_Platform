# Discovery

Discovery est intégré à `scripts/quality-gate.ps1`. Il accepte un dossier externe via `-RepositoryPath` et peut être lancé sans contrôles avec `-DiscoveryOnly`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -DiscoveryOnly -RepositoryPath <chemin-du-depot>
```

Le JSON Discovery contient `schema_version`, `repository`, `technologies`, `project_roots`, `ambiguities`, `capability_matrix`, `tool_resolution`, `scan_complete` et `scan_errors`. Une entree de technologie expose `technology`, `status`, `evidence`, `roots` et `ambiguities`.

## Détecteurs

| Technologie | Signaux observés dans le code | Limites |
| --- | --- | --- |
| Python | `.py`; racine au manifeste Python le plus proche (`pyproject.toml`, `setup.py`, `setup.cfg`, `requirements.txt`) | Sans manifeste, racine du dossier; tests différenciés par segment `tests` |
| PowerShell | `.ps1`, `.psm1`, `.psd1` | Chaque dossier de fichier devient une racine candidate |
| Terraform | `.tf`; `.terraform-version` comme marqueur explicite | `.tf` sans marqueur reste ambigu avec OpenTofu |
| OpenTofu | `.tofu`, `.opentofu-version`, `.tofurc` | Fichiers `.tf` partagés produisent une ambiguïté explicite |
| Terragrunt | `terragrunt.hcl`, `terragrunt.stack.hcl` | HCL générique non classé Terragrunt |
| Ansible | `ansible.cfg`, `galaxy.yml`, `meta/runtime.yml`, chemins `roles/`, `playbooks/`, `requirements.yml`, ou YAML avec `hosts:` | `hosts:` seul est ambigu; les marqueurs de chemins sont heuristiques |
| Docker/Compose | `Dockerfile`, `Containerfile` avec suffixe, `docker-compose.yml`, `compose.yaml` | Aucun build ou lancement de conteneur |
| Kubernetes | YAML avec `apiVersion` et un `kind` reconnu | `{{` dans le document marque une ambiguïté de template |
| Helm | `Chart.yaml` | `values.yaml` seul ne suffit pas; aucun rendu n'est exécuté |
| Shell | `.sh` | Scripts sans extension et dialecte non détectés |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs`, ou `package.json` | La présence d'un manifeste peut classer le projet même sans source JS |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts`, ou `tsconfig*.json` | Aucun contrôle TypeScript n'est configuré dans le profil actuel |
| Markdown | `.md` | Tous les fichiers sont rattachés à la racine du repository |

Remplacer `<chemin-du-depot>` par un chemin local entre guillemets. Le parcours exclut `.git`, `.venv`, `.tools`, `reports`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.cache`, `.terraform` et `.terragrunt-cache` avant descente. Il ne descend pas dans les répertoires marqués comme points de réanalyse; les liens de fichiers ne sont pas explicitement filtrés. Les racines sont déduites de marqueurs locaux et ne représentent pas encore un graphe de sous-projets complet.

## Ambiguïtés

Une détection ambiguë reste une entrée distincte, avec ses preuves et raisons. Un `.tf` partagé ne déclenche pas les contrôles Terraform. Une clé YAML `hosts:` seule ne déclenche pas le contrôle Ansible. Ces cas apparaissent aussi dans la Capability Matrix et le Tool Resolver.

Les tests utilisent des fixtures synthétiques. Aucun corpus de repositories représentatifs ni mesure de faux positifs/faux négatifs n'est présent.

## Portée vérifiée

Les 37 scénarios du socle ont été réexécutés dans Full le 6 octobre 2026, dont le cas CLI sur dépôt externe. Aucun override déclaratif ni fichier de configuration Discovery n'est accepté par la CLI actuelle. Les YAML sont reconnus par expressions régulières, sans analyse structurelle de leurs documents.

La selection Terraform/OpenTofu recherche maintenant le marqueur le plus proche de chaque `.tf`: `.terraform-version`, `.opentofu-version` ou `.tofurc`. Des projets separes d'un monorepo peuvent donc etre identifies sans contamination. Marqueurs contradictoires ou absents restent ambigus. Une racine ambigue rend le statut agrege conservativement ambigu et bloque les controles Terraform globaux, meme si une autre racine est certaine. `.terraform-version` seul, sans `.tf`, ne declare pas Terraform present. La recherche TypeScript reste limitee a `tsconfig.json`/`package.json` et le corpus reel reste a qualifier.

Discovery n'execute ni build ni controle. Il peut ecrire un rapport sur demande, y compris dans le depot analyse si ce chemin est choisi. Les erreurs de parcours et lecture sont conservees dans `scan_errors` avec chemin relatif, operation et type d'erreur; les doublons de lecture sont dedupliques. Un scan incomplet emet le JSON partiel, ecrit le rapport demande et retourne code 2. Les erreurs d'entree, de configuration du runtime ou d'ecriture du rapport restent des erreurs distinctes. Voir [reporting.md](reporting.md) et [testing.md](testing.md).
