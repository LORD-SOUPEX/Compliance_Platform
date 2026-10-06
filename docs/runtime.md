# Runtime partagé

Le Tool Runtime est sous `.tools/runtime/`, séparé des repositories analysés. Son index est `.tools/runtime/index.json`, schéma 1, indexé par identifiant OS + architecture.

## Index actuel

Apres correction du cache deplace et execution complete du bootstrap le 6 octobre 2026, l'index declare `windows-x64: qualified` et cinq binaires actifs. Ce marqueur de fin d'installation ne remplace pas la qualification de securite ou les preuves sur poste neuf:

| Outil | Version |
| --- | --- |
| Gitleaks | 8.30.1 |
| TFLint | 0.64.0 |
| Terragrunt | 1.1.6 |
| Hadolint | 2.15.1 |
| Trivy | 0.75.0 |

L'index conserve pour chaque outil son nom, commande, version, chemin relatif, empreinte SHA-256, état et indicateur actif. Le resolver refuse un outil runtime quand la plateforme ou l'outil n'est pas `qualified`, vérifie que le chemin reste sous la racine du runtime et que le fichier existe.

Il ne recalcule pas l'empreinte à la résolution et ne réexécute pas la commande de version. Les contrôles historiques utilisent encore `.tools/bin`, même quand le resolver refuse l'entrée indexée. Le statut `experimental` n'empêche donc pas ces contrôles de s'exécuter.

## Outils hors index

Python et les paquets verrouillés restent dans `.venv`; PSScriptAnalyzer reste dans `.tools/powershell-modules`. Le resolver les recherche dans ces emplacements et les marque comme gérés par la plateforme, mais le bootstrap ne les enregistre pas encore dans l'index central. Certains outils peuvent aussi être trouvés dans le `PATH`; ces résultats ne sont pas gérés par le runtime.

## État de qualification

Le bootstrap actuel ne vise que Windows x64. Il retrograde la plateforme a `experimental` au debut d'une installation/mise a jour et ne la passe a `qualified` qu'apres toutes ses etapes. Le cycle d'implementation a termine ces etapes en code 0. Le blocage historique du cache pre-commit est corrige.

`Repair-PreCommitCache` lit en SQLite les clones enregistres. Si leur chemin sort du cache courant ou n'existe plus, il execute `pre-commit clean` avant la reconstruction officielle des hooks. Un cache valide est conserve. En mode hors ligne, un cache deplace provoque une erreur explicite sans suppression. Le test couvre plusieurs clones et la preservation des autres outils et de `PRE_COMMIT_HOME`.

Linux, macOS, Windows ARM64, Linux ARM64, macOS Intel x64 et Apple Silicon ARM64 ne sont pas qualifiés par le code actuel. L'index ne contient pas encore leurs binaires.

## Bootstrap réellement livré

Depuis la racine de la plateforme:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
```

Le bootstrap recherche Python 3.11 existant ou extrait le runtime épinglé, prépare `.venv`, installe avec `requirements-dev.txt` et les contraintes de `requirements-dev.lock`, puis PSScriptAnalyzer et cinq binaires. Il installe les hooks pre-commit du dépôt de la plateforme avant les vérifications finales. Il ne lance pas pip-audit ni Full: son passage à `qualified` est un marqueur de fin d'installation, pas une certification de sécurité ou de portabilité.

Les téléchargements de binaires vérifient le manifeste de sommes épinglé et l'archive. Un binaire déjà présent avec la version attendue est toutefois réindexé sans nouvelle comparaison avec l'archive officielle; la copie runtime est comparée à la source locale. PSScriptAnalyzer est épinglé, sans somme publiée dans le catalogue. Le verrou Python comporte 154 paquets pour Windows/Python 3.11, sans empreintes de roues; les environnements Node et hooks ont leurs propres pins.

`-Force` peut recréer `.venv` et réinstaller les outils. `-Offline` nécessite des archives, roues et modules déjà disponibles, sans qualification hors ligne des hooks. `-SkipOptionalTools` peut omettre Terragrunt, alors que Doctor l'exige. Terraform est uniquement recherché dans le PATH; aucun téléchargement Terraform/OpenTofu n'est implémenté. Les relais Bash exigent `powershell.exe` et ne sont pas des installateurs Linux/macOS.

Doctor vérifie encore `.tools/python` même si le bootstrap a choisi un Python existant. Il ne lit pas l'index runtime, ne valide pas le cache des clones de hooks et ne remplace pas un audit des dépendances. Les preuves et blocages restent dans [testing.md](testing.md).
