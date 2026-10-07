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

Il recalcule maintenant SHA-256 a la resolution; une empreinte absente/invalide ou differente produit `integrity_error`. L'executeur verifie aussi les binaires sous `.tools/runtime` et leurs copies `.tools/bin` avant demarrage, et refuse index absent/invalide, plateforme non qualifiee ou outil non actif. Les outils hors de ces emplacements restent hors de cette garantie. La commande de version n'est pas encore reexecutee a chaque resolution.

## Outils hors index

Python et les paquets verrouillés restent dans `.venv`; PSScriptAnalyzer reste dans `.tools/powershell-modules`. Le resolver les recherche dans ces emplacements et les marque comme gérés par la plateforme, mais le bootstrap ne les enregistre pas encore dans l'index central. Certains outils peuvent aussi être trouvés dans le `PATH`; ces résultats ne sont pas gérés par le runtime.

## État de qualification

Le bootstrap runtime actuel ne vise que Windows x64. Son statut `qualified` dans l'index signifie que l'installation des outils est terminee; ce n'est pas la qualification produit. La matrice produit est maintenue dans [platform-support.json](../.config/platform-support.json), chargee et validee par le gate, et son statut est expose facultativement dans les rapports v1.

| Plateforme | Statut produit | Preuve et limite principale |
| --- | --- | --- |
| Windows x64 | experimental | Tests locaux et Quick passent; Full échoue sur pip-audit et les consommateurs externes ne sont pas qualifiés. |
| Windows ARM64 | targeted | Bootstrap et runtime natifs non qualifiés. |
| Linux x64 | targeted | Exécution native et runtime non qualifiés. |
| Linux ARM64 | targeted | Exécution native et runtime non qualifiés. |
| macOS x64 | targeted | Exécution native et runtime non qualifiés. |
| macOS ARM64 | targeted | Exécution native et runtime non qualifiés. |

Le validateur exige exactement ces six couples OS/architecture, des statuts connus et une preuve non vide avant `qualified`. Le statut n'autorise ni ne bloque les contrôles; il rend la qualification visible. Aucun produit n'est actuellement `qualified` au sens de cette matrice.

Le bootstrap Windows x64 retrograde le statut runtime a `experimental` au debut d'une installation/mise a jour et ne le passe a `qualified` qu'apres toutes ses etapes. Le cycle d'implementation a termine ces etapes en code 0. Le blocage historique du cache pre-commit est corrige.

`Repair-PreCommitCache` lit en SQLite les clones enregistres. Si leur chemin sort du cache courant ou n'existe plus, il execute `pre-commit clean` avant la reconstruction officielle des hooks. Un cache valide est conserve. En mode hors ligne, un cache deplace provoque une erreur explicite sans suppression. Le test couvre plusieurs clones et la preservation des autres outils et de `PRE_COMMIT_HOME`.

Linux, macOS, Windows ARM64, Linux ARM64, macOS Intel x64 et Apple Silicon ARM64 ne sont pas qualifiés par le code actuel. L'index ne contient pas encore leurs binaires.

## Qualification reproductible

Pour vérifier une installation Windows x64 depuis la racine, exécuter dans cet ordre:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Quick -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Full -NoColor
```

Conserver les codes de sortie et les rapports datés comme preuves; ne pas remplacer une exécution Full bloquée par Quick. Au 7 octobre 2026, tests et Quick passent, mais Full échoue sur les avis pip-audit `asteval==1.0.6` et `ecdsa==0.19.2`. Le runner GitLab distant, les dépôts consommateurs représentatifs et les plateformes autres que Windows x64 restent non qualifiés. Répéter cette procédure après toute modification des verrous, du bootstrap, du runtime ou des contrôles.

## Bootstrap réellement livré

Depuis la racine de la plateforme:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
```

Le bootstrap recherche Python 3.11 existant ou extrait le runtime épinglé, prépare `.venv`, installe avec `requirements-dev.txt` et les contraintes de `requirements-dev.lock`, puis PSScriptAnalyzer et cinq binaires. Il installe les hooks pre-commit du dépôt de la plateforme avant les vérifications finales. Il ne lance pas pip-audit ni Full: son passage à `qualified` est un marqueur de fin d'installation, pas une certification de sécurité ou de portabilité.

Les téléchargements de binaires vérifient le manifeste de sommes épinglé et l'archive. Un binaire déjà présent avec la version attendue est toutefois réindexé sans nouvelle comparaison avec l'archive officielle; la copie runtime est comparée à la source locale. PSScriptAnalyzer est épinglé, sans somme publiée dans le catalogue. Le verrou Python comporte 154 paquets pour Windows/Python 3.11, sans empreintes de roues; les environnements Node et hooks ont leurs propres pins.

## Procédure de mise à jour

Pour mettre à jour une dépendance Python, modifier sa version exacte dans `requirements-dev.txt`, le pin correspondant dans `requirements-dev.lock` et la version du manifeste `.config/tool-versions.yml`. Le bootstrap vérifie l'égalité des pins déclarés et le succès des commandes de version. Le verrou complet doit rester exact pour Python 3.11/Windows x64; aucune commande de régénération reproductible du verrou n'est encore livrée, donc ne pas produire un verrou avec des contraintes flottantes ni prétendre qu'il est reproductible sans noter l'outil et sa version.

Pour un outil PowerShell ou binaire, modifier la version et les références immuables dans le manifeste. Vérifier la somme publiée depuis la source officielle avant de changer `checksum_asset_sha256`; ne jamais calculer une nouvelle somme depuis le fichier téléchargé puis la considérer comme preuve de provenance. Le bootstrap doit télécharger, contrôler, installer et confirmer la version avant que l'index local soit marqué `qualified`.

Après toute mise à jour, exécuter bootstrap, Doctor, `scripts/test.ps1`, Quick puis Full selon la procédure de qualification ci-dessus. Examiner tous les nouveaux avis pip-audit; aucun Full en échec ne peut être requalifié par un Quick vert. Conserver les sorties et les versions source utilisées. Une nouvelle plateforme demande ses propres artefacts, sommes officielles et exécution complète sur cette plateforme; le manifeste Windows ne la qualifie pas.

`-Force` peut recréer `.venv` et réinstaller les outils. `-Offline` nécessite des archives, roues et modules déjà disponibles, sans qualification hors ligne des hooks. `-SkipOptionalTools` peut omettre Terragrunt, alors que Doctor l'exige. Terraform est uniquement recherché dans le PATH; aucun téléchargement Terraform/OpenTofu n'est implémenté. Les relais Bash exigent `powershell.exe` et ne sont pas des installateurs Linux/macOS.

Doctor vérifie encore `.tools/python` même si le bootstrap a choisi un Python existant. Il ne lit pas l'index runtime, ne valide pas le cache des clones de hooks et ne remplace pas un audit des dépendances. Les preuves et blocages restent dans [testing.md](testing.md).
