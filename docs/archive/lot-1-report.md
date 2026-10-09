# Audit Lot 1 - Socle actuel et Discovery

Date: 6 octobre 2026
Périmètre: Roadmap Phase 1 (stabilisation du socle) et Phase 2 (Discovery Engine).
Sources examinées: `scripts/quality-gate.ps1`, `scripts/test.ps1`, `tests/integration/quality-gate.Tests.ps1`, `.config/quality-gate.yml`, `README.md`, les configurations du dépôt et les fichiers présents dans le workspace.
Aucun code, script ou configuration technique n'a été modifié. Aucun bootstrap ni pipeline n'a été lancé. La suite de tests a été exécutée directement et par Full; Quick et Full ont aussi été lancés selon les consignes du dépôt.

## Résumé exécutif

Le socle actuel est un Quality Gate PowerShell centré sur le repository qui contient le script. Son inventaire est construit globalement à partir d'extensions, de noms, de marqueurs de chemins et d'une heuristique YAML. Il ne reçoit pas encore le chemin d'un dépôt externe, ne restitue pas les racines de projet et ne distingue pas OpenTofu de Terraform.

Dans le dépôt Compliance_Platform observé, les signaux de fichiers indiquent PowerShell, Shell et Markdown. Aucun fichier `.py`, `.tf`, `.hcl`, Dockerfile ou Containerfile n'a été trouvé. Aucun marqueur Ansible ni clé YAML `hosts:` n'a été trouvé. L'absence de ces marqueurs décrit ce dépôt observé, pas les dépôts futurs.

La suite a terminé avec 25 PASS et 3 FAIL sur 28 scénarios. Les échecs sont liés à un environnement `.venv` dont `pyvenv.cfg` référence l'ancien chemin `D:\git\service-manager-template\.tools\python\python.exe`, qui n'existe pas. Le lanceur `.venv\Scripts\python.exe` existe, mais son interpréteur de base est périmé. Aucun environnement n'a été réparé pendant l'audit.

**Décision: No-Go pour le Lot 2.** Le Lot 1 n'est pas clôturé: il faut retrouver un environnement de test reproductible et vert, puis qualifier Discovery sur un corpus représentatif avant d'engager le runtime.

## Travaux réalisés

- Lecture du détecteur, des fonctions d'exécution, du contrat de rapport JSON et des paramètres du Quality Gate.
- Lecture des 28 scénarios d'intégration et du script d'orchestration des tests.
- Examen du README, de la politique YAML et des configurations liées aux outils et à VS Code.
- Inventaire des extensions de fichiers présentes dans le repository, hors répertoires exclus par le scanner.
- Exécution de `scripts/test.ps1`; vérification de `pyvenv.cfg`, des chemins d'interpréteur et du nettoyage de l'espace temporaire.
- Mise à jour de la roadmap (`docs/roadmap.md`) avec les résultats, les limites de preuve, les questions Discovery et la décision de jalon.

## Découvertes

## État réel de la détection

| Technologie ou format | Signal réellement implémenté | État observé dans ce repository |
| --- | --- | --- |
| Python | Tous les fichiers `.py`; fichiers sous `tests/` séparés des autres sources | Aucun `.py` détecté |
| PowerShell | `.ps1`, `.psm1`, `.psd1` | Présent dans `scripts/` et les tests d'intégration |
| Terraform | Tous les `.tf` | Aucun `.tf` détecté |
| OpenTofu | Pas de distinction; les `.tf` sont classés Terraform | Non déterminable par le détecteur actuel |
| Terragrunt | Noms `terragrunt.hcl` et `terragrunt.stack.hcl` | Aucun fichier détecté |
| Ansible | Marqueurs à la racine `ansible.cfg`, `galaxy.yml`, `meta/runtime.yml`, dossiers `roles`/`playbooks`; `requirements.yml` parmi les fichiers; ou clé YAML `hosts:` | Aucun marqueur observé |
| Conteneurs | Noms `Dockerfile`/`Containerfile`, avec suffixe facultatif | Aucun fichier détecté |
| Shell | Extension `.sh` | Présent dans les relais Bash de `scripts/` |
| Markdown | Extension `.md` | Présent: notamment README, plan et documentation |
| Kubernetes, Helm, Compose, JavaScript, TypeScript | Aucun détecteur dédié dans le moteur actuel | Non détectés; présence non qualifiée |
| YAML, JSON, TOML, XML | Inventaire de formats génériques pour des validations, pas détection d'une technologie métier | Configurations YAML/JSON présentes; les formats ne prouvent pas une technologie |

Le parcours est global: `Get-ProjectFile` énumère les fichiers sous le repository du script, puis `Get-Technology` produit des indicateurs par technologie. Le chemin racine est calculé depuis `$PSScriptRoot`; aucun paramètre ne permet actuellement de fournir un autre repository local. Les racines de projets imbriquées ne sont donc pas restituées.

Les dossiers exclus sont identifiés par leur nom (`.git`, `.venv`, `.tools`, `reports` et plusieurs caches); les points de réanalyse sont aussi ignorés. Le calcul `hcl_files` existe, mais n'est pas utilisé pour distinguer ou sélectionner une technologie. La sélection effective des contrôles reste une orchestration fixe par catégorie et technologie, pas un Discovery Engine autonome.

## Tests et environnement

- Résultat observé aux deux exécutions: **25 PASS, 3 FAIL** sur 28 scénarios.
- Échecs: `Arguments avec espaces et guillemets`, `Délai externe bloque` et `Formats JSON TOML XML valides`.
- Cause démontrée: `\.venv\pyvenv.cfg` pointe vers l'ancien dépôt `service-manager-template`; le chemin de base est absent. Les appels à Python sortent avec le code 103, ce qui invalide ces vérifications.
- Les trois contrôles de lancement YAML, TOML et Markdownlint échouent aussi parce que les lanceurs yamllint et pre-commit tentent de démarrer depuis l'ancien `.venv\Scripts\python.exe`. L'exécution directe des deux lanceurs confirme cette erreur de création de processus; aucune faute YAML ou Markdown n'est ainsi établie.
- Un cas nommé `Code externe non nul bloque` est marqué PASS après un processus Python qui n'a pas démarré et a retourné le code 103. L'assertion vérifie seulement qu'un échec est remonté, pas que le processus lancé retourne bien le code attendu 7. C'est une faiblesse de ce test, distincte des trois scénarios en FAIL.
- Les tests créent leurs fixtures dans `.tools/test-workspaces` et leur bloc `finally` les nettoie; aucun workspace de fixture ne restait après l'exécution.

Les scénarios testent quelques marqueurs nominaux et exclusions, mais ne mesurent pas les faux positifs/négatifs sur des repositories réels ni des layouts de monorepo.

## Quick et Full

- **Quick:** 7 PASS, 3 FAIL, 1 WARN, 6 SKIP; code de sortie 1.
- **Full:** 7 PASS, 5 FAIL, 1 WARN, 6 SKIP; code de sortie 1. Les échecs supplémentaires sont l'audit des dépendances et la suite de tests, bloqués par le même environnement Python.
- Les deux modes confirment la détection observée: PowerShell, Shell et Markdown; Python, Terraform, Terragrunt, Ansible et conteneurs absents dans ce dépôt.
- PSScriptAnalyzer, Gitleaks, hygiène des fichiers, contrôle des pictogrammes et JSON passent. ShellCheck produit le WARN documenté sous Windows.
- `reports/quick.json` et `reports/full.json` ont été produits par les tâches existantes. Ils sont intégrés au constat, non interprétés comme preuve de conformité complète.

## Écarts avec le plan

- Le plan décrit une analyse d'un chemin local fourni par l'utilisateur; le script actuel analyse son propre repository, déduit de son emplacement.
- Le plan décrit un moteur générique piloté par des capacités; le code actuel n'a ni Capability Matrix ni Tool Resolver autonome.
- Le plan cible plusieurs technologies; l'implémentation n'en distingue qu'un sous-ensemble et ne détecte pas Kubernetes, Helm, Compose ou JavaScript/TypeScript.
- Terraform et OpenTofu ne sont pas différenciés; les racines des sous-projets ne sont pas calculées.
- Le plan vise Windows, Linux et macOS, ainsi que plusieurs architectures; le socle observé et les scripts restent Windows x64/PowerShell 5.1. Les relais Bash actuels ne constituent pas une exécution native Linux/macOS.
- Le plan suppose un bootstrap et runtime centraux futurs; le README demande encore Terraform fourni séparément et décrit des limitations Ansible/Shell sous Windows. Ces capacités relèvent du Lot 2 ou ultérieur et n'ont pas été modifiées ici.
- La suite locale n'est pas verte à cause de l'environnement Python périmé. Les résultats antérieurs Quick/Full ne remplacent pas cette exécution actuelle.
- Le README conserve l'ancien titre `service-manager-template`; la vision actuelle du plan est plus récente. Aucun changement au README n'est inclus dans ce lot.

## Architecture validée

Les éléments suivants sont confirmés comme description de l'existant, pas comme validation de la cible produit:

- Détection globale par marqueurs de fichiers et quelques marqueurs de contenu.
- Séparation des sources Python et tests Python par chemin, après détection de `.py`.
- Statut différent entre technologie absente et certains outils manquants, selon les fonctions de contrôle; la sémantique n'est pas centralisée.
- Rapport JSON contenant indicateurs de technologies, statuts, résumé et code de sortie.
- Exclusions de répertoires générés et absence de suivi des points de réanalyse.
- Référence opérationnelle principalement Windows x64 et PowerShell 5.1.

## Architecture remise en question

- Le nom « moteur d'analyse d'un repository fourni » ne correspond pas encore à l'API actuelle: le script est lié à sa propre racine.
- Les catégories de technologie, les contrôles et leurs conditions d'applicabilité sont dispersés dans le même script; une nouvelle technologie peut exiger des modifications à plusieurs emplacements.
- L'inventaire global ne permet pas d'expliquer quel contrôle s'applique à quelle racine d'un dépôt multi-projets.
- L'heuristique YAML `hosts:` et les marqueurs de dossiers Ansible peuvent confondre des contenus génériques et Ansible; aucun jeu de contre-exemples n'a mesuré ce risque.
- L'appellation « Terraform détecté » masque le cas OpenTofu lorsque seuls des fichiers `.tf` sont présents.
- Les tests chargent les fonctions PowerShell par AST et sont sensibles à l'environnement local, ce qui limite leur valeur comme contrat stable du moteur.

## Risques identifiés

- **Élevé, environnement de validation:** virtualenv périmée après changement de nom/chemin; trois cas échouent et d'autres assertions peuvent réussir sur le mauvais code de sortie.
- **Élevé, faux statut d'applicabilité:** les marqueurs heuristiques peuvent produire une détection inexacte; l'absence de marqueur n'est pas une preuve universelle d'absence technologique.
- **Élevé, périmètre:** contrôles lancés à la racine globale plutôt qu'aux racines réelles des composants.
- **Élevé, portabilité:** les chemins `.exe`, `.venv\Scripts`, `taskkill` et les dépendances Windows ne qualifient pas les plateformes OS + architecture cibles.
- **Moyen, couverture:** tests de détection limités à des fixtures synthétiques nominales; pas de métriques de précision/rappel ni de corpus multi-projets.
- **Moyen, source documentaire:** README ancien et plan cible ne décrivent pas le même positionnement ni le même niveau de support.

## Recommandations

1. Ne pas commencer le Lot 2 tant que l'environnement de tests courant n'est pas reproductible et que la suite n'est pas verte.
2. Corriger ou recréer l'environnement `.venv` via une procédure approuvée, sans modification globale ni suppression d'un environnement utilisateur; rejouer les 28 scénarios et confirmer que les cas externes testent les codes attendus.
3. Avant de conclure Discovery, constituer un corpus autorisé couvrant marqueurs nominaux, faux positifs plausibles, faux négatifs connus, monorepos et racines imbriquées.
4. Distinguer explicitement « absent », « ambigu », « détecté » et « non couvert »; ne pas présenter une absence de détection comme absence certaine de technologie.
5. Arbitrer la capacité à fournir un chemin de repository externe et les responsabilités de résolution des racines dans un lot autorisé; cela ne relève pas de ce rapport de diagnostic.
6. Maintenir les limites OS + architecture actuelles dans la documentation jusqu'à qualification réelle, sans assimiler un binaire disponible à une plateforme supportée.

## Mise à jour du plan

La roadmap (`docs/roadmap.md`) consignait alors:

- le résultat actuel de 25 PASS / 3 FAIL et la cause environnementale démontrée;
- la cartographie présente et absente de ce repository;
- les règles de détection, limites, ambiguïtés et risques de faux positifs/faux négatifs non mesurés;
- l'écart entre l'analyse cible d'un chemin local et la racine fixe du script actuel;
- les questions de corpus, monorepos, marqueurs et qualification des technologies;
- la phase 1 comme non satisfaite et le No-Go pour le Lot 2.

## Go / No-Go pour le lot suivant

**NO-GO pour le Lot 2.** Conditions minimales de réévaluation: environnement Python de test corrigé ou recréé selon une procédure approuvée; 28 scénarios exécutés avec succès et assertions renforcées sur les échecs de lancement externe; ambiguïtés et périmètre de Discovery documentés avec un corpus représentatif ou un arbitrage explicite sur l'absence de ce corpus.

L'audit s'arrête ici. Aucun travail du Lot 2 (runtime, bootstrap, resolver ou Capability Matrix) n'a commencé.
