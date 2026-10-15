# Changelog

## 2.0.15

- **Registre d'outils auto-hébergé (`tools-v1`)** : Suppression de toutes les dépendances d'installation envers des forges tierces (éditeurs, PyPI, npm, PowerShell Gallery). Tous les outils du catalogue sont désormais hébergés, précompilés et distribués via la release GitHub `tools-v1` (`https://github.com/LORD-SOUPEX/Compliance_Platform/releases/tag/tools-v1`).
- **Bundle Python 100 % relocalisable** : Remplacement des environnements virtuels `venv` à chemins codés en dur par un bundle CPython autonome sans shebangs absolus. Les outils Python (`checkov`, `bandit`, `pylint`, `pytest`, `pip-audit`, `yamllint`, `ansible-lint`) s'exécutent via l'interpréteur autonome du bundle (`python -m <module>`).
- **Module PowerShell `PSScriptAnalyzer`** : Packaging de `PSScriptAnalyzer-1.23.0.zip` dans le registre, installable en 1 clic sous Windows sans dépendre de la PowerShell Gallery.
- **Ordre strict de résolution des outils** :
  1. `eslint`/`tsc` : `node_modules/.bin` de la Target en priorité, sinon bundle `~/.compliance/tools/node`.
  2. Autres outils : `.tools/bin/` (dev local) ➔ `~/.compliance/tools/{bin,python,node,powershell-modules}` (registre installé) ➔ `PATH` système.
- **Compatibilité entreprise et miroirs privés** : Support des réglages `compliance.registryUrl` (ou `COMPLIANCE_REGISTRY_URL`) et `compliance.registryToken` (`COMPLIANCE_REGISTRY_TOKEN`) pour rediriger les téléchargements vers un miroir Artifactory, Nexus ou GitLab Package Registry privé.
- **Publication multi-OS et format d'assets aplati** : Reconditionnement des 10 outils natifs pour les 5 plateformes sous un format à plat `<platform>-<tool>-<version>.<ext>` compatible GitHub Releases, avec formats d'archives `.zip` et `.tar.gz` supportés nativement en Go.
- **Synchronisation automatique du manifeste** : `package_vsix.py` synchronise `.config/runtime-manifest.json` vers les assets embarqués Go avant la cross-compilation des démons.

## 2.0.14

- Le lancement accepte un plan qui contient `platform_unsupported`. Le rejet nomme le contrôle, la racine et la raison. La préparation valide le même plan.
- Chaque racine retenue conserve une preuve. `Dockerfile` et `Containerfile` couvrent aussi `Dockerfile.*`, `*.Dockerfile` et `.gitpod.Dockerfile`. Le canal Output et le compteur Indisponibles utilisent les mêmes codes.
- Checkov d'un Python autonome (interpréteur au-dessus de `Scripts`) est lancé avec cet interpréteur.
- Hadolint, ESLint, `tsc` et `ruff format` exposent un fichier, une ligne, une règle et un message. Un chemin déjà relatif au dépôt n'est plus préfixé une seconde fois. ESLint et `tsc` passent par `node` et le script du paquet.
- `pip-audit` signale une dépendance non épinglée. `pytest` signale une erreur de collecte. Une sortie pylint JSON coupée conserve les objets déjà complets.
- L'absence de PSScriptAnalyzer est un module manquant. La page Détails décrit l'architecture en Markdown. Le schéma Mermaid reste dans le README du dépôt.

Sessions Windows x64 de cette version : `content` et `cloud-foundation-toolkit` jusqu'au rapport, plus un dépôt de fixture (Ansible/yamllint, Docker, Helm, JavaScript, Kubernetes, Markdown, OpenTofu, Python, Shell, Terraform, Terragrunt, TypeScript). `ansible-lint` reste réservé à Linux et macOS. PSScriptAnalyzer n'était pas installé. Trivy sécurité Kubernetes et Helm n'est pas lancé quand checkov couvre déjà cette capacité.

## 2.0.13

- Le bandeau du rapport garde la maquette 2.0.12 et remplace les emoji par des icônes SVG. Le logo est `media/icon.png`.
- **Ouvrir à la ligne** reconstitue le chemin `<racine du contrôle>/<fichier>` lorsque l'outil remonte `/fichier` ou `\fichier`, puis ouvre ce fichier dans l'éditeur.
- ShellCheck et les autres outils à liste de fichiers s'exécutent par lots sous la limite Windows de ligne de commande. Ruff, Pylint, Bandit, pytest, pip-audit et yamllint exposent des findings (fichier, ligne, règle, message).
- Sur Windows, `ansible-lint` n'est plus proposé comme installable depuis le manifeste. Il reste réservé à Linux et macOS ; `yamllint` couvre Ansible.
- La découverte reconnaît `Dockerfile`, `Dockerfile.*`, `Containerfile` et `*.Dockerfile`, y compris dans un sous-dossier.
- Le canal Output n'inscrit plus une technologie dans `ignorés (technologie absente)` si elle vient d'être exécutée.
- L'image d'architecture du README pointe vers l'URL brute GitHub, affichable par la page Détails une fois le fichier sur `main`.

## 2.0.12

- Le VSIX compile le TypeScript avant de copier `.extension-build`. La 2.0.11 embarquait encore l'ancien `reportPanel.js` (compteurs collés, section Findings, pas de casiers de fichiers).
- Le bandeau du rapport reprend la maquette : fond `#111622`, titre `ICP COMPLIANCE`, verdict en pilule, chemin, version et durée, puis les cinq compteurs dans un encadré.
- Chaque contrôle qui a des anomalies est un casier : fichiers, puis ligne, règle et message. La section Findings n'est plus générée.
- `eslint` et `tsc` utilisent `node_modules/.bin` de la cible, sinon la chaîne installée par `compliance runtime node` dans `~/.compliance/tools/node`.
- L'image d'architecture reste dans le VSIX. La page Détails de VS Code 1.141 lit le README tel quel et retire le `src` relatif ; aucun type d'asset du manifeste ne réécrit cette image.

## 2.0.11

- Le bandeau du rapport agrandit le logo, le titre et le verdict. Les métadonnées, les boutons et les compteurs sont des cartes distinctes, lisibles quand le panneau est étroit.
- Les anomalies d'un contrôle se déroulent dans sa carte : sous-dossier, puis fichier, puis ligne, règle et message. La section Findings en bas de page n'est plus affichée.
- `pytest` avec le code de sortie 5 et aucune anomalie est un succès (`no_tests_collected`). Gitleaks ignore les dossiers d'artefacts (dont `.vscode`, `.vscode-test`, `.rumdl_cache`) et les fichiers `.vsix`, `.exe`, `.dll`, `.pdb`, `.pyc`, `.zip`. Pylint charge le `.pylintrc` du dépôt.
- La page Détails de VS Code 1.141 retire l'attribut `src` de `./media/architecture.jpg` : le rendu n'autorise que `http` et `https`, puis la webview n'affiche que `https` et `data`. Le dépôt GitHub répond 404, donc aucune URL publique ne peut afficher ce JPEG aujourd'hui. Le fichier reste dans le VSIX.

## 2.0.10

- Le rapport groupe chaque outil dans une carte et liste les sous-dossiers avec leur statut, leur durée et leurs anomalies.
- Checkov, TFLint, ShellCheck, Trivy et `terraform fmt` produisent des findings structurés (règle, fichier, ligne, message). La section Findings et les raisons du verdict restent lisibles.
- Une technologie déjà exécutée sur une racine n'apparaît plus dans les contrôles non applicables.
- Sans configuration Markdown du dépôt, `rumdl` est appelé avec `--disable MD013`.
- L'image d'architecture est référencée en `./media/architecture.jpg` et déclarée en `image/jpeg` dans le VSIX.

## 2.0.9

- L'image d'architecture est en tête du README de l'extension et dans le VSIX.
- Un script Python `.cmd` est lancé avec le `python.exe` du venv. Checkov installé est donc retrouvé et exécuté à l'audit suivant.
- Le rapport regroupe les contrôles exécutés par outil, dédoublonne les outils à installer et les lacunes, et n'affiche pas les findings issus de `testdata`, `fixtures` ou `__snapshots__`. `rumdl` reçoit les mêmes exclusions que la découverte.

## 2.0.8

- Le rapport s'ouvre comme un tableau de bord : indicateurs sur une ligne, une ligne par contrôle exécuté, findings repliés par outil puis par fichier.
- Les contrôles indisponibles sont regroupés par technologie, outil et raison, dans le rapport et dans le canal Output.
- L'installation conserve les outils qui ont réussi. « Réseau indisponible » ne s'affiche que pour un échec DNS ou TCP. Un HTTP 404 ou un échec pip nomme l'outil et la cause.
- Les paquets Python (`bandit`, `pylint`, `pytest`, `pip-audit`, `checkov`, `yamllint`, `ansible-lint`) s'installent dans un venv, après un CPython autonome.
- Un dossier `.tf` sans marqueur OpenTofu est Terraform. `testdata`, `fixtures` et `__snapshots__` ne deviennent pas des racines.

## 2.0.7

- Un rapport rechargé depuis le disque affiche la durée (`metrics.total_duration_ms`, sinon la somme des contrôles exécutés) et le bouton « Ouvrir les sorties » sur chaque contrôle exécuté, y compris les réussites.
- Chaque contrôle exécuté a son fichier de log dans le dossier de session, même si la sortie est vide.
- La fin d'audit ouvre la session courante. Un autre fichier reste un rapport historique, avec durée et sorties.
- Le démon est copié avec `.config` dans `~/.compliance/bin/<version>/` et démarre avec ce dossier comme répertoire de travail. La désactivation et la désinstallation envoient l'arrêt (500 ms) puis tuent le processus, y compris `compliance-windows-amd64.exe`.
- Les findings `rumdl` reprennent le fichier, la ligne, la colonne et la règle Markdown.

## 2.0.6

- Le rapport embarque son script (nonce). Les contrôles réussis se déplient et « Ouvrir les sorties » affiche le texte. « Actualiser » est remplacé par « Ouvrir un rapport… ».
- `rumdl` s'installe depuis le manifeste. Une signature absente ou différente, et une somme SHA-256 différente, ne bloquent plus le téléchargement HTTPS.
- Gitleaks scanne le dossier cible sans historique git, hors `node_modules`, `.git`, `dist`, `build` et `.venv`. Chaque fuite est un finding (fichier, ligne, règle) sans le secret. Les séquences ANSI sont retirées des sorties.
- Chaque contrôle exécuté a le bouton « Ouvrir les sorties ». Le nombre de sessions reste libre de 1 à 1000.
- Réglages d'application : dossier des sessions, nombre conservé de 1 à 1000, technologies et contrôles ignorés. Un dépôt ne peut pas les imposer. Un refus d'installation est mémorisé.
- Le démon est lancé depuis `~/.compliance/bin/<version>` pour ne plus verrouiller le dossier de l'extension. Désactivation, désinstallation et « Réinitialiser » arrêtent uniquement ce processus. Les rapports ne sont pas effacés.

## 2.0.5

- Le rapport liste les contrôles non applicables en texte fixe, regroupés par technologie. Les boutons du rapport restent reliés aux commandes ; les contrôles réussis se déplient en HTML natif.
- La couverture est un nombre de technologies couvertes sur les technologies détectées, le même libellé dans le JSON, le journal et le rapport.
- ESLint et `tsc` ne sont plus un succès si l'outil du dépôt ou la configuration manque.
- Au plus cinq sessions. La purge ignore les liens et tout dossier qui n'est pas une session de l'outil.
- Markdown : contrôle `rumdl` (MIT). L'entrée de manifeste est calculée sur les archives officielles et n'est pas signée tant que la clé privée n'est pas fournie.
- Documentation alignée sur le catalogue. Seul Windows x64 est qualifié.

## 2.0.4

- Rapport recentré, verdict partiel quand une technologie détectée n'est pas couverte, installation de gitleaks depuis le manifeste après accord. La signature n'est plus exigée depuis 2.0.6.

## 2.0.3

- ESLint du dépôt et gitleaks pour JavaScript. Version du moteur alignée sur l'extension. Page de rapport et boutons de session.

## 2.0.0

- Binaires macOS dans le VSIX universel, catalogue embarqué, chemins canoniques.
