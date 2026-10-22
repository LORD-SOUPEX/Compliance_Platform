# Changelog

## Non publié

- **Journal du démon** : `~/.compliance/logs/daemon.log` en JSON, avec rotation, et `daemon-console.log` pour stdout et stderr du processus. Chaque phase du démarrage est horodatée. Les sondes d'outils sont tracées avec le résultat du cache. Le flux `GET /api/v1/logs/stream` relaie le journal à l'extension.
- **Commandes exécutées** : chaque processus d'un contrôle est décrit dans `invocations[]` (exécutable, arguments, `cwd`, variables ajoutées ou retirées, timeout, code retour, durée, octets lus) et annoncé par l'évènement `control_invocation`. Les secrets sont masqués.
- **Sorties complètes** : stdout et stderr de chaque processus sont écrits séparément dans le dossier `logs` de la session, au-delà de la limite de capture du rapport.
- **Canal Compliance** : `LogOutputChannel` avec niveaux et horodatage, corrélation par session et par contrôle. Nouvelle commande **ICP: Ouvrir le journal du démon**.
- **Robustesse** : analyseur SSE conservant son état entre paquets ; une erreur pendant le flux d'un audit termine l'audit au lieu de le bloquer ; délai maximal sur chaque requête au démon ; deux démarrages simultanés partagent un même démon ; un démon déjà lancé par une autre fenêtre (code de sortie 3) n'est plus une erreur.
- **Jeton du registre** : stocké dans le stockage sécurisé de VS Code (**ICP: Définir le jeton du registre d'outils**). Un `compliance.registryToken` présent dans `settings.json` y est déplacé puis effacé.
- **Installation des outils** : l'extension lit le manifeste actif (cache du registre) comme le moteur. La sortie de `compliance runtime sync` est relayée dans le canal.
- **ICP: Ouvrir les sorties du contrôle** affiche de nouveau stdout, stderr et diagnostics du contrôle choisi.
- **Premier démarrage sans rechargement** : le démon écoute avant de consulter le registre distant (vérifié en arrière-plan, catalogue basculé à chaud). L'extension démarre le moteur dès l'activation sans bloquer, réessaie un démarrage raté, attend la fin réelle d'un démon d'une autre version avant de lancer le nouveau, et accorde 60 secondes à un premier lancement analysé par l'antivirus.
- **Verrou du démon sous Windows** : `LockFileEx`, libéré par le système à la mort du processus. Un PID réattribué ne bloque plus le démarrage.
- **Outils** : un verrou inter-processus (`~/.compliance/tools/.install.lock`) est partagé par les plans et audits et exclusif pour les installations et mises à jour, y compris entre le démon, `compliance runtime sync` et plusieurs fenêtres. Les bundles Python, Node et PowerShell sont extraits à côté puis basculés par renommage : aucun audit ne voit un bundle à moitié extrait.
- **Cache des sondes** : un résultat est oublié quand l'exécutable change, après toute installation (`~/.compliance/tools/.generation`), ou au bout de 60 secondes pour un échec. `POST /api/v1/tools/invalidate` le vide.
- **PATH vivant** : chaque plan et audit ajoute au PATH du démon les dossiers du PATH de la fenêtre et, sous Windows, du PATH du registre. Un outil installé après le démarrage de VS Code est trouvé sans redémarrage.
- **Plusieurs fenêtres** : fermer ou recharger une fenêtre n'arrête plus le démon des autres. Chaque fenêtre s'enregistre (`/api/v1/clients`) ; le démon s'arrête seul 30 minutes après le départ de la dernière (`COMPLIANCE_DAEMON_IDLE_MINUTES`, 0 désactive). Un démon lancé à la main ne s'arrête jamais seul.
- **Barre d'état** : état du moteur (démarrage, prêt, mise à jour d'outils, indisponible), activité en cours, progression par outil pendant une installation.
- **Selftest** : 24 étapes, avec le verrou des outils, le PATH vivant, la rotation du journal et la capture complète des sorties.

## 2.1.3

- **Sonde et installation** : un outil présent dont la qualification échoue ou expire reste un échec de sonde (`probe_failed`). Il n'est plus réécrit en « Outil installable depuis le manifeste » et ne relance pas l'installation. Seul un outil absent du disque et déclaré au manifeste reste `tool_unavailable`.
- **Checkov** : la qualification importe le module et affiche sa version, avec un délai de 60 secondes. L'interpréteur reçoit `PYTHONNOUSERSITE=1`, un `PYTHONPATH` vide et `PYTHONDONTWRITEBYTECODE=1`. L'extraction Windows utilise les chemins étendus au-delà de 248 caractères.
- **Trivy** : la qualification impose `TRIVY_SKIP_VERSION_CHECK`, `TRIVY_SKIP_DB_UPDATE`, `TRIVY_DISABLE_TELEMETRY` et un cache sous `~/.compliance/cache/trivy`. Une sortie vide au code 1 est réessayée une fois sans console masquée, puis le rapport nomme le binaire.
- **Certificats et proxy** : le bundle d'entreprise (`COMPLIANCE_CA_BUNDLE`, `SSL_CERT_FILE`, fichier local, puis magasin Windows) est injecté dans les sondes, les contrôles et les téléchargements (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`). Les variables de proxy du processus sont conservées. Une somme SHA-256 divergente refuse l'exécutable.

## 2.1.2

- **Marketplace VS Code** : l'identifiant technique est `compliance-pipelines` (`compliance-platform.compliance-pipelines`). Le nom affiché sur le Marketplace est « ICP IaC Compliance Platform », l'ancien libellé restant réservé par la fiche précédente. Le manifeste déclare `GalleryFlags` Public et la cible `Microsoft.VisualStudio.Code`. `package.json` contient `engines.vscode` et aucune clé `private`.

## 2.1.1

- **Marketplace** : republication publique. `package.json` ne contient pas de clé `private`. La version 2.1.0, déjà déposée, ne peut pas être réécrite.

## 2.1.0

- **Registre vivant** : le démon compare `runtime-manifest.json` et `control-catalog.json` publiés sur la release `tools-v1` au cache `~/.compliance/registry-cache/`, puis aux fichiers embarqués. Un outil déjà installé est remplacé quand le manifeste distant annonce une version plus haute. Hors ligne, le cache puis les fichiers du binaire suffisent. Le `.vsix` n'a pas à être réinstallé.
- **Une commande par linter** : `.config/tools-lock.json` concentre les versions. `py scripts/build_and_publish_tools.py --only ruff` reconstruit et publie cet outil, le manifeste et le catalogue.

## 2.0.20

- **Racines imbriquées** : pour `hadolint`, `trivy`, `shellcheck`, `ruff`, `pylint`, `bandit` et `pytest`, la racine parente n'audite plus les fichiers déjà couverts par une sous-racine planifiée du même outil. Un même fichier n'est plus compté deux fois.
- **pip-audit** : chaque dépendance sans version exacte est une anomalie avec le fichier `requirements*.txt` et la ligne. L'outil n'est lancé que sur les lignes épinglées. Une erreur de résolution nomme le fichier concerné.
- **Verdict** : la phrase sans accent « Au moins un controle de conformite echoue. » n'est plus répétée à côté de la raison déjà affichée.

## 2.0.19

- **Compteurs du rapport** : Applicables ne compte plus un contrôle écarté (`ambiguous`, alternative non retenue, non applicable, technologie absente, plateforme non prise en charge, réglage local). Le bandeau et la section Indisponibles utilisent le même nombre. Les sections Lacunes de couverture et Indisponibles listent les raisons dédoublonnées et disparaissent quand elles valent 0.
- **Parseurs** : `yamllint -f parsable` ne reçoit `-c` que si le fichier de configuration existe, et chaque ligne Windows devient une anomalie. `pip-audit` ignore une racine sans `requirements*.txt` ni `pyproject.toml` au lieu d'auditer l'environnement global, et rapporte chaque dépendance non épinglée. `bandit` émet une ligne par anomalie pour que le JSON `metrics` tronqué ne se résume plus à une seule anomalie générique.
- **ESLint** : sans `eslint.config.js` ni `.eslintrc`, le moteur passe `--no-config-lookup` et une configuration minimale de règles de base, y compris pour TypeScript, au lieu de laisser JavaScript et TypeScript en couverture partielle.
- **Documentation** : l'autorisation machine unique et l'installation silencieuse sont décrites dans la documentation de l'extension. `docs/outils.md` est repris dans `docs/architecture.md` pour ne plus répéter le registre, le résolveur et la signature.

## 2.0.18

- **Rapports de gros dépôts** : la lecture d'un `compliance-report.json` n'a plus de plafond (le rapport `content`, 74 Mo, était rejeté à 32 Mo). La validation HTTP n'envoie plus les findings ni les sorties capturées. Le panneau s'ouvre sur les compteurs et les contrôles ; les fichiers et les lignes se chargent à l'ouverture du contrôle, sans construire des dizaines de milliers de lignes d'un coup.
- **Autorisation machine unique** : un seul dialogue mémorisé couvre l'installation des outils du registre, le réseau et l'exécution de code. Il n'est plus redemandé à chaque outil, à chaque session ni à chaque dépôt. La commande **ICP: Autoriser Compliance sur cette machine** permet de revenir sur un refus.

## 2.0.16

- **Suppression définitive de `npm install`** : Le binaire Go (`compliance runtime sync`, `compliance runtime node`) et l'extension VS Code n'appellent plus jamais `npm install`. L'installation de `eslint` et `tsc` télécharge et extrait directement le bundle `node` (`windows-x64-node-tools-22.14.0.zip`) depuis le registre `tools-v1`.
- **Sécurisation de l'extraction d'archives (anti-évasion Tar)** : Interdiction absolue des liens symboliques pointant vers des chemins absolus (`/`, `\`, disques) ou s'échappant hors du répertoire de destination via des segments relatifs (`../`). Suppression du repli de lecture de fichiers arbitraires hors destination.
- **Sécurisation des jetons de registre** : Le jeton d'authentification du registre n'est plus jamais passé sur la ligne de commande (`-registry-token`). Il est transmis exclusivement au sous-processus via la variable d'environnement `COMPLIANCE_REGISTRY_TOKEN`.
- **Confinement Job Object sous Windows** : En cas d'échec d'assignation du processus enfant au Windows Job Object (`assignProcessToJob`), le processus créé est immédiatement terminé pour éliminer tout risque d'orphelin.
- **Transparence SHA-256 et signatures Ed25519** : Les divergences de somme SHA-256 ou d'intégrité de signature de manifeste émettent un avertissement explicite (`[WARN]`) dans les logs sans bloquer l'installation, assurant le bon fonctionnement sur les miroirs d'entreprise.
- **Purge d'artefacts et assainissement du code** : Nettoyage des anciens fichiers VSIX versionnés (65+ Mo libérés), suppression des images et fragments orphelins, élimination du code mort des pipelines déclaratifs inutilisés (`LoadPipelineFile`, `ValidateDAG`, `ComputeTopologicalOrder`), et vérification stricte des écritures disque du serveur.
- **Documentation et matrice des plateformes** : Documentation explicite de la couverture du registre (10 binaires natifs pour les 5 plateformes cibles, bundles Python, Node et PSScriptAnalyzer qualifiés pour Windows x64 sur `tools-v1`).

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
