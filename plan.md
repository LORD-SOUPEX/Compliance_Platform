# Compliance_Platform

## Vision

## Finalité

`Compliance_Platform` est un moteur portable d'analyse de dépôt, de conformité,
d'audit, de qualité et de standardisation. Il examine uniquement le contenu d'un
repository local fourni par l'utilisateur, éventuellement accompagné d'un
fichier de configuration. Il ne gouverne aucun hébergeur Git et ne requiert
aucune intégration à une forge.

Son usage est volontaire et à la demande. Après avoir cloné et développé un
projet, l'utilisateur choisit ou non de lancer Compliance_Platform. Le moteur
analyse le dépôt, découvre ses technologies, construit un plan d'exécution,
exécute les contrôles et fournit un rapport avec un verdict `PASS` ou `FAIL`.
Ce verdict est un avis sur les résultats du scan, pas une autorisation technique:
il ne bloque ni commit, ni push, ni merge. La décision finale reste humaine.

Le moteur est indépendant de GitLab, GitHub, Bitbucket, Azure DevOps et de tout
autre fournisseur. Il peut être lancé depuis VS Code, PowerShell, Bash, une tâche
CI choisie par l'utilisateur, un adaptateur de forge optionnel ou entièrement
hors CI. Ces interfaces transmettent un chemin local et une configuration
éventuelle; elles ne changent pas la nature consultative du verdict.

Compliance_Platform fournit également son propre runtime partagé d'outils. Un
bootstrap exécuté à l'installation initiale ou lors d'une mise à jour prépare
les outils supportés, vérifie leurs versions et leur intégrité, puis les conserve
dans un cache géré par la plateforme. Pour chaque dépôt, le Tool Resolver choisit
uniquement les outils correspondant aux technologies détectées. Les outils ne
sont pas installés ni dupliqués dans les repositories analysés.

Une plateforme d'exécution est définie par la paire système d'exploitation et
architecture processeur (`OS + architecture`). La cible comprend Windows x64 et
ARM64, Linux x64 et ARM64, macOS Intel x64 et Apple Silicon ARM64. Ces cibles ne
sont pas toutes déjà qualifiées: le socle observé reste principalement Windows
x64 et PowerShell 5.1, et ses relais Bash ne constituent pas un runtime natif
Linux/macOS. Le plan distinguera les plateformes ciblées, qualifiées sur preuves,
et expérimentales, sans déclarer une combinaison supportée avant sa qualification.

## Périmètre de ce document

État du projet audité le 6 octobre 2026 à partir du code, des tests, des
configurations, de l'index runtime et des rapports locaux. Quick et Full ont été
réexécutés pendant cet audit documentaire; aucun script, outil, verrou ou hook
n'a été corrigé. Ce fichier est la source de vérité pour la
vision, les statuts d'implémentation et les priorités. Les preuves indiquent leur
date et leur portée; un échec d'environnement ou de sécurité reste distinct d'une
capacité implémentée.

Les descriptions de finalité et d'architecture cible expriment des objectifs,
pas des garanties déjà livrées. Les écarts observés figurent dans l'état actuel
et les phases existantes ci-dessous. Les détails opérationnels sont maintenus
dans [docs/architecture-current.md](docs/architecture-current.md) et les preuves
de cet audit dans [docs/testing.md](docs/testing.md).

Le cycle d'implementation suivant a repare le cache pre-commit deplace et les
erreurs Markdown ainsi exposees. Bootstrap termine en code 0 et positionne
`windows-x64` a `qualified` dans son index. Quick: 10 PASS, 0 FAIL, 1 WARN,
6 SKIP, 0 ERROR, code 0. La suite comporte desormais 38 tests reussis. La
qualification poste neuf/runner et les vulnerabilites Checkov restent ouvertes;
les resultats de l'audit documentaire ci-dessous sont historiques.

Full du cycle: 11 PASS, 1 FAIL, 1 WARN, 6 SKIP, 0 ERROR, code 1; seul
pip-audit echoue. Checkov 3.3.25 publie conserve les contraintes asteval 1.0.6
et ecdsa >=0.19.0,<1.0.0; ecdsa 0.19.2 reste la derniere version publiee
observee. Une mise a jour simple ne satisfait donc pas Full sans masquer le risque.

Le cycle integrite ajoute la verification SHA-256 des binaires indexes a la
resolution et avant execution, y compris les copies `.tools/bin`. L'empreinte
absente/invalide, l'alteration et le schema d'index invalide sont refuses. La
suite compte 39 tests reussis; paquets Python et modules hors index restent ouverts.

## Principes proposés

- Séparer la présence d'une technologie, la disponibilité de ses outils et la
  conformité du projet: ces trois notions ne sont pas interchangeables.
- Mutualiser les capacités communes tout en conservant une exécution adaptée aux
  systèmes, aux services et aux niveaux de confiance.
- Si le moteur est lancé localement ou en CI, appliquer la même politique de
  référence, sans exiger que les analyses soient exécutées à chaque commit.
- Rendre explicables les contrôles sélectionnés, les limites, les exclusions et
  les verdicts et recommandations.
- Distinguer observation, installation, correction et opérations à effets de bord.
- Conserver la règle de non-déploiement implicite: aucun contrôle ne doit autoriser
  silencieusement une action sur une infrastructure réelle.
- Étendre progressivement le socle après qualification, sans réécriture générale
  préalable ni accumulation immédiate de nouvelles technologies.
- Traiter Compliance_Platform comme le produit commun et les dépôts métier comme
  ses consommateurs, avec des versions et des résultats traçables.
- Séparer la mesure technique, la décision de politique et l'acceptation
  organisationnelle d'un risque.
- Privilégier l'audit à la demande et la validation volontaire; ne pas imposer
  l'adoption du moteur ni conditionner les opérations Git à son verdict.
- Maintenir le cœur agnostique des forges: seules des interfaces optionnelles
  connaissent leur environnement d'appel ou de publication.
- Préparer et maintenir les outils dans un runtime partagé de Compliance_Platform,
  jamais dans chaque repository analysé.
- Exécuter le bootstrap à l'installation ou lors des mises à jour, puis réutiliser
  le cache local pour les audits successifs.
- Résoudre les outils après détection des technologies et ne lancer que les
  contrôles pertinents pour le dépôt.
- Viser Windows, Linux et macOS sans présenter cette cible comme déjà qualifiée.
- Définir chaque plateforme comme un couple OS + architecture et suivre
  séparément les états ciblé, qualifié et expérimental.
- Garder le moteur générique: les technologies consomment ses capacités et ne
  dictent pas son architecture ni ne dupliquent ses composants communs.

## Indépendance technologique

Compliance_Platform n'est conçue autour d'aucune technologie particulière.
Terraform, OpenTofu, Terragrunt, Ansible, Python, PowerShell, Docker, Kubernetes,
Helm, Shell, JavaScript, TypeScript et toute technologie future sont des
consommateurs du moteur générique.

La plateforme reste propriétaire du bootstrap, du runtime, du Tool Resolver,
de la Capability Matrix, de l'exécution, du moteur de conformité, du reporting
et du calcul du verdict. Une technologie contribue uniquement des détecteurs,
des contrôles, des capacités, des outils spécialisés et des règles d'applicabilité.
L'ajout d'une technologie ne doit pas imposer une réécriture du moteur, une
duplication des composants communs, une architecture dédiée ou une logique
spécifique dispersée dans plusieurs composants.

## Réutilisation raisonnée

Compliance_Platform peut réutiliser un outil open source lorsqu'une évaluation
démontre sa valeur. L'intégration d'un outil tiers n'est jamais une fin en soi.
Avant de le retenir, il faut peser la valeur apportée, la complexité, la
maintenabilité, la sécurité, la pérennité, la portabilité et le coût opérationnel.

Un outil externe mature peut éviter de réinventer un composant complexe; une
orchestration native peut être préférable lorsqu'elle reste plus simple et
maîtrisable. Aucune dépendance ou marque d'outil n'est imposée par le plan.
mise, asdf, MegaLinter, pre-commit, OPA, Trivy, Checkov et Terrascan sont des
pistes d'étude remplaçables, pas des décisions d'architecture.

## État actuel

## Inventaire objectif

| Élément présent | Réalité observée | Potentiel de réutilisation |
| --- | --- | --- |
| [README.md](README.md) | Documentation Windows, modes, outils, limites et blocage de sécurité | Documentation de référence et point d'entrée des consommateurs |
| [scripts/bootstrap.ps1](scripts/bootstrap.ps1) | Recherche Python 3.11, installation locale, vérification des archives, paquets et hooks | Expérience d'installation et catalogue de distribution |
| [scripts/doctor.ps1](scripts/doctor.ps1) | Diagnostic des versions, exécutables, fichiers et hygiène; réparation limitée sur demande | Futur diagnostic de capacités et de conformité |
| [scripts/quality-gate.ps1](scripts/quality-gate.ps1) | Détection et orchestration multi-technologies dans un script | Comportements de référence à stabiliser avant séparation |
| [scripts/check-emoji.ps1](scripts/check-emoji.ps1) | Contrôle des pictogrammes dans les textes, avec exclusions des contenus générés | Exemple de contrôle transverse indépendant d'une technologie métier |
| [scripts/test.ps1](scripts/test.ps1) | Tests PowerShell du socle et éventuels tests Python avec couverture | Point d'entrée de validation |
| [scripts/quality-gate.sh](scripts/quality-gate.sh) et autres relais Bash | Relais vers Windows PowerShell, pas moteurs Linux/macOS | Compatibilité Git Bash à conserver tant qu'elle est utile |
| [.config/tool-versions.yml](.config/tool-versions.yml) | Catalogue de versions, sources, emplacements et sommes disponibles | Base d'un catalogue d'outils gouverné |
| [requirements-dev.txt](requirements-dev.txt) et [requirements-dev.lock](requirements-dev.lock) | Versions directes et verrou de 154 paquets directs/transitifs pour Windows/Python 3.11 | Base de reproductibilité à compléter et qualifier |
| [.config/quality-gate.yml](.config/quality-gate.yml) | Politique descriptive: statuts, seuils, exclusions et modes | Point de départ du futur catalogue déclaratif |
| [pyproject.toml](pyproject.toml) | Paramètres Ruff, Pylint, mypy, pytest, couverture et Bandit | Standards Python initiaux, pas un produit Python métier |
| [.pre-commit-config.yaml](.pre-commit-config.yaml) | Hooks génériques, Ruff, YAML, Markdown, secrets et catégories du gate | Adaptateur local existant |
| [.vscode/tasks.json](.vscode/tasks.json) | Tâches bootstrap, Doctor, Quick, Full, Fix, Ci, hooks et tests | Expérience développeur déjà accessible |
| [.vscode/settings.json](.vscode/settings.json) et [.vscode/extensions.json](.vscode/extensions.json) | Interpréteur local, hygiène des fichiers et recommandations d'extensions | Expérience développeur facultative; ni source de vérité ni prérequis des contrôles |
| [.gitlab-ci.yml](.gitlab-ci.yml) | Un job Windows sans `allow_failure`, rapports conservés sept jours | Point d'entrée CI du socle; son échec n'est pas rendu consultatif |
| [tests/integration/quality-gate.Tests.ps1](tests/integration/quality-gate.Tests.ps1) | 37 scénarios PowerShell sur Discovery, Matrix, Resolver, Runtime, exclusions, formats, processus et rapports | Fixtures synthétiques; pas de corpus réel de repositories consommateurs |
| [.github/copilot-instructions.md](.github/copilot-instructions.md) et [.github/merge_request_template.md](.github/merge_request_template.md) | Consignes et checklist de contribution | Premiers supports de gouvernance humaine |
| [.gitleaks.toml](.gitleaks.toml), [.yamllint.yml](.yamllint.yml), [.markdownlint.json](.markdownlint.json) et [.config/PSScriptAnalyzerSettings.psd1](.config/PSScriptAnalyzerSettings.psd1) | Paramètres spécialisés des contrôles | Règles existantes à inventorier et justifier |
| [.editorconfig](.editorconfig), [.gitattributes](.gitattributes) et [.gitignore](.gitignore) | Conventions de fichiers et exclusion des environnements, caches et rapports | Standards transverses à conserver |
| [docs/](docs/) | Documentation des composants actuels, limites, statuts et tests | Détails opérationnels liés depuis README et ce plan |

`src/` et `tests/unit/` contiennent uniquement des fichiers de maintien des dossiers.
Il n'existe pas de code métier, de services consommateurs de démonstration, de
registre de plugins, ni de catalogue exécuté par un moteur indépendant.

Les environnements `.venv/`, les outils et caches `.tools/`, ainsi que les rapports
locaux existent sur ce poste. Leur présence n'est pas une preuve de disponibilité
sur un poste neuf ou un runner différent.

L'état Git consulté montre le README modifié et une grande partie du socle encore
non suivie. L'analyse porte donc sur le workspace réel, et non sur une version
publiée ou déjà reproductible depuis un clone. Aucune régularisation Git n'est
réalisée dans cette phase.

## Niveau de validation disponible

Les rapports existants et les réexécutions du 6 octobre 2026 sont distingués:

| Preuve existante | Résultat enregistré | Limite d'interprétation |
| --- | --- | --- |
| [reports/doctor-report.json](reports/doctor-report.json) | 67 PASS, aucun FAIL ou ERROR, 3 SKIP | Disponibilité et hygiène sur le poste observé, pas certification de sécurité |
| [reports/quick.json](reports/quick.json), preuve antérieure du jour | 9 PASS, 1 FAIL, 1 WARN, 6 SKIP | Rapport non réécrit pendant cet audit; échec Markdownlint/cache pre-commit |
| [reports/full.json](reports/full.json), preuve antérieure du jour | 10 PASS, 2 FAIL, 1 WARN, 6 SKIP | Rapport non réécrit; Markdownlint et audit des dépendances échouent |
| Réexécution Quick pendant cet audit, sans `-ReportPath` | 9 PASS, 1 FAIL, 1 WARN, 6 SKIP, 0 ERROR; code 1 | Markdownlint reproduit le chemin obsolète; ShellCheck absent sous Windows |
| Réexécution Full pendant cet audit, sans `-ReportPath` | 10 PASS, 2 FAIL, 1 WARN, 6 SKIP, 0 ERROR; code 1 | Inclut les 37 tests réussis et un audit réseau des dépendances de la plateforme |
| [reports/quality-report.json](reports/quality-report.json) | Rapport Ci antérieur: 11 PASS, 1 FAIL, 1 WARN, 6 SKIP | Preuve historique, distincte du Full courant; pas une exécution GitLab distante |
| Exécution actuelle de `scripts/test.ps1` | 37 PASS, 0 FAIL | Tests PowerShell complets; aucun test Python métier n'est présent. Full exécute également la suite |
| Dernière exécution documentée de `scripts/bootstrap.ps1` | Python 3.11 et cinq binaires vérifiés/indexés | Code 1 aux hooks; non relancée pendant l'audit; index relu: `windows-x64: experimental` |

Le corpus actuel comprend 37 scénarios PowerShell, dont les tests Discovery,
Capability Matrix, Tool Resolver et Tool Runtime. Ils valident des fixtures
synthétiques; ils ne mesurent pas la précision sur un corpus de repositories
réels ni ne qualifient toutes les plateformes OS + architecture.

Le Bootstrap a été exécuté après recréation de `.venv`. Python, dépendances et
cinq binaires (Gitleaks, TFLint, Terragrunt, Hadolint, Trivy) ont été vérifiés et
inscrits dans `.tools/runtime/index.json` pour `windows-x64`. L'index porte le
statut `experimental`: le bootstrap s'arrête à l'installation pre-commit car un
clone du hook utilise encore l'ancien emplacement `service-manager-template` absent.
Il n'atteint donc pas l'étape de qualification finale.

Full a réinterrogé les avis et affiché quatre lignes pour `asteval==1.0.6` et
`ecdsa==0.19.2`, avec un identifiant ecdsa répété. Les avis asteval annoncent 1.0.9
comme correction; les métadonnées installées de Checkov 3.3.23 imposent néanmoins
`asteval==1.0.6`. Aucune version corrective ecdsa n'est affichée. Les identifiants,
pins et limites d'interprétation sont conservés dans [docs/testing.md](docs/testing.md).
Le JSON du gate n'enregistre pas ces avis structurés. Aucune dépendance ni
exclusion n'a été modifiée pour obtenir un succès.

Les cinq artefacts de l'index runtime ont été contrôlés en lecture seule: ils
existent et leurs SHA-256 recalculés correspondent à l'index local. Les 73 liens
Markdown locaux du périmètre documentaire sont valides, ancre Roadmap incluse;
aucun nouveau document ni déplacement n'a été nécessaire. Markdownlint reste
non exécuté sur le contenu à cause de son cache invalide.

## Bilan d'implémentation audité

| Composant | Fonctionnalités achevées dans le socle | État et éléments manquants |
| --- | --- | --- |
| Discovery Engine | CLI externe, JSON v1, 13 technologies, preuves, racines, ambiguïtés | Partiel: corpus réel, overrides, exclusion configurable, limites de lecture et racines mixtes non qualifiés |
| Tool Bootstrap | Installation locale épinglée, vérification des téléchargements binaires, copie/indexation multiversion | Partiel: hooks en échec, qualification poste neuf/runner et autres plateformes absente |
| Tool Runtime | Index v1, version active, chemin relatif, SHA-256 enregistré et statuts | Partiel: cinq binaires Windows x64, plateforme expérimentale; paquets/modules hors index, hash non revérifié à l'usage |
| Capability Matrix | Capacités et candidats par technologie, disponibilités et motifs OS + architecture | Partiel: profils en code, disponibilité fondée sur présence, alternatives et exécution native non qualifiées |
| Tool Resolver | Sélection des candidats disponibles, déduplication par commande au sein d'une technologie, refus des ambiguïtés | Partiel: sélection descriptive de tous les candidats disponibles, sans pilotage Quick/Full ni déduplication globale |
| Compliance Engine | Exécuteur et séquence historique réutilisables | Aucun composant autonome ni plan générique; audit externe et garanties d'effets de bord incomplets |
| Control Catalog | Fonctions de contrôles et profils de capacités présents | Aucun catalogue indépendant chargé à l'exécution |
| Reporting Engine | JSON Discovery versionné et JSON du gate, résumé/code testés | Aucun composant commun; pas de verdict explicite, versions moteur/politique ou rapport garanti sur exception |
| Policy Engine | YAML descriptif et règles codées du gate | Aucun moteur, profil consommateur ou cycle d'exceptions évalué |
| Optional Integrations | Relais Bash Windows, tâches VS Code, hooks et job GitLab du socle | Aucun adaptateur produit portable; hooks/CI peuvent bloquer contrairement à la cible consultative |
| Industrialisation | Pins, contraintes, cache local et 37 tests synthétiques | Non commencée comme qualification produit multi-plateforme reproductible |

Une fonctionnalité implémentée ne suffit pas à clore la phase qui la contient.
Aucune phase entière n'atteint actuellement tous ses critères de sortie.

## Forces du socle

- Le gate est déjà multi-technologies: il ne se limite pas à Terraform.
- Les points d'entrée, les statuts et les modes sont explicites et utilisables
  depuis le terminal, VS Code et une CI Windows.
- Les installations et caches sont locaux; les versions et sources sont
  identifiées, avec vérification des sommes pour les archives concernées. Il
  s'agit du socle actuel et non encore du runtime partagé cible.
- Les contrôles possèdent des cas négatifs: outil absent, code non nul, délai
  dépassé, formats invalides et pictogrammes refusés.
- Les dossiers générés sont écartés avant parcours et les liens de réanalyse
  ne sont pas suivis, ce qui limite récursion et coûts inutiles.
- L'exécution des processus dispose d'une base commune avec capture des sorties
  et délai, et les rapports évitent la sérialisation récursive des objets fichiers.
- Les limites Windows et le blocage de sécurité sont visibles; l'échec de Full
  n'est pas transformé en succès artificiel.
- La documentation et les consignes imposent absence de secrets, de pictogrammes
  et d'actions d'infrastructure destructives.

## Limitations structurantes

1. Discovery, Capability Matrix, Tool Resolver et orchestration des contrôles
  sont encore implémentés dans `scripts/quality-gate.ps1`; il n'existe pas de
  modules autonomes ou de contrats séparés.
2. La politique YAML n'est pas consommée par le gate. Les seuils, exclusions,
   catégories et règles de blocage restent codés dans plusieurs composants.
3. Les versions sont répétées entre catalogue, dépendances, hooks et Doctor.
   Le bootstrap lit des portions YAML par expressions régulières, sensibles à
   leur représentation et non à un véritable schéma validé.
4. Tous les outils Python, notamment Checkov et Ansible, partagent `.venv` même
   lorsque leur technologie n'est pas présente. Full audite cet environnement
   commun: une dépendance IaC bloque donc également un dépôt sans IaC.
5. Windows x64 et PowerShell 5.1 sont la seule référence opérationnelle.
   Les relais Bash ne fournissent pas de prise en charge Linux/macOS.
6. Discovery accepte désormais un chemin externe et retourne des preuves,
  racines, ambiguïtés, matrice et résolution JSON. Les marqueurs restent
  heuristiques et leur précision n'a pas été évaluée sur des repositories réels.
7. Les rapports ne sont pas un contrat versionné de preuves: ils donnent des
   statuts de contrôles, mais peu de diagnostics normalisés, de provenance ou de
   justification du choix des contrôles.
8. Les recommandations VS Code ne vérifient ni l'installation ni les versions
   des extensions. Il n'existe pas de gestion centralisée de conformité du poste.
9. La CI possède un seul job, sans orchestration par capacités, sans matrice
   de systèmes qualifiés et sans consommation démontrée par plusieurs services.
10. Les règles, exceptions et dérogations ne disposent pas d'un cycle de vie
    formalisé avec propriétaire, approbation et expiration.
11. `-RepositoryPath` ne suffit pas à auditer un consommateur autonome: plusieurs
  contrôles cherchent outils/configurations dans ce dépôt, Terraform y crée des
  caches et les tests exécutés sont ceux de la plateforme. Les racines Discovery
  ne pilotent pas l'exécution.
12. Le caractère consultatif cible n'est pas assuré par les hooks et la CI du
  socle: les codes non nuls y sont propagés. Le gate ne lance toutefois aucune
  opération Git lui-même.

## Risques techniques à prioriser

| Risque | Origine concrète | Orientation à instruire |
| --- | --- | --- |
| Diffusion d'un socle non qualifié | Full courant est bloqué par pip-audit (`asteval`, `ecdsa`) et l'index runtime reste expérimental | Maintenir le blocage visible et résoudre ou arbitrer les vulnérabilités avant qualification |
| Illusion de source de vérité | Politique YAML descriptive et décisions effectives codées en dur | Choisir une politique authoritative, puis une migration vérifiée |
| Divergence d'applicabilité | Doctor détecte moins de marqueurs Ansible que le gate; optionalité différente selon installation et analyse | Partager les notions de capacité, présence et obligation |
| Diagnostic incohérent avec l'installation | Bootstrap accepte Python existant, Doctor exige aussi un runtime dans `.tools/python`; Terragrunt peut être omis puis exigé par Doctor | Définir la conformité d'un poste à partir de son profil effectif |
| Reproductibilité incomplète | Verrou Windows sans empreintes des roues; environnements des hooks et dépendances Node distincts | Définir le périmètre exact des verrous, plateformes et preuves de provenance |
| Risque de chaîne d'approvisionnement | Téléchargements externes, module PowerShell sans somme publiée dans le catalogue, plugins futurs | Sources approuvées, garanties de provenance et procédure de mise à jour |
| Portabilité supposée | Bootstrap refuse les OS autres que Windows et les architectures autres que x64; chemins `Scripts`, `.exe` et `taskkill` | Qualifier chaque couple OS + architecture avant de le déclarer supporté |
| Couverture annoncée supérieure à la couverture réelle | Parseur PowerShell sur les fichiers détectés, PSScriptAnalyzer limité à `scripts/`; Python applicatif classé hors `tests/`, couverture liée à `src/` | Définir les unités d'analyse et les sources réellement couvertes |
| Faux positifs et faux négatifs | YAML Ansible par motif `hosts`, règles Docker par expressions régulières, `.tf` non distinctif entre Terraform et OpenTofu | Combiner signaux et preuves structurées, traiter les ambiguïtés |
| Mauvais périmètre d'exécution | Terraform détecté récursivement mais init et validate lancés à la racine; `.dockerignore` attendu à la racine | Identifier les racines de projets et contextes des contrôles |
| Effets de bord et accès réseau | Init Terraform sans backend, audits réseau, hooks correctifs, futur Molecule avec driver | Classer les contrôles par effets, permissions et contexte autorisé |
| Délai et rapport incomplets | Certains appels Git/TOML ou Doctor ne passent pas par l'exécuteur borné; une exception globale peut sortir sans rapport final | Garanties d'exécution, annulation et restitution à définir |
| Diagnostics volumineux ou sensibles | Sorties externes capturées en mémoire; masquage dépendant de chaque outil | Limites de ressources, politique de logs et confidentialité |
| Contournement de périmètre | Une catégorie seule peut réussir sans tous les contrôles de Full; hooks limités aux fichiers Git connus | Identifier explicitement une validation partielle et le périmètre couvert |
| Exceptions invisibles à l'échelle | Règles Markdown et Pylint déjà désactivées, sans registre gouverné associé | Inventorier et justifier ces choix sans nouvelle désactivation |
| Tests couplés aux détails internes | Chargement des fonctions par AST et dépendance aux variables de portée du script | Préserver les cas, puis tester des contrats stables lors d'une évolution autorisée |
| Intégrité annoncée sans revérification à l'usage | Resolver vérifie chemin et présence, pas SHA-256; bootstrap réutilise un binaire local sur sa seule version | Séparer empreinte enregistrée, provenance officielle et vérification avant exécution |
| Support déduit de la seule présence | Lanceur ansible-lint ou pre-commit présent peut être `available` sans exécution native/hook fonctionnel | Qualifier les capacités réellement exécutables, pas uniquement les commandes résolues |
| Verdict consultatif non assuré par les adaptateurs actuels | Hook pre-commit et job GitLab propagent les codes non nuls | Préserver le gate du socle et qualifier séparément les futurs adaptateurs consommateurs |

## Consumer Architecture

## Dépôt analysé

Le dépôt analysé est un repository local déjà disponible sur le poste ou le
runner de l'utilisateur. Compliance_Platform reçoit son chemin et, facultativement,
un fichier de configuration. L'utilisateur choisit le dépôt et le moment de
l'analyse; aucun enregistrement central du projet, accès distant à une forge,
jeton Git ou installation obligatoire dans le dépôt n'est requis par le moteur.

Le dépôt garde son code, ses tests, son cycle de livraison et ses contraintes
métier. Il peut fournir un profil ou des paramètres pour préciser le périmètre,
mais ces informations ne sont pas une intégration de forge et ne rendent pas
l'exécution obligatoire.

## Utilisation volontaire

Le workflow est: clone d'un projet, développement, choix de l'utilisateur de
lancer ou non Compliance_Platform, scan local, rapport et décision humaine.
L'analyse peut être déclenchée depuis VS Code, PowerShell, Bash, une tâche CI,
un adaptateur optionnel ou hors CI. L'utilisateur conserve la possibilité de
commit, push et merger, que le verdict soit `PASS`, `FAIL` ou indisponible.

Le verdict exprime les résultats des contrôles et les limites du scan. `PASS`
ne signifie pas qu'un push est autorisé ou requis; `FAIL` ne déclenche aucun
blocage technique. Compliance_Platform formule un avis et des recommandations;
la personne responsable décide des suites à donner.

## Repository Assessment Workflow

**État actuel: implémenté pour DiscoveryOnly et partiellement intégré au Quality Gate.**
L'interface accepte un chemin externe, retourne les preuves et les structures
Discovery/Matrix/Resolver; les contrôles Quick/Full utilisent encore l'orchestration
historique du script.

Le workflow en huit étapes ci-dessous reste la cible. Le resolver ne pilote pas
encore l'exécution et la CLI n'accepte pas de configuration facultative. Discovery
peut écrire un rapport sur demande; Quick/Full peuvent écrire des caches et des
rapports dans le dépôt analysé. Le partage sans installation ni écriture côté
consommateur n'est donc pas encore garanti.

Avant le premier audit, l'utilisateur initialise Compliance_Platform: Tool Bootstrap
télécharge et vérifie une fois les outils supportés, puis les place dans le cache
local partagé. Les mises à jour réexécutent le bootstrap; un audit ordinaire
réutilise le runtime sans installer d'outils dans le repository.

Le workflow d'audit reçoit ensuite un chemin vers un repository local et, si
nécessaire, une configuration. Il fonctionne de la même manière quel que soit le
fournisseur Git ou le mode de lancement.

1. **Scan du dépôt**: parcourir le contenu local dans le périmètre demandé,
  appliquer les exclusions configurées et relever les limites de lecture.
2. **Détection des technologies**: identifier les technologies et unités de
  projet à partir des fichiers, formats et déclarations disponibles.
3. **Construction du plan**: sélectionner et ordonner les contrôles applicables
  selon les technologies découvertes, le profil et la configuration.
4. **Résolution des outils**: choisir dans le Tool Runtime partagé uniquement
  les versions nécessaires aux contrôles retenus.
5. **Exécution des contrôles**: exécuter les analyses prévues avec leurs limites
  de temps, ressources, permissions et effets de bord documentés.
6. **Agrégation des résultats**: consolider les constats, sévérités, statuts,
  erreurs techniques et contrôles non exécutés sans masquer leurs distinctions.
7. **Génération du rapport**: produire un rapport local standardisé, traçable et
  exploitable, comprenant le périmètre, les versions, les constats et les limites.
8. **Verdict**: calculer `PASS` ou `FAIL` à partir des résultats et de la
  politique appliquée, puis présenter les recommandations à l'utilisateur.

`PASS` ne constitue pas une condition pour commit, push ou merge. `FAIL` ne bloque
pas automatiquement le dépôt, une branche ou une merge request. Le moteur fournit
un avis; l'utilisateur ou l'organisation décide volontairement de son usage.

## Tool Bootstrap

**État actuel: partiel.** Le bootstrap vérifie et indexe cinq binaires Windows x64,
mais ne termine pas l'installation pre-commit dans l'environnement présent. Il
ne gère pas encore toutes les dépendances Python/PowerShell dans l'index Runtime.

Le Tool Bootstrap prépare le runtime central de Compliance_Platform. Il est
exécuté une fois lors de l'installation initiale, puis uniquement lors d'une
mise à jour explicite ou planifiée du moteur et de son catalogue d'outils. Un
scan ordinaire réutilise le runtime préparé et ne réinstalle pas les outils.

Ses responsabilités sont:

- télécharger les outils supportés et les dépendances nécessaires depuis des
  sources approuvées;
- sélectionner, installer ou extraire les artefacts correspondant à la
  plateforme d'exécution exacte (OS + architecture);
- vérifier les versions attendues, les empreintes ou signatures disponibles et
  l'intégrité des artefacts avant leur activation;
- consigner pour chaque artefact les plateformes ciblées, qualifiées ou
  expérimentales, sans confondre publication d'un binaire et support qualifié;
- gérer les mises à jour, la compatibilité, le remplacement et le retour à une
  version précédente;
- préparer et valider l'environnement d'exécution partagé, sans modifier le
  PATH système ni installer d'outils dans le dépôt analysé.

L'utilisateur ne doit pas installer manuellement Terraform, OpenTofu, TFLint,
Checkov, ansible-lint, yamllint, Ruff, Pylint, Hadolint, Trivy ou les autres
outils pris en charge. Le bootstrap les rend disponibles au runtime selon le
catalogue et les plateformes qualifiées. Il ne lance pas l'ensemble des outils
sur chaque repository.

## Tool Resolver

**État actuel: implémenté comme fonction intégrée à Discovery.** Il résout les
capacités à partir de profils codés, retient les outils disponibles, déduplique
les commandes et expose les capacités non résolues. Il ne lance pas les outils.

Le Tool Resolver reçoit les technologies et unités détectées, détermine les
capacités requises par le profil et les contrôles, consulte la Capability Matrix,
puis choisit les outils compatibles disponibles dans le runtime partagé. Il
raisonne d'abord en capacités, puis en outils. Il évite les invocations inutiles
et explique les capacités requises, disponibles ou indisponibles ainsi que les
outils retenus et écartés.

| Technologies détectées | Capacités requises | Outils candidats |
| --- | --- | --- |
| Ansible | linting, policy validation | ansible-lint, yamllint |
| Terraform | formatting, linting, security | terraform fmt, tflint, checkov |
| Python | linting, testing | ruff, pylint, pytest |

La résolution tient compte du profil, des dépendances, des versions et de la
plateforme active (OS + architecture). Plusieurs outils peuvent satisfaire une
capacité, mais le resolver ne lance jamais tous les outils sur tous les dépôts.
Le remplacement d'un outil par un autre qui fournit la même capacité ne doit pas
imposer de modifier le moteur commun.

Dans l'implémentation actuelle, Ansible ne déclare que `linting`, avec ansible-lint
et yamllint; le tableau ci-dessus est illustratif de la cible. Le resolver retient
tous les candidats disponibles et déduplique par commande au sein de chaque
technologie, pas globalement. Il ne vérifie ni contraintes de dépendances ni
versions exécutables à chaque résolution. Voir [docs/resolver.md](docs/resolver.md).

## Capability Matrix

**État actuel: implémentée à l'exécution locale.** Elle sérialise les capacités,
candidats, disponibilités, motifs et plateforme dans le résultat Discovery. Elle
n'a pas encore de catalogue ou version indépendante.

La Capability Matrix décrit, pour une exécution et une plateforme données,
les technologies détectées, les capacités requises, les outils candidats ou
sélectionnés et la disponibilité effective de chaque capacité et outil. Elle
constitue le niveau explicite entre la découverte, la résolution et l'exécution.

Les capacités sont génériques et indépendantes des outils, par exemple:
formatting, linting, testing, security, documentation, secrets scanning,
compliance, policy validation, dependency audit, infrastructure analysis et
container analysis. Cette liste évolue avec les besoins sans spécialiser le
moteur autour d'une technologie.

Pour chaque capacité, la matrice indique au minimum si elle est requise et si
elle est disponible, partiellement disponible ou indisponible, avec la raison
et les outils compatibles associés. Pour chaque outil, elle distingue notamment
disponible, non installé, incompatible avec la plateforme et temporairement
indisponible. La disponibilité d'une capacité est évaluée à partir des outils
compatibles qui peuvent réellement la satisfaire; l'indisponibilité d'un outil
ne rend pas la capacité indisponible si une alternative qualifiée la fournit.

Le rapport distingue sans ambiguïté:

- technologie absente;
- contrôle non applicable;
- capacité indisponible;
- outil indisponible, avec son motif;
- erreur technique lors de la préparation ou de l'exécution;
- échec de conformité constaté par un contrôle exécuté.

Une technologie détectée reste présente même si ses outils sont absents,
incompatibles ou temporairement indisponibles. L'indisponibilité ne doit jamais
être convertie en technologie absente, contrôle non applicable ou réussite.
La représentation JSON et la plateforme sont déjà exposées dans les rapports;
le contrat indépendant, son versionnement et son lien au catalogue restent à
définir. La disponibilité est totale lorsque tous
les candidats sont résolus, partielle lorsqu'une partie seulement l'est. Une
alternative disponible ne produit donc pas systématiquement `available`. Un
lanceur présent n'atteste pas l'exécution native ni le fonctionnement des hooks.

## Tool Runtime

**État actuel: partiel et expérimental.** L'index runtime contient cinq binaires
`windows-x64`; les OS et architectures cibles restantes ne sont ni installés ni
qualifiés. Le bootstrap local n'atteint pas sa qualification finale.

Le Tool Runtime est un espace partagé, géré par Compliance_Platform et séparé
des repositories analysés. Il héberge plusieurs versions vérifiées d'outils et
leurs dépendances, sans duplication dans chaque dépôt. Il associe chaque artefact
à une plateforme définie comme OS + architecture, par exemple Windows x64,
Windows ARM64, Linux x64, Linux ARM64, macOS Intel x64 ou macOS Apple Silicon
ARM64.

Pour chaque combinaison, le runtime distingue les plateformes ciblées,
expérimentales et qualifiées. Une plateforme est qualifiée uniquement après des
preuves définies pour l'installation, l'intégrité, l'exécution des outils et la
production des résultats attendus. La présence d'un binaire n'est pas une preuve
de qualification. Les outils peuvent avoir des plateformes qualifiées différentes;
la Capability Matrix rend alors visibles les capacités disponibles et absentes.

Le runtime permet plusieurs versions, l'isolation lorsque nécessaire et le
remplacement d'un outil derrière son contrat de capacité, sans changement majeur
du moteur. L'emplacement du cache, ses permissions, sa durée de vie, son nettoyage
et son partage entre processus ou utilisateurs restent à définir. Les artefacts
doivent être vérifiés avant usage; un cache partagé n'est pas en soi une source
de confiance.

Le multiversion et le pointeur actif sont déjà implémentés/testés dans l'index.
Le cache actuel est `.tools/runtime` de la plateforme; son contrat de distribution,
son isolation et sa gestion concurrente restent ouverts. La résolution contrôle
chemin et existence, sans recalculer SHA-256. Quick/Full utilisent encore les
copies `.tools/bin`, même si l'index est expérimental.

## Compliance Engine

**État actuel: non implémenté comme moteur autonome.** Les fonctions du Quality
Gate gardent l'orchestration, l'exécution et les statuts; la matrice et le resolver
ne forment pas encore un plan de contrôles générique exécuté.

Le Compliance Engine est le moteur local qui transforme l'inventaire d'un dépôt
et une politique sélectionnée en résultats, rapport et verdict vérifiables. Il
coordonne les capacités spécialisées sans confondre découverte, sélection,
exécution et évaluation.

Ses responsabilités cibles sont:

- recevoir un chemin local et une configuration facultative, puis identifier
  les versions du moteur et de la politique utilisées;
- demander au Discovery Engine un inventaire explicable des technologies et
  unités de projet;
- déterminer les capacités requises puis consulter la Capability Matrix pour
  connaître les capacités et outils disponibles sur la plateforme active;
- sélectionner les contrôles requis et construire dynamiquement un plan
  d'exécution ordonné, tenant compte des dépendances, capacités et budgets;
- exécuter les contrôles avec limites de temps, ressources, permissions et
  effets de bord définis;
- agréger les résultats et preuves en distinguant échec de conformité, échec
  technique, capacité indisponible, outil indisponible et contrôle non applicable;
- évaluer les constats au regard de la politique et rendre une décision
  déterministe `PASS` ou `FAIL`;
- produire les rapports standardisés et les informations nécessaires à leur
  publication et à leur audit.

L'ordre de contrôle et les règles de décision doivent être explicables. Le moteur
ne déploie pas d'infrastructure, ne contacte pas une forge et ne transforme pas
un échec technique en conformité. Son `PASS` ou `FAIL` est consultatif: il ne
refuse aucune opération Git. Les scripts actuels constituent un socle à
qualifier, pas encore ce moteur séparé ni un contrat stable entre composants.

## Discovery Engine

**État actuel: implémenté, qualification en cours.** `-RepositoryPath` et
`-DiscoveryOnly` produisent technologies, preuves, racines, ambiguïtés, matrice
et résolution. Les heuristiques ne sont pas encore mesurées sur un corpus réel.

Le Discovery Engine identifie les technologies, les unités de projet et les
preuves qui justifient la sélection de contrôles. Il combine des marqueurs de
fichiers, des formats structurés et, si cela est approuvé, des déclarations
explicites du consommateur. Pour chaque détection, il doit exposer le périmètre,
les signaux retenus et les ambiguïtés. La découverte ne lance ni build, ni
déploiement, ni commande d'infrastructure.

La première matrice de découverte à qualifier comprend Terraform, OpenTofu,
PowerShell, Python, Ansible, Kubernetes, Helm, Docker et Shell. Elle doit rester
extensible à de futures technologies selon un processus commun d'ajout,
d'approbation, de tests et de support. Les distinctions Terraform/OpenTofu,
manifestes Kubernetes et YAML générique, chart Helm et ressources rendues,
ainsi que dialectes Shell sont des cas à expliciter, pas des détections
interchangeables.

Le moteur doit différencier une technologie absente d'une technologie présente
dont l'outil ou le runner est indisponible. Il doit reconnaître plusieurs
racines dans un monorepo, respecter les périmètres configurés et éviter que les
fichiers générés, exemples ou dépendances embarquées faussent l'inventaire. La
table détaillée des signaux et ambiguïtés figure dans le chapitre Discovery
Catalog plus loin dans ce plan.

## Policy Engine

**État actuel: non implémenté.** Le YAML reste descriptif; les décisions et seuils
du Quality Gate ne sont pas chargés depuis un moteur de politique.

Le Policy Engine évalue les résultats avec une politique organisationnelle
versionnée. Les profils définissent les standards communs et les contrôles
applicables à des catégories de consommateurs; ils ne constituent pas une
copie locale de la politique. Les adaptations permises doivent être déclarées,
validées et limitées à un périmètre connu.

La politique devra préciser:

- les niveaux de sévérité et leur effet sur la décision;
- les seuils mesurables et leur portée (projet, unité ou contrôle);
- les obligations conditionnelles ou inconditionnelles, y compris la conduite
  attendue lorsqu'un contrôle ne peut pas s'exécuter;
- les exclusions techniques justifiées, distinguées des dérogations au risque;
- les propriétaires, approbateurs, preuves, dates d'expiration et réexamens;
- les règles de compatibilité et de priorité entre standard central et profil
  consommateur.

Une exception corrige un périmètre ou un faux positif documenté; une dérogation
accepte temporairement un risque réel. Ni l'une ni l'autre ne doit effacer le
constat brut. Une dérogation ne produit un effet sur la décision que si elle est
approuvée par une autorité désignée, encore valide et strictement applicable au
projet et au contrôle concernés. Une politique absente, invalide ou incompatible
doit entraîner un résultat explicite et non une acceptation implicite.

## Optional Integrations

**État actuel: non implémentées comme adaptateurs produit.** Des scripts PowerShell,
Bash, tâches VS Code et un job GitLab propres au dépôt existent, mais aucun paquet
d'adaptateurs portables ou de contrat commun n'est livré.

Le cœur de Compliance_Platform ne connaît aucun fournisseur Git ni service
d'hébergement. Il reçoit un chemin local et une configuration éventuelle. Toute
connaissance de VS Code, PowerShell, Bash, d'une CI ou d'une forge appartient à
un adaptateur optionnel qui prépare cet appel ou présente les résultats.

Des points d'entrée peuvent être proposés pour VS Code, PowerShell, Bash, une
tâche CI, GitLab, GitHub, Bitbucket ou d'autres environnements. Ils sont des
façons facultatives de lancer l'analyse ou d'afficher le rapport, pas des
dépendances du moteur ni des conditions d'utilisation du dépôt.

Un adaptateur de forge peut déclencher une évaluation à la demande sur une copie
locale du dépôt et publier le rapport dans l'interface de la forge, si l'utilisateur
le configure. Il ne bloque pas commit, push, branches ou merge requests et ne
modifie pas les règles du dépôt. La décision d'agir sur un verdict reste humaine.

Les adaptateurs ne transmettent pas implicitement les sources ni des secrets à
un service central. Ils doivent documenter les permissions, données publiées,
formats de rapport, versions compatibles et limites de leur environnement. Le
rapport de base doit rester accessible sans GitLab, GitHub ou Bitbucket.

## Architecture actuelle

## Organisation et responsabilités

Le bootstrap installe les dépendances du socle, vérifie cinq binaires Windows x64
et les inscrit dans `.tools/runtime/index.json`. L'index gère versions, empreintes,
outil actif et état de plateforme; le bootstrap courant échoue néanmoins à l'étape
pre-commit sur un clone utilisant l'ancien chemin du dépôt, si bien que la plateforme
reste `experimental`. Les outils Python et PSScriptAnalyzer sont actuellement
résolus depuis `.venv` et les modules locaux, pas tous représentés dans l'index.

Doctor vérifie le poste et le dépôt selon des attentes majoritairement explicites
dans son propre script. Il propose un diagnostic, pas une attestation de conformité
à une politique organisationnelle ni une validation complète des contrôles.

Le Quality Gate accepte `-RepositoryPath`; `-DiscoveryOnly` retourne un JSON de
Discovery sans lancer de contrôles. Le résultat contient technologies, preuves,
racines, ambiguïtés, Capability Matrix et Tool Resolver. Les modes Quick/Full/Ci/Fix
continuent ensuite leur orchestration fixe dans le même script; aucun Compliance
Engine autonome ni graphe configurable de contrôles n'existe encore.

L'exécuteur commun transforme essentiellement les codes de sortie en statuts.
Les fonctions des contrôles prennent elles-mêmes les décisions d'applicabilité
et de blocage. Le fichier de politique ne détermine pas ces décisions à l'exécution.

Les hooks peuvent appeler le gate et le gate appelle pre-commit pour Markdown.
Cette relation croisée reste bornée par les hooks ciblés, mais devra être clarifiée
avant de proposer un moteur indépendant des adaptateurs locaux.

La CI de ce dépôt appelle successivement bootstrap, Doctor et Ci dans un seul job
Windows. Les tâches VS Code et les relais Bash exposent les mêmes scripts. Il
s'agit de l'état actuel de ce dépôt, pas d'une exigence pour les dépôts analysés
ni d'une intégration produit portable. Le job n'a pas de `allow_failure`; les
hooks installés peuvent aussi refuser un commit du socle. Le comportement
consultatif cible reste donc à qualifier séparément. Cette proximité limite certaines
divergences, sans garantir une parité de couverture ou de configuration entre
tous les modes.

## Frontières aujourd'hui absentes ou partielles

- Discovery, Capability Matrix et Tool Resolver sont présents dans `quality-gate.ps1`,
  mais ne sont pas encore séparés en composants ou contrats versionnés.
- Le runtime partagé et le bootstrap couvrent cinq binaires sous Windows x64;
  l'index reste `experimental` et ne prouve pas la qualification de la plateforme.
- Linux, macOS, ARM64 et l'isolation par plateforme ne sont pas qualifiés.
- Le Tool Resolver s'appuie sur des profils de capacités codés dans le script;
  il n'existe pas encore de Control Catalog indépendant.
- Pas de Compliance Engine autonome: les contrôles Quick/Full/Ci/Fix restent
  orchestrés dans le Quality Gate.
- Pas de Reporting Engine séparé: Discovery et les rapports Quick/Full sont
  sérialisés par le Quality Gate, avec des contrats JSON différents.
- Pas de Policy Engine autonome: `.config/quality-gate.yml` ne gouverne pas encore
  les décisions effectives.
- Pas d'intégrations optionnelles packagées distinctes des scripts et tâches actuels.
- Pas de profil de service consommateur séparé du socle.
- Pas de protocole de plugins ou de distribution de standards partagés.
- Les racines détectées sont heuristiques; le plan d'exécution par racine n'est
  pas encore intégré aux contrôles Quick/Full.
- Pas de modèle commun de constats, preuves et résultats entre contrôles.
- Pas de registre d'exceptions et de dérogations approuvées.

## Sort des éléments existants lors d'une évolution future

| Décision proposée | Éléments concernés | Condition et justification |
| --- | --- | --- |
| Conserver | Documentation, conventions de fichiers, installations locales, statuts, principes de sécurité | Ils constituent déjà des repères utiles pour les développeurs |
| Réutiliser | Discovery, Capability Matrix, Resolver, exécuteur, index Runtime et 37 scénarios | Base intégrée; plusieurs contrats restent dans `quality-gate.ps1` |
| Conserver comme points d'entrée | Scripts actuels, tâches VS Code, hooks, adaptateur GitLab | Préserver les usages pendant une transition, si une nouvelle architecture est approuvée |
| Faire évoluer | Catalogue d'outils et politique YAML | Passer d'informations partiellement dupliquées à des références gouvernées et validées |
| Refactorer à terme | Mélange détection/exécution/politique/reporting et parcours répétés | Uniquement après définition des responsabilités et tests d'équivalence |
| Revoir | Environnement Python unique, besoins d'installation et contrôles de poste | Réduire les couplages démontrés sans cacher les vulnérabilités d'un outil déplacé |
| Arbitrer | Checkov et sa stratégie de mise à jour ou de remplacement | Décision de sécurité explicite; aucune suppression automatique proposée |
| Retirer après migration | Copies de versions, règles de sélection dupliquées et lecture YAML par motifs | Seulement lorsque la nouvelle source de vérité couvre les usages existants |
| Retirer ou adapter conditionnellement | Relais Bash Windows | Seulement si des points d'entrée natifs qualifiés les remplacent et si leur usage est connu |
| Examiner avant retrait | Désactivations de règles et hypothèses héritées du squelette | Évaluer pertinence et impact; ne pas imposer une suppression indistincte |

Aucun retrait ni refactoring de cette table n'est exécuté par ce plan.

## Architecture cible

## Responsabilités envisageables

Une architecture cible pourrait distinguer les responsabilités suivantes sans
imposer encore une structure de fichiers, des classes ou une API:

| Responsabilité | Finalité | Ancrage dans l'existant |
| --- | --- | --- |
| Distribution de la plateforme | Fournir aux consommateurs une version approuvée du moteur, des contrôles et des politiques | Les scripts et le job GitLab existent, mais aucun contrat de consommation multi-projets n'est démontré |
| Tool Bootstrap | Télécharger, vérifier et inscrire les outils du runtime partagé | Bootstrap inscrit cinq binaires Windows x64 après validation; étape pre-commit échoue encore, donc pas de qualification finale |
| Tool Resolver | Résoudre les outils disponibles qui satisfont les capacités requises | Profils et sélection déterministes intégrés à `quality-gate.ps1`; l'exécution des contrôles reste dans les fonctions existantes |
| Tool Runtime | Mettre à disposition les outils vérifiés depuis un cache central | `.tools/runtime/index.json` contient cinq binaires pour `windows-x64`, statut `experimental`; dépendances Python/PowerShell hors index |
| Inventaire et détection | Identifier technologies, sous-projets et preuves de présence | `-RepositoryPath` et Discovery JSON v1; heuristiques et racines par marqueur |
| Capability Matrix | Relier technologies, capacités requises et disponibilité réelle par plateforme | JSON généré par exécution; profils hardcodés, sans catalogue ou version indépendante |
| Catalogue de contrôles | Décrire les analyses disponibles et leur applicabilité | Fonctions spécialisées du gate |
| Planification | Choisir une séquence adaptée au profil, au mode et au runner | Ordre et catégories actuellement codés en dur |
| Exécution | Appliquer les garanties de ressources, permissions et isolation | Exécuteur de processus existant |
| Politique et gouvernance | Décider du niveau d'exigence et de l'acceptation des résultats | Statuts et politique descriptive actuelle |
| Restitution et preuves | Donner des résultats explicables, comparables et traçables | JSON Discovery et rapports du Quality Gate; schémas encore distincts |
| Adaptateurs | Exposer le socle aux développeurs, éditeurs et fournisseurs CI | Tâches VS Code, hooks, GitLab et relais |

Ces responsabilités pourraient cohabiter dans une même distribution au départ.
Les séparer conceptuellement ne signifie pas créer immédiatement des microservices
ou multiplier les dépôts et les processus.

## Choix d'architecture à instruire

| Choix | Options à comparer | Recommandation de cadrage |
| --- | --- | --- |
| Distribution et installation | Installation autonome de Compliance_Platform, paquet ou archive approuvée | Préparer le runtime central par le bootstrap de la plateforme; ne pas installer les outils dans les repositories analysés |
| Langage du moteur | PowerShell actuel, PowerShell plus récent, Python, exécutable autonome | Décider selon portabilité, support, packaging et compétences; ne pas présumer une réécriture Python |
| Plateformes cibles | Combinaisons OS + architecture: Windows x64/ARM64, Linux x64/ARM64, macOS Intel x64/Apple Silicon ARM64 | Les cibles doivent être qualifiées une par une; le socle actuel observé reste principalement Windows x64 et PowerShell 5.1 |
| Évolution Windows | Maintien PowerShell 5.1 pendant la transition ou coexistence de runtimes | Préserver la compatibilité Windows déclarée sans en faire la seule cible produit |
| Source de vérité | Catalogue générique de capacités, contrôles, outils et politiques | Favoriser des contrats déclaratifs validés, sans disperser la logique d'une technologie dans le moteur |
| Granularité | Dépôt entier, sous-projet, module ou composant | Étudier un inventaire par unité de projet, motivé par les limites IaC et monorepo actuelles |
| Gestion des outils | Runtime partagé géré par Compliance_Platform, avec isolation logique des outils et versions | Privilégier un cache local central de la plateforme; ne pas installer ni dupliquer les outils dans les repositories analysés |
| Isolation des outils | Runtime partagé avec environnements isolés par outil ou famille lorsque nécessaire | Garder un seul runtime géré par la plateforme; l'isolation interne ne doit pas entraîner de duplication dans les repositories analysés |
| Personnalisation | Standards uniques ou socle commun avec profils de services | Préférer un socle commun et des adaptations contrôlées, sans affaiblissement silencieux |
| Exécution | Locale native, runners spécialisés, environnement conteneurisé | Qualifier les options par capacité; ne pas supposer qu'un conteneur résout tous les besoins Windows |
| Gouvernance des résultats | Un code de sortie unique ou résultats structurés évalués par une politique | Conserver le code de sortie, enrichir les preuves et leur interprétation |

## Évolutions recommandées dans leur ordre logique

La progression cible est de stabiliser le socle, qualifier la découverte des
technologies, puis mettre en place le Tool Bootstrap, le Tool Resolver et la
Capability Matrix pour chaque plateforme OS + architecture. Le Compliance Engine,
le catalogue de contrôles et le reporting s'appuient sur ces contrats génériques.
Les intégrations ne viennent qu'ensuite et restent optionnelles; l'industrialisation
porte sur la reproductibilité du runtime et la qualité des audits, pas sur
l'imposition du moteur aux dépôts.

Une interface web, un service de télémétrie ou une exécution distribuée ne sont
pas des prérequis démontrés par le dépôt actuel. Ces capacités restent des options
futures à justifier par des besoins et des contraintes identifiés.

## Discovery Catalog

## Pistes possibles, sans conception détaillée

Le moteur possède déjà une détection simple. Il faut envisager son évolution vers
des signaux combinés, des unités de projet et des raisons explicites de sélection,
plutôt que repartir d'une liste théorique de scanners.

| Technologie | Détection implémentée | Preuves et racines actuellement restituées | Ambiguïtés et limites |
| --- | --- | --- | --- |
| Terraform | `.tf`; `.terraform-version` sert de marqueur explicite | Fichiers de preuve et répertoires contenant les fichiers | `.tf` seul demeure ambigu Terraform/OpenTofu; seules les preuves explicites résolvent Terraform |
| OpenTofu | `.tofu`, `.opentofu-version`, `.tofurc`; `.tf` partagé demeure ambigu | Fichiers de preuve et racines par dossier | L'ambiguïté des sources `.tf` n'autorise aucun contrôle Terraform automatique |
| Terragrunt | `terragrunt.hcl`, `terragrunt.stack.hcl` | Fichier de preuve et dossier parent | Le HCL générique n'est pas classé Terragrunt |
| PowerShell | `.ps1`, `.psm1`, `.psd1` | Fichiers de preuve et dossiers contenant les scripts | Les fichiers de données `.psd1` sont également classés comme PowerShell |
| Python | `.py`; recherche ascendante de `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements.txt` | Sources/tests et racine au manifeste le plus proche | Sans manifeste, racine = dossier du fichier; la classification tests dépend du segment `tests` |
| Ansible | Marqueurs `ansible.cfg`, `galaxy.yml`, `meta/runtime.yml`, `roles/`, `playbooks/`, `requirements.yml`, ou clé YAML `hosts:` | Racine de configuration/projet/rôle calculée depuis la preuve | `hosts:` reste ambigu et les marqueurs de répertoires peuvent confondre YAML générique |
| Kubernetes | YAML contenant `apiVersion` et un `kind` reconnu | Fichier de preuve et dossier parent | Liste finie de kinds; `{{` classe le manifeste comme ambigu (template Helm possible) |
| Helm | `Chart.yaml` | Chart et dossier du fichier | Les fichiers values seuls ne suffisent pas; aucun rendu du chart n'est exécuté |
| Docker et Compose | `Dockerfile`, `Containerfile` avec suffixe facultatif, `docker-compose.yml`, `compose.yaml` | Fichiers de preuve et dossiers parents | La détection ne lance ni build ni conteneur |
| Shell | `.sh` | Fichier de preuve et dossier parent | Les scripts sans extension ne sont pas détectés; le dialecte n'est pas vérifié par Discovery |
| Markdown | `.md` | Fichiers et racine du dépôt | Le rôle documentaire du fichier n'est pas différencié |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs`, ou `package.json` | Fichiers de preuve et racine `package.json` la plus proche | `package.json` classe JavaScript même si le projet est TypeScript |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts`, ou `tsconfig*.json` | Fichiers de preuve et `tsconfig.json`/`package.json` le plus proche | Capacité linting déclarée sans candidat; recherche ascendante limitée à `tsconfig.json`/`package.json` |

La liste future devrait rester ouverte, mais une technologie ne devrait être
annoncée comme supportée qu'avec une détection qualifiée, des contrôles définis,
des outils disponibles et des limites documentées.

## État actuel de Discovery

`scripts/quality-gate.ps1` accepte désormais `-RepositoryPath` et le mode
`-DiscoveryOnly`. Le scan reste en lecture seule et retourne du JSON versionné
avec le repository, les technologies, les preuves, les racines de projet, les
ambiguïtés, la Capability Matrix et la résolution des outils. Le mode Discovery
n'exécute pas les contrôles.

Les détecteurs couvrent actuellement Python, PowerShell, Terraform/OpenTofu,
Terragrunt, Ansible, Docker/Compose, Kubernetes, Helm, Shell, Markdown,
JavaScript et TypeScript. Les heuristiques et leurs preuves sont détaillées dans
[docs/discovery.md](docs/discovery.md). Les principales limites sont les
marqueurs faibles `hosts:` et `.tf`, les formats de fichiers non déclaratifs et
l'absence de corpus de dépôts consommateurs permettant de mesurer les faux
positifs/faux négatifs.

Le repository Compliance_Platform observé ne contient pas de sources Python,
Terraform, HCL, Dockerfile ou Containerfile; la présence des scripts PowerShell,
Shell et Markdown est confirmée. Ce constat local ne décrit pas les technologies
supportées en général.

`hosts:` seul est effectivement classé `ambiguous` et ne lance aucun contrôle
Ansible. Les `.tf` et marqueurs Terraform/OpenTofu sont comparés à l'échelle du
dépôt, pas de chaque racine: les layouts mixtes restent à qualifier. Compose
partage les contrôles Dockerfile, sans validation dédiée. Les profils
Kubernetes/Helm ne déclenchent pas encore de contrôles dans Quick/Full; OpenTofu,
JavaScript et TypeScript n'ont pas de séquence dédiée non plus.

## Arbitrages de détection

- Extension seule, contenu structuré, déclaration explicite ou combinaison de
  ces signaux: comparer fiabilité, coût et explicabilité.
- Détection exhaustive ou différentielle: le ciblage des changements doit
  préserver les dépendances et un filet de validation complète.
- Dépôt unique ou monorepo: reconnaître plusieurs racines sans imposer un layout.
- Contenus générés, exemples et dépendances embarquées: distinguer leur rôle
  avant de généraliser les exclusions actuelles.
- Détection automatique et corrections déclarées: tracer les overrides plutôt
  que permettre la désactivation invisible d'un contrôle obligatoire.
- Technologie présente mais outil non disponible: ne pas la convertir en
  technologie absente pour obtenir un `SKIP` favorable.

## Catalogue des contrôles

**État actuel: non implémenté comme catalogue indépendant.** Les associations
technologie-capacité-outil vivent dans le script PowerShell; `.config/quality-gate.yml`
ne les gouverne pas à l'exécution.

## Familles envisageables

| Famille | Base déjà présente | Extensions possibles à instruire |
| --- | --- | --- |
| Qualité | Ruff, Pylint, mypy, PSScriptAnalyzer, YAML, formats, TFLint, Hadolint | Contrôles par langage, structure des projets et diagnostics normalisés |
| Sécurité | Gitleaks, Bandit, pip-audit, Checkov, Trivy, règles Docker | Provenance des outils, dépendances, images, IaC et historique Git selon une politique définie |
| Conformité | Quelques règles de fichiers, versions et interdictions | Mapping de contrôles aux exigences internes, preuves et limites d'attestation |
| Documentation | Markdownlint et README détaillé | Complétude documentaire, liens, descriptions d'exploitation et cohérence des standards |
| Tests | 37 scénarios d'intégration PowerShell du socle et de Discovery; aucun test Python métier | Corpus réel multi-repository, qualification plateformes et contrats autonomes restent absents |
| Standards | Conventions de fichiers, versions, consignes et checklist | Profils de services, règles de contribution et règles métier approuvées |

Ces familles se recouvrent: une règle de conteneur peut servir la sécurité et
la conformité. Il faut éviter de compter deux fois le même constat tout en
permettant son rattachement à plusieurs exigences.

## Questions à poser pour chaque futur contrôle

Chaque contrôle devrait pouvoir être décrit par son objectif, son périmètre,
sa justification, ses dépendances, les plateformes supportées, son coût et ses
effets possibles. Il faudrait aussi préciser sa correction éventuelle, son
propriétaire, le niveau d'exigence et la preuve attendue.

Ces informations sont des besoins de gouvernance, pas un schéma de configuration
défini dans ce document. Les contrôles statiques, les audits nécessitant un réseau,
les tests exécutant du code et les corrections doivent rester distinguables.

Les presets Quick, Full et Ci peuvent être réutilisés comme repères d'usage.
Leur signification devra devenir explicite pour chaque profil: un succès de
Quick ou d'une catégorie ne constitue pas une attestation de conformité complète.

Un environnement séparé pour Checkov pourrait limiter les conflits de
dépendances, mais ne corrigerait pas ses vulnérabilités. Le catalogue devrait
prévoir l'audit des outils eux-mêmes en plus de celui des projets consommateurs.

## Expérience locale des consommateurs

## Réutilisation du fonctionnement actuel

Bootstrap, Doctor, le catalogue d'outils et les tâches VS Code offrent une base
concrète pour préparer le runtime de Compliance_Platform et lancer un audit.
La cible est une installation centralisée dans l'espace de la plateforme, sans
modifier le PATH système ni dupliquer les outils dans les dépôts analysés.

## Pistes de mécanisme futur

| Besoin | Orientation à examiner | Écart réel à combler |
| --- | --- | --- |
| Gérer les outils du moteur | Bootstrap à l'installation et aux mises à jour, cache partagé, versions épinglées et provenance vérifiée | Installation largement exhaustive, centrée Windows; resolver descriptif livré mais non utilisé pour exécuter les contrôles |
| Maintenir les versions | Releases identifiées, compatibilité vérifiée et retour à une version antérieure | Pins dupliqués et absence de stratégie de migration multi-services |
| Gérer les dépendances | Verrous qualifiés par plateforme et environnements adaptés aux contraintes | Un verrou et un `.venv` partagés pour toutes les familles |
| Intégrer VS Code | Extension facultative pour lancer un scan, consulter le rapport et améliorer l'expérience développeur | Recommandations actuelles non vérifiées; aucune extension n'est source de vérité des contrôles |
| Vérifier la conformité | Comparer profil attendu, versions effectives, disponibilité et politiques de confiance | Doctor n'est pas un audit complet du poste et diverge parfois du bootstrap |
| Fonctionner hors ligne | Artefacts approuvés, caches maîtrisés et diagnostic de complétude | Premier bootstrap hors ligne non supporté, plusieurs sources et environnements |
| Gérer proxy et certificats | Processus approuvé de confiance et renouvellement des autorités publiques | Bundle Windows local réutilisé sans mécanisme de renouvellement explicite |
| Partager les ressources | Qualifier le runtime de la plateforme et ses caches mutualisés de confiance | Cache runtime présent, mais certains contrôles exigent encore des chemins sous les dépôts analysés |

L'installation initiale du runtime et ses mises à jour doivent être explicites
et séparées de chaque audit. Un scan réutilise le runtime sans réinstaller les
outils. Un diagnostic ne modifie pas silencieusement le poste. Les extensions
VS Code restent optionnelles et servent l'expérience développeur; Compliance_Platform
et son catalogue versionné restent la référence des contrôles.

La préparation locale facilite l'usage de la plateforme, mais la conformité du
poste ne doit pas être confondue avec celle du projet: un poste correctement
préparé peut exécuter un contrôle qui relève un défaut de sévérité élevée et
produit un verdict `FAIL`. Le passage de Doctor ne remplace donc pas l'analyse du
dépôt; celle-ci reste volontaire et son verdict ne bloque aucune opération Git.

## Extensibilité des contrôles

## Motivation fondée sur l'existant

Les familles de contrôles sont aujourd'hui des fonctions ajoutées directement au
gate. Les catégories, la détection et l'orchestration doivent être modifiées
ensemble. Ce couplage constitue une raison concrète d'étudier l'extensibilité,
sans imposer immédiatement un système de plugins complexe.

## Types d'extension envisageables

- Une nouvelle technologie pourrait apporter des critères de présence et des
  limites de support, sans redéfinir le moteur des processus.
- Un nouveau linter pourrait être rattaché à une technologie existante et au
  catalogue d'outils, avec une restitution compatible avec les autres contrôles.
- Un nouveau scanner pourrait préciser ses besoins réseau, ses capacités, ses
  permissions et les preuves produites.
- Une règle métier pourrait enrichir un profil de service, tout en restant
  distinguée des standards transverses et soumise à son propre propriétaire.

Il faut décider si ces extensions sont déclaratives, exécutables ou mixtes,
et si les détecteurs, les adaptateurs d'outils et les politiques constituent
des extensions différentes. Aucun contrat technique n'est fixé ici.

## Conditions de sécurité et de pérennité

Un plugin exécutable est du code de confiance: son référencement dans un
catalogue ne le rend pas sûr. Les pistes à évaluer comprennent revue,
provenance, versions approuvées, compatibilité, permissions minimales et isolation.
Une contribution locale au projet ne doit pas obtenir automatiquement les secrets
ou privilèges du runner.

Le verdict devrait rester calculé par le moteur à partir des résultats et de la
politique, jamais par un plugin d'analyse isolé. L'absence, la panne ou
l'incompatibilité d'un plugin doivent être visibles dans le rapport, sans
empêcher l'utilisateur de poursuivre ses opérations Git.

Les tests existants pourraient devenir le premier corpus de validation d'un
contrat d'extension, après arbitrage. Les fonctions actuelles ne sont pas déjà
des plugins et le chargement AST utilisé par les tests n'est pas une architecture
de plugins à généraliser.

## Modes d'exécution

## Lancement local

Le mode de référence analyse un chemin local choisi par l'utilisateur. Les
commandes PowerShell et Bash, une tâche VS Code ou une interface équivalente
transmettent ce chemin et une configuration facultative au même moteur. La
plateforme peut fonctionner sans accès réseau, sans compte de forge et sans
pipeline.

Le plan d'exécution, ses dépendances, les limites de ressources, l'annulation et
les résultats partiels doivent avoir une sémantique identique quel que soit le
point d'entrée. Une panne de contrôle ou une erreur technique est rapportée
distinctement d'un constat de non-conformité.

## Exécution en CI, au choix

Une tâche CI peut lancer Compliance_Platform sur le checkout local du job et
conserver ou publier le rapport. Cette possibilité vaut pour GitLab CI, GitHub
Actions, Bitbucket Pipelines ou tout autre runner compatible; elle n'est ni
requise ni configurée automatiquement par la plateforme.

Les adaptateurs fournis ne transforment pas `FAIL` en échec de job bloquant et
ne modifient pas les règles de branches ou de fusion. Le statut du verdict doit
être publié comme information consultative. Un opérateur reste libre de lire le
rapport et de décider des suites, sans que le moteur empêche commit, push ou
merge.

Les runners spécialisés, l'accès réseau, les secrets, les coûts et les
contributions non fiables restent des paramètres à documenter pour chaque
environnement. Aucun service distant ni collecte centrale n'est nécessaire au
fonctionnement du moteur.

## Gouvernance

## Gestion des standards

Identifier les propriétaires du socle, des politiques transverses, des technologies
et des profils de services. Les consignes et la checklist actuelles peuvent être
réutilisées, mais ne remplacent pas les responsabilités et circuits d'approbation.

Une règle devrait être reliée à un objectif connu: qualité, sécurité, exploitation
ou exigence de conformité. Le rattachement à un référentiel doit préciser les
preuves et les limites; un scanner ne certifie pas à lui seul un service.

Les choix existants, notamment les règles Markdown et Pylint désactivées, doivent
être inventoriés et justifiés avant généralisation. Aucune nouvelle désactivation
n'est proposée pour obtenir un gate vert.

## Gestion des versions

Distinguer version du socle, version de politique, versions des outils et versions
des extensions. Un service devrait pouvoir connaître exactement ce qu'il consomme.
Les mises à jour devraient être qualifiées, compatibles ou explicitement annoncées
comme ruptures, avec accompagnement et possibilité de retour contrôlé.

L'épingle d'une version ne garantit pas sa sécurité: les avis évoluent après la
publication. Le cas Checkov démontre la nécessité d'un processus continu de
surveillance, d'arbitrage et de diffusion de corrections.

## Exceptions et dérogations

Une exception de périmètre ou un faux positif justifié doit être distingué d'une
dérogation acceptant temporairement un risque réel. Les deux nécessitent un objet
identifié, une justification, un propriétaire, un approbateur et une échéance.

Une dérogation ne doit pas effacer le constat technique ni le renommer en `PASS`.
L'acceptation éventuelle du risque relève d'une décision de gouvernance explicite
et traçable, séparée de la mesure. Les politiques de non-contournement du socle
ne doivent pas être affaiblies implicitement par un profil de service.

Il faut décider comment les exceptions sont distribuées, limitées, réexaminées
et invalidées lorsqu'elles expirent ou que leur périmètre change. Les exclusions
actuelles des contenus générés constituent un point de départ, pas un mécanisme
général de dérogation.

## Preuves, confidentialité et responsabilités

Définir les exigences de conservation des résultats, le niveau de détail nécessaire
et les accès. Les sept jours de rétention configurés en CI ne sont pas, à eux seuls,
une politique de preuve de conformité. Les rapports actuels sont utiles localement,
mais ne décrivent pas encore toutes les versions ou décisions de sélection.

Toute collecte centrale devrait faire l'objet d'une décision distincte: nature
des données, confidentialité des sources, masquage, durée, droits et usage des
indicateurs. La comparaison entre services doit tenir compte de leur périmètre
réel et de la maturité des contrôles, pas seulement de compteurs de succès.

## Roadmap

Les phases indiquent l'ordre de priorité et l'état réel d'implémentation; elles
ne bloquent pas le développement des capacités suivantes. `PHASE TERMINÉE`
signifie que les critères de sortie sont démontrés, `PHASE EN COURS` qu'une partie
est utilisable mais qu'il reste des écarts, et `PHASE NON COMMENCÉE` qu'aucun
composant autonome n'est livré pour cette phase.

**PHASE TERMINÉE: aucune phase complète à ce jour.** Les fonctionnalités testées
sont cochées ci-dessous; les critères de qualification encore ouverts empêchent
de transformer ces réussites locales en clôture de phase.

## Phase 1: Stabilisation du socle

Statut: **PHASE EN COURS**.

Objectif: disposer d'une base fiable et clairement qualifiée avant d'élargir les
capacités d'analyse et les usages volontaires de la plateforme.

- [ ] Traiter ou arbitrer le blocage Checkov et ses dépendances vulnérables sans
  suppression d'avis ni retrait silencieux d'un contrôle; asteval 1.0.9 est annoncé
  correctif, mais Checkov installé impose encore 1.0.6.
- [x] Clarifier le support Windows, les prérequis et le périmètre réel du verrou
  de dépendances, des hooks et du diagnostic.
- [x] Examiner les divergences entre catalogues, scripts et Doctor, y compris les
  notions d'outils facultatifs et de Python déjà fourni par le poste.
- [ ] Définir la qualification sur poste neuf et runner, ainsi que les scénarios
  réseau, hors ligne et d'échec; préparer les preuves attendues.
- [x] Préserver et étendre les tests du socle: `scripts/test.ps1` exécute
  actuellement 37 scénarios avec 37 PASS, réobservés dans Full pendant cet audit.
- [x] Recréer l'environnement Python local et vérifier les lanceurs Python/TOML.
- [x] Corriger les tests de processus pour qu'ils valident les codes de sortie,
  les arguments et les délais sans dépendre de Python.
- [x] Reparer automatiquement le cache pre-commit deplace, avec verification
  SQLite, preservation d'un cache valide et refus explicite hors ligne; bootstrap
  complet valide en code 0, regression multiclone couverte.
- [x] Corriger les erreurs Markdown revelees par le cache repare et obtenir
  Quick sans FAIL ni ERROR, sans desactivation de regle.
- [x] Réexécuter Quick/Full et documenter distinctement les échecs d'environnement
  et de sécurité, sans modifier les rapports antérieurs ni contourner le gate.
- [ ] Obtenir Quick/Full sans échec de Markdownlint ni d'audit de dépendances.
- [ ] Prévoir, sous autorisation distincte, la publication d'un état identifié du
  socle; le workspace non suivi ne constitue pas une release consommable.

Réutilisation: scripts, tests, conventions, rapports et documentation existants.

Critères de sortie proposés: blocages de sécurité résolus ou arbitrés;
environnement de test reproductible; 37 scénarios verts; Quick/Full reproductibles
et limites documentees. Les 38 tests et Quick passent; Full reste bloque
uniquement par l'audit des dependances. Poste neuf/runner non qualifies.

## Phase 2: Discovery Engine

Statut: **PHASE EN COURS**.

Objectif: rendre la découverte des technologies et unités de projet fiable et
explicable, sans annoncer comme supportées des technologies non qualifiées.

- [x] Accepter un chemin de repository externe et offrir `-DiscoveryOnly`.
- [x] Retourner technologies, preuves, racines de projet et ambiguïtés en JSON.
- [x] Détecter Terraform/OpenTofu comme ambigus sur `.tf` sans marqueur explicite.
- [x] Couvrir Ansible, Kubernetes, Helm, Docker Compose, JavaScript et TypeScript
  par marqueurs dédiés.
- [x] Classer `hosts:` seul comme signal Ansible ambigu et éviter l'exécution
  automatique du contrôle; scénario négatif validé.
- [x] Exclure les dossiers générés avant parcours et ne pas descendre dans les
  répertoires de réanalyse; limites des liens de fichiers documentées.
- [ ] Mesurer faux positifs/faux négatifs sur un corpus autorisé de repositories.
- [ ] Étendre la résolution des racines et qualifier les heuristiques sur monorepos,
  layouts mixtes et projets imbriqués, notamment Terraform/OpenTofu par racine.
- [ ] Ajouter une stratégie d'override déclaratif et d'exclusion explicable.
- [ ] Restituer les limites et erreurs d'accès d'un scan incomplet sans perdre
  l'inventaire et le rapport diagnostique.

Réutilisation: inventaire et cas de détection actuels.

Critères de sortie proposés: inventaire explicable, précision évaluée sur corpus,
racines vérifiées sur projets représentatifs et limites documentées. La CLI et
les tests existent; la qualification sur corpus reste à faire. Les détecteurs ne
déclenchent aucune opération d'infrastructure.

## Phase 3: Tool Bootstrap & Tool Resolver

Statut: **PHASE EN COURS**.

Objectif: préparer une fois un runtime central multi-plateforme, puis résoudre
les capacités et outils réellement nécessaires à chaque repository analysé.

- [x] Réutiliser le catalogue existant de versions/sources et enregistrer les
  versions actives et SHA-256 des binaires dans `.tools/runtime/index.json`.
- [ ] Étendre le catalogue des outils aux artefacts et dépendances par chaque
  couple OS + architecture.
- [x] Vérifier versions et intégrité des cinq binaires Windows x64 actuellement
  installés.
- [x] Enregistrer Gitleaks 8.30.1, TFLint 0.64.0, Terragrunt 1.1.6,
  Hadolint 2.15.1 et Trivy 0.75.0 dans l'index Runtime.
- [ ] Définir une qualification mesurée pour toutes les combinaisons OS + architecture.
- [x] Implémenter Capability Matrix, états disponibilité et raisons.
- [x] Implémenter un Tool Resolver qui déduplique les outils disponibles par
  commande au sein d'une technologie et refuse les technologies ambiguës.
- [x] Rétrograder la plateforme à `experimental` au début du bootstrap et la
  qualifier uniquement en fin d'exécution complète.
- [x] Corriger le cache/install pre-commit et terminer le bootstrap Windows x64;
  le marqueur `qualified` est atteint en fin d'installation. La qualification
  sur poste neuf et la securite du runtime restent distinctes et ouvertes.
- [ ] Gérer les versions des dépendances Python et modules PowerShell dans le
  même index versionné du runtime.
- [ ] Qualifier les binaires Windows ARM64, Linux x64/ARM64 et macOS x64/ARM64.
- [x] Vérifier les sommes des téléchargements binaires, comparer la copie runtime
  à sa source et interrompre le bootstrap sur erreur d'installation.
- [ ] Completer la provenance des binaires reutilises et qualifier l'integrite
  des modules/paquets et les garanties de gestion d'echec par artefact.
- [x] Recalculer SHA-256 a la resolution et avant execution des binaires indexes,
  y compris les copies historiques; refuser empreinte absente, alteration,
  plateforme non qualifiee et schema invalide, avec regression negative.
- [ ] Distinguer présence de commande et exécution réellement supportée, résoudre
  les alternatives et les divergences Doctor/bootstrap sur Python et Terragrunt.
- [ ] Mesurer le coût de résolution et l'absence d'outils inutiles sur des fixtures.

Critères de sortie proposés: 37 tests verts; matrice et résolution sérialisées;
versions d'outils binaires vérifiées; `windows-x64` reste expérimental tant que le
bootstrap ne termine pas; autres plateformes et dépendances runtime non couvertes.

## Phase 4: Compliance Engine

Statut: **PHASE NON COMMENCÉE**.

Le Quality Gate orchestre des contrôles fixes, mais aucun Compliance Engine
autonome ne planifie et agrège un modèle générique de contrôles.

Objectif: transformer l'inventaire du consommateur et sa politique en plan
d'exécution, résultats agrégés et décision explicable.

- [ ] Séparer sélection, planification, exécution, agrégation et décision.
- [ ] Définir dépendances, capacités, délais, permissions et effets de bord des
  contrôles.
- [ ] Normaliser les statuts et preuves, y compris les erreurs techniques et les
  contrôles obligatoires impossibles à exécuter.
- [ ] Comparer les décisions du moteur cible aux comportements actuels avant toute
  migration des consommateurs.
- [ ] Exécuter à partir des capacités résolues et des racines Discovery, supprimer
  les attentes de runtime/configuration sous les consommateurs et qualifier
  l'absence d'écritures implicites dans les dépôts analysés.

Réutilisation: exécuteur, familles de contrôles, statuts, politique descriptive
et rapports existants.

Critères de sortie proposés: plan explicable et reproductible; résultats
normalisés; échec technique distingué de l'échec de conformité; décision
vérifiable pour un dépôt consommateur.

Statut Policy Engine: **PHASE NON COMMENCÉE**.

`.config/quality-gate.yml` décrit des statuts et seuils, mais le Quality Gate ne
l'interprète pas comme une politique d'exécution. Profils, obligations,
exceptions et dérogations ne sont pas évalués par un moteur dédié.

## Phase 5: Control Catalog

Statut: **PHASE NON COMMENCÉE**.

Les capacités candidates sont définies dans le code de Discovery; aucun catalogue
indépendant de contrôles, versionné et gouverné, n'est chargé à l'exécution.

Objectif: définir un catalogue explicite des contrôles, de leur applicabilité,
de leurs dépendances et des preuves qu'ils produisent.

- [ ] Décrire pour chaque contrôle son objectif, son périmètre, ses paramètres,
  outils, limites, coût, effets de bord et compatibilités.
- [ ] Distinguer contrôle, règle, outil, technologie, profil et sévérité.
- [ ] Définir comment les profils sélectionnent les contrôles sans transformer
  cette sélection en obligation d'exécuter le moteur.
- [ ] Qualifier les contrôles existants et leur restitution avant d'élargir le
  catalogue à de nouvelles technologies.

Réutilisation: politique descriptive, familles et contrôles existants,
configurations d'outils et scénarios de référence.

Critères de sortie proposés: catalogue documenté et versionné; applicabilité
explicable; contrôles et limites identifiables sans dépendance à une forge.

## Phase 6: Reporting Engine

Statut: **PHASE NON COMMENCÉE**.

Le Quality Gate et DiscoveryOnly produisent déjà des JSON, mais aucun Reporting
Engine autonome ni schéma commun versionné aux contrôles n'est implémenté.

Objectif: agréger les constats et produire un rapport standardisé, portable et
compréhensible, avec un verdict consultatif `PASS` ou `FAIL`.

- [ ] Définir le contrat du rapport, ses versions, ses métadonnées et ses formats
  lisibles par un humain et exploitables par des outils.
- [ ] Distinguer les constats, sévérités, erreurs techniques, contrôles ignorés et
  limites de couverture.
- [ ] Calculer et expliquer le verdict à partir du profil et des résultats, sans
  assimiler `PASS` à une autorisation ni `FAIL` à un blocage.
- [ ] Préserver un rapport diagnostique en cas de contrôle échoué ou d'exécution
  partielle, et documenter les règles de confidentialité et de rétention.

Réutilisation: rapports JSON actuels, statuts, logs et contrôles existants.

Critères de sortie proposés: rapport traçable du dépôt et des versions utilisés;
verdict explicable; résultat transportable sans format propriétaire d'une forge;
aucun effet automatique sur les opérations Git.

## Phase 7: Optional Integrations

Statut: **PHASE NON COMMENCÉE**.

Les scripts PowerShell/Bash, tâches VS Code et pipeline GitLab de ce dépôt sont
des points d'entrée existants, pas encore des adaptateurs portables versionnés
pour un moteur générique.

Objectif: proposer des points d'entrée facultatifs sans coupler le moteur à un
éditeur, un shell, une CI ou un fournisseur Git.

- [ ] Qualifier les lancements depuis VS Code, PowerShell et Bash avec un chemin
  local et une configuration facultative.
- [ ] Étudier des adaptateurs optionnels pour une tâche CI, GitLab, GitHub, Bitbucket
  et d'autres environnements, ainsi que leur publication de rapports.
- [ ] Garantir que les intégrations n'imposent ni installation, ni pipeline, ni
  règle de branche, ni blocage automatique en cas de `FAIL`.
- [ ] Documenter les permissions, formats, données transmises et compatibilités de
  chaque adaptateur.

Réutilisation: tâches VS Code, scripts PowerShell et Bash, job GitLab et formats
de rapports existants, après qualification de leur comportement consultatif.

Critères de sortie proposés: moteur utilisable sans adaptateur; mêmes résultats
de fond pour un même dépôt et une même configuration; intégrations facultatives
qui n'empêchent aucune opération Git.

## Phase 8: Industrialisation

Statut: **PHASE NON COMMENCÉE**.

Le runtime n'est pas qualifié au-delà de Windows x64 et son bootstrap ne termine
pas avec l'état local actuel. Aucune exploitation multi-plateforme n'est établie.

Objectif: rendre le moteur et ses contrôles maintenables, reproductibles et
portables pour des usages volontaires variés.

- [ ] Stabiliser versions, configuration, documentation, support des plateformes et
  procédures de mise à jour.
- [ ] Mesurer qualité de détection, coût, temps d'exécution, couverture et utilité
  des rapports sans compter l'adoption comme une obligation.
- [ ] Organiser les contributions, la qualification des contrôles et le support des
  utilisateurs et mainteneurs.
- [ ] Étendre progressivement les technologies et adaptateurs selon des besoins
  observés et des critères de qualité documentés.

Critères de sortie proposés: exécutions reproductibles, limites connues,
maintenance définie, usages locaux et intégrés documentés, sans dépendance
obligatoire à une forge ni mécanisme de blocage.

## Questions ouvertes

## Discovery et racines de projets

- Quel corpus de repositories représentatifs peut être utilisé avec autorisation
  pour mesurer les faux positifs, faux négatifs et ambiguïtés ?
- Quels marqueurs suffisent à distinguer Terraform et OpenTofu sans exécuter les
  deux outils sur les mêmes fichiers HCL ?
- Comment identifier les racines Terraform, Ansible, conteneur et autres
  sous-projets dans un monorepo, puis associer chaque contrôle à sa racine ?
- Quels marqueurs Ansible et Shell sont requis au-delà de `hosts:` et `.sh`, et
  comment éviter de traiter un YAML générique comme un playbook ?
- À quel moment déclarer Kubernetes, Helm, Compose, JavaScript ou TypeScript
  détectés et supportés, avec quels tests de qualification ?
- Comment auditer les erreurs d'accès, liens symboliques et répertoires exclus
  afin qu'un scan incomplet soit visible dans son résultat ?

## Usage et valeur de l'audit volontaire

1. Quels utilisateurs et types de repository local doivent être les premiers
   cas d'usage représentatifs ?
2. Quels bénéfices mesurables apporte un audit lancé à la demande: retour rapide,
   visibilité sur les risques, standardisation ou réduction du travail manuel ?
3. Comment présenter les limites de couverture afin qu'un `PASS` ne soit pas
   interprété comme une certification ou une garantie absolue ?
4. Quelles informations et recommandations aident réellement une personne à
   décider des suites après un `FAIL` ?
5. Comment garantir que le verdict reste consultatif et ne conditionne jamais
   commit, push, merge ou l'accès à un dépôt ?

## Entrée locale et moteurs

1. Le contrat d'entrée se limite-t-il à un chemin de dépôt local et à un fichier
   de configuration facultatif, et quels chemins ou formats faut-il accepter ?
2. Quelles plateformes, shells et environnements doivent être qualifiés en
   premier: Windows PowerShell, Bash, VS Code ou runners CI ?
3. Comment garantir la même détection, le même plan et le même rapport pour un
   même dépôt, quel que soit le lanceur utilisé ?
4. Quelle granularité retenir pour les sous-projets et monorepos, et comment
   combiner signaux de fichiers et déclarations explicites ?
5. Comment gérer les ambiguïtés Terraform/OpenTofu, YAML/Ansible/Kubernetes,
  Helm, contenus générés et futures technologies ?
6. Comment rendre le plan d'exécution explicable, reproductible et adapté aux
  contrôles disponibles sans action réseau ou infrastructure implicite ?
7. Quelles métadonnées, sévérités, seuils, obligations et dérogations doivent
  figurer dans le catalogue et la politique ?
8. Quels éléments et formats composent le rapport standard, et comment distinguer
  constats, erreurs techniques, contrôles absents et limites du scan ?

## Runtime partagé et outils

- Où stocker le runtime partagé et son cache local, avec quelles permissions,
  règles de nettoyage et garanties contre les écritures dans les dépôts analysés ?
- Comment inventorier explicitement les plateformes sous la forme OS +
  architecture et distinguer plateformes ciblées, expérimentales et qualifiées ?
- Comment organiser les binaires et dépendances pour Windows x64/ARM64, Linux
  x64/ARM64, macOS Intel x64 et Apple Silicon ARM64 ?
- Comment qualifier Windows ARM64 et macOS ARM64, et quelles preuves exiger
  avant de déclarer ces plateformes supportées ?
- Comment garantir une résolution d'outils cohérente entre OS et architectures,
  avec des résultats explicables lorsque les artefacts diffèrent ?
- Quelle stratégie appliquer lorsqu'un outil est disponible sur une plateforme
  mais pas sur une autre ?
- Comment versionner les outils, leurs dépendances et les métadonnées des
  artefacts pour rendre chaque scan reproductible ?
- Comment gérer la découverte des mises à jour, leur validation, leur activation
  explicite et le retour à une version précédente ?
- Comment vérifier puis auditer les outils et dépendances utilisés par la
  plateforme elle-même, y compris leur provenance et leurs vulnérabilités ?
- Quels outils sont inclus par défaut au bootstrap, lesquels sont téléchargés
  à la demande, et lesquels peuvent rester optionnels selon les technologies ?
- Comment résoudre les dépendances et incompatibilités d'outils sans imposer
  leur installation manuelle à l'utilisateur ?

## Questions sur la Capability Matrix

- Faut-il raisonner principalement en capacités ou en outils, et comment
  exprimer les capacités requises par technologie, profil et contrôle ?
- Comment représenter dans le rapport une capacité disponible, partiellement
  disponible ou indisponible, avec son motif et les outils candidats ?
- Faut-il versionner la Capability Matrix indépendamment du catalogue d'outils,
  et à quelle portée: plateforme, profil ou exécution ?
- Comment distinguer sans ambiguïté technologie absente, contrôle non applicable,
  capacité indisponible, outil indisponible, erreur technique et échec de conformité ?
- Comment garantir qu'une indisponibilité d'outil ne requalifie jamais une
  technologie détectée comme absente ?
- Comment vérifier si un autre outil peut satisfaire une capacité lorsqu'un
  outil particulier est indisponible ou incompatible ?

## Réutilisation raisonnée des outils externes

- Quels critères démontrent qu'un outil externe apporte une valeur supérieure
  à la complexité, au risque et au coût de maintenance ajoutés ?
- Quand vaut-il mieux développer une capacité en interne plutôt que dépendre
  d'un outil open source, et quand une orchestration native est-elle plus simple ?
- Comment évaluer sécurité, pérennité, portabilité, licence, provenance et
  maintenance avant adoption, puis auditer les dépendances du runtime ?
- Comment garder remplaçables des options telles que mise, asdf, MegaLinter,
  pre-commit, OPA, Trivy, Checkov et Terrascan sans les traiter comme des choix
  déjà décidés ?

## Intégrations facultatives et portabilité

1. Faut-il réellement développer des intégrations GitLab, GitHub ou Bitbucket,
  et quel cas d'usage concret justifierait chacune ?
2. Comment garder le cœur indépendant des forges, notamment sans appels API,
  jetons, règles de branche ou dépendance à une configuration distante ?
3. Comment rendre l'exécution portable entre GitLab, GitHub, Bitbucket, autres
  runners CI, VS Code, PowerShell, Bash et usage entièrement local ?
4. Quelles garanties empêchent un adaptateur optionnel de transformer un `FAIL`
  en blocage automatique de pipeline ou de fusion ?
5. Quels bénéfices apporte la publication facultative d'un rapport dans une CI
  par rapport à la seule génération locale ?
6. Quelles permissions et données un adaptateur peut-il utiliser ou publier,
  et comment rendre ces choix explicites à l'utilisateur ?

## Sécurité, gouvernance et maintenance

1. Quels contrôles peuvent exécuter du code ou accéder au réseau, avec quelles
  limites et quels consentements explicites ?
2. Qui maintient les standards, le catalogue, les profils et les exceptions, et
  comment versionner ces éléments sans imposer leur adoption ?
3. Quels référentiels et quelles preuves sont visés, sans assimiler un scan à
  une certification ?
4. Quelles règles de confidentialité, de rétention et de partage s'appliquent
  aux rapports locaux ou publiés par un adaptateur ?
5. Quels indicateurs mesurent la qualité et l'utilité du moteur sans compter
  les dépôts non audités comme non conformes ?
6. Quel support, processus de contribution et cycle de mise à jour conviennent
  à un outil portable consommé volontairement ?

L'audit documentaire est réalisé; les priorités techniques restent les tâches
ouvertes des phases 1 à 3 et la qualification du contrat consommateur. Les pages
existantes dans [docs/](docs/) portent les détails opérationnels et
[docs/roadmap-status.md](docs/roadmap-status.md) résume les statuts sans créer une
roadmap indépendante. Aucune évolution technique ne doit être engagée sur la
seule base de ce document, sans décision et autorisation explicites.
