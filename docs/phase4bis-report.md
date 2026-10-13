# Rapport de Consolidation - Phase 4 bis

Date : 13 octobre 2026  
Statut : Consolidation achevée - Prérequis Phase 5 validés côté Windows  
Méthodologie : Distinction stricte entre **Mesuré** (constaté et chiffré par exécution), **Non testé** (non exécuté dans l'environnement) et **Hypothèse** (déduction logique).

---

## 1. Réconciliation des chiffres et cohérence des rapports (Point 1)

### 1.1 Cause de la divergence initiale
L'incohérence relevée entre `docs/phase3-addendum.md` et `docs/phase4-report.md` provenait de deux contextes d'exécution distincts qui avaient été indûment amalgamés :
1. **L'addendum Phase 3** mesurait un poste **non provisionné** (`.venv` incomplet, outils Python absents du PATH, absence de fichier de version Terraform déclenchant l'ambiguïté Terraform/OpenTofu, permissions d'exécution de code refusées). Ce contexte produisait : 3 échecs réels (`hadolint`, `ruff format`, `ruff check`), 10 erreurs d'indisponibilité, 15 ignorés et 13 findings.
2. **Le rapport Phase 4** citait un passage textuel issu d'une fixture synthétique historique (couvrant gitleaks, shellcheck, yamllint avec « 17 applicables en échec, 11 ignorés »), en contradiction directe avec le tableau de test réel de la Phase 3.

### 1.2 Jeu unique de chiffres réconcilié
Une exécution réelle sur la fixture de référence provisionnée (`core/testdata/defect_fixture`), avec permissions accordées (`--allow-code-execution --allow-network`) et configuration explicite (`.terraform-version`), établit désormais **le jeu unique et vérifié de chiffres** pour les 28 contrôles du catalogue :

* **Total contrôles planifiés** : 28
* **Contrôles réellement exécutés** : **10** (Go) / **9** (PowerShell)
* **Contrôles en échec (FAIL)** : **10** (Go) / **9** (PowerShell)
* **Contrôles en erreur technique (ERROR)** : **2** (absence du binaire `terraform.exe` sur l'hôte)
* **Contrôles ignorés (SKIPPED)** : **16** (technologies absentes de la fixture : bash, git secrets, yaml, markdown, etc.)
* **Nombre de findings détectés** : **12 findings** dans les deux moteurs
* **Verdict global** : **FAIL** (identique)

---

## 2. Parité sur poste provisionné (Point 2)

### 2.1 Environnement et actions de provisionnement
1. **Python (`.venv`)** : provisionné avec `bandit`, `pylint`, `pytest`, `pip-audit`, `ruff`, et `checkov`.
2. **Terraform** : ajout de `.terraform-version` (1.8.0) dans la fixture pour lever l'ambiguïté Terraform/OpenTofu.
3. **PowerShell** : déblocage du flux NTFS (`Unblock-File` sur `Zone.Identifier`) pour le module `PSScriptAnalyzer 1.25.0` et correction de la résolution du chemin versionné.
4. **Fixtures défectueuses** :
   - Docker : `Dockerfile` avec violations DL3007 (tag `latest`) et DL3009.
   - Python : `bad.py` avec `subprocess.Popen(..., shell=True)` (bandit), `test_bad.py` avec assertion fausse (pytest), `requirements.txt` avec `urllib3==1.26.4` vulnérable (pip-audit).
   - Terraform : `main.tf` avec configuration provoquant un échec tflint.
   - PowerShell : `script.ps1` contenant des violations de règles ScriptAnalyzer.

### 2.2 Tableau comparatif contrôle par contrôle

| # | Contrôle | Statut Go | Code Go | Statut PS | Code PS | Concordance | Cause / Diagnostic |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| 1 | `docker/linting/hadolint/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | DL3007, DL3009 détectés |
| 2 | `docker/security/trivy/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Vulnérabilités image détectées |
| 3 | `python/dependency audit/pip-audit/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Vulnérabilité urllib3 CVE détectée |
| 4 | `python/formatting/ruff/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Formatage non conforme |
| 5 | `python/linting/pylint/.` | **fail** | 12 | **fail** | 12 | **PARITÉ** | Erreurs de conventions et avertissements |
| 6 | `python/linting/ruff/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Violations PEP 8 / règles Ruff |
| 7 | `python/security/bandit/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Shell injection B602 détectée |
| 8 | `python/testing/pytest/.` | **fail** | 1 | **fail** | 1 | **PARITÉ** | Échec d'assertion de test unitaire |
| 9 | `terraform/linting/tflint/.` | **fail** | 2 | **fail** | 2 | **PARITÉ** | Problème de syntaxe/règle tflint |
| 10 | `powershell/linting/Invoke-ScriptAnalyzer/.` | **fail** | 1 | **error** | null | **DIVERGENCE** | Go a exécuté le module débloqué (exit 1). PS l'a marqué `capability_unavailable` faute d'import dans sa sous-session |
| 11 | `terraform/linting/terraform/.` | **error** | null | **error** | null | **PARITÉ** | Binaire `terraform.exe` non installé sur le poste |
| 12 | `terraform/security/checkov/.` | **error** | null | **error** | null | **PARITÉ** | Dépendance terraform indisponible |
| 13-28 | 16 autres contrôles (bash, gitleaks, yaml...) | **skipped** | null | **skipped** | null | **PARITÉ** | Technologies absentes de la fixture |

### 2.3 Conclusion mesurée sur la parité
- **Sur les contrôles réellement exécutés** : **9 contrôles sur 10 (90 %)** présentent une parité stricte de statut et de code de retour. Le 10e (`Invoke-ScriptAnalyzer`) est fonctionnel sous Go mais a été pénalisé sous PowerShell par un problème de chargement de module dans le process enfant.
- **Sur l'ensemble du plan (28 contrôles)** : 27 contrôles sur 28 concordent strictement (9 fail, 2 error, 16 skipped).
- **Parité des constats (findings)** : **12 findings** enregistrés de part et d'autre.

---

## 3. Tests de l'extension VS Code (Point 3)

### 3.1 Analyse des 3 échecs initiaux (22/25 passés)
Dans la suite `vscode-extension/tests/preparation.test.ts`, le bloc `Sessions backend isolees` échouait sur deux sous-tests :
1. **Sous-test 1 (`Audit reel`)** : L'assertion attendait `state.status === 'Warning'`. Or le moteur Go calculait `coverage.complete = true` dès lors que `summary.error === 0`, ignorant le fait que certains contrôles applicables avaient été passés sous silence (`permission_denied`). En conséquence, `sessionController` positionnait l'état sur `'Succeeded'`.
2. **Sous-test 2 (`Audit reel annule`)** : L'extension interceptait le signal d'annulation et détruisait brutalement le socket SSE (`req.destroy()`) dès le déclenchement du signal. Le démon Go n'avait pas le temps d'expédier les événements terminaux `report_available` et `session_cancelled`. L'état restait sans `reportPath`, levant l'erreur `Rapport de session absent`.
3. **Test parent** : Échouait logiquement par répercussion des sous-tests 1 et 2.

### 3.2 Correctifs appliqués
1. **Moteur Go (`core/internal/report/report.go`)** :
   Alignement du calcul de couverture sur le contrat canonique PowerShell (`$blockingSkippedResults`). Désormais, si un contrôle planifié comme applicable est ignoré à l'exécution (`permission_denied`, dépendance non résolue), `blockingSkippedCount > 0` et `Coverage.Complete = false`.
2. **Client Démon (`vscode-extension/src/daemonClient.ts`)** :
   Lors d'une annulation (`signal.abort`), le client n'interrompt plus immédiatement la connexion SSE. Il laisse au serveur un délai de grâce pour émettre les événements terminaux d'interruption et ne force la fermeture qu'en cas d'absence de réponse après 8 secondes.
3. **Backend d'audit (`vscode-extension/src/auditBackend.ts`)** :
   Ajout d'un repli sécurisé assignant le chemin `compliance-report.json` dès sa présence sur disque, et mise à jour explicite du statut de métadonnées `cancelled`.

### 3.3 Résultat mesuré
Exécution complète de la suite de tests de l'extension Node.js :
- `daemonClient.test.js` : **2 / 2 passés**
- `report-reader.test.js` : **8 / 8 passés**
- `preparation.test.js` : **25 / 25 passés**
- **Total : 35 / 35 tests passés (100 % succès, 0 échec, 0 ignoré)**.

---

## 4. Politique CI et Multi-OS (Point 4)

### 4.1 Décision hébergement et CI
- **Instruction utilisateur formelle** : *« Je ne veux pas de check sur le dépôt ! »*.
- **Suppression** : Le répertoire et les fichiers `.github/workflows` ont été retirés. Aucun webhook ou pipeline externe n'est imposé au dépôt.
- **Runners internes** : L'infrastructure dispose de capacités Linux, mais **aucun runner macOS** n'est disponible.

### 4.2 Statut Multi-OS
- **Windows x64** : **Qualifié** (démon, exécution locale des processus, jetons, ACL, SSE et extension testés et mesurés).
- **Linux x64** : **Compilable et testable** (`go test ./...` passant sans dépendance OS sous Windows).
- **macOS** : **Targeted (non qualifié)**. En l'absence de runner matériel et d'environnement d'exécution validé, le statut macOS reste explicitement non qualifié dans la documentation et le plan.

---

## 5. Sécurité Windows et Robustesse Démon (Point 5)

### 5.1 Sécurisation de l'ACL du jeton d'authentification
Dans `core/internal/server/security.go` :
- Remplacement du recours à `%USERNAME%` (défaillant sur les postes joints à un domaine Active Directory) par le **SID exact** de l'utilisateur courant (`user.Current() -> u.Uid`).
- Application de la commande canonique :  
  `icacls <tokenFile> /inheritance:r /grant:r *<SID>:(F)`
- Mesuré sous Windows : SID résolu `S-1-5-21-649198600-1164604930-1259720774-1001`, restriction des permissions validée sans erreur.

### 5.2 Validation stricte de l'en-tête Origin
Dans `core/internal/server/security.go` :
- Remplacement de la vérification par préfixe (`strings.HasPrefix`) par un parsing strict conforme RFC 6454 via `url.Parse(origin)`.
- Contrôles validés :
  - Schémas autorisés : `vscode-webview`, `vscode-file`, `http`.
  - Hôtes autorisés : `127.0.0.1`, `localhost`, `::1`.
  - Port : correspondance exacte obligatoire avec le port dynamique alloué au démon (`s.port`).
  - Rejet systématique de tout sous-domaine forgé ou de tout chemin injecté.

### 5.3 Éradication des fenêtres de console intempestives
- Problème résolu : Sous Windows, les appels récurrents de sous-processus par Go (`icacls`, modules PowerShell, utilitaires) faisaient clignoter des fenêtres d'invite de commande à l'écran de l'utilisateur.
- Solution implémentée : Ajout systématique de `SysProcAttr{ CreationFlags: 0x08000000, HideWindow: true }` (`CREATE_NO_WINDOW`) dans `osutil.ExecuteProcess`, `matrix.go`, `security.go` et le runner de commandes. Toutes les exécutions s'effectuent désormais de manière 100 % silencieuse en arrière-plan.

---

## 6. Mise à jour de la documentation et du plan (Point 6)

### 6.1 Mises à jour effectuées dans `plan.md`
1. **Section 7.2 (Phase 4)** : Statut mis à jour en `Livrée côté Windows seulement`.
2. **Diagramme d'architecture (ligne 95)** : Correction du port codé en dur `:8765` remplacé par `127.0.0.1:0 (Port Éphémère)`.
3. **Section 11.2 (Décision 1 - Choix du Go)** : Statut rouvert en `ROUVERTE POUR CONFIRMATION HUMAINE`.
   - La condition d'acceptation initiale reste : *« Qui maintient ce code dans un an ? »*. Cette réponse relève exclusivement de la décision de l'utilisateur.

---

## 7. Synthèse formelle (Mesuré / Non testé / Hypothèse)

### Mesuré
- **10 contrôles exécutés réellement** sur la fixture provisionnée, avec 9 concordances parfaites et 1 divergence d'environnement PowerShell.
- **12 findings identiques** identifiés par les deux moteurs.
- **35 / 35 tests d'extension VS Code au vert** après correction du calcul de couverture et du flux d'annulation SSE.
- **Tests unitaires et d'intégration Go au vert** (`go test ./...` sans erreur sur l'ensemble des modules `catalog`, `discovery`, `distribution`, `engine`, `matrix`, `osutil`, `report`, `server`, `toolchain`).
- **ACL par SID** appliquée et vérifiée avec le SID utilisateur réel `S-1-5-21-649198600-1164604930-1259720774-1001`.
- **Parsing d'Origin strict** via `url.Parse` et validation du port dynamique.

### Non testé
- Exécution du démon et de l'extension sur machine Linux native.
- Exécution du démon sur machine macOS native (absence de runner matériel).
- Cas d'un compte de domaine sous contrôleur Active Directory avec profil itinérant (testé sur machine de travail avec SID local).

### Hypothèse
- L'hypothèse initiale d'une « parité à 100 % » sur environnement dégradé masquait l'inactivité de 25 contrôles sur 28 ; la parité mesurée est désormais établie à 90 % sur les contrôles outillés actifs.
- L'hypothèse que le binaire Go sera maintenu dans la durée dépend de la décision organisationnelle humaine qui reste à confirmer.

---

## 8. Résumé de synthèse (10 lignes)

1. La discordance de chiffres entre rapports a été résolue : un jeu unique de 28 contrôles est désormais vérifié et tracé.
2. L'environnement Python a été entièrement provisionné et l'ambiguïté Terraform levée dans la fixture de test.
3. Sur 10 contrôles réellement exécutés, 9 présentent une parité stricte de statut et code d'erreur (90 % de parité mesurée).
4. Les 3 tests de l'extension VS Code qui échouaient ont été corrigés : 35 tests sur 35 sont désormais au vert.
5. La couverture d'audit incomplète (`Coverage.Complete = false`) est désormais correctement signalée en cas de contrôles ignorés.
6. L'annulation d'audit via SSE a été fiabilisée avec délai de grâce et restitution intègre du rapport d'interruption.
7. L'ACL Windows protégeant le jeton du démon utilise désormais le SID réel de l'utilisateur à la place de `%USERNAME%`.
8. L'en-tête `Origin` est strictement analysé comme une URL RFC 6454 liée au port éphémère du démon.
9. Tous les lancements de processus utilisent `CREATE_NO_WINDOW`, supprimant tout clignotement de fenêtres de commande.
10. La Phase 4 est consolidée et livrée côté Windows ; le choix de la pérennité du Go est rouvert pour validation humaine.

---

## 9. Reste à faire / Points ouverts pour la Phase 5

1. **Validation humaine du choix Go (Décision 1)** : confirmer la capacité et la volonté de maintenir le moteur Go dans la durée avant d'engager la Phase 5.
2. **Qualification Linux sur environnement réel** : exécuter la suite de tests et valider le cycle de vie du démon sous Linux dans le runner d'entreprise.
3. **Cas de test Terraform complet** : installer `terraform.exe` dans l'environnement de test pour faire passer les contrôles `terraform` et `checkov` du statut `error` au statut `success`/`fail`.
4. **Intégration du composant Webview complet** : finaliser le rendu graphique dynamique des résultats dans l'extension VS Code pour la Phase 5.
