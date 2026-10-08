# Tests et validation

## Cycle d'implementation courant

Phases 4–8, validation locale du 7 octobre 2026: **27 tests unitaires Compliance, 11 adaptateur, 5 reproductibilité, 6 Control Catalog, 4 matrice plateforme, 13 intégrations Compliance, 4 intégrations adaptateur et 48 scénarios Quality Gate historiques** réussis. Couverture: DAG/cycles, budgets, sorties bornées, catalogue, rapports, masquage configurable, rétention locale ciblée, permissions, métriques de phase, parité, contrats PowerShell/VS Code/GitLab, relais Git Bash, lock exact Windows x64 et corpus consommateurs synthétique.
Chaque mode historique écrit aussi le rapport de référence sous `reports/compliance-report.json`; les fixtures valident ce contrat tout en vérifiant que le rapport historique et le code de sortie restent inchangés. Aucun pipeline GitLab distant n'a été exécuté.

La qualification runtime locale couvre sommes de source/archive, SHA-256 de copie/index, sélection de version active, coexistence multi-version, rollback vers une version conservée et réactivation; les anomalies de hash, outil absent et index invalide restent des erreurs explicites. Les fixtures couvrent aussi timeout avec sorties partielles et rapport Discovery bloqué/partiel. Ces tests ne remplacent pas une provenance indépendante du fournisseur ni un bootstrap poste neuf.

Quick du 7 octobre: **10 PASS, 0 FAIL, 1 WARN, 6 SKIP, 0 ERROR**, code 0. Full: **11 PASS, 1 FAIL, 1 WARN, 6 SKIP, 0 ERROR**, code 1; seul pip-audit échoue sur `asteval==1.0.6` et `ecdsa==0.19.2` (quatre lignes d'avis, dont un identifiant répété). Aucun avis n'est ignoré. ShellCheck reste indisponible sur Windows.

La procédure de qualification locale prévue sous Windows x64 est: bootstrap, Doctor, tests, Quick puis Full. Un index `qualified` prouve la fin du bootstrap seulement; la réussite Quick/tests ne qualifie ni les consommateurs réels, ni un runner CI, ni une plateforme différente. Le Full en échec reste un blocage explicite de qualification globale.

Le corpus synthétique Discovery rapporte 10 échantillons positifs, 2 négatifs, 3 ambiguïtés attendues, 0 faux positif, 0 faux négatif et 0 ambiguïté inattendue. Ces mesures sont des tests de régression à marqueurs connus, pas une mesure sur la diversité de dépôts consommateurs.

Le corpus synthétique de Discovery rapporte 10 échantillons positifs, 2 négatifs, 3 ambiguïtés attendues, 0 faux positif, 0 faux négatif et 0 ambiguïté inattendue. Ce résultat est un test de régression à marqueurs connus, pas une mesure sur la prévalence ni la diversité de dépôts consommateurs.

Le lancement Compliance sur le depot local a produit [compliance-report.json](../reports/compliance-report.json): 32 controles planifies, 4 success, 1 fail, 1 error et 26 skipped, verdict **FAIL**, couverture partielle. Le fail concerne `Update-Detection` du harnais historique (`PSUseShouldProcessForStateChangingFunctions`); l'erreur critique est ShellCheck indisponible sous Windows. Les nouveaux fichiers du module, de l'adaptateur et des tests passent l'analyse PowerShell. Aucun controle n'a ete ignore pour rendre ce rapport vert.

Cycle Resolver: **44 PASS, 0 FAIL**. Les nouvelles regressions couvrent alternative de secours, priorite du profil quand plusieurs candidats sont disponibles, disponibilite alternative dans la matrice et incompatibilite native Ansible Windows malgre un lanceur present. Les compteurs de selection et reutilisation sont verifies dans le scenario Python complementaire.

Cycle Discovery: **42 PASS, 0 FAIL**. Trois scenarios supplementaires couvrent le monorepo IaC mixte avec une racine non selectionnee, la lecture d'un YAML verrouille (JSON et rapport partiels, code 2, erreur dedupliquee), et l'erreur d'enumeration. Les scenarios precedents restent verts. Ces fixtures ne remplacent pas un corpus autorise de repositories reels.

Cycle integrite: **39 PASS, 0 FAIL**. La nouvelle regression couvre un artefact intact, une alteration du runtime, une copie historique alteree bloquee avant execution, une empreinte absente et un schema d'index invalide. Les preuves cache ci-dessous decrivent le cycle precedent.

Le 6 octobre 2026, la regression du cache pre-commit deplace porte la suite a **38 PASS, 0 FAIL**. Bootstrap complet: code 0, hooks reconstruits et marqueur runtime `windows-x64: qualified`. Quick: **10 PASS, 0 FAIL, 1 WARN, 6 SKIP, 0 ERROR**, code 0, Markdownlint execute et reussi. Aucune regle ni aucun controle n'a ete retire. Les resultats de l'audit documentaire ci-dessous restent des preuves historiques.

Full du cycle: **11 PASS, 1 FAIL, 1 WARN, 6 SKIP, 0 ERROR**, code 1. Seul pip-audit echoue. L'index PyPI affiche Checkov 3.3.25, dont les metadonnees imposent toujours `asteval==1.0.6` et `ecdsa>=0.19.0,<1.0.0`. Ecdsa 0.19.2 est la version publiee la plus recente observee. Aucun pin n'a ete force, aucun controle retire et aucun avis ignore.

## Suite automatisée

Lancer les scénarios PowerShell avec:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1
```

Les tests d'intégration chargent les fonctions du Quality Gate par AST et créent des repositories fixtures sous `.tools/test-workspaces`, supprimés à la fin. Ils couvrent marqueurs Discovery, racines imbriquées, ambiguïtés Terraform/OpenTofu et Ansible, Kubernetes/Helm/JS/TS, Capability Matrix, Resolver, runtime versionné/qualifié, rapports, formats et contrôles existants.

Résultat réobservé dans Full pendant l'audit documentaire du 6 octobre 2026: **37 PASS, 0 FAIL**, code 0 pour le lanceur de tests. Aucun scénario nouveau n'a été ajouté: seuls les documents sont modifiés. Les messages FAIL/ERROR des fixtures négatives sont attendus et ne signifient pas que ces tests échouent. Le cas TOML utilise le Python de `.venv`; aucun test Python métier n'est présent.

## Quality Gates

Commandes exécutées pendant l'audit, depuis la racine, sans `-ReportPath` pour préserver les rapports existants:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Quick -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Full -NoColor
```

- Quick: 9 PASS, 1 FAIL, 1 WARN, 6 SKIP, 0 ERROR; code 1. Markdownlint échoue car un clone pre-commit recherche son manifeste sous l'ancien emplacement `service-manager-template`.
- Full: 10 PASS, 2 FAIL, 1 WARN, 6 SKIP, 0 ERROR; code 1. Outre Markdownlint, pip-audit affiche quatre lignes d'avis sur `asteval==1.0.6` et `ecdsa==0.19.2`.
- PSScriptAnalyzer, syntaxe PowerShell, Gitleaks, YAML, TOML et tests PowerShell passent dans le dernier Full.

Les rapports [quick.json](../reports/quick.json) et [full.json](../reports/full.json) sont des preuves antérieures du même jour, pas les sorties de cette réexécution. `reports/*` est ignoré par Git. Le rapport [Doctor](../reports/doctor-report.json) indique historiquement 67 PASS et 3 SKIP; Doctor n'a pas été relancé pendant cet audit. Aucun rapport ni fichier runtime n'est volontairement réécrit.

## Avis de dépendances observés

| Paquet installé | Identifiant affiché | Correction annoncée par pip-audit |
| --- | --- | --- |
| asteval 1.0.6 | PYSEC-2026-3807 | 1.0.9 |
| asteval 1.0.6 | GHSA-9w56-46f6-3qhx | 1.0.9 |
| ecdsa 0.19.2 | PYSEC-2026-1325, affiché deux fois | Aucune version affichée |

Les quatre lignes ne démontrent pas quatre vulnérabilités distinctes: un identifiant est répété et les alias ne sont pas normalisés. Les métadonnées installées de Checkov 3.3.23 imposent `asteval==1.0.6` et `ecdsa>=0.19.0,<1.0.0`; le verrou fixe ecdsa à 0.19.2. Remplacer asteval seul par 1.0.9 contredirait donc cette dépendance stricte. Aucune mise à jour, exclusion d'avis ni décision de dérogation n'a été effectuée.

## Bootstrap

La dernière exécution documentée du bootstrap a restauré `.venv`, installé les paquets verrouillés et inscrit cinq binaires avec SHA-256, puis terminé en code 1 à l'installation des hooks. Il n'a pas été réexécuté pendant cet audit, afin de ne pas modifier dépendances, hooks ou qualification. L'index relu déclare toujours `windows-x64: experimental`; ne pas annoncer une plateforme qualifiée sur la seule présence des binaires. Voir [runtime.md](runtime.md).

Pendant cet audit, les cinq fichiers référencés dans l'index ont été vérifiés en lecture seule: tous existent et leurs SHA-256 recalculés avec `Get-FileHash` correspondent aux valeurs enregistrées. Cette comparaison à l'index local ne prouve pas à elle seule une provenance officielle ni une qualification de plateforme.

## Validation documentaire

Le contrôle des cibles des 73 liens Markdown locaux dans README, plan et les dix pages de docs, y compris l'ancre Roadmap, ne relève aucun lien invalide. Aucun lien Markdown externe n'est présent dans ce périmètre. Les diagnostics VS Code sur les documents ne signalent aucune erreur; cela ne remplace pas Markdownlint, bloqué avant analyse par son cache.

README est le point d'entrée court et renvoie aux dix pages existantes. Aucun document n'a été créé ou déplacé; le plan a été modifié en place. Le code, les tests, les configurations, les verrous et les rapports existants sont conservés.

## Limites de validation

Les tests sont synthétiques et couplés aux fonctions extraites par AST. Ils ne qualifient ni un poste neuf, ni une CI distante, ni Linux/macOS/ARM64, ni l'audit complet d'un dépôt externe. Les tests runtime valident indexation, copie/hash, version active et refus d'une plateforme expérimentale; ils ne prouvent pas la revérification d'intégrité à chaque usage.

Markdownlint s'execute maintenant avec succes apres reconstruction du cache et correction des erreurs de forme. Les limites de reporting restent dans [reporting.md](reporting.md).
