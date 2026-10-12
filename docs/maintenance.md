# Maintenance et qualification

Ce guide regroupe installation, mises à jour, validation et limites produit. Pour auditer un nouveau projet, suivre [Utilisation](utilisation.md); les contrats sont dans [Architecture](architecture-current.md).

## Installation de la plateforme

Prérequis observés: Windows x64, Windows PowerShell 5.1, Git et accès HTTPS pour une première installation. Python 3.11 est recherché ou installé localement depuis les artefacts épinglés.

Depuis la racine de la plateforme:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
```

Bootstrap prépare `.venv`, le générateur isolé `.tools/lock-venv`, PSScriptAnalyzer, cinq binaires et les hooks de la plateforme. Il valide le manifeste YAML (clés uniques, structure, URLs HTTPS, chemins relatifs, pins cohérents) et le lock hashé, sans modifier le PATH système. Aucun outil n'est installé dans les projets analysés.

`-Offline` exige les archives, wheels et modules déjà en cache; ce n'est pas une installation vierge. Un cache pre-commit déplacé est refusé hors ligne sans suppression. En ligne, Bootstrap peut reconstruire ce cache via pre-commit. `-Force` peut recréer `.venv`; `-SkipOptionalTools` peut omettre Terragrunt, alors que Doctor l'exige. Terraform/OpenTofu ne sont pas téléchargés par Bootstrap.

## Espaces locaux

| Emplacement | Usage |
| --- | --- |
| `.venv/` | Dépendances Python de la plateforme |
| `.tools/python/` | Python local si nécessaire |
| `.tools/runtime/` | Index et binaires multiversions |
| `.tools/bin/` | Copies historiques vérifiées avant usage |
| `.tools/cache/wheels/` | Wheels vérifiées et wheelhouse hors ligne |
| `.tools/powershell-modules/` | PSScriptAnalyzer local |
| `.tools/pre-commit/` | Environnements des hooks |
| `.tools/lock-venv/` | Générateur de lock isolé |
| `.tools/test-workspaces/` | Fixtures temporaires nettoyées par les tests |
| `reports/` | Rapports locaux, potentiellement sensibles |

Ne placer aucun secret ni configuration propre à un poste dans les caches. Doctor vérifie l'index, Python sélectionné et `.venv`, lock, versions/provenances de wheels, module et binaires; il ne remplace pas pip-audit.

## Validation reproductible

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -Offline -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1 -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Quick -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Full -NoColor
```

Pour une première installation, utiliser Bootstrap sans `-Offline`. Les tâches VS Code correspondantes existent. Les hooks doivent utiliser le cache local configuré par le dépôt; aucune installation globale n'est autorisée.

### Extension Locale

Le MVP local utilise Node 26.10.0 et npm 11.19.1 du hook Markdown local, sans installation globale. TypeScript 5.9.3, les types et l'outil de test sont épinglés dans [le manifeste](../vscode-extension/package.json) et son lock. `Install` applique `npm ci` avec scripts d'installation désactivés sous `.tools/vscode-extension/` et cache sous `.tools/cache/npm/` ; il nécessite le réseau ou les artefacts npm déjà en cache. Il reste explicite, jamais déclenché par la sélection d'une Target.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Install
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action Test
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/vscode-extension.ps1 -Action TestHost
```

`Test` compile et couvre projection, séquences, statuts, erreurs, stockage, permissions, masquage, audits réels avec annulation et lecteur : historiques v1, fichiers invalides/modifiés, identités, chemins et messages hostiles. Il est également appelé par les tests du socle. Les fixtures d'audit indépendantes sont concurrentes dans les tests uniquement. Le moteur et l'interface exécutent toujours un audit global à la fois et des contrôles séquentiels. La suite PowerShell de session vérifie aussi la terminaison du processus et de son enfant ; celle du lecteur vérifie la validation canonique et les octets associés. `TestHost` utilise l'exécutable VS Code installé accessible via `code`, avec profils locaux isolés sous `.tools/`, et vérifie activation, TreeView, commandes, ouverture du lecteur, échappement des sorties et JSON brut. Le host observé est VS Code 1.81.1 x64 ; sa version n'est pas téléchargée ni considérée comme une qualification de toutes les versions compatibles. Le drapeau de confiance désactivée est réservé au host de test isolé, pas au lancement utilisateur. La vérification visuelle des dialogues natifs et de l'écran d'initiation reste une étape manuelle distincte.

Le lecteur valide un snapshot temporaire sous `.tools/state/report-reader/` puis le supprime ; il compare le hash des octets validés et détecte les modifications raisonnablement observables pendant lecture/validation. La référence persistante VS Code ne contient que run_id, Target et source. Aucun consentement n'est réutilisé. La rétention CLI des anciens JSON sous `reports/` n'est pas étendue aux sessions : aucune suppression automatique de session n'est ajoutée.

La compilation produit uniquement `vscode-extension/.extension-build/`, ignoré par Git et exclu des inventaires et scans de fichiers générés. Les sources TypeScript restent analysables. Cette exclusion ne qualifie pas le lint JS/TS : ces technologies restent sans outil configuré dans le catalogue. Les sessions sont sous `.tools/state/runs/` ; elles n'utilisent pas la rétention historique de `reports/`. Linux/macOS et ARM64 restent hors périmètre de ce prototype. Aucun VSIX n'est produit à cette étape.

Derniers résultats consignés le 9 octobre 2026, pas une promesse de résultats futurs:

| Validation | Résultat |
| --- | --- |
| Bootstrap Offline | Code 0 |
| Doctor | 71 PASS, 0 FAIL, 0 WARN, 3 SKIP |
| Quick | 10 PASS, 0 FAIL, 1 WARN, 6 SKIP, code 0 |
| Full | 11 PASS, 1 FAIL, 1 WARN, 6 SKIP, code 1 |
| Hooks | Réussis |
| Tests | 49 Quality Gate, 27 Compliance unitaires, 11 adaptateur unitaires, 8 reproductibilité, 14 provenance, 6 catalogue, 4 matrice plateforme, 13 intégrations Compliance et 4 intégrations adaptateur |

Les messages FAIL/ERROR des fixtures négatives sont attendus si leur scénario termine PASS. Aucun test Python métier n'est présent. Le corpus synthétique Discovery couvre 10 positifs, 2 négatifs et 3 ambiguïtés attendues: zéro faux positif/négatif observé sur ces fixtures uniquement.

## Sécurité et qualification produit

Full reste bloqué par quatre lignes pip-audit (pas nécessairement quatre vulnérabilités distinctes):

| Package | Avis affiché | Correction annoncée |
| --- | --- | --- |
| asteval 1.0.6 | PYSEC-2026-3807 | 1.0.9 |
| asteval 1.0.6 | GHSA-9w56-46f6-3qhx | 1.0.9 |
| ecdsa 0.19.2 | PYSEC-2026-1325, affiché deux fois | Aucune affichée |

Checkov installé impose asteval 1.0.6; forcer sa mise à jour contredirait cette contrainte. Aucun finding n'est ignoré et aucun Quick vert ne remplace Full. ShellCheck est indisponible sous Windows.

Le runtime Windows x64 peut être `qualified` après Bootstrap complet; le produit reste `experimental`. Windows ARM64, Linux x64/ARM64 et macOS x64/ARM64 sont `targeted`. Les preuves poste neuf, runner GitLab, UI VS Code et corpus consommateurs autorisés sont absentes. Les permissions ne sont pas un sandbox; les flux sont tronqués après buffering, pas limités en mémoire avant capture.

## Mise à jour contrôlée

Pour une dépendance Python, modifier le pin exact dans [requirements-dev.txt](../requirements-dev.txt) et [tool-versions.yml](../.config/tool-versions.yml), puis utiliser:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/update-lock.ps1 -Update
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/update-lock.ps1 -Check
```

`-Update` préserve les transitives non libérées; `-UpgradeAll` demande une mise à niveau générale. Le générateur pip-tools épinglé est isolé par [requirements-lock-tools.txt](../requirements-lock-tools.txt). Le lock applicatif est propre à Python 3.11/Windows x64; les hashes proviennent des wheels acquises et vérifiées contre PyPI. La génération pip-compile hashée avait été bloquée par le proxy; la génération locale depuis les wheels vérifiées reste distincte.

Pour un binaire/module, mettre à jour version et sources immuables dans le manifeste avec une somme indépendante publiée par le fournisseur, jamais avec un hash calculé puis présenté comme preuve officielle. Après tout changement, exécuter tests, Quick et Full et examiner les nouveaux avis. Ne contourner aucune règle de sécurité.

## Critères de clôture conservés

La documentation compacte ne change ni les critères de phase ni les obligations RC. Les phases 4, 5 et 6 sont terminées pour le v1; les phases 1, 2, 3, 7 et 8 restent ouvertes sur qualification ou décisions externes. Le Policy Engine n'est pas implémenté.

| Phase | Critères conservés |
| --- | --- |
| 1 | Blocages de sécurité résolus ou arbitrés; environnement de test reproductible; 37 scénarios verts; Quick/Full reproductibles et limites documentées. |
| 2 | Inventaire explicable, précision évaluée sur corpus, racines vérifiées sur projets représentatifs et limites documentées. |
| 3 | 37 tests verts; matrice et résolution sérialisées; versions d'outils binaires vérifiées; Windows x64 reste expérimental tant que Bootstrap ne termine pas; autres plateformes et dépendances runtime non couvertes. |
| 4 v1 | Plan explicable, déterministe et reproductible; résultats normalisés; échec technique distingué de la non-conformité; rapport/verdict vérifiés sur consommateurs fixtures; parité Quick Python comparée sans migration historique. |
| 5 v1 | Catalogue v1 et JSON Schema validés; applicabilité, outils, permissions et limites explicables sans dépendance à une forge. |
| 6 v1 | Contrat versionné, metadata, findings/diagnostics/coverage, verdict explicable, sortie humaine et JSON de référence commun; masquage et rétention locale ciblée testés. |
| 7 | Moteur utilisable sans adaptateur; mêmes résultats de fond pour un même dépôt et une même configuration; intégrations facultatives n'empêchant aucune opération Git. |
| 8 | Exécutions reproductibles, limites connues, maintenance définie, usages locaux et intégrés documentés, sans dépendance obligatoire à une forge ni mécanisme de blocage. |

La RC reste BLOQUÉE: sécurité Full sans findings masqués; Bootstrap poste propre, lock/pip check/Doctor/hooks réussis; preuves natives pour toute plateforme annoncée supportée; corpus réel autorisé; GitLab et UI réels; responsabilités de support définies. Runtime `qualified` ne suffit pas.

Les décisions d'override/politique, propriétaires et approbations relèvent de la gouvernance; les nouvelles technologies doivent répondre à un besoin consommateur autorisé. Un signalement doit inclure commit, OS/architecture, versions, mode, codes de sortie et extrait de rapport expurgé. Aucun responsable/SLA dédié n'est nommé.
