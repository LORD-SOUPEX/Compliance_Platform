# Outils locaux

Les outils téléchargés et les environnements générés restent dans ce dossier et sont ignorés par Git.

- `python/` contient le runtime Python local lorsque le poste n’en fournit aucun qui fonctionne.
- `bin/` contient les exécutables autonomes vérifiés par leur somme SHA-256.
- `cache/` contient les archives et roues nécessaires aux installations, notamment au mode hors ligne.
- `powershell-modules/` contient PSScriptAnalyzer installé sans portée globale ni profil utilisateur.
- `pre-commit/` contient les environnements isolés créés par les hooks.
- `test-workspaces/` contient les projets temporaires des tests du Quality Gate.

Les versions, sources officielles et sommes publiées sont centralisées dans [`.config/tool-versions.yml`](../.config/tool-versions.yml). Ne placez ici aucun secret ou fichier de configuration propre à un poste.
