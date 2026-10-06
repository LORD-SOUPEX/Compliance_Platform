# État des phases

Synthèse de [la roadmap existante dans plan.md](../plan.md#roadmap), mise à jour le 6 octobre 2026 après lecture du code et réexécution des gates. Cette page n'est pas une roadmap indépendante. Les phases fixent les priorités, elles ne bloquent pas l'avancement.

| Phase/composant | Statut | Preuve et reste principal |
| --- | --- | --- |
| Stabilisation du socle | PHASE EN COURS | 44 tests reussis; cache repare, Markdownlint et Quick passent. Full reste bloque par les dependances; poste neuf non qualifie. |
| Discovery Engine | PHASE EN COURS | Racines IaC mixtes et diagnostics de scan partiel testes; corpus reel, overrides et autres layouts complexes restent ouverts. |
| Tool Bootstrap & Tool Resolver | PHASE EN COURS | Bootstrap termine, integrite des binaires indexes, alternatives et compteurs testes; paquets/modules, provenance et qualification produit restent ouverts. |
| Compliance Engine | PHASE NON COMMENCÉE | L'orchestration reste dans le Quality Gate monolithique. |
| Control Catalog | PHASE NON COMMENCÉE | Profils capacités/outils codés dans PowerShell; pas de catalogue indépendant. |
| Reporting Engine | PHASE NON COMMENCÉE | JSON Discovery et Quality Gate présents, sans contrat commun ni composant dédié. |
| Policy Engine | PHASE NON COMMENCÉE | YAML descriptif, non autoritaire à l'exécution. |
| Optional Integrations | PHASE NON COMMENCÉE | Pas d'adaptateurs portables distincts; les scripts/tâches/job GitLab restent propres au dépôt actuel. |
| Industrialisation | PHASE NON COMMENCÉE | Runtime multi-OS/architecture et bootstrap reproductible non qualifiés. |

## Gates de validation courants

Les résultats détaillés et leur provenance sont centralisés dans [testing.md](testing.md). Aucun gate n'a été contourné.

## Fonctionnalités achevées et phases restantes

`PHASE TERMINÉE`: aucune phase complète, car aucun ensemble de critères de sortie n'est entièrement démontré. Cela ne remet pas en cause les fonctionnalités livrées: CLI Discovery externe, JSON v1, preuves/racines/ambiguïtés, matrice calculée, resolver descriptif et index runtime multiversion sont implémentés et testés.

Les phases 1 a 3 restent `PHASE EN COURS`: vulnerabilites, reproductibilite poste neuf/runner, qualification Discovery sur corpus et runtime multi-plateforme restent ouverts. Le cache pre-commit est repare et Quick passe. Les phases 4 a 8 et Policy Engine restent `PHASE NON COMMENCÉE` au sens de composants autonomes livres.

Le partage sans écriture dans les dépôts consommateurs, l'exécution pilotée par le resolver, les alternatives de capacités et la neutralité des futurs adaptateurs ne sont pas encore démontrés. Les tâches détaillées sont maintenues uniquement dans [plan.md](../plan.md).
