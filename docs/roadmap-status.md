# État des phases

Synthèse de [la roadmap existante dans plan.md](../plan.md#roadmap), mise à jour le 6 octobre 2026 après lecture du code et réexécution des gates. Cette page n'est pas une roadmap indépendante. Les phases fixent les priorités, elles ne bloquent pas l'avancement.

| Phase/composant | Statut | Preuve et reste principal |
| --- | --- | --- |
| Stabilisation du socle | PHASE EN COURS | 44 tests historiques et 32 Compliance verts; cache repare et Quick vert. Full reste bloque par les dependances. |
| Discovery Engine | PHASE EN COURS | Racines IaC mixtes et diagnostics de scan partiel testes; corpus reel, overrides et autres layouts complexes restent ouverts. |
| Tool Bootstrap & Tool Resolver | PHASE EN COURS | Bootstrap termine, integrite des binaires indexes, alternatives et compteurs testes; paquets/modules, provenance et qualification produit restent ouverts. |
| Compliance Engine | PHASE EN COURS | Parcours v1 complet: plan, execution bornee, resultats, aggregation et verdict, avec 21 unitaires et 11 integrations. Migration historique et qualifications avancees restent ouvertes. |
| Control Catalog | PHASE NON COMMENCÉE | Profils capacités/outils codés dans PowerShell; pas de catalogue indépendant. |
| Reporting Engine | PHASE EN COURS | Rapport Compliance v1 commun et versionne livre; enveloppes historiques, formats humains et gouvernance de retention non migres. |
| Policy Engine | PHASE NON COMMENCÉE | YAML descriptif, non autoritaire à l'exécution. |
| Optional Integrations | PHASE NON COMMENCÉE | Pas d'adaptateurs portables distincts; les scripts/tâches/job GitLab restent propres au dépôt actuel. |
| Industrialisation | PHASE NON COMMENCÉE | Runtime multi-OS/architecture et bootstrap reproductible non qualifiés. |

## Gates de validation courants

Les résultats détaillés et leur provenance sont centralisés dans [testing.md](testing.md). Aucun gate n'a été contourné.

## Fonctionnalités achevées et phases restantes

`PHASE TERMINÉE`: aucune phase complète, car aucun ensemble de critères de sortie n'est entièrement démontré. Cela ne remet pas en cause les fonctionnalités livrées: CLI Discovery externe, JSON v1, preuves/racines/ambiguïtés, matrice calculée, resolver descriptif et index runtime multiversion sont implémentés et testés.

Les phases 1 a 3 continuent sans bloquer la Phase 4. Compliance et Reporting sont `PHASE EN COURS` avec une premiere livraison exploitable. Les phases 5, 7, 8 et Policy Engine restent `PHASE NON COMMENCÉE` comme composants produit autonomes.

Le nouveau parcours suit le resolver et les racines, traite les alternatives et affiche les controles omis. Les operations autorisees a executer du code ne sont pas isolees; toutes les plateformes et technologies ne sont pas encore qualifiees. Les taches detaillees restent dans [plan.md](../plan.md).
