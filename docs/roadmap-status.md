# État des phases

Synthèse de [la roadmap existante dans plan.md](../plan.md#roadmap), mise à jour le 7 octobre 2026 après exécution des tests et gates. Cette page n'est pas une roadmap indépendante. Les phases fixent les priorités, elles ne bloquent pas l'avancement.

| Phase/composant | Statut | Preuve et reste principal |
| --- | --- | --- |
| Stabilisation du socle | PHASE EN COURS | 45 tests historiques, 27 Compliance unitaires, 13 intégrations Compliance, 4 adaptateurs et 6 tests catalogue; Quick vert. Full reste bloqué par pip-audit. |
| Discovery Engine | PHASE EN COURS | Racines IaC mixtes et diagnostics de scan partiel testes; corpus reel, overrides et autres layouts complexes restent ouverts. |
| Tool Bootstrap & Tool Resolver | PHASE EN COURS | Bootstrap termine, integrite des binaires indexes, alternatives et compteurs testes; paquets/modules, provenance et qualification produit restent ouverts. |
| Compliance Engine | PHASE TERMINÉE | Critères v1: DAG, budgets, exécution, résultats, findings/verdict et parité fixtures; sandbox et consommateurs réels suivent en Phase 8. |
| Control Catalog | PHASE TERMINÉE | Catalogue JSON/Schema v1, 28 contrôles, objectifs/limites; Matrix et Plan consomment les métadonnées. Qualification réelle suivie en Phase 8. |
| Reporting Engine | PHASE TERMINÉE | Schéma/validateurs v1 et rapport de référence pour Compliance et modes historiques; findings, diagnostics, coverage, limitations, metadata et résumé stderr. Masquage/nettoyage avancés en Phase 8. |
| Policy Engine | PHASE NON COMMENCÉE | YAML descriptif, non autoritaire à l'exécution. |
| Optional Integrations | PHASE EN COURS | Contrat commun et wrappers PowerShell/Bash/VS Code/GitLab testés localement; runner GitLab distant non qualifié. |
| Industrialisation | PHASE EN COURS | Procédure de qualification Windows x64 et résultats Quick/Full documentés; reproductibilité sur poste neuf, autres plateformes, support et maintenance restent ouverts. |

## Gates de validation courants

Les résultats détaillés et leur provenance sont centralisés dans [testing.md](testing.md). Aucun gate n'a été contourné.

## Fonctionnalités achevées et phases restantes

Les critères v1 des phases 4, 5 et 6 sont démontrés; cela ne clôt pas les travaux de qualification multi-plateforme ou de gouvernance ultérieurs.

Les phases 1 à 3 continuent sans bloquer. Les critères v1 des phases 4 à 6 sont terminés; Phase 7 reste ouverte jusqu'à l'essai du runner GitLab distant. Phase 8 a commencé par la formalisation des gates et de la qualification locale; Policy Engine reste à construire.

Le nouveau parcours suit le resolver et les racines, traite les alternatives et affiche les controles omis. Les operations autorisees a executer du code ne sont pas isolees; toutes les plateformes et technologies ne sont pas encore qualifiees. Les taches detaillees restent dans [plan.md](../plan.md).
