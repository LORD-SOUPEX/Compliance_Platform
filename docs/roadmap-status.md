# État des phases

Synthèse de [la roadmap existante dans plan.md](../plan.md#roadmap), mise à jour le 9 octobre 2026 après exécution des tests et gates. Cette page n'est pas une roadmap indépendante. Les phases fixent les priorités, elles ne bloquent pas l'avancement.

| Phase/composant | Statut | Preuve et reste principal |
| --- | --- | --- |
| Stabilisation du socle | PHASE EN COURS | 49 scénarios Quality Gate, 27 Compliance unitaires, 11 adaptateur, 8 reproductibilité, 13 provenance/probes runtime, 13 intégrations Compliance, 4 intégrations adaptateur, 6 catalogue et 4 matrice plateforme; Quick vert, Full bloqué par pip-audit. |
| Discovery Engine | PHASE EN COURS | Corpus synthétique de 10 technologies: 0 faux positif/négatif et 0 ambiguïté inattendue; mesure réelle BLOQUÉE faute de corpus autorisé. Overrides/layouts restent des tâches locales. |
| Tool Bootstrap & Tool Resolver | PHASE EN COURS | Runtime Index lie provenance binaire/wheels et inventaires Python cohérents; Bootstrap, Doctor et Resolver valident snapshots, hashes et probes natifs. Qualification des autres plateformes et coût réel BLOQUÉS par hôtes/corpus indisponibles. |
| Compliance Engine | PHASE TERMINÉE | Critères v1: DAG, budgets, exécution, résultats, findings/verdict et parité fixtures; sandbox et consommateurs réels suivent en Phase 8. |
| Control Catalog | PHASE TERMINÉE | Catalogue JSON/Schema v1, 28 contrôles, objectifs/limites; Matrix et Plan consomment les métadonnées. Qualification réelle suivie en Phase 8. |
| Reporting Engine | PHASE TERMINÉE | Schéma/validateurs v1, métriques Discovery/Resolver/Compliance/Reporting, rapport de référence, masquage configurable et rétention locale ciblée, avec tests opt-in. |
| Policy Engine | PHASE NON COMMENCÉE | YAML descriptif, non autoritaire à l'exécution. |
| Optional Integrations | PHASE EN COURS | Contrats testés en fixtures; runner GitLab, dépôts consommateurs et contextes UI/CI réels BLOQUÉS par accès externe. |
| Industrialisation | PHASE EN COURS | Matrice, lock hashé, provenance, probes et critères de support validés localement; mesures réelles, plateformes natives et responsable de support BLOQUÉS par accès/décision externes. |

## Gates de validation courants

Les résultats détaillés et leur provenance sont centralisés dans [testing.md](testing.md). Aucun gate n'a été contourné.

## Fonctionnalités achevées et phases restantes

Les critères v1 des phases 4, 5 et 6 sont démontrés; cela ne clôt pas les travaux de qualification multi-plateforme ou de gouvernance ultérieurs.

Les phases 1 à 3 continuent sans bloquer. Les critères v1 des phases 4 à 6 sont terminés; Phase 7 reste ouverte pour runner GitLab, consommateurs autorisés et contextes réels. Phase 8 a validé une matrice produit et un corpus synthétique, sans qualification native multi-plateforme; Policy Engine reste à construire.

Le nouveau parcours suit le resolver et les racines, traite les alternatives et affiche les controles omis. Les operations autorisees a executer du code ne sont pas isolees; toutes les plateformes et technologies ne sont pas encore qualifiees. Les taches detaillees restent dans [plan.md](../plan.md).
