# Tool Resolver

`Resolve-CapabilityTool` consomme la Capability Matrix. Pour chaque technologie certaine, il retient uniquement les candidats dont la disponibilité est `available`, déduplique les commandes partagées et associe à chaque outil les capacités qu'il satisfait.

Le résultat par technologie contient `technology_status`, plateforme, `status`, `selected_tools`, `unresolved_capabilities` et `reasons`. Les technologies ambiguës ou absentes ne sélectionnent aucun outil. Les résolutions peuvent être `ready`, `partial`, `unavailable`, `ambiguous` ou `absent`.

La résolution est descriptive: elle ne lance pas les outils. L'orchestration Quick/Full/Ci/Fix demeure dans le Quality Gate et utilise encore ses chemins d'exécution propres. Les profils capacités/outils sont hardcodés dans `Get-CapabilityProfile`; aucun catalogue externe de profils n'est chargé.

La disponibilité est recherchée dans l'index du Runtime, puis dans `.venv`, modules PowerShell, commandes visibles et binaires locaux historiques. Un outil issu du `PATH` ou d'un emplacement non indexé peut être utilisable mais n'est pas qualifié par plateforme dans l'index central.

Pour une capacité, le resolver sélectionne **tous** les candidats disponibles, pas une unique alternative. La déduplication par commande est limitée à chaque technologie; elle n'est pas globale au dépôt. Les résultats sont triés par commande, sans mesure de coût, budget ou graphe de dépendances.

Une entree active non qualifiee provoque un refus immediat sans repli vers `.tools/bin`. Les chemins doivent rester relatifs et sous le runtime. Le SHA-256 est maintenant recalcule a la resolution; son absence ou une alteration donne `integrity_error`. L'executeur protege aussi les copies historiques indexees avant demarrage. Les statuts ne constituent toujours pas une preuve d'execution native. Voir [runtime.md](runtime.md).
