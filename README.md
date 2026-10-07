# Compliance_Platform

Socle d'un moteur local d'audit volontaire. Discovery inspecte un repository fourni; Quick/Full valident le socle et retournent des statuts et un code de sortie. Le verdict produit cible est consultatif; les limites des hooks et de la CI actuels sont précisées ci-dessous.

## Démarrage rapide

Plateforme locale actuellement ciblée: Windows x64, PowerShell 5.1. Git et un accès HTTPS sont nécessaires au bootstrap.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -DiscoveryOnly -RepositoryPath <chemin-du-depot>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Compliance -RepositoryPath <chemin-du-depot> -PlanOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Compliance -RepositoryPath <chemin-du-depot>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Quick
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1
```

Remplacer `<chemin-du-depot>` par un chemin local entre guillemets. Exécuter les commandes depuis la racine de Compliance_Platform.

`-DiscoveryOnly` retourne le JSON de détection, matrice de capacités et résolution d'outils sans exécuter de contrôles. Ajouter `-ReportPath discovery.json` pour conserver ce résultat sous `reports/` de Compliance_Platform. Quick/Full valident le socle local; leur utilisation sur un dépôt externe n'est pas encore qualifiée.

`-Compliance` execute le moteur v1 et produit le rapport JSON consultatif PASS/FAIL. Quick/Full/Ci/Fix produisent aussi le rapport de référence, en plus de leurs sorties historiques. `-PlanOnly` n'execute rien et ne donne pas de verdict. Les contrôles réseau ou chargeant du code demandent des permissions explicites; voir [le moteur](docs/compliance-engine.md). Le rapport montre couverture partielle et contrôles omis.

Ajouter `-HumanSummary` pour un résumé sur stderr tout en conservant stdout JSON pur. Le moteur utilise le Control Catalog v1 ci-dessous.

Le bootstrap Windows x64 termine maintenant et marque son index `qualified`; Quick passe sans echec. Ce marqueur ne certifie ni la securite du runtime ni un poste neuf. Le bootstrap installe aussi des hooks dans le depot de la plateforme. Les limites et blocages restants sont decrits dans [les validations](docs/testing.md). Le verdict cible est consultatif, mais les hooks et la CI du socle peuvent echouer.

## Documentation

- [Architecture implémentée](docs/architecture-current.md), [Discovery](docs/discovery.md).
- [Bootstrap et runtime](docs/runtime.md), [Capability Matrix](docs/capability-matrix.md), [Tool Resolver](docs/resolver.md).
- [Compliance Engine](docs/compliance-engine.md), [Reporting](docs/reporting.md), [Policy Engine](docs/policy-engine.md).
- [Catalogue de contrôles v1](.config/control-catalog.json) et [schéma](.config/control-catalog.schema.json).
- [Intégrations optionnelles](docs/integrations.md) PowerShell, Bash, VS Code et GitLab.
- [Tests et validations](docs/testing.md), [statuts de la roadmap](docs/roadmap-status.md).
- [Vision, état et priorités du projet](plan.md), source de vérité.
