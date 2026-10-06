# Compliance_Platform

Socle d'un moteur local d'audit volontaire. Discovery inspecte un repository fourni; Quick/Full valident le socle et retournent des statuts et un code de sortie. Le verdict produit cible est consultatif; les limites des hooks et de la CI actuels sont précisées ci-dessous.

## Démarrage rapide

Plateforme locale actuellement ciblée: Windows x64, PowerShell 5.1. Git et un accès HTTPS sont nécessaires au bootstrap.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -DiscoveryOnly -RepositoryPath <chemin-du-depot>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quality-gate.ps1 -Mode Quick
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1
```

Remplacer `<chemin-du-depot>` par un chemin local entre guillemets. Exécuter les commandes depuis la racine de Compliance_Platform.

`-DiscoveryOnly` retourne le JSON de détection, matrice de capacités et résolution d'outils sans exécuter de contrôles. Ajouter `-ReportPath discovery.json` pour conserver ce résultat sous `reports/` de Compliance_Platform. Quick/Full valident le socle local; leur utilisation sur un dépôt externe n'est pas encore qualifiée.

Le bootstrap Windows x64 termine maintenant et marque son index `qualified`; Quick passe sans echec. Ce marqueur ne certifie ni la securite du runtime ni un poste neuf. Le bootstrap installe aussi des hooks dans le depot de la plateforme. Les limites et blocages restants sont decrits dans [les validations](docs/testing.md). Le verdict cible est consultatif, mais les hooks et la CI du socle peuvent echouer.

## Documentation

- [Architecture implémentée](docs/architecture-current.md), [Discovery](docs/discovery.md).
- [Bootstrap et runtime](docs/runtime.md), [Capability Matrix](docs/capability-matrix.md), [Tool Resolver](docs/resolver.md).
- [Compliance Engine](docs/compliance-engine.md), [Reporting](docs/reporting.md), [Policy Engine](docs/policy-engine.md).
- [Tests et validations](docs/testing.md), [statuts de la roadmap](docs/roadmap-status.md).
- [Vision, état et priorités du projet](plan.md), source de vérité.
