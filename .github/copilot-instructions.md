# Consignes Copilot

- Rédige en français la documentation et les commentaires ajoutés au projet.
- N’ajoute aucun emoji ni pictogramme décoratif au dépôt.
- Ne force aucune langue générale pour les noms futurs de fichiers ou de dossiers métier.
- Conserve sans traduction les noms conventionnels et identifiants imposés par les outils.
- N’ajoute aucun secret, certificat privé, jeton, mot de passe ou chemin propre à un poste.
- Ne contourne jamais le Quality Gate et ne désactive aucune règle pour faire passer un changement.
- Ne supprime pas un test uniquement parce qu’il échoue; corrige le défaut ou explique le blocage.
- Ajoute ou adapte des tests pour chaque fonctionnalité ou changement de comportement.
- Exécute Quick après toute modification significative et Full avant de déclarer le travail terminé.
- Installe les outils uniquement dans `.venv/`, `.tools/` ou un emplacement local documenté; aucune installation globale.
- Verrouille toute dépendance et toute version d’outil; n’utilise jamais de version flottante ni `latest`.
- N’exécute aucun `terraform apply`, `terraform destroy`, déploiement ou commande d’infrastructure destructive.
- N’effectue aucun push sans demande explicite.
- Justifie toute exception ou exclusion et limite-la au strict nécessaire.
- Préserve la compatibilité déclarée Windows; documente les limites Linux/macOS ou des outils non pris en charge.
- Garde les changements petits, lisibles et vérifiables.
- Lorsqu’une correction complète de script est demandée, fournis un fichier complet et cohérent.
