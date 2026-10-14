# Développement

Version courante : 2.0.13.

Les commandes ci-dessous construisent et vérifient le dépôt. Elles ne font pas partie de la page Marketplace.

```bash
cd vscode-extension
npm install
npm test
npm run package
```

`npm test` compile le TypeScript, compare la version du moteur à `package.json`, lance les tests Go (découverte, moteur, rapport, distribution, sessions, matrice), vérifie le VSIX et exécute `compliance selftest`.

Go utilisé par ces scripts : `.tools/go/bin/go`. Python : `py -3` sur Windows.

Réinstaller l'extension de test, sans script PowerShell :

```bash
cd vscode-extension
npm run reinstall -- dist/compliance-local-pipelines-2.0.13.vsix
```

Cela arrête le démon, désinstalle l'extension, supprime les dossiers résiduels de l'extension et installe le VSIX. Les sessions restent dans le dossier utilisateur.

La signature du manifeste est facultative. L'installation des outils et `npm run package` ne s'arrêtent pas si elle est absente ou différente. Pour la produire malgré tout, avec la clé privée hors dépôt :

```bash
compliance runtime sign -manifest .config/runtime-manifest.json -key-file <clé-hex> -out .config/runtime-manifest.json.sig
```

La clé est une seed Ed25519 de 32 octets ou une clé privée de 64 octets, en hexadécimal. Le dépôt ne la contient pas.
