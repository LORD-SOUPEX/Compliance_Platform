# Spécification de l'API Démon (Local HTTP / SSE)

Le démon Compliance Platform expose une API REST et un flux Server-Sent Events (SSE) local pour permettre le pilotage de l'audit depuis l'extension VS Code ou d'autres intégrations locales.

## Caractéristiques réseau et sécurité

- **Hôte** : Exclusivement `127.0.0.1`.
- **Port** : Port TCP éphémère (`127.0.0.1:0`) alloué dynamiquement par le système d'exploitation à l'écoute.
- **Authentification** : Jeton Bearer aléatoire 256 bits (`Authorization: Bearer <token>`).
- **Contrôle d'origine** : Rejet (403) si `Origin` est présent et non autorisé (`vscode-webview://*` ou `http://127.0.0.1:*`).
- **Contrôle d'hôte** : Rejet (403) si `Host` ne correspond pas exactement à `127.0.0.1:<port>`.

### Fichier d'état (`daemon.json`)

À son démarrage, le démon enregistre ses paramètres d'accès dans `<state_dir>/daemon.json` (permissions `0600` sur systèmes POSIX, isolation par profil utilisateur et descripteurs de sécurité restreints sous Windows) :

```json
{
  "pid": 12345,
  "port": 54321,
  "host": "127.0.0.1",
  "token_path": "<state_dir>/token.txt",
  "state_dir": "<state_dir>",
  "started_at": "2026-10-14T00:00:00Z",
  "version": "2.0.0"
}
```

---

## Endpoints de l'API

### 1. Santé du démon

- **Méthode** : `GET`
- **Chemin** : `/api/v1/health`
- **Authentification** : Optionnelle (permet le test d'écoute initial)
- **Réponse (200 OK)** :
  ```json
  {
    "status": "ok",
    "version": "2.0.0",
    "pid": 12345,
    "port": 54321,
    "started_at": "2026-10-14T00:00:00Z"
  }
  ```

---

### 2. Approbation d'un workspace (*Guardrail*)

- **Méthode** : `POST`
- **Chemin** : `/api/v1/workspaces/approve`
- **Authentification** : Bearer obligatoire
- **Corps de requête** :
  ```json
  {
    "path": "/chemin/du/projet"
  }
  ```
- **Réponse (200 OK)** :
  ```json
  {
    "status": "approved",
    "path": "/chemin/du/projet"
  }
  ```

---

### 3. Découverte (Discovery)

- **Méthode** : `POST`
- **Chemin** : `/api/v1/discovery`
- **Authentification** : Bearer obligatoire
- **Corps de requête** :
  ```json
  {
    "target_path": "/chemin/du/projet"
  }
  ```
- **Réponse (200 OK)** : Enveloppe JSON conforme au schéma v1 décrivant les technologies détectées, preuves, racines et erreurs éventuelles.

---

### 4. Génération d'un plan de contrôles

- **Méthode** : `POST`
- **Chemin** : `/api/v1/plans`
- **Authentification** : Bearer obligatoire
- **Corps de requête** :
  ```json
  {
    "target_path": "/chemin/du/projet"
  }
  ```
- **Réponse (200 OK)** : Rapport d'état `planned` contenant `discovery`, `matrix`, `resolver` et `execution_plan` (ordonnancement DAG des 28 contrôles).

---

### 5. Création et lancement d'une session d'audit

- **Méthode** : `POST`
- **Chemin** : `/api/v1/runs`
- **Authentification** : Bearer obligatoire
- **Corps de requête** :
  ```json
  {
    "target_path": "/chemin/du/projet",
    "run_id": "a1b2c3d4e5f6...",
    "output_dir": "/chemin/vers/session",
    "plan_only": false,
    "allow_network": false,
    "allow_code_execution": false,
    "confirm_apply_destroy": false,
    "redaction_patterns": ["[A-Za-z0-9_-]{20,}"]
  }
  ```
- **Gardes-fous** :
  - `target_path` doit appartenir à un workspace préalablement approuvé.
  - Si un contrôle destructif est détecté, `confirm_apply_destroy: true` est exigé (sinon 400 Bad Request).
- **Réponse (201 Created)** :
  ```json
  {
    "run_id": "a1b2c3d4e5f6...",
    "status": "started",
    "events_url": "/api/v1/runs/a1b2c3d4e5f6.../events",
    "report_url": "/api/v1/runs/a1b2c3d4e5f6.../report"
  }
  ```

---

### 6. Flux d'événements temps réel (Server-Sent Events)

- **Méthode** : `GET`
- **Chemin** : `/api/v1/runs/{id}/events`
- **En-têtes** : `Accept: text/event-stream`, `Authorization: Bearer <token>`
- **Support de reprise** : En-tête standard `Last-Event-ID` géré pour rejouer les événements manqués en cas de reconnexion.
- **Types d'événements émis** :
  - `event: session_started` : Initialisation de la session.
  - `event: plan_available` : Plan de contrôles arrêté.
  - `event: control_started` : Démarrage d'un contrôle spécifique (`control_id`).
  - `event: control_completed` : Fin d'un contrôle (résultat, durée, statut visuel, chemin des journaux).
  - `event: report_available` : Rapport JSON final persisté sur disque.
  - `event: session_completed` : Session terminée avec verdict (`PASS` ou `FAIL`).
  - `event: session_cancelled` : Session interrompue suite à une demande d'annulation.
  - `event: session_failed` : Erreur technique non recouvrable.

---

### 7. Annulation d'une session

- **Méthode** : `POST`
- **Chemin** : `/api/v1/runs/{id}/cancel`
- **Authentification** : Bearer obligatoire
- **Effet** : Interrompt immédiatement l'exécution en cours et résilie tous les processus enfants rattachés via le Job Object (Windows) ou le groupe de processus (POSIX). Aucun processus orphelin ne subsiste.
- **Réponse (200 OK)** :
  ```json
  {
    "status": "cancelled",
    "run_id": "a1b2c3d4e5f6..."
  }
  ```

---

### 8. Consultation du rapport final

- **Méthode** : `GET`
- **Chemin** : `/api/v1/runs/{id}/report`
- **Authentification** : Bearer obligatoire
- **Réponse (200 OK)** : Rapport JSON complet conforme au schéma `compliance-report-v1.json`.

---

### 9. Consultation des journaux d'un contrôle

- **Méthode** : `GET`
- **Chemin** : `/api/v1/runs/{id}/logs/{control_id}` (ou `/api/v1/runs/{id}/logs/{control_id...}`)
- **Authentification** : Bearer obligatoire
- **Gestion des slashs et points dans `control_id`** :
  - Les identifiants de contrôles contiennent structurellement des barres obliques et un point de racine (ex. `python/linting/ruff/.`, `terraform/linting/tflint/infra`).
  - Le serveur supporte nativement deux modes d'appel sans risque d'erreur 404 :
    1. **Format encodé URL (Recommandé côté clients HTTP / TypeScript)** : `encodeURIComponent(control_id)` (ex: `/api/v1/runs/{id}/logs/python%2Flinting%2Fruff%2F.`).
    2. **Format multi-segments brut (CLI / curl)** : transmission directe avec slashs (ex: `/api/v1/runs/{id}/logs/python/linting/ruff/.`).
  - **Résilience RFC 3986** : Si un proxy ou un client HTTP normalise automatiquement les segments de chemin (éliminant le segment `/.` final en application de la RFC 3986 section 5.2.4), le serveur Go résout automatiquement le contrôle par repli résilient sur sa racine par défaut `/.`.
- **Réponse (200 OK)** :
  ```json
  {
    "run_id": "a1b2c3d4e5f6...",
    "control_id": "python/linting/ruff/.",
    "status": "success",
    "exit_code": 0,
    "stdout": "All checks passed!\n",
    "stderr": "",
    "duration_ms": 42,
    "tool_version": "0.16.10"
  }
  ```

---

### 10. Validation d'un rapport (`/reports/validate`)

- **Méthode** : `POST`
- **Chemin** : `/api/v1/reports/validate`
- **Authentification** : Bearer obligatoire
- **Corps de requête** :
  ```json
  {
    "report_sha256": "abcdef123456...",
    "report": { /* Contenu JSON du rapport */ }
  }
  ```
- **Réponse (200 OK)** :
  ```json
  {
    "schema_version": 1,
    "report_sha256": "abcdef123456...",
    "presentations": [
      {
        "control_id": "python/linting/ruff/.",
        "status": "Succeeded",
        "reason": null
      }
    ]
  }
  ```

---

### 11. Arrêt ordonné du démon

- **Méthode** : `POST`
- **Chemin** : `/api/v1/shutdown`
- **Authentification** : Bearer obligatoire
- **Effet** : Fermeture propre du serveur HTTP, résiliation des éventuels processus actifs, libération du verrou `daemon.lock`, suppression de `daemon.json` et sortie du processus démon.
- **Réponse (200 OK)** :
  ```json
  {
    "status": "shutting_down"
  }
  ```
