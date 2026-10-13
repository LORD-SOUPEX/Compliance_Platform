import { strict as assert } from 'node:assert';
import * as path from 'node:path';
import { test } from 'node:test';
import { DaemonClient } from '../src/daemonClient';

const platformRoot = path.resolve(__dirname, '../../..');
const defectFixture = path.join(platformRoot, 'core', 'testdata', 'defect_fixture');

test('DaemonClient: Lifecycle, Santé, Plan et Flux SSE bout-en-bout', { timeout: 120000 }, async () => {
    const daemon = new DaemonClient();

    // 1. Démarrage ou connexion au démon Go local
    const health = await daemon.ensureDaemon(platformRoot);
    assert.equal(health.status, 'ok');
    assert.ok(health.pid > 0);
    assert.ok(daemon.getPort() > 0);

    // 2. Approbation du workspace cible
    await daemon.approveWorkspace(defectFixture);

    // 3. Récupération du plan via API REST
    const plan = await daemon.getPlan(defectFixture, {
        allowNetwork: false,
        allowCodeExecution: false
    });
    assert.equal(plan.schema_version, 1);
    assert.equal(plan.execution_status, 'planned');
    assert.equal(plan.verdict, null);
    assert.ok(Array.isArray(plan.execution_plan.controls));
    assert.equal(plan.execution_plan.controls.length, 28);

    // 4. Création d'une session de run en PlanOnly (pour rapidité d'intégration)
    const run = await daemon.createRun(defectFixture, {
        planOnly: true
    });
    assert.equal(typeof run.run_id, 'string');
    assert.equal(run.run_id.length, 32);

    // 5. Streaming des événements SSE via client Node (processus d'extension)
    const receivedEvents: string[] = [];
    await daemon.streamEvents(run.run_id, (ev) => {
        receivedEvents.push(ev.type);
    });

    assert.ok(receivedEvents.includes('session_started'), 'Doit inclure session_started');
    assert.ok(receivedEvents.includes('preparation_completed'), 'Doit inclure preparation_completed');
    assert.ok(receivedEvents.includes('session_completed'), 'Doit inclure session_completed');

    // 6. Récupération du rapport final calculé par le démon
    const report = await daemon.getReport(run.run_id);
    assert.equal(report.schema_version, 1);
    assert.ok(report.verdict === null || report.verdict === 'PASS' || report.verdict === 'FAIL');
    assert.ok(report.execution_status === 'planned' || report.execution_status === 'completed');
});

test('DaemonClient: Rejet de workspace non approuvé', async () => {
    const daemon = new DaemonClient();
    await daemon.ensureDaemon(platformRoot);

    const forbiddenPath = path.resolve(platformRoot, '..');
    await assert.rejects(
        () => daemon.getPlan(forbiddenPath),
        /403/
    );
});
