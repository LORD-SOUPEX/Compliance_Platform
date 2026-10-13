import { strict as assert } from 'node:assert';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { prepare, validateTarget } from '../src/backend';
import { DaemonClient } from '../src/daemonClient';
import { containsPath, controlOutputText, parsePreparation, PreparationReport, projectPlan } from '../src/model';
import { audit, sessionArtifact, validateSource } from '../src/auditBackend';
import { AuditState, SessionController } from '../src/sessionController';

const source = path.resolve(__dirname, '../../..');
function fixture(target: string): PreparationReport {
    return {
        schema_version: 1, repository: target, execution_status: 'planned', verdict: null,
        metadata: { run_id: 'fixture', source_adapter: 'VSCode' },
        discovery: { scan_complete: true, scan_errors: [], technologies: [
            { technology: 'future-tool', status: 'detected', roots: ['nested'], evidence: ['nested/input'], ambiguities: [] },
            { technology: 'absent', status: 'absent', roots: [], evidence: [], ambiguities: [] }
        ] },
        execution_plan: { repository: target, permissions: { network: false, code_execution: false }, controls: [
            { id: 'future/one', name: 'Future lint', technology: 'future-tool', capability: 'future-capability', root: 'nested', applicability: 'applicable', reason: '', execution_order: 2 },
            { id: 'future/two', name: 'Future unavailable', technology: 'future-tool', capability: 'unknown', root: 'nested', applicability: 'capability_unavailable', reason: 'Outil non configure.', execution_order: 1 }
        ] }, execution_results: []
    };
}

test('Projection generique, racines, ordre backend et motif obligatoire', () => {
    const nodes = projectPlan(fixture(source));
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].label, 'future-tool');
    assert.equal(nodes[0].children[0].label, 'nested');
    assert.equal(nodes[0].children[0].children[0].status, 'Blocked');
    assert.deepEqual(nodes[0].children[0].children[0].reason, { code: 'capability_unavailable', message: 'Outil non configure.' });
    assert.equal(nodes[0].children[0].children[1].status, 'Pending');
});

test('Applicabilites conservees et scan incomplet jamais execute', () => {
    const report = fixture(source);
    report.execution_plan.controls[0].applicability = 'not_applicable';
    assert.equal(projectPlan(report)[0].children[0].children[1].status, 'Not applicable');
    assert.ok(projectPlan(report)[0].children[0].children[1].reason?.code);
    report.discovery.scan_complete = false;
    assert.equal(projectPlan(report)[0].status, 'Blocked');
    assert.ok(projectPlan(report)[0].children[0].children.every(control => control.status === 'Blocked' && control.reason?.code === 'incomplete_scan'));
});

test('Contrat planned strict : version, Target, permissions, execution et racines', () => {
    const report = fixture(source);
    assert.equal(parsePreparation(JSON.stringify(report), source).verdict, null);
    assert.throws(() => parsePreparation('', source));
    for (const mutate of [
        (value: Record<string, unknown>) => { value.schema_version = 2; },
        (value: Record<string, unknown>) => { value.verdict = 'PASS'; },
        (value: Record<string, unknown>) => { value.repository = os.tmpdir(); },
        (value: Record<string, unknown>) => { value.execution_results = [{}]; }
    ]) {
        const changed = JSON.parse(JSON.stringify(report));
        mutate(changed);
        assert.throws(() => parsePreparation(JSON.stringify(changed), source));
    }
    report.execution_plan.permissions.network = true;
    assert.throws(() => parsePreparation(JSON.stringify(report), source));
    report.execution_plan.permissions.network = false;
    report.execution_plan.controls[0].root = '../outside';
    assert.throws(() => parsePreparation(JSON.stringify(report), source));
});

test('Source et Target separees, dossier invalide refuse', async () => {
    await assert.rejects(validateTarget(source, source));
    await assert.rejects(validateTarget(source, path.join(source, 'src')));
    await assert.rejects(validateTarget(source, path.dirname(source)));
    await assert.rejects(validateTarget(source, path.join(source, 'README.md')));
});

test('Rapport manquant, invalide et erreur technique ne reutilisent pas une session', async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-errors-'));
    const pipeline = path.join(workspace, 'pipeline');
    const target = path.join(workspace, 'target');
    try {
        await fs.mkdir(pipeline);
        await fs.mkdir(target);
        const errorClient1 = { ensureDaemon: async () => {}, approveWorkspace: async () => {}, getPlan: async () => { throw new Error('plan error 1'); } } as unknown as DaemonClient;
        await assert.rejects(prepare(pipeline, target, errorClient1), /Preparation impossible/);

        const errorClient2 = { ensureDaemon: async () => {}, approveWorkspace: async () => {}, getPlan: async () => { throw new Error('plan error 2'); } } as unknown as DaemonClient;
        await assert.rejects(prepare(pipeline, target, errorClient2), /Preparation impossible/);

        const errorClient3 = { ensureDaemon: async () => {}, approveWorkspace: async () => {}, getPlan: async () => { throw new Error('plan error 3'); } } as unknown as DaemonClient;
        await assert.rejects(prepare(pipeline, target, errorClient3), /Preparation impossible/);

        const mockClient = {
            ensureDaemon: async () => {},
            approveWorkspace: async () => {},
            getPlan: async () => {
                const report = fixture(target);
                report.discovery.scan_complete = false;
                report.discovery.scan_errors = [{ message: 'Fichier inaccessible.' }];
                return report;
            }
        } as unknown as DaemonClient;
        const prepared = await prepare(pipeline, target, mockClient);
        assert.equal(projectPlan(prepared.report)[0].status, 'Blocked');
        assert.equal((await fs.readdir(path.join(pipeline, '.tools/state/runs'))).length, 4);
        assert.deepEqual(await fs.readdir(target), []);
    } finally { await fs.rm(workspace, { recursive: true, force: true }); }
});

test('Un lien de dossier d etat ne peut pas ecrire dans la Target', async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-state-'));
    const pipeline = path.join(workspace, 'pipeline');
    const target = path.join(workspace, 'target');
    try {
        await fs.mkdir(pipeline);
        await fs.mkdir(target);
        await fs.symlink(target, path.join(pipeline, '.tools'), 'junction');
        await assert.rejects(prepare(pipeline, target, { ensureDaemon: async () => { throw new Error('Ne doit pas lancer.'); } } as unknown as DaemonClient), /ne doit pas etre un lien/);
        assert.deepEqual(await fs.readdir(target), []);
    } finally { await fs.rm(workspace, { recursive: true, force: true }); }
});

test('Backend reel externe : technologies, racines, etat dans la source uniquement', { timeout: 120000 }, async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-target-'));
    let session: string | undefined;
    try {
        const nested = path.join(target, 'service espaces \u00e9');
        await fs.mkdir(nested);
        await fs.writeFile(path.join(nested, 'main.ps1'), "Write-Output 'fixture'\n");
        await fs.writeFile(path.join(target, 'index.ts'), 'export const value = 1;\n');
        await fs.writeFile(path.join(target, 'compose.yaml'), 'services: {}\n');
        const preparation = await prepare(source, target);
        session = preparation.directory;
        assert.ok(containsPath(path.join(source, '.tools/state/runs'), session));
        assert.deepEqual(preparation.report.execution_results, []);
        assert.equal(preparation.report.verdict, null);
        assert.ok(preparation.report.discovery.technologies.some(technology => technology.technology === 'docker' && technology.status === 'detected'));
        const controls = projectPlan(preparation.report).flatMap(technology => technology.children.flatMap(root => root.children));
        assert.ok(controls.some(control => control.label.includes('powershell') && control.status === 'Pending'));
        assert.ok(controls.some(control => control.label.includes('typescript') && control.status === 'Blocked' && control.reason?.code));
        assert.deepEqual((await fs.readdir(target)).sort(), ['compose.yaml', 'index.ts', 'service espaces \u00e9'].sort());
        assert.ok(await fs.stat(path.join(session, 'plan.json')));
    } finally {
        await fs.rm(target, { recursive: true, force: true });
        if (session) { await fs.rm(session, { recursive: true, force: true }); }
    }
});

test('Lancement refuse sans Target/preparation/confiance ; session unique ; changement invalide l etat', () => {
    const controller = new SessionController(source);
    assert.throws(() => controller.begin(true));
    controller.select(source);
    assert.throws(() => controller.begin(true));
    controller.preparation = { report: fixture(source), directory: source, target: source };
    controller.sourceValid = true;
    assert.throws(() => controller.begin(false));
    const state = controller.begin(true);
    assert.match(state.runId, /^[a-f0-9]{32}$/);
    assert.throws(() => controller.begin(true));
    assert.throws(() => controller.select(os.tmpdir()));
    controller.cancel(); assert.equal(controller.abort?.signal.aborted, true);
    controller.end(); controller.select(os.tmpdir());
    assert.equal(controller.preparation, undefined); assert.equal(controller.audit, undefined); assert.equal(controller.canRun(true), false);
});

function emit(state: AuditState, type: string, data: unknown = {}, controlId?: string): void {
    state.receive({ schema_version: 1, run_id: state.runId, sequence: state.sequence + 1, timestamp: new Date().toISOString(), type, data, control_id: controlId });
}
function plannedState(): AuditState {
    const state = new AuditState('a'.repeat(32), source);
    emit(state, 'session_started');
    const report = fixture(source); report.metadata.run_id = state.runId;
    emit(state, 'plan_available', report);
    return state;
}

for (const [status, canonical, code] of [
    ['Succeeded', 'success', undefined], ['Failed', 'fail', 'exit_nonzero'], ['Error', 'error', 'timeout'],
    ['Warning', 'success', 'output_truncated'], ['Skipped', 'skipped', 'permission_denied'],
    ['Blocked', 'error', 'dependency_failed'], ['Not applicable', 'skipped', 'technology_absent']
] as const) {
    test(`Transition Running vers ${status}, duree canonique et motif`, () => {
        const state = plannedState();
        emit(state, 'control_started', { execution_start: new Date().toISOString() }, 'future/one');
        assert.equal(state.controls.get('future/one')?.status, 'Running');
        emit(state, 'control_completed', { status, reason: code ? { code, message: 'Fixture' } : null, result: { control_id: 'future/one', status: canonical, duration_ms: 1234 }, output_path: path.join(source, '.tools/state/runs', state.runId, 'logs/output.json') }, 'future/one');
        assert.equal(state.controls.get('future/one')?.status, status);
        assert.equal(state.controls.get('future/one')?.duration_ms, 1234);
        assert.ok(state.controls.get('future/one')?.output_path);
        if (code) { assert.equal(state.controls.get('future/one')?.reason?.code, code); }
    });
}

test('Evenement inconnu sans crash ; sequence, duplicat et rapport ancien refuses', () => {
    const state = plannedState(); emit(state, 'future_event');
    assert.equal(state.reason?.code, 'unknown_event');
    assert.throws(() => state.receive({ schema_version: 1, run_id: state.runId, sequence: state.sequence, timestamp: new Date().toISOString(), type: 'future_event' }));
    assert.throws(() => state.receive({ schema_version: 1, run_id: 'old', sequence: state.sequence + 1, timestamp: new Date().toISOString(), type: 'report_available' }));
    assert.throws(() => emit(state, 'session_completed', { verdict: 'PASS', coverage: { complete: true } }));
    state.fail('Backend disparu'); assert.equal(state.status, 'Error');
    assert.ok([...state.controls.values()].every(control => control.status !== 'Succeeded'));
});

test('Annulation terminale et chemin de sortie confine a la session', async () => {
    const state = plannedState(); emit(state, 'session_cancelling'); emit(state, 'session_cancelled');
    assert.equal(state.status, 'Skipped'); assert.equal(state.terminal, true); assert.ok(state.reason?.code);
    await assert.rejects(sessionArtifact(source, path.join(os.tmpdir(), 'outside.json')), /hors dossier/);
});

test('Sorties HTML conservees comme texte, identite de controle verifiee', () => {
    const result = { control_id: 'fixture', status: 'success', stdout: '<script>alert(1)</script>', stderr: 'diagnostic', duration_ms: 20, diagnostics: [] };
    assert.ok(controlOutputText('run', 'fixture', result).includes('<script>alert(1)</script>'));
    assert.throws(() => controlOutputText('run', 'other', result));
});

test('Runtime altere ou manquant refuse avant lancement', async () => {
    const pipeline = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-integrity-'));
    try {
        await assert.rejects(validateSource(pipeline), /Catalogue/);
        await fs.mkdir(path.join(pipeline, '.config'), { recursive: true });
        await fs.writeFile(path.join(pipeline, '.config/control-catalog.json'), '{}');
        const failingDaemon = { ensureDaemon: async () => { throw new Error('Démon indisponible'); } } as unknown as DaemonClient;
        await assert.rejects(validateSource(pipeline, failingDaemon), /Démon/);
    } finally { await fs.rm(pipeline, { recursive: true, force: true }); }
});

test('Panne du processus de preparation : session incomplete sans reutiliser un rapport', async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-process-error-'));
    const state = new AuditState(randomUUID().replace(/-/g, ''), target);
    const directory = path.join(source, '.tools/state/runs', state.runId);
    try {
        const failingClient = {
            ensureDaemon: async () => {},
            approveWorkspace: async () => {},
            getPlan: async () => { throw new Error('Panne demon simulee'); }
        } as unknown as DaemonClient;
        await assert.rejects(audit(source, state, async () => ({ network: false, code_execution: false }), () => undefined, new AbortController().signal, undefined, failingClient));
        assert.equal(state.status, 'Error');
        assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'session.json'), 'utf8')).state, 'incomplete');
        await assert.rejects(fs.access(path.join(directory, 'compliance-report.json')));
    } finally { await fs.rm(target, { recursive: true, force: true }); await fs.rm(directory, { recursive: true, force: true }); }
});

test('Sessions backend isolees', { concurrency: 3 }, async context => {
await Promise.all([
context.test('Audit reel : reparation backend, refus, progression et rapport de la session exacte', { timeout: 120000 }, async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-audit-'));
    const state = new AuditState(randomUUID().replace(/-/g, ''), target);
    const directory = path.join(source, '.tools/state/runs', state.runId);
    let asked = 0;
    try {
        await fs.writeFile(path.join(target, 'main.ps1'), "Write-Output 'ok'\n");
        await fs.writeFile(path.join(target, 'app.py'), '"""Module."""\n');
        await audit(source, state, async fresh => { asked++; assert.ok(fresh.report.execution_plan.controls.some(control => control.reason_code === 'permission_denied')); return { network: false, code_execution: false }; }, () => undefined, new AbortController().signal);
        assert.equal(asked, 1); assert.equal(state.terminal, true); assert.equal(state.status, 'Warning');
        assert.ok([...state.controls.values()].some(control => control.status === 'Succeeded'));
        assert.ok([...state.controls.values()].some(control => control.status === 'Skipped' && control.reason?.code === 'permission_denied'));
        const report = JSON.parse(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8'));
        const snapshot = JSON.parse(await fs.readFile(path.join(directory, 'execution-plan.json'), 'utf8'));
        const session = JSON.parse(await fs.readFile(path.join(directory, 'session.json'), 'utf8'));
        assert.throws(() => state.verifyReport({ ...report, execution_results: [] }), /absent/);
        assert.throws(() => state.verifyReport({ ...report, metadata: { ...report.metadata, run_id: 'old' } }));
        assert.equal(report.metadata.run_id, state.runId); assert.equal(snapshot.metadata.run_id, state.runId); assert.equal(session.run_id, state.runId);
        assert.equal(session.state, 'completed'); assert.deepEqual(session.permissions, { network: false, code_execution: false });
        assert.deepEqual((await fs.readdir(target)).sort(), ['app.py', 'main.ps1']);
    } finally { await fs.rm(target, { recursive: true, force: true }); await fs.rm(directory, { recursive: true, force: true }); }
}),

context.test('Audit reel annule : pas de PASS complet, rapport conserve et session cancelled', { timeout: 120000 }, async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-cancel-'));
    const state = new AuditState(randomUUID().replace(/-/g, ''), target);
    const directory = path.join(source, '.tools/state/runs', state.runId);
    const cancellation = new AbortController();
    try {
        await fs.writeFile(path.join(target, 'main.ps1'), "Write-Output 'ok'\n");
        await audit(source, state, async () => ({ network: false, code_execution: false }), () => {
            if ([...state.controls.values()].some(control => control.status === 'Running')) { cancellation.abort(); }
        }, cancellation.signal);
        assert.equal(state.status, 'Skipped'); assert.equal(state.terminal, true);
        const report = JSON.parse(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8'));
        assert.equal(report.verdict, 'FAIL'); assert.equal(report.coverage.complete, false);
        assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'session.json'), 'utf8')).state, 'cancelled');
        assert.ok(report.execution_results.some((result: { diagnostics: { code: string }[] }) => result.diagnostics.some(diagnostic => diagnostic.code.startsWith('cancelled_'))));
    } finally { await fs.rm(target, { recursive: true, force: true }); await fs.rm(directory, { recursive: true, force: true }); }
}),

context.test('Permission code accordee au backend pour une session seulement ; secret masque', { timeout: 120000 }, async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-permissions-'));
    const state = new AuditState(randomUUID().replace(/-/g, ''), target);
    const directory = path.join(source, '.tools/state/runs', state.runId);
    try {
        await fs.writeFile(path.join(target, 'app.py'), 'value = 1\n');
        await fs.mkdir(path.join(target, 'tests'));
        await fs.writeFile(path.join(target, 'tests/test_fixture.py'), 'def test_fixture():\n    raise AssertionError("fixture-secret")\n');
        await audit(source, state, async () => ({ network: false, code_execution: true }), () => undefined, new AbortController().signal, 'fixture-secret');
        const report = JSON.parse(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8'));
        assert.equal(report.metadata.code_execution_authorized, true); assert.equal(report.metadata.network_authorized, false);
        assert.ok(report.execution_results.some((result: { capability: string; exit_code: number | null }) => result.capability === 'testing' && result.exit_code !== null));
        const eventText = await fs.readFile(path.join(directory, 'events.ndjson'), 'utf8');
        assert.ok(!eventText.includes('fixture-secret')); assert.ok(eventText.includes('[REDACTED]'));
        assert.ok(!(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8')).includes('fixture-secret'));
    } finally { await fs.rm(target, { recursive: true, force: true }); await fs.rm(directory, { recursive: true, force: true }); }
})
]);
});
