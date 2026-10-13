import { strict as assert } from 'node:assert';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import {
    AuditState,
    audit,
    DaemonClient,
    displayReport,
    findingLocation,
    loadReport,
    maximumReportBytes,
    prepare,
    readSession,
    readStable,
    ReportReference,
    reportMessage,
    SessionController,
    targetFile,
    validateSource,
    validateTarget
} from '../src/daemonClient';
import { containsPath, controlOutputText, parsePreparation, PreparationReport, projectPlan } from '../src/model';
import { reportFixture } from './reportFixture';

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
});

test('Source et Target separees, dossier invalide refuse', async () => {
    await assert.rejects(validateTarget(source, source));
    await assert.rejects(validateTarget(source, path.join(source, 'child')));
    await assert.rejects(validateTarget(path.join(source, 'child'), source));
    await assert.rejects(validateTarget(source, path.join(source, 'absent')));
});

test('Rapport manquant, invalide et erreur technique ne reutilisent pas une session', async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-invalid-'));
    try {
        await assert.rejects(prepare(source, target, {
            ensureDaemon: async () => { throw new Error('Daemon start failed'); }
        } as unknown as DaemonClient));
    } finally { await fs.rm(target, { recursive: true, force: true }); }
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

test('Backend reel externe : technologies, racines, etat dans la source uniquement', async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-real-'));
    try {
        await fs.writeFile(path.join(target, 'main.tf'), 'resource "null_resource" "x" {}\n');
        await fs.writeFile(path.join(target, 'main.ps1'), "Write-Output 'ok'\n");
        const prep = await prepare(source, target);
        assert.equal(prep.target, await fs.realpath(target));
        assert.ok(containsPath(path.join(source, '.tools/state/runs'), prep.directory));
        assert.equal((await fs.readdir(target)).sort().join(','), 'main.ps1,main.tf');
        const recorded = JSON.parse(await fs.readFile(path.join(prep.directory, 'session.json'), 'utf8'));
        assert.equal(recorded.source, await fs.realpath(source));
    } finally { await fs.rm(target, { recursive: true, force: true }); }
});

test('Lancement refuse sans Target/preparation/confiance ; session unique ; changement invalide l etat', () => {
    const controller = new SessionController(source);
    assert.equal(controller.canRun(true), false);
    controller.select(source);
    assert.equal(controller.canRun(true), false);
    controller.sourceValid = true;
    controller.preparation = { report: fixture(source), directory: source, target: source };
    assert.equal(controller.canRun(false), false);
    assert.equal(controller.canRun(true), true);
    controller.begin(true);
    assert.equal(controller.canRun(true), false);
    assert.throws(() => controller.begin(true));
    assert.throws(() => controller.select(source));
    controller.cancel();
    controller.end();
    controller.select(source);
    assert.equal(controller.canRun(true), false);
});

function plannedState(id = 'run-state'): AuditState {
    const state = new AuditState(id, source);
    state.receive({ schema_version: 1, run_id: id, sequence: 1, timestamp: new Date().toISOString(), type: 'session_started', data: null });
    const rep = fixture(source); rep.metadata.run_id = id;
    state.receive({ schema_version: 1, run_id: id, sequence: 2, timestamp: new Date().toISOString(), type: 'plan_available', data: rep });
    return state;
}

for (const [status, canonical, code] of [
    ['Succeeded', 'success', undefined], ['Failed', 'fail', 'exit_nonzero'], ['Error', 'error', 'timeout'],
    ['Warning', 'success', 'output_truncated'], ['Skipped', 'skipped', 'permission_denied'],
    ['Blocked', 'error', 'dependency_failed'], ['Not applicable', 'skipped', 'technology_absent']
] as const) {
    test(`Transition Running vers ${status}, duree canonique et motif`, () => {
        const state = plannedState();
        state.receive({ schema_version: 1, run_id: state.runId, sequence: 3, timestamp: new Date().toISOString(), type: 'control_started', control_id: 'future/one', data: { execution_start: new Date().toISOString() } });
        assert.equal(state.controls.get('future/one')?.status, 'Running');
        state.receive({ schema_version: 1, run_id: state.runId, sequence: 4, timestamp: new Date().toISOString(), type: 'control_completed', control_id: 'future/one', data: { status, reason: code ? { code, message: 'Fixture' } : null, result: { control_id: 'future/one', status: canonical, duration_ms: 1234 }, output_path: path.join(source, '.tools/state/runs', state.runId, 'logs/output.json') } });
        assert.equal(state.controls.get('future/one')?.status, status);
        assert.equal(state.controls.get('future/one')?.duration_ms, 1234);
        assert.ok(state.controls.get('future/one')?.output_path);
        if (code) { assert.equal(state.controls.get('future/one')?.reason?.code, code); }
    });
}

test('Evenement inconnu sans crash ; sequence, duplicat et rapport ancien refuses', () => {
    const state = new AuditState('run-8', source);
    state.receive({ schema_version: 1, run_id: 'run-8', sequence: 1, timestamp: new Date().toISOString(), type: 'session_started', data: null });
    state.receive({ schema_version: 1, run_id: 'run-8', sequence: 2, timestamp: new Date().toISOString(), type: 'custom_event', data: null });
    assert.throws(() => state.receive({ schema_version: 1, run_id: 'run-8', sequence: 2, timestamp: new Date().toISOString(), type: 'dup' }));
});

test('Annulation terminale et chemin de sortie confine a la session', async () => {
    const state = new AuditState('run-9', source);
    state.receive({ schema_version: 1, run_id: 'run-9', sequence: 1, timestamp: new Date().toISOString(), type: 'session_started', data: null });
    state.receive({ schema_version: 1, run_id: 'run-9', sequence: 2, timestamp: new Date().toISOString(), type: 'session_cancelled', data: null });
    assert.equal(state.status, 'Skipped');
    assert.equal(state.terminal, true);
});

test('Sorties HTML conservees comme texte, identite de controle verifiee', () => {
    const result = { control_id: 'fixture', status: 'success', stdout: '<script>alert(1)</script>', stderr: 'diagnostic', duration_ms: 20, diagnostics: [] };
    assert.ok(controlOutputText('run', 'fixture', result).includes('<script>alert(1)</script>'));
    assert.throws(() => controlOutputText('run', 'other', result));
});

test('Runtime altere ou manquant refuse avant lancement', async () => {
    await assert.rejects(validateSource(path.join(source, 'missing-source')));
});

test('Panne du processus de preparation : session incomplete sans reutiliser un rapport', async () => {
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'compliance-broken-'));
    try {
        await assert.rejects(prepare(source, target, {
            ensureDaemon: async () => ({ status: 'ok' }),
            approveWorkspace: async () => ({ approved: true }),
            getPlan: async () => { throw new Error('Daemon boom'); }
        } as unknown as DaemonClient));
    } finally { await fs.rm(target, { recursive: true, force: true }); }
});

test('Sessions backend isolees', async context => {
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
                const session = JSON.parse(await fs.readFile(path.join(directory, 'session.json'), 'utf8'));
                assert.throws(() => state.verifyReport({ ...report, execution_results: [] }), /absent/);
                assert.throws(() => state.verifyReport({ ...report, metadata: { ...report.metadata, run_id: 'old' } }));
                assert.equal(report.metadata.run_id, state.runId); assert.equal(session.run_id, state.runId);
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

test('Rapport historique v1 valide sans champs modernes ; outil generique, durees et sorties', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-historical-'));
    try {
        const file = path.join(directory, 'rapport espaces \u00e9.json');
        const raw = reportFixture(directory);
        await fs.writeFile(file, JSON.stringify(raw));
        const loaded = await loadReport(source, file);
        assert.equal(loaded.historical, true); assert.equal(loaded.session, undefined);
        assert.equal(loaded.report.verdict, 'PASS'); assert.equal(loaded.controls[0].status, 'Succeeded');
        assert.equal(loaded.controls[0].result?.duration_ms, 1234); assert.equal(loaded.controls[0].result?.stdout, 'sortie');
        assert.equal(loaded.controls[0].technology, 'future');
        raw.coverage.complete = false; raw.limitations = ['Couverture partielle'];
        await fs.writeFile(file, JSON.stringify(raw));
        assert.equal((await loadReport(source, file)).report.coverage && raw.coverage.complete, false);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Vide, JSON invalide, racine incorrecte, version inconnue, contrat absent et rapport absent refuses', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-invalid-'));
    try {
        const file = path.join(directory, 'report.json');
        for (const content of ['', '{invalid', '[]', 'null', '{"schema_version":2}', '{"schema_version":1}']) {
            await fs.writeFile(file, content); await assert.rejects(loadReport(source, file));
        }
        await assert.rejects(loadReport(source, path.join(directory, 'absent.json')));
        await fs.writeFile(file, '{}'); await fs.truncate(file, maximumReportBytes + 1);
        await assert.rejects(loadReport(source, file), /volumineux/);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Session exacte, restauration historique sans consentement, run_id et Target incoherents refuses', async () => {
    const runId = randomUUID().replace(/-/g, '');
    const directory = path.join(source, '.tools/state/runs', runId);
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-session-'));
    const reference: ReportReference = { runId, target, source };
    try {
        await fs.mkdir(directory);
        const reportPath = path.join(directory, 'compliance-report.json');
        const now = new Date().toISOString();
        await fs.writeFile(path.join(directory, 'session.json'), JSON.stringify({ schema_version: 1, run_id: runId, target, pipeline_source: source, started_at: now, ended_at: now, state: 'completed', report_path: reportPath, permissions: { network: false, code_execution: false } }));
        const raw = reportFixture(target, runId); await fs.writeFile(reportPath, JSON.stringify(raw));
        assert.equal((await loadReport(source, reportPath, reference, false)).historical, false);
        assert.equal((await loadReport(source, reportPath, reference, true)).historical, true);
        assert.equal((await readSession(source, reference)).session.state, 'completed');
        raw.metadata.run_id = 'old'; await fs.writeFile(reportPath, JSON.stringify(raw));
        await assert.rejects(loadReport(source, reportPath, reference), /run_id/);
        raw.metadata.run_id = runId; raw.repository = source; await fs.writeFile(reportPath, JSON.stringify(raw));
        await assert.rejects(loadReport(source, reportPath, reference), /Target/);
        await assert.rejects(readSession(source, { ...reference, runId: '../outside' }));
        await assert.rejects(readSession(source, { ...reference, source: target }));
    } finally { await fs.rm(directory, { recursive: true, force: true }); await fs.rm(target, { recursive: true, force: true }); }
});

test('Rapport annule FAIL et motif ; aucune conversion en PASS complet', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-cancelled-'));
    try {
        const raw = reportFixture(directory);
        raw.execution_results[0].status = 'error'; raw.execution_results[0].critical = true;
        raw.execution_results[0].diagnostics = [{ code: 'session_interrupted', message: 'Session annulee', critical: true }];
        raw.findings = [{ id: 'fixture', control_id: raw.execution_results[0].control_id, severity: 'medium', status: 'error', diagnostics: raw.execution_results[0].diagnostics }];
        raw.summary = { success: 0, fail: 0, error: 1, skipped: 0, critical_errors: 1 };
        raw.coverage.complete = false; raw.execution_status = 'blocked'; raw.verdict = 'FAIL'; raw.verdict_reasons = ['Session annulee'];
        await fs.writeFile(path.join(directory, 'report.json'), JSON.stringify(raw));
        const loaded = await loadReport(source, path.join(directory, 'report.json'));
        assert.equal(loaded.report.verdict, 'FAIL'); assert.equal(loaded.controls[0].status, 'Error');
        assert.equal(loaded.controls[0].reason?.code, 'session_interrupted');
        raw.execution_results[0].status = 'fail'; raw.execution_results[0].critical = false; raw.execution_results[0].diagnostics[0].critical = false;
        raw.findings[0].status = 'fail'; raw.summary = { success: 0, fail: 1, error: 0, skipped: 0, critical_errors: 0 };
        await fs.writeFile(path.join(directory, 'report.json'), JSON.stringify(raw));
        assert.equal((await loadReport(source, path.join(directory, 'report.json'))).controls[0].status, 'Failed');
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Neuf statuts et motifs defensifs ; identifiant duplique et statut absent refuses', () => {
    for (const status of ['Pending', 'Running', 'Succeeded', 'Failed', 'Error', 'Warning', 'Skipped', 'Blocked', 'Not applicable']) {
        const raw = reportFixture(source);
        const state = { control_id: raw.execution_results[0].control_id, status, reason: { code: 'fixture', message: 'Fixture' } };
        assert.equal(displayReport(raw, [state]).controls[0].status, status);
        if (['Warning', 'Skipped', 'Blocked', 'Not applicable'].includes(status)) { assert.throws(() => displayReport(raw, [{ ...state, reason: null }])); }
    }
    const raw = reportFixture(source);
    assert.throws(() => displayReport(raw, []));
    raw.execution_results[0].duration_ms = Infinity;
    assert.throws(() => displayReport(raw, [{ control_id: raw.execution_results[0].control_id, status: 'Succeeded' }]));
    raw.execution_results.push(raw.execution_results[0]); assert.throws(() => displayReport(raw, []));
});

test('Fichier modifie pendant validation refuse ; plan seul et scan incomplet restent explicites', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-modified-'));
    try {
        const file = path.join(directory, 'report.json'); const raw = reportFixture(directory);
        await fs.writeFile(file, JSON.stringify(raw));
        const mockClient = {
            ensureDaemon: async () => {},
            validateReport: async (r: any, d?: string) => {
                const daemon = new DaemonClient();
                await daemon.ensureDaemon(source);
                const env = await daemon.validateReport(r, d || '');
                raw.execution_results[0].stdout = 'Sortie modifiee';
                await fs.writeFile(file, JSON.stringify(raw));
                return env;
            }
        } as unknown as DaemonClient;
        await assert.rejects(loadReport(source, file, undefined, true, mockClient), /modifie/);
        raw.execution_results = []; raw.summary.success = 0; raw.execution_status = 'planned'; raw.verdict = null; raw.coverage.complete = false; raw.coverage.executed_controls = 0;
        await fs.writeFile(file, JSON.stringify(raw));
        assert.equal((await loadReport(source, file)).controls[0].status, 'Pending');
        raw.execution_status = 'blocked'; raw.verdict = 'FAIL'; raw.discovery.scan_complete = false; raw.summary.critical_errors = 1;
        await fs.writeFile(file, JSON.stringify(raw));
        const loaded = await loadReport(source, file);
        assert.equal(loaded.controls[0].status, 'Blocked'); assert.ok(loaded.controls[0].reason?.code);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Messages Webview stricts et chemins confines ; fichier avec accents, liens et URL javascript', async () => {
    assert.deepEqual(reportMessage({ schema_version: 1, action: 'output', controlId: 'fixture' }), { schema_version: 1, action: 'output', controlId: 'fixture' });
    for (const value of [null, {}, { action: 'raw' }, { schema_version: 1, action: 'openUrl', url: 'javascript:alert(1)' }, { schema_version: 1, action: 'raw', path: '../outside' }, { schema_version: 1, action: 'finding', index: -1 }]) { assert.throws(() => reportMessage(value)); }
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-paths-'));
    try {
        const file = path.join(directory, 'fichier espaces \u00e9.txt'); await fs.writeFile(file, 'fixture');
        assert.equal(await targetFile(directory, path.basename(file)), file);
        await assert.rejects(targetFile(directory, '../../outside-target.txt'), /hors Target/);
        await assert.rejects(targetFile(directory, 'javascript:alert(1)'));
        await fs.symlink(directory, path.join(directory, 'linked'), 'junction');
        await assert.rejects(readStable(path.join(directory, 'linked', path.basename(file))), /reanalyse/);
        assert.equal(findingLocation({ message: 'line 12 in file.txt' }), undefined);
        assert.equal(findingLocation({ file: 'javascript:alert(1)' }), undefined);
        assert.deepEqual(findingLocation({ file: path.basename(file), line: 3, column: 2 }), { file: path.basename(file), line: 3, column: 2 });
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('Script local executable dans une Webview sans CommonJS ; handshake et boutons', async () => {
    const messages: unknown[] = [];
    const handlers = new Map<string, (event: unknown) => void>();
    class ElementFixture { closest(): unknown { return { disabled: false, dataset: { action: 'raw' } }; } }
    const script = await fs.readFile(path.join(source, 'vscode-extension/.extension-build/media/report.js'), 'utf8');
    runInNewContext(script, {
        acquireVsCodeApi: () => ({ postMessage: (message: unknown) => messages.push(message) }),
        Element: ElementFixture, HTMLDetailsElement: class {},
        document: { addEventListener: (name: string, handler: (event: unknown) => void) => handlers.set(name, handler), getElementById: () => null },
        window: { addEventListener: (name: string, handler: (event: unknown) => void) => handlers.set(name, handler) }
    });
    assert.equal(JSON.stringify(messages[0]), JSON.stringify({ schema_version: 1, action: 'ready' }));
    handlers.get('click')?.({ target: new ElementFixture() });
    assert.equal(JSON.stringify(messages[1]), JSON.stringify({ schema_version: 1, action: 'raw' }));
    handlers.get('message')?.({ data: { type: 'focus', id: 'unknown' } });
});
