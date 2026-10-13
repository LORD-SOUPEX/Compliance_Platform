import { strict as assert } from 'node:assert';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { displayReport, findingLocation, loadReport, maximumReportBytes, readSession, readStable, reportMessage, targetFile, ReportReference } from '../src/reportReader';
import { reportFixture } from './reportFixture';
import { DaemonClient } from '../src/daemonClient';
import { runInNewContext } from 'node:vm';

const source = path.resolve(__dirname, '../../..');

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
                const env = await daemon.validateReport(r, d);
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
