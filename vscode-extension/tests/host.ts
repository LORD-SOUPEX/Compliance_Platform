import { strict as assert } from 'node:assert';
import * as vscode from 'vscode';
import { PlanNode } from '../src/model';
import { escaped, ReportPanel, reportHtml, sectionId } from '../src/reportPanel';
import { fields } from '../src/daemonClient';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { reportFixture } from './reportFixture';
import { randomUUID } from 'node:crypto';

export async function run(): Promise<void> {
    const extension = vscode.extensions.getExtension<{ getNodes(): PlanNode[]; getReportHtml(): string | undefined }>('compliance-platform.compliance-local-pipelines');
    assert.ok(extension, 'Extension chargee dans le host.');
    const api = await extension.activate();
    const nodes = api.getNodes();
    assert.equal(nodes[0].label, 'Pipeline source');
    assert.equal(nodes[1].label, 'Target');
    assert.equal(nodes[1].description, 'Non selectionnee');
    assert.equal(nodes[2].status, 'Pending');
    const commands = await vscode.commands.getCommands(true);
    for (const command of ['compliance.selectTarget', 'compliance.refreshPlan', 'compliance.showLogs', 'compliance.runAudit', 'compliance.cancelAudit', 'compliance.openControlOutput', 'compliance.openSessionFolder', 'compliance.openLastReport', 'compliance.openReportFile', 'compliance.refreshReport', 'compliance.openRawReport']) { assert.ok(commands.includes(command)); }
    await vscode.commands.executeCommand('compliance.refreshPlan');
    assert.equal(api.getNodes()[2].status, 'Pending');
    await vscode.commands.executeCommand('compliance.showLogs');
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-host-'));
    try {
        const file = path.join(directory, 'report.json');
        const raw = reportFixture(directory);
        raw.execution_results[0].stdout = '<script>alert(1)</script><img onerror="alert(1)">';
        raw.execution_results[0].stderr = 'javascript:alert(1)';
        raw.execution_plan.controls[0].name = '<script>name</script>';
        raw.limitations = ['<script>limitation</script>'];
        raw.execution_results[0].diagnostics = [{ code: 'output_truncated', message: '<script>diagnostic</script>', critical: false }];
        raw.execution_results[0].output_truncated = true;
        await fs.writeFile(file, JSON.stringify(raw));
        await vscode.commands.executeCommand('compliance.openReportFile', vscode.Uri.file(file));
        const html = api.getReportHtml(); assert.ok(html);
        assert.ok(html.includes('Rapport historique')); assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
        assert.ok(!html.includes('<img onerror=')); assert.ok(html.includes("connect-src 'none'"));
        assert.ok(html.includes(sectionId('future/lint/.')));
        await vscode.commands.executeCommand('compliance.openRawReport');
        assert.equal(vscode.window.activeTextEditor?.document.languageId, 'json');
        const minimal = { file, report: raw, controls: [], historical: true, sha256: 'fixture', runId: raw.metadata.run_id, target: directory };
        raw.coverage.complete = false;
        raw.findings = [{ id: '<script>id</script>', name: '<script>finding</script>', severity: 'high', technology: '<img onerror="x">', root: '../../outside-target.txt', control_id: 'fixture', file: 'javascript:alert(1)', diagnostics: [{ message: '<script>message</script>' }] }];
        const hostileHtml = reportHtml(minimal, 'local.css', 'local.js', 'local-source', 'nonce');
        assert.ok(hostileHtml.includes('couverture partielle')); assert.ok(hostileHtml.includes('&lt;script&gt;finding&lt;/script&gt;'));
        assert.ok(!hostileHtml.includes('<img onerror=')); assert.ok(!hostileHtml.includes('data-action="finding"'));
        assert.ok(escaped('x'.repeat(100000)).length < 51000);
        assert.ok(fields(raw.metadata));
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
    const source = path.resolve(extension.extensionPath, '..');
    const target = await fs.mkdtemp(path.join(os.tmpdir(), 'reader-host-session-'));
    const runId = randomUUID().replace(/-/g, '');
    const sessionDirectory = path.join(source, '.tools/state/runs', runId);
    const reference = { runId, target, source };
    let persisted: unknown;
    const reportContext = { extensionUri: extension.extensionUri, workspaceState: { get: () => reference, update: async (_key: string, value: unknown) => { persisted = value; } } } as unknown as vscode.ExtensionContext;
    const panel = new ReportPanel(reportContext, source);
    try {
        await fs.mkdir(sessionDirectory);
        const file = path.join(sessionDirectory, 'compliance-report.json');
        await fs.writeFile(file, JSON.stringify(reportFixture(target, runId)));
        const now = new Date().toISOString();
        await fs.writeFile(path.join(sessionDirectory, 'session.json'), JSON.stringify({ schema_version: 1, run_id: runId, target, pipeline_source: source, started_at: now, ended_at: now, state: 'completed', permissions: { network: false, code_execution: false }, report_path: file }));
        await panel.restore(); assert.deepEqual(panel.knownReference(), reference); assert.equal(panel.html(), undefined);
        await panel.openSession(undefined, 'future/lint/.', true);
        assert.ok(panel.html()?.includes('Rapport historique')); assert.deepEqual(persisted, reference);
        assert.equal(api.getNodes()[1].description, 'Non selectionnee');
        await panel.openSession(reference, 'root/future/.'); assert.ok(panel.html()?.includes('session courante'));
        await assert.rejects(panel.openSession(reference, 'unknown'), /inconnue/);
        const handler = panel as unknown as { handle(value: unknown): Promise<void> };
        await assert.rejects(handler.handle({ schema_version: 1, action: 'output', controlId: 'unknown' }), /inconnu/);
        await handler.handle({ schema_version: 1, action: 'output', controlId: 'future/lint/.' });
        assert.equal(vscode.window.activeTextEditor?.document.languageId, 'plaintext');
    } finally { panel.dispose(); await fs.rm(target, { recursive: true, force: true }); await fs.rm(sessionDirectory, { recursive: true, force: true }); }
    console.log('Extension Host : activation, TreeView, identites et commandes PASS.');
}
