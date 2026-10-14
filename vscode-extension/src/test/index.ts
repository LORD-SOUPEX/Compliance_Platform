import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { spawn } from 'node:child_process';
import { reportHtml, revealFinding, visibleFindings } from '../reportPanel';
import { reportMessage, technologiesAbsentFromRun } from '../daemonClient';
import type { LoadedReport } from '../daemonClient';

export async function run(): Promise<void> {
    assert.deepStrictEqual(technologiesAbsentFromRun(['shell', 'python'], ['shell', 'docker', 'python']), ['docker']);
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-report-'));
    const source = path.join(folder, 'infra', 'vpc');
    fs.mkdirSync(source, { recursive: true });
    fs.writeFileSync(path.join(source, 'main.tf'), 'one\ntwo\nresource "net" "vpc" {}\n');
    const stdout = 'eslint-ok-marker';
    const document = {
        file: path.join(folder, 'compliance-report.json'),
        sha256: 'abc',
        historical: true,
        directory: folder,
        target: folder,
        runId: 'a'.repeat(32),
        report: {
            verdict: 'PASS',
            engine_version: '2.0.13',
            metrics: { discovery_ms: 1, resolver_ms: 1, compliance_ms: 1, reporting_ms: 1, total_duration_ms: 4321 },
            verdict_reasons: [],
            findings: [{ control_id: 'javascript/linting/eslint/.', root: 'infra/vpc', file: '/main.tf', line: 3, column: 1, name: 'CKV_TF_1', message: 'pin the source', diagnostics: [] }],
            coverage: { complete: true, executed_controls: 2, detected_technologies: 1, covered_technologies: 1, label: 'Couverture complète : 1 technologie(s) couverte(s) sur 1 détectée(s).' },
            discovery: { technologies: [{ technology: 'javascript', status: 'detected', evidence: [] }] }
        },
        controls: [{
            id: 'javascript/linting/eslint/.',
            name: 'JavaScript lint',
            technology: 'javascript',
            root: '.',
            status: 'Succeeded' as const,
            result: { status: 'success', duration_ms: 12, stdout, stderr: '', diagnostics: [] },
            findings: []
        }, {
            id: 'javascript/security/gitleaks/.',
            name: 'JavaScript secrets',
            technology: 'javascript',
            root: '.',
            status: 'Succeeded' as const,
            result: { status: 'success', duration_ms: 4, stdout: '', stderr: '', diagnostics: [] },
            findings: []
        }]
    } as LoadedReport;
    fs.writeFileSync(document.file, '{}\n');
    const received: string[] = [];
    const outputIds: string[] = [];
    let openedFinding = '';
    let openedLine = -1;
    let findingError = '';
    let sawGitleaks = false;
    const extensionRoot = path.resolve(__dirname, '../../..');
    const panel = vscode.window.createWebviewPanel('compliance.report.test', 'Rapport Compliance', vscode.ViewColumn.One, {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.file(path.join(extensionRoot, 'media'))]
    });
    const ready = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Le script de la webview n a pas envoyé ready (CSP, nonce ou script bloqué).')), 20000);
        panel.webview.onDidReceiveMessage(message => {
            const parsed = reportMessage(message);
            received.push(parsed.action);
            if (parsed.action === 'output') { outputIds.push(parsed.controlId); }
            if (parsed.action === 'finding') {
                const finding = visibleFindings(document.report)[parsed.index];
                void revealFinding(document.target, finding).then(editor => {
                    openedFinding = editor.document.uri.fsPath;
                    openedLine = editor.selection.active.line;
                }).catch(error => { findingError = String(error); });
            }
            if (parsed.action === 'ready') { clearTimeout(timer); resolve(); }
            if (parsed.action === 'output') {
                const marker = parsed.controlId === 'javascript/security/gitleaks/.' ? 'gitleaks-empty-output' : stdout;
                void vscode.workspace.openTextDocument({ content: marker, language: 'plaintext' }).then(doc => vscode.window.showTextDocument(doc)).then(editor => {
                    if (editor.document.getText().includes('gitleaks-empty-output')) { sawGitleaks = true; }
                });
            }
        });
    });
    const css = panel.webview.asWebviewUri(vscode.Uri.file(path.join(extensionRoot, 'media/report.css'))).toString();
    const icon = panel.webview.asWebviewUri(vscode.Uri.file(path.join(extensionRoot, 'media/icon.png'))).toString();
    panel.webview.html = reportHtml(document, css, panel.webview.cspSource, 'a'.repeat(32), icon);
    panel.reveal();
    await ready;
    const driver = spawn(process.env.COMPLIANCE_NODE || 'node', [path.join(extensionRoot, 'scripts', 'cdp-drive.js')], {
        env: { ...process.env, COMPLIANCE_CDP_PORT: process.env.COMPLIANCE_CDP_PORT || '9333' },
        windowsHide: true
    });
    let driverLog = '';
    driver.stdout?.on('data', chunk => { driverLog += String(chunk); });
    driver.stderr?.on('data', chunk => { driverLog += String(chunk); });
    const driverCode = await new Promise<number>(resolve => driver.on('close', code => resolve(code ?? 1)));
    assert.strictEqual(driverCode, 0, driverLog);
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && (!['output', 'pick', 'raw', 'folder', 'finding'].every(action => received.includes(action)) || outputIds.length < 2 || !openedFinding || !sawGitleaks)) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.deepStrictEqual(['output', 'pick', 'raw', 'folder', 'finding'].filter(action => !received.includes(action)), [], `Messages manquants : ${received.join(',')}`);
    assert.strictEqual(findingError, '', findingError);
    assert.ok(openedFinding.replace(/\\/g, '/').endsWith('infra/vpc/main.tf'), `Fichier ouvert : ${openedFinding}`);
    assert.strictEqual(openedLine, 2, `Ligne ouverte : ${openedLine}`);
    assert.deepStrictEqual(outputIds.slice().sort(), ['javascript/linting/eslint/.', 'javascript/security/gitleaks/.'], `Sorties : ${outputIds.join(',')}`);
    assert.strictEqual(sawGitleaks, true, 'Les sorties du contrôle sans texte capturé ne se sont pas affichées.');
    panel.dispose();
}
