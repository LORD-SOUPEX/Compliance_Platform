import { createHash, randomBytes } from 'node:crypto';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { reportButtonCommand } from './reportActions.js';
import { buildReportModel, LayoutControl, nonApplicableMarkup, reportDurationMs, unavailableSummary } from './reportLayout';
import { controlOutputText } from './model';
import { controlRelativeFile, Fields, fields, findingLocation, LoadedReport, loadReport, readSession, readStable, ReportControl, ReportReference, reportMessage, runsDirectory, targetFile, text } from './daemonClient';

export function escaped(value: unknown, limit = 50000): string {
    const original = text(value);
    const bounded = original.length > limit ? `${original.slice(0, limit)}\n[Affichage limite ; ouvrir les sorties ou le JSON brut.]` : original;
    return bounded.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]!));
}
export function sectionId(id: string): string { return `section-${createHash('sha256').update(id).digest('hex')}`; }
const array = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const reasonText = (value: unknown) => fields(value) ? `${text(value.code)} : ${text(value.message)}` : text(value);

export function reportHtml(document: LoadedReport, css: string, cspSource: string, nonce: string, iconSrc: string): string {
    const report = document.report;
    const coverage = fields(report.coverage) ? report.coverage : {};
    const discovery = fields(report.discovery) ? report.discovery : {};
    const technologies = array(discovery.technologies).filter(fields).map(item => ({
        technology: String(item.technology || ''),
        status: String(item.status || ''),
        evidence: array(item.evidence).map(value => text(value))
    }));
    const model = buildReportModel({
        verdict: report.verdict,
        coverage: {
            complete: coverage.complete,
            executed_controls: typeof coverage.executed_controls === 'number' ? coverage.executed_controls : undefined,
            applicable_controls: typeof coverage.applicable_controls === 'number' ? coverage.applicable_controls : undefined,
            detected_technologies: typeof coverage.detected_technologies === 'number' ? coverage.detected_technologies : undefined,
            covered_technologies: typeof coverage.covered_technologies === 'number' ? coverage.covered_technologies : undefined,
            label: typeof coverage.label === 'string' ? coverage.label : undefined
        },
        verdictReasons: report.verdict_reasons,
        technologies,
        controls: document.controls.map(layoutControl)
    });
    const metrics = fields(report.metrics) ? report.metrics : {};
    const duration = reportDurationMs({
        metrics,
        controls: model.executed,
        startedAt: document.session?.started_at,
        endedAt: document.session?.ended_at
    });
    const findings = visibleFindings(report);
    const findingCount = new Map<string, number>();
    for (const finding of findings) {
        const id = String(finding.control_id || '').replace(/\\/g, '/');
        findingCount.set(id, (findingCount.get(id) || 0) + 1);
    }
    const executedRows = executedMarkup(model.executed, findingCount, findings, !!document.directory);
    const unavailable = unavailableSummary(document.controls.map(layoutControl));
    const tools = model.tools.length ? `<details><summary>Outils à provisionner <span>${escaped(new Set(model.tools).size)}</span></summary><ul>${[...new Set(model.tools)].map(tool => `<li>${escaped(tool)}</li>`).join('')}</ul><button type="button" data-action="provision">Installer les outils manquants</button></details>` : '';
    const unavailableBlock = unavailable.length ? `<details><summary>Indisponibles <span>${escaped(unavailable.length)}</span></summary><ul>${unavailable.map(line => `<li>${escaped(line)}</li>`).join('')}</ul></details>` : '';
    const absent = nonApplicableMarkup(document.controls.map(layoutControl));
    const durationText = formatDuration(duration);
    const sessionLabel = document.historical ? 'Rapport historique' : 'Session courante';
    const complete = coverage.complete === true;
    const versionLabel = text(report.engine_version).replace(/^v/, '');
    return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${escaped(cspSource)}; script-src 'nonce-${nonce}'; img-src ${escaped(cspSource)};"><link rel="stylesheet" href="${escaped(css)}"><title>Rapport Compliance</title></head><body data-brand="${escaped(iconSrc)}">
      <section class="hero">
        <header class="report-top">
          <div class="top-row">
            <div class="brand">
              <img class="shield" src="${escaped(iconSrc)}" alt="" />
              <h1>ICP COMPLIANCE</h1>
              <p class="verdict ${model.verdict.kind}" role="status"><span class="vicon">${verdictIcon(model.verdict.kind)}</span> ${escaped(model.verdict.label)}</p>
            </div>
            <div class="pills">
              <span class="pill" title="${escaped(document.target)}">${svgIcon(icons.folder)} ${escaped(document.target)}</span>
              <span class="pill">${svgIcon(icons.tag)} v${escaped(versionLabel)}</span>
              <span class="pill">${svgIcon(icons.clock)} ${escaped(durationText)}</span>
            </div>
          </div>
          <div class="mid-row">
            <p class="coverage">${complete ? svgIcon(icons.check) : svgIcon(icons.alert)} ${escaped(model.coverageText)}</p>
            <div class="session-actions">
              <span class="session-label">${escaped(sessionLabel)}</span>
              <nav class="actions" aria-label="Actions du rapport">
                <button type="button" class="primary" data-action="pick">${svgIcon(icons.file)} Ouvrir un rapport…</button>
                <button type="button" class="ghost" data-action="raw">${svgIcon(icons.braces)} JSON brut</button>
                <button type="button" class="ghost" data-action="folder" ${document.directory ? '' : 'disabled'}>${svgIcon(icons.folder)} Dossier de session</button>
              </nav>
            </div>
          </div>
        </header>
        <div class="kpi-frame" aria-label="Compteurs">${model.cards.map(item => card(item.label, item.value, item.tone)).join('')}</div>
      </section>
      <section><h2>Contrôles exécutés</h2><div class="control-list">${executedRows || '<p class="muted">Aucun contrôle exécuté.</p>'}</div></section>
      ${reasonBlock(model.verdict.detail, model.verdictReasons)}${gapBlock(model.gaps)}${unavailableBlock}${tools}${absent}
      <script nonce="${nonce}">${reportScript()}</script></body></html>`;
}

function skippedFinding(finding: Fields): boolean {
    const file = (findingLocation(finding)?.file || String(finding.file || '')).replace(/\\/g, '/').toLowerCase();
    return ['/testdata/', '/fixtures/', '/__snapshots__/', '/node_modules/', '/vendor/', '/dist/', '/build/'].some(part => `/${file}/`.includes(part));
}

function controlIdentity(control: LayoutControl): { capability: string; tool: string; root: string } {
    const parts = control.id.split('/');
    return {
        capability: parts[1] || '',
        tool: parts[2] || control.name,
        root: control.root || (parts.length >= 4 ? parts.slice(3).join('/') : '.')
    };
}

function sameControl(findingId: string, controlId: string): boolean {
    return findingId.replace(/\\/g, '/') === controlId.replace(/\\/g, '/');
}

function formatDuration(duration: number | undefined): string {
    if (duration === undefined) { return 'Non renseignée'; }
    return `${String(duration).replace(/\B(?=(\d{3})+(?!\d))/g, ' ')} ms`;
}

const icons = {
    folder: '<path d="M3 7h6l2 2h10v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 7V5a2 2 0 0 1 2-2h4l2 2"/>',
    tag: '<path d="M20 13l-7 7-9-9V4h7z"/><circle cx="7.5" cy="7.5" r="1" fill="currentColor" stroke="none"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v6l4 2"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    braces: '<path d="M8 4c-2 0-2 2-2 4v2c0 2-1 2-2 2 1 0 2 0 2 2v2c0 2 0 4 2 4"/><path d="M16 4c2 0 2 2 2 4v2c0 2 1 2 2 2-1 0-2 0-2 2v2c0 2 0 4-2 4"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 9v5"/><path d="M12 17h.01"/>',
    check: '<path d="M5 12l5 5L20 7"/>',
    cross: '<path d="M6 6l12 12M18 6L6 18"/>'
};

function svgIcon(pathData: string): string {
    return `<svg class="ico" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${pathData}</svg>`;
}

function verdictIcon(kind: string): string {
    if (kind === 'pass') { return svgIcon(icons.check); }
    if (kind === 'unevaluated') { return '<span class="ico dash" aria-hidden="true">-</span>'; }
    return svgIcon(icons.alert);
}

export function visibleFindings(report: Fields): Fields[] {
    return array(report.findings).filter(fields).filter(finding => !skippedFinding(finding));
}

export async function revealFinding(target: string, finding: Fields): Promise<vscode.TextEditor> {
    const location = findingLocation(finding);
    if (!location) { throw new Error('Localisation fiable ou confiance absente.'); }
    const relative = controlRelativeFile(String(finding.root || ''), location.file);
    const file = await targetFile(target, relative);
    const opened = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
    const editor = await vscode.window.showTextDocument(opened);
    if (location.line !== undefined) {
        if (location.line > opened.lineCount || (location.column !== undefined && location.column - 1 > opened.lineAt(location.line - 1).text.length)) { throw new Error('Position du finding devenue incoherente avec le fichier ; aucune position inventee.'); }
        const position = new vscode.Position(location.line - 1, (location.column || 1) - 1);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position));
    }
    return editor;
}

function fileTreeMarkup(controlId: string, findings: Fields[]): string {
    const files = new Map<string, number[]>();
    findings.forEach((finding, index) => {
        if (skippedFinding(finding) || !sameControl(String(finding.control_id || ''), controlId)) { return; }
        const located = findingLocation(finding);
        const file = located ? controlRelativeFile(String(finding.root || ''), located.file) : '(sans fichier)';
        files.set(file, [...(files.get(file) || []), index]);
    });
    if (!files.size) { return ''; }
    const nodes = [...files.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([file, indexes]) => {
        const rows = indexes.map(index => {
            const finding = findings[index];
            const location = findingLocation(finding);
            const rule = String(finding.name || finding.rule_id || '');
            const message = String(finding.message || array(finding.diagnostics).map(reasonText).join('; '));
            const open = location ? `<button type="button" data-action="finding" data-finding-index="${index}">Ouvrir à la ligne</button>` : '';
            return `<tr><td>${escaped(location?.line ?? '')}</td><td>${escaped(rule)}</td><td>${escaped(message, 500)}</td><td>${open}</td></tr>`;
        }).join('');
        return `<details class="file-node"><summary><code>${escaped(file)}</code><span>${escaped(indexes.length)} anomalie${indexes.length === 1 ? '' : 's'}</span></summary><div class="finding-table"><table><thead><tr><th>Ligne</th><th>Règle</th><th>Message</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
    }).join('');
    return `<div class="file-tree">${nodes}</div>`;
}

function executedMarkup(controls: Array<LayoutControl & { label: string; showOutput: boolean }>, findingCount: Map<string, number>, findings: Fields[], canOpen: boolean): string {
    const groups = new Map<string, typeof controls>();
    for (const control of controls) {
        const identity = controlIdentity(control);
        const key = `${control.technology}/${identity.capability}/${identity.tool}`;
        groups.set(key, [...(groups.get(key) || []), control]);
    }
    return [...groups.values()].map(rows => {
        const sample = controlIdentity(rows[0]);
        const failed = rows.some(control => control.resultStatus !== 'success');
        const total = rows.reduce((sum, control) => sum + (findingCount.get(control.id) || 0), 0);
        const lines = rows.map(control => {
            const identity = controlIdentity(control);
            const output = control.showOutput && canOpen ? `<button type="button" data-action="output" data-control-id="${escaped(control.id, 4096)}">Ouvrir les sorties</button>` : '';
            const count = findingCount.get(control.id.replace(/\\/g, '/')) || 0;
            const head = `<span class="badge ${control.resultStatus === 'success' ? 'pass' : 'fail'}">${escaped(control.label)}</span><span class="root">${escaped(identity.root || '.')}</span><span>${control.durationMs === undefined ? '' : `${escaped(control.durationMs)} ms`}</span><span>${escaped(count)} anomalie${count === 1 ? '' : 's'}</span>${output}`;
            const tree = fileTreeMarkup(control.id, findings);
            if (!tree) {
                return `<div class="control ${control.resultStatus === 'success' ? 'pass' : 'fail'}" id="${sectionId(control.id)}">${head}</div>`;
            }
            return `<details class="control ${control.resultStatus === 'success' ? 'pass' : 'fail'}" id="${sectionId(control.id)}"><summary>${head}</summary>${tree}</details>`;
        }).join('');
        return `<article class="tool-card ${failed ? 'fail' : 'pass'}"><header><span class="badge ${failed ? 'fail' : 'pass'}">${failed ? 'Échec' : 'Réussi'}</span><div><strong>${escaped(rows[0].technology)} · ${escaped(sample.capability)} · ${escaped(sample.tool)}</strong><p>${escaped(rows.length)} dossier${rows.length === 1 ? '' : 's'} · ${escaped(total)} anomalie${total === 1 ? '' : 's'}</p></div></header><div class="control-list">${lines}</div></article>`;
    }).join('') || '<p class="muted">Aucun contrôle exécuté.</p>';
}

function reasonBlock(detail: string, reasons: string[]): string {
    const lines = [...new Set([detail, ...reasons].map(line => line.trim()).filter(Boolean))];
    if (!lines.length) { return ''; }
    return `<section class="reasons"><h2>Raisons du verdict</h2><ul>${lines.map(line => `<li>${escaped(line)}</li>`).join('')}</ul></section>`;
}

function gapBlock(gaps: string[]): string {
    if (!gaps.length) { return ''; }
    return `<details><summary>Lacunes de couverture <span>${escaped(gaps.length)}</span></summary><ul>${gaps.map(line => `<li>${escaped(line)}</li>`).join('')}</ul></details>`;
}

function reportScript(): string {
    return `(function () {
  var api = acquireVsCodeApi();
  document.addEventListener('click', function (event) {
    var target = event.target instanceof Element ? event.target : null;
    if (!target) { return; }
    var summary = target.closest('summary');
    if (summary && summary.parentElement && summary.parentElement.tagName === 'DETAILS' && !target.closest('button')) {
      event.preventDefault();
      summary.parentElement.open = !summary.parentElement.open;
      return;
    }
    var element = target.closest('button[data-action]');
    if (!element || element.disabled) { return; }
    var action = element.getAttribute('data-action');
    var message = { schema_version: 1, action: action };
    if (action === 'output') { message.controlId = element.getAttribute('data-control-id'); }
    if (action === 'finding') { message.index = Number(element.getAttribute('data-finding-index')); }
    api.postMessage(message);
  });
  window.addEventListener('message', function (event) {
    var message = event.data;
    if (!message || message.type !== 'focus' || typeof message.id !== 'string') { return; }
    var node = document.getElementById(message.id);
    if (!node) { return; }
    var parent = node;
    while (parent) { if (parent.tagName === 'DETAILS') { parent.open = true; } parent = parent.parentElement; }
    node.scrollIntoView({ block: 'start' });
  });
  api.postMessage({ schema_version: 1, action: 'ready' });
})();`;
}

function card(label: string, value: unknown, tone: string): string {
    const mark = tone === 'passed' ? `<i class="mark">${svgIcon(icons.check)}</i>` : tone === 'failed' ? `<i class="mark">${svgIcon(icons.cross)}</i>` : '';
    return `<article class="kpi ${escaped(tone)}"><strong>${escaped(value)}${mark}</strong><span>${escaped(label)}</span></article>`;
}
function layoutControl(control: ReportControl): LayoutControl {
    const diagnostic = array(control.result?.diagnostics).find(fields);
    return {
        id: control.id,
        name: control.name,
        technology: control.technology,
        root: control.root,
        resultStatus: String(control.result?.status || ''),
        reasonCode: control.reason?.code || (fields(diagnostic) && typeof diagnostic.code === 'string' ? diagnostic.code : ''),
        reasonMessage: control.reason?.message || (fields(diagnostic) && typeof diagnostic.message === 'string' ? diagnostic.message : ''),
        durationMs: typeof control.result?.duration_ms === 'number' ? control.result.duration_ms : undefined,
        stdout: typeof control.result?.stdout === 'string' ? control.result.stdout : '',
        stderr: typeof control.result?.stderr === 'string' ? control.result.stderr : ''
    };
}
export class ReportPanel implements vscode.Disposable {
    private panel?: vscode.WebviewPanel;
    private document?: LoadedReport;
    private reference?: ReportReference;
    private last?: ReportReference;
    private navigationApproved = false;
    private pendingFocus?: string;
    private requestSequence = 0;
    constructor(private readonly context: vscode.ExtensionContext, private readonly source: string, private readonly provision?: (commands: string[]) => Promise<void>) {}
    dispose(): void { this.panel?.dispose(); }
    html(): string | undefined { return this.panel?.webview.html; }
    knownReference(): ReportReference | undefined { return this.last; }
    async restore(): Promise<void> {
        const value: unknown = this.context.workspaceState.get('compliance.lastReport');
        if (!vscode.workspace.isTrusted || !fields(value) || typeof value.runId !== 'string' || typeof value.target !== 'string' || typeof value.source !== 'string') { return; }
        const reference = value as unknown as ReportReference;
        try {
            const session = await readSession(this.source, reference);
            await loadReport(this.source, path.join(session.directory, 'compliance-report.json'), reference, true);
            this.last = reference;
        } catch (error) { await vscode.window.showWarningMessage(`Derniere session non restaurable : ${String(error)}`); }
    }
    async openSession(reference?: ReportReference, focus?: string, historical = false): Promise<void> {
        const selected = reference || this.last;
        if (!selected) { throw new Error('Aucun rapport explicitement rattache a une session connue.'); }
        const session = await readSession(this.source, selected);
        await this.open(path.join(session.directory, 'compliance-report.json'), selected, historical || !reference, focus);
        this.last = selected;
        await this.context.workspaceState.update('compliance.lastReport', selected);
    }
    async open(file: string, reference?: ReportReference, historical = true, focus?: string): Promise<void> {
        if (!vscode.workspace.isTrusted) { throw new Error('Approuver la Pipeline source avant sa validation.'); }
        const request = ++this.requestSequence;
        const loaded = await loadReport(this.source, file, reference, historical);
        if (reference && reference.runId === loaded.runId && !historical) { loaded.historical = false; }
        if (request !== this.requestSequence) { return; }
        if (focus && !loaded.controls.some(control => control.id === focus || `root/${control.technology}/${control.root}` === focus || `technology/${control.technology}` === focus)) { throw new Error('Section de rapport inconnue.'); }
        this.document = loaded; this.reference = reference; this.navigationApproved = !historical;
        this.pendingFocus = focus;
        if (!this.panel) {
            this.panel = vscode.window.createWebviewPanel('compliance.report', 'Rapport Compliance', vscode.ViewColumn.One, {
                enableScripts: true, retainContextWhenHidden: false,
                localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'media'), vscode.Uri.joinPath(this.context.extensionUri, '.extension-build/media')]
            });
            this.panel.onDidDispose(() => { this.panel = undefined; this.document = undefined; });
            this.panel.webview.onDidReceiveMessage(message => { void this.handle(message).catch(error => vscode.window.showErrorMessage(String(error))); });
        }
        const webview = this.panel.webview;
        this.panel.title = `Compliance ${text(loaded.report.verdict || 'PLAN')} : ${loaded.runId.slice(0, 8)}`;
        const icon = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media/icon.png')).toString();
        webview.html = reportHtml(loaded, webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media/report.css')).toString(),
            webview.cspSource, randomBytes(16).toString('hex'), icon);
        this.panel.reveal();
    }
    async pick(): Promise<void> {
        const folder = runsDirectory(this.source);
        const selected = await vscode.window.showOpenDialog({
            defaultUri: vscode.Uri.file(folder),
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            filters: { 'compliance-report.json': ['json'] },
            openLabel: 'Ouvrir le rapport'
        });
        if (!selected?.length) { return; }
        if (path.basename(selected[0].fsPath) !== 'compliance-report.json') {
            throw new Error('compliance.openReportFile : choisir un fichier nommé compliance-report.json.');
        }
        await this.open(selected[0].fsPath);
    }
    async refresh(): Promise<void> {
        if (!this.document) { throw new Error('Aucun rapport ouvert.'); }
        await this.open(this.document.file, this.reference, this.document.historical);
    }
    async raw(): Promise<void> {
        if (!this.document) { throw new Error('Aucun rapport ouvert.'); }
        const bytes = await readStable(this.document.file);
        if (createHash('sha256').update(bytes).digest('hex') !== this.document.sha256) { throw new Error('Rapport modifié ; actualiser avant ouverture du JSON brut.'); }
        await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(vscode.Uri.file(this.document.file)));
    }
    async openFolder(): Promise<void> {
        const document = this.document;
        if (!document?.directory) { throw new Error('Aucune session associée : le dossier ne peut pas être ouvert.'); }
        if (this.reference) { await readSession(this.source, this.reference); }
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(document.directory));
    }
    private async handle(value: unknown): Promise<void> {
        const message = reportMessage(value);
        const document = this.document;
        if (!document) { throw new Error('Rapport ferme.'); }
        if (message.action === 'ready') {
            if (this.pendingFocus) { await this.panel?.webview.postMessage({ type: 'focus', id: sectionId(this.pendingFocus) }); this.pendingFocus = undefined; }
            return;
        }
        if (message.action === 'provision') {
            const commands = document.controls.filter(control => control.reason?.code === 'tool_unavailable').map(control => {
                const tool = fields(control.plan?.tool) ? control.plan?.tool : undefined;
                return fields(tool) && typeof tool.command === 'string' ? tool.command : '';
            }).filter(command => command && command !== 'none');
            if (!this.provision) { throw new Error('compliance.provisionTools : installation indisponible dans cette vue.'); }
            await this.provision([...new Set(commands)]);
            return;
        }
        if (message.action === 'pick' || message.action === 'raw' || message.action === 'folder') {
            const command = reportButtonCommand(message.action);
            if (!command) { throw new Error('Action Webview inconnue.'); }
            try {
                if (message.action === 'pick') { await this.pick(); }
                else if (message.action === 'raw') { await this.raw(); }
                else { await this.openFolder(); }
            } catch (error) {
                throw new Error(`${command} : ${error instanceof Error ? error.message : String(error)}`);
            }
            return;
        }
        if (message.action === 'output') {
            const control = document.controls.find(item => item.id === message.controlId);
            if (!control?.result) { throw new Error('Controle inconnu ou sans sortie.'); }
            await vscode.window.showTextDocument(await vscode.workspace.openTextDocument({ content: controlOutputText(document.runId, control.id, control.result), language: 'plaintext' })); return;
        }
        if (message.action !== 'finding') { throw new Error('Action Webview inconnue.'); }
        const findings = visibleFindings(document.report);
        const finding = findings[message.index];
        if (!finding) { throw new Error('Finding inconnu.'); }
        if (!findingLocation(finding) || !vscode.workspace.isTrusted) { throw new Error('Localisation fiable ou confiance absente.'); }
        if (!this.navigationApproved) {
            const approval = await vscode.window.showWarningMessage(`Rapport historique : autoriser la navigation dans cette Target ?\n${document.target}\nAucun controle ne sera execute.`, { modal: true }, 'Autoriser la navigation');
            if (approval !== 'Autoriser la navigation') { return; }
            this.navigationApproved = true;
        }
        await revealFinding(document.target, finding);
    }
}
