import { createHash, randomBytes } from 'node:crypto';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { controlOutputText } from './model';
import { fields, Fields, findingLocation, LoadedReport, loadReport, readSession, readStable, ReportReference, reportMessage, targetFile, text } from './reportReader';

export function escaped(value: unknown, limit = 50000): string {
    const original = text(value);
    const bounded = original.length > limit ? `${original.slice(0, limit)}\n[Affichage limite ; ouvrir les sorties ou le JSON brut.]` : original;
    return bounded.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]!));
}
export function sectionId(id: string): string { return `section-${createHash('sha256').update(id).digest('hex')}`; }
const array = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const info = (label: string, value: unknown) => `<dt>${escaped(label)}</dt><dd>${escaped(value)}</dd>`;
const reasonText = (value: unknown) => fields(value) ? `${text(value.code)} : ${text(value.message)}` : text(value);
const list = (values: unknown[]) => values.length ? `<ul>${values.map(value => `<li>${escaped(fields(value) ? value.message || value.reason || value : value)}</li>`).join('')}</ul>` : '<p class="muted">Aucun element.</p>';

export function reportHtml(document: LoadedReport, css: string, script: string, cspSource: string, nonce: string): string {
    const report = document.report;
    const metadata = report.metadata as Fields;
    const coverage = report.coverage as Fields;
    const summary = report.summary as Fields;
    const discovery = report.discovery as Fields;
    const findings = array(report.findings).filter(fields);
    const start = document.session?.started_at;
    const end = document.session?.ended_at;
    const duration = typeof start === 'string' && typeof end === 'string' ? Math.max(0, Date.parse(end) - Date.parse(start)) : undefined;
    const warning = coverage.complete !== true || document.session?.state === 'cancelled' || document.session?.state === 'incomplete' || report.execution_status !== 'completed';
    const counts = new Map<string, number>();
    for (const control of document.controls) { counts.set(control.status, (counts.get(control.status) || 0) + 1); }
    const groups = new Map<string, typeof document.controls>();
    for (const control of document.controls) {
        const key = JSON.stringify([control.technology, control.root]);
        groups.set(key, [...(groups.get(key) || []), control]);
    }
    const technologies = new Set<string>();
    const pipelines = [...groups.values()].map(controls => {
        const first = controls[0];
        const technologyAnchor = technologies.has(first.technology) ? '' : `<div id="${sectionId(`technology/${first.technology}`)}"></div>`;
        technologies.add(first.technology);
        const details = controls.map(control => {
            const result = control.result;
            const tool = fields(control.plan?.tool) ? control.plan!.tool as Fields : undefined;
            return `<details class="control" id="${sectionId(control.id)}"><summary><span class="status">${escaped(control.status)}</span><strong>${escaped(control.name, 2000)}</strong><span>${result ? `${escaped(result.duration_ms)} ms` : 'Non execute'}</span></summary>
              <dl>${info('Instance', control.id)}${info('Technologie / racine', `${control.technology} / ${control.root}`)}${info('Outil', tool?.name || tool?.command)}${info('Resultat canonique', result?.status)}${info('Motif', control.reason ? reasonText(control.reason) : 'Aucun')}${info('Code de sortie', result?.exit_code)}${info('Sortie tronquee', result?.output_truncated === true ? 'Oui' : 'Non')}</dl>
              <button type="button" data-action="output" data-control-id="${escaped(control.id, 4096)}" ${result ? '' : 'disabled'}>Ouvrir les sorties</button>
              <h4>Diagnostics</h4>${list(array(result?.diagnostics).map(reasonText))}<h4>Findings</h4>${list(control.findings.map(finding => finding.message || array(finding.diagnostics).map(reasonText).join('; ')))}
              <h4>stdout</h4><pre>${escaped(result?.stdout || '')}</pre><h4>stderr</h4><pre>${escaped(result?.stderr || '')}</pre></details>`;
        }).join('');
        return `${technologyAnchor}<section id="${sectionId(`root/${first.technology}/${first.root}`)}"><h3>${escaped(first.technology)} <span class="muted">/ ${escaped(first.root)}</span></h3>${details}</section>`;
    }).join('');
    const findingRows = findings.map((finding, index) => {
        const location = findingLocation(finding);
        return `<article class="finding"><h3>${escaped(finding.severity)} : ${escaped(finding.name || finding.id || finding.control_id)}</h3><dl>${info('Identifiant', finding.id)}${info('Controle', finding.control_id)}${info('Technologie / racine', `${text(finding.technology)} / ${text(finding.root)}`)}${info('Message', finding.message || array(finding.diagnostics).map(reasonText).join('; '))}${info('Recommandation', finding.recommendation)}${location ? info('Fichier', location.file) + info('Ligne', location.line) + info('Colonne', location.column) : info('Localisation', 'Non fournie par le backend')}</dl>${location ? `<button type="button" data-action="finding" data-finding-index="${index}">Ouvrir le fichier</button>` : ''}</article>`;
    }).join('');
    const permissions = (['network', 'code_execution'] as const).map(permission => {
        const granted = metadata[permission === 'network' ? 'network_authorized' : 'code_execution_authorized'] === true;
        const denied = document.controls.filter(control => control.reason?.code === 'permission_denied' && array(control.plan?.permissions).includes(permission));
        return `<li>${permission === 'network' ? 'Reseau' : 'Execution de code'} : ${granted ? 'accordee pour cette session' : 'non accordee'}${denied.length ? ` ; ${denied.length} controle(s) omis` : ''}</li>`;
    }).join('');
    return `<!doctype html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${escaped(cspSource)}; script-src 'nonce-${nonce}'; img-src 'none'; connect-src 'none';"><link rel="stylesheet" href="${escaped(css)}"><title>Rapport Compliance</title></head><body>
      <header><div><p class="muted">${document.historical ? 'Rapport historique : aucune session active associee' : 'Rapport de la session courante'}</p><h1>Compliance <span>${escaped(report.verdict || 'PLAN')}</span></h1></div><nav aria-label="Actions du rapport"><button data-action="refresh">Actualiser</button><button data-action="raw">JSON brut</button><button data-action="folder" ${document.directory ? '' : 'disabled'}>Dossier de session</button></nav></header>
      ${warning ? '<p class="notice" role="status">Evaluation incomplete ou couverture partielle. Le verdict canonique ne garantit pas une couverture complete.</p>' : ''}
      <section><h2>Identite</h2><dl>${info('Etat', document.session?.state || report.execution_status)}${info('Target', document.target)}${info('Pipeline source', document.session?.pipeline_source || metadata.pipeline_source || 'Non renseignee dans ce rapport historique')}${info('run_id', document.runId)}${info('Debut', start)}${info('Fin', end || report.generated_at)}${info('Duree totale', duration === undefined ? 'Non renseignee ; durees des controles disponibles' : `${duration} ms`)}${info('Version rapport / moteur', `${text(report.schema_version)} / ${text(report.engine_version)}`)}${info('Catalogue', metadata.catalog_sha256)}${info('Fichier ouvert', document.file)}${info('SHA-256 du rapport', document.sha256)}</dl></section>
      <section><h2>Resume</h2><div class="metrics">${['Succeeded', 'Failed', 'Error', 'Warning', 'Skipped', 'Blocked', 'Not applicable', 'Pending', 'Running'].map(status => `<div><strong>${counts.get(status) || 0}</strong><span>${status}</span></div>`).join('')}</div><p>Resume canonique : ${escaped(JSON.stringify(summary))}</p><ul>${permissions}</ul></section>
      <section><h2>Verdict et couverture</h2><p>Verdict du moteur : <strong>${escaped(report.verdict || 'Aucun verdict : plan seul')}</strong>. Couverture : <strong>${coverage.complete === true ? 'complete' : 'partielle'}</strong>.</p>${list(array(report.verdict_reasons))}<dl>${info('Controles planifies', coverage.planned_controls)}${info('Controles executes', coverage.executed_controls)}${info('Controles requis omis', coverage.omitted_required_controls)}${info('Dependances bloquees', coverage.dependency_skips)}</dl><h3>Omissions</h3>${list(array(coverage.limitations))}<h3>Limitations</h3>${list(array(report.limitations))}<h3>Ambiguites et preparation</h3>${list([...array(discovery.ambiguities), ...array(discovery.scan_errors)])}<h3>Capacites et outils indisponibles</h3>${list(document.controls.filter(control => ['Blocked', 'Error', 'Skipped'].includes(control.status)).map(control => `${control.id} : ${control.reason ? reasonText(control.reason) : control.status}`))}</section>
      <section><h2>Pipelines</h2>${pipelines || '<p>Aucun controle planifie.</p>'}</section><section><h2>Findings</h2>${findingRows || '<p>Aucun finding.</p>'}</section><section><h2>Diagnostics globaux</h2>${list(array(report.diagnostics).map(reasonText))}</section>
      <script nonce="${nonce}" src="${escaped(script)}"></script></body></html>`;
}

export class ReportPanel implements vscode.Disposable {
    private panel?: vscode.WebviewPanel;
    private document?: LoadedReport;
    private reference?: ReportReference;
    private last?: ReportReference;
    private navigationApproved = false;
    private pendingFocus?: string;
    private requestSequence = 0;
    constructor(private readonly context: vscode.ExtensionContext, private readonly source: string) {}
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
        if (!vscode.workspace.isTrusted) { throw new Error('Approuver la Pipeline source avant sa validation PowerShell.'); }
        const request = ++this.requestSequence;
        const loaded = await loadReport(this.source, file, reference, historical);
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
        webview.html = reportHtml(loaded, webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media/report.css')).toString(),
            webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, '.extension-build/media/report.js')).toString(), webview.cspSource, randomBytes(16).toString('hex'));
        this.panel.reveal();
    }
    async refresh(): Promise<void> {
        if (!this.document) { throw new Error('Aucun rapport ouvert.'); }
        await this.open(this.document.file, this.reference, this.document.historical);
    }
    async raw(): Promise<void> {
        if (!this.document) { throw new Error('Aucun rapport ouvert.'); }
        const bytes = await readStable(this.document.file);
        if (createHash('sha256').update(bytes).digest('hex') !== this.document.sha256) { throw new Error('Rapport modifie ; actualiser avant ouverture du JSON brut.'); }
        await vscode.window.showTextDocument(await vscode.workspace.openTextDocument({ content: bytes.toString('utf8'), language: 'json' }));
    }
    private async handle(value: unknown): Promise<void> {
        const message = reportMessage(value);
        const document = this.document;
        if (!document) { throw new Error('Rapport ferme.'); }
        if (message.action === 'ready') {
            if (this.pendingFocus) { await this.panel?.webview.postMessage({ type: 'focus', id: sectionId(this.pendingFocus) }); this.pendingFocus = undefined; }
            return;
        }
        if (message.action === 'refresh') { await this.refresh(); return; }
        if (message.action === 'raw') { await this.raw(); return; }
        if (message.action === 'folder') {
            if (!document.directory || !this.reference) { throw new Error('Aucune session associee au rapport historique choisi.'); }
            await readSession(this.source, this.reference);
            await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(document.directory)); return;
        }
        if (message.action === 'output') {
            const control = document.controls.find(item => item.id === message.controlId);
            if (!control?.result) { throw new Error('Controle inconnu ou sans sortie.'); }
            await vscode.window.showTextDocument(await vscode.workspace.openTextDocument({ content: controlOutputText(document.runId, control.id, control.result), language: 'plaintext' })); return;
        }
        if (message.action !== 'finding') { throw new Error('Action Webview inconnue.'); }
        const findings = array(document.report.findings).filter(fields);
        const finding = findings[message.index];
        if (!finding) { throw new Error('Finding inconnu.'); }
        const location = findingLocation(finding);
        if (!location || !vscode.workspace.isTrusted) { throw new Error('Localisation fiable ou confiance absente.'); }
        if (!this.navigationApproved) {
            const approval = await vscode.window.showWarningMessage(`Rapport historique : autoriser la navigation dans cette Target ?\n${document.target}\nAucun controle ne sera execute.`, { modal: true }, 'Autoriser la navigation');
            if (approval !== 'Autoriser la navigation') { return; }
            this.navigationApproved = true;
        }
        const file = await targetFile(document.target, location.file);
        const opened = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
        const editor = await vscode.window.showTextDocument(opened);
        if (location.line !== undefined) {
            if (location.line > opened.lineCount || (location.column !== undefined && location.column - 1 > opened.lineAt(location.line - 1).text.length)) { throw new Error('Position du finding devenue incoherente avec le fichier ; aucune position inventee.'); }
            const position = new vscode.Position(location.line - 1, (location.column || 1) - 1);
            editor.selection = new vscode.Selection(position, position); editor.revealRange(new vscode.Range(position, position));
        }
    }
}
