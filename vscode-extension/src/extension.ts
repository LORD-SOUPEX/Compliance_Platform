import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as vscode from 'vscode';
import { audit, Permissions, prepare, sessionArtifact, SessionController, validateSource, validateTarget } from './daemonClient';
import { controlOutputText, PlanNode, projectPlan, VisualStatus } from './model';
import { ReportPanel } from './reportPanel';

class PipelineTree implements vscode.TreeDataProvider<PlanNode> {
    private readonly changed = new vscode.EventEmitter<PlanNode | undefined>();
    readonly onDidChangeTreeData = this.changed.event;
    status: VisualStatus = 'Pending';
    message = 'Aucune Target selectionnee.';
    constructor(readonly controller: SessionController) {}
    refresh(): void { this.changed.fire(undefined); }
    dispose(): void { this.changed.dispose(); }
    getChildren(node?: PlanNode): PlanNode[] {
        if (node) { return node.children; }
        const report = this.controller.preparation?.report;
        const session = this.controller.audit;
        return [
            { id: 'source', label: 'Pipeline source', description: this.controller.source, detail: report ? `Produit : ${report.metadata.platform_qualification_status || 'non qualifie'}\nCatalogue : ${report.metadata.catalog_sha256 || 'inconnu'}` : this.controller.source, children: [] },
            { id: 'target', label: 'Target', description: this.controller.target || 'Non selectionnee', children: [] },
            { id: 'session', label: session ? `Session ${session.runId}` : 'Preparation', status: session?.status || this.status, reason: session?.reason || (this.status === 'Blocked' ? { code: 'incomplete_scan', message: this.message } : undefined), detail: this.message, children: [] },
            { id: 'pipelines', label: 'Pipelines', children: session?.snapshot ? session.nodes() : report ? projectPlan(report) : [] }
        ];
    }
    getTreeItem(node: PlanNode): vscode.TreeItem {
        if (node.status && ['Blocked', 'Skipped', 'Warning', 'Not applicable'].includes(node.status) && (!node.reason?.code || !node.reason.message)) {
            throw new Error('Un statut non executable exige un motif structure.');
        }
        const item = new vscode.TreeItem(node.label, node.children.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None);
        item.id = node.id;
        const elapsed = node.status === 'Running' && node.execution_start ? Math.max(0, Date.now() - Date.parse(node.execution_start)) : node.duration_ms;
        item.description = [node.status, node.description, elapsed === undefined ? undefined : `${(elapsed / 1000).toFixed(1)} s`].filter(Boolean).join(' | ');
        item.tooltip = [node.label, node.description, node.reason ? `${node.reason.code}: ${node.reason.message}` : undefined, node.detail].filter(Boolean).join('\n');
        const icons: Record<VisualStatus, string> = { Pending: 'clock', Running: 'loading~spin', Succeeded: 'pass', Failed: 'error', Error: 'stop-circle', Warning: 'warning', Skipped: 'debug-step-over', Blocked: 'lock', 'Not applicable': 'circle-slash' };
        if (node.status) { item.iconPath = new vscode.ThemeIcon(icons[node.status]); }
        if (node.output_path) { item.contextValue = 'complianceControlOutput'; item.command = { command: 'compliance.openLastReport', title: 'Ouvrir le controle dans le rapport', arguments: [node.id] }; }
        else if (this.controller.audit?.terminal && this.controller.audit.reportPath && (node.id === 'session' || node.id.startsWith('root/') || node.id.startsWith('technology/'))) {
            item.command = { command: 'compliance.openLastReport', title: 'Ouvrir le rapport de session', arguments: [node.id === 'session' ? undefined : node.id] };
        }
        return item;
    }
}

export function activate(context: vscode.ExtensionContext): { getNodes(): PlanNode[]; getReportHtml(): string | undefined } {
    const source = path.resolve(context.extensionPath, '..');
    const controller = new SessionController(source);
    const tree = new PipelineTree(controller);
    const output = vscode.window.createOutputChannel('Compliance');
    const reports = new ReportPanel(context, source);
    const view = vscode.window.createTreeView('compliance.pipelines', { treeDataProvider: tree, showCollapseAll: true });
    const update = () => {
        tree.refresh();
        void vscode.commands.executeCommand('setContext', 'compliance.canRun', controller.canRun(vscode.workspace.isTrusted));
        void vscode.commands.executeCommand('setContext', 'compliance.auditActive', controller.busy && !!controller.audit);
        void vscode.commands.executeCommand('setContext', 'compliance.hasSession', !!controller.audit);
        void vscode.commands.executeCommand('setContext', 'compliance.hasReport', !!controller.audit?.reportPath || !!reports.knownReference());
    };
    const ticker = setInterval(() => { if (controller.busy && controller.audit?.snapshot) { tree.refresh(); } }, 1000);
    const sourceWatcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(source, '{.config/control-catalog.json,.tools/runtime/index.json,requirements-dev.lock}'));
    const invalidate = () => {
        controller.cancel(); controller.sourceValid = false; controller.preparation = undefined;
        tree.status = 'Blocked'; tree.message = 'Pipeline source modifiee ; actualiser la preparation et les consentements.'; update();
    };
    async function refresh(): Promise<void> {
        if (controller.busy || !controller.target) { return; }
        if (!vscode.workspace.isTrusted) { await vscode.window.showWarningMessage('Approuver le workspace avant de sonder les outils locaux.'); return; }
        controller.busy = true; controller.abort = new AbortController(); controller.preparation = undefined; controller.audit = undefined; controller.sourceValid = false;
        tree.status = 'Running';
        tree.message = 'Discovery, Matrix et Resolver ; aucun controle execute.';
        update();
        output.appendLine(`Pipeline source : ${source}\nTarget : ${controller.target}`);
        try {
            await validateSource(source);
            controller.preparation = await prepare(source, controller.target, undefined, controller.abort.signal);
            controller.sourceValid = true;
            tree.status = controller.preparation.report.discovery.scan_complete ? 'Succeeded' : 'Blocked';
            tree.message = `Plan prepare. Session : ${controller.preparation.directory}`;
            output.appendLine(tree.message);
        } catch (error) {
            tree.status = 'Error';
            tree.message = error instanceof Error ? error.message : String(error);
            output.appendLine(tree.message);
            await vscode.window.showErrorMessage(tree.message);
        } finally { controller.end(); update(); }
    }
    async function askPermissions(fresh: Awaited<ReturnType<typeof prepare>>): Promise<Permissions> {
        controller.preparation = fresh;
        const permissions: Permissions = { network: false, code_execution: false };
        for (const permission of ['network', 'code_execution'] as const) {
            const controls = fresh.report.execution_plan.controls.filter(control => control.reason_code === 'permission_denied' && control.permissions?.includes(permission));
            if (!controls.length || controller.abort?.signal.aborted) { continue; }
            const details = controls.map(control => `${control.name}\nTechnologie : ${control.technology} ; racine : ${control.root}\nEffets : ${control.side_effect_level}\n${control.reason}`).join('\n\n');
            const result = await vscode.window.showWarningMessage(`Permission ${permission === 'network' ? 'reseau' : 'execution de code'} pour cette session.\n\n${details}\n\nCette autorisation ne constitue pas un sandbox.`, { modal: true }, 'Refuser', 'Autoriser pour cette session');
            permissions[permission] = result === 'Autoriser pour cette session';
        }
        return permissions;
    }
    async function launch(): Promise<void> {
        if (!controller.canRun(vscode.workspace.isTrusted)) { await vscode.window.showWarningMessage('Target, source valide, preparation et autorisation requises avant l audit.'); return; }
        try {
            const state = controller.begin(vscode.workspace.isTrusted); update();
            tree.message = 'Nouvelle preparation avant audit ; consentements limites a cette session.';
            output.appendLine(`Session ${state.runId}\nTarget : ${state.target}\nPipeline source : ${source}`);
            const patterns = vscode.workspace.getConfiguration('compliance').get<string[]>('reportRedactionPatterns', []);
            for (const pattern of patterns) { new RegExp(pattern); }
            const directory = await audit(source, state, askPermissions, update, controller.abort!.signal, patterns.length ? patterns.map(pattern => `(?:${pattern})`).join('|') : undefined);
            tree.message = `${state.status} ; session : ${directory}`; output.appendLine(tree.message);
            if (state.reportPath) {
                try { await reports.openSession({ runId: state.runId, target: state.target, source }); }
                catch (error) { tree.message = `Rapport non ouvert : ${String(error)} ; dossier de session conserve.`; output.appendLine(tree.message); await vscode.window.showErrorMessage(tree.message); }
            }
        } catch (error) { controller.audit?.fail(String(error)); tree.message = String(error); output.appendLine(tree.message); await vscode.window.showErrorMessage(tree.message); }
        finally { controller.end(); update(); }
    }
    context.subscriptions.push(tree, output, view, reports, { dispose: () => { controller.cancel(); clearInterval(ticker); } },
        sourceWatcher, sourceWatcher.onDidChange(invalidate), sourceWatcher.onDidCreate(invalidate), sourceWatcher.onDidDelete(invalidate),
        vscode.workspace.onDidGrantWorkspaceTrust(update),
        vscode.commands.registerCommand('compliance.showLogs', () => output.show()),
        vscode.commands.registerCommand('compliance.refreshPlan', refresh),
        vscode.commands.registerCommand('compliance.runAudit', launch),
        vscode.commands.registerCommand('compliance.cancelAudit', () => { controller.cancel(); output.appendLine('Annulation demandee au backend.'); update(); }),
        vscode.commands.registerCommand('compliance.openLastReport', async (focus?: string) => {
            try {
                const state = controller.audit;
                if (state) {
                    if (!state.terminal || !state.reportPath) { throw new Error('Rapport de la session courante non disponible ; consulter ses journaux.'); }
                    await reports.openSession({ runId: state.runId, target: state.target, source }, focus);
                } else { await reports.openSession(undefined, focus, true); }
            } catch (error) { await vscode.window.showErrorMessage(String(error)); }
        }),
        vscode.commands.registerCommand('compliance.openReportFile', async (selected?: vscode.Uri) => {
            try {
                const selection = selected ? [selected] : await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFolders: false, filters: { 'Rapport JSON': ['json'] }, openLabel: 'Ouvrir le rapport historique' });
                if (!selection?.length) { return; }
                if (selection[0].scheme !== 'file') { throw new Error('Choisir un rapport JSON local.'); }
                await reports.open(selection[0].fsPath);
            } catch (error) { await vscode.window.showErrorMessage(`Rapport non ouvert : ${String(error)}`); }
        }),
        vscode.commands.registerCommand('compliance.refreshReport', async () => { try { await reports.refresh(); } catch (error) { await vscode.window.showErrorMessage(String(error)); } }),
        vscode.commands.registerCommand('compliance.openRawReport', async () => { try { await reports.raw(); } catch (error) { await vscode.window.showErrorMessage(String(error)); } }),
        vscode.commands.registerCommand('compliance.openSessionFolder', async () => {
            const runId = controller.audit?.runId || reports.knownReference()?.runId;
            if (!runId) { return; }
            const directory = path.join(source, '.tools/state/runs', runId);
            await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(await sessionArtifact(directory, directory)));
        }),
        vscode.commands.registerCommand('compliance.openControlOutput', async (node: PlanNode) => {
            try {
                if (!controller.audit || !node?.output_path) { return; }
                const directory = path.join(source, '.tools/state/runs', controller.audit.runId);
                const result = JSON.parse(await fs.readFile(await sessionArtifact(directory, node.output_path), 'utf8'));
                const content = controlOutputText(controller.audit.runId, node.id, result);
                await vscode.window.showTextDocument(await vscode.workspace.openTextDocument({ content, language: 'plaintext' }));
            } catch (error) { await vscode.window.showErrorMessage(String(error)); }
        }),
        vscode.commands.registerCommand('compliance.selectTarget', async () => {
            if (controller.busy) { await vscode.window.showInformationMessage('Une session est deja active.'); return; }
            if (!vscode.workspace.isTrusted) { await vscode.window.showWarningMessage('Approuver le workspace avant de preparer une Target.'); return; }
            const selection = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, canSelectMany: false, openLabel: 'Selectionner la Target' });
            if (!selection?.length) { return; }
            if (selection[0].scheme !== 'file') { await vscode.window.showErrorMessage('Choisir un dossier local.'); return; }
            try {
                const target = await validateTarget(source, selection[0].fsPath);
                const approval = await vscode.window.showWarningMessage(`Target : ${target}\nConfirmer ce dossier de confiance pour la preparation et l audit. Les permissions reseau/code seront demandees separement.`, { modal: true }, 'Preparer');
                if (approval !== 'Preparer') { return; }
                controller.select(target);
                await refresh();
            } catch (error) { await vscode.window.showErrorMessage(error instanceof Error ? error.message : String(error)); }
        }));
    update();
    void reports.restore().then(update);
    return { getNodes: () => tree.getChildren(), getReportHtml: () => reports.html() };
}
