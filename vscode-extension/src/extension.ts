import * as path from 'node:path';
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as vscode from 'vscode';
import { audit, DaemonClient, Permissions, prepare, runsDirectory, sessionArtifact, SessionController, setAuditFilters, setExpectedEngineVersion, shutdownComplianceDaemon, validateSource, validateTarget } from './daemonClient';
import { applicationValue, parseSessionKeep, sessionDirectory } from './localSettings';
import { classifyProvisionError, hasMachineConsent, machineConsentKey, machineConsentText, MachineConsent, missingToolCommands, selectManifestTools, shouldAskMachineConsent } from './toolProvision';
import { controlOutputText, paceNotice, PlanNode, projectPlan, VisualStatus } from './model';
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

function resolvePlatformSource(extensionPath: string): string {
    const inside = path.join(extensionPath, '.config', 'control-catalog.json');
    if (fsSync.existsSync(inside)) { return extensionPath; }
    const parent = path.resolve(extensionPath, '..');
    if (fsSync.existsSync(path.join(parent, '.config', 'control-catalog.json'))) { return parent; }
    throw new Error('Catalogue de contrôles introuvable dans l\'extension installée ou dans le dépôt.');
}

export function activate(context: vscode.ExtensionContext): { getNodes(): PlanNode[]; getReportHtml(): string | undefined } {
    setExpectedEngineVersion(String((context.extension.packageJSON as { version?: string }).version || ''));
    const applyFilters = () => {
        const config = vscode.workspace.getConfiguration('compliance');
        setAuditFilters(applicationValue(config.inspect<string[]>('disabledTechnologies'), []), applicationValue(config.inspect<string[]>('disabledControls'), []));
    };
    applyFilters();
    const source = resolvePlatformSource(context.extensionPath);
    const controller = new SessionController(source);
    const tree = new PipelineTree(controller);
    const output = vscode.window.createOutputChannel('Compliance');
    let provisionToolsRef: (commands: string[]) => Promise<boolean> = async () => false;
    const reports = new ReportPanel(context, source, async commands => {
        const installed = await provisionToolsRef(commands);
        if (installed && controller.canRun(vscode.workspace.isTrusted)) { await launch(1); }
    });
    provisionToolsRef = commands => provisionTools(commands, 'manual');
    const view = vscode.window.createTreeView('compliance.pipelines', { treeDataProvider: tree, showCollapseAll: true });
    const update = () => {
        tree.refresh();
        void vscode.commands.executeCommand('setContext', 'compliance.canRun', controller.canRun(vscode.workspace.isTrusted));
        void vscode.commands.executeCommand('setContext', 'compliance.auditActive', controller.busy && !!controller.audit);
        void vscode.commands.executeCommand('setContext', 'compliance.hasSession', !!controller.audit);
        void vscode.commands.executeCommand('setContext', 'compliance.hasReport', !!controller.audit?.reportPath || !!reports.knownReference());
    };
    const slowLogged = new Set<string>();
    const ticker = setInterval(() => {
        if (!(controller.busy && controller.audit?.snapshot)) { return; }
        for (const control of controller.audit.controls.values()) {
            if (control.status !== 'Running' || !control.execution_start || slowLogged.has(control.id)) { continue; }
            const notice = paceNotice(Date.now() - Date.parse(control.execution_start));
            if (!notice) { continue; }
            slowLogged.add(control.id);
            control.reason = { code: 'control_slow', message: notice };
            output.appendLine(`${control.label} : ${notice}`);
        }
        tree.refresh();
    }, 1000);
    const sourceWatcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(source, '{.config/control-catalog.json,.tools/runtime/index.json,requirements-dev.lock}'));
    const invalidate = () => {
        controller.cancel(); controller.sourceValid = false; controller.preparation = undefined;
        tree.status = 'Blocked'; tree.message = 'Pipeline source modifiee ; actualiser la preparation.'; update();
    };
    async function refresh(): Promise<void> {
        if (controller.busy || !controller.target) { return; }
        if (!vscode.workspace.isTrusted) { await vscode.window.showWarningMessage('Approuver le workspace avant de sonder les outils locaux.'); return; }
        controller.busy = true; controller.abort = new AbortController(); controller.preparation = undefined; controller.audit = undefined; controller.sourceValid = false;
        tree.status = 'Running';
        tree.message = 'Discovery, Matrix et Resolver ; aucun controle execute.';
        update();
        output.appendLine(`Pipeline source : ${source}\nTarget : ${controller.target}`);
        await purgeSessions(1);
        const started = Date.now();
        try {
            await validateSource(source);
            output.appendLine(`source validee : ${Date.now() - started} ms`);
            const detected = Date.now();
            controller.preparation = await prepare(source, controller.target, undefined, controller.abort.signal, undefined, line => output.appendLine(line));
            output.appendLine(`detection et plan : ${Date.now() - detected} ms`);
            controller.sourceValid = true;
            const renderStarted = Date.now();
            tree.status = controller.preparation.report.discovery.scan_complete ? 'Succeeded' : 'Blocked';
            const waiting = controller.preparation.report.execution_plan.controls.filter(control => control.reason_code === 'permission_denied');
            const authorized = hasMachineConsent(context.globalState.get<MachineConsent>(machineConsentKey));
            tree.message = waiting.length && !authorized
                ? `Plan prepare. ${waiting.length} controle(s) exigent l'autorisation machine, demandee une seule fois au lancement.`
                : `Plan prepare. Session : ${controller.preparation.directory}`;
            output.appendLine(`rendu : ${Date.now() - renderStarted} ms`);
            output.appendLine(tree.message);
            output.appendLine(`preparation visible : ${Date.now() - started} ms`);
        } catch (error) {
            tree.status = 'Error';
            tree.message = error instanceof Error ? error.message : String(error);
            output.appendLine(tree.message);
            await vscode.window.showErrorMessage(tree.message);
        } finally { controller.end(); update(); }
    }
    async function ensureMachineConsent(force = false): Promise<boolean> {
        const memory = context.globalState.get<MachineConsent>(machineConsentKey);
        if (!force && hasMachineConsent(memory)) { return true; }
        if (!force && !shouldAskMachineConsent(memory)) { return false; }
        const choice = await vscode.window.showWarningMessage(machineConsentText(), { modal: true }, 'Autoriser', 'Refuser');
        const decision = choice === 'Autoriser' ? 'accepted' : 'refused';
        await context.globalState.update(machineConsentKey, { schema_version: 1, decision } satisfies MachineConsent);
        if (decision === 'refused') {
            output.appendLine('Autorisation machine refusée. Les contrôles qui exigent le réseau ou l\'exécution de code restent non couverts. Relancez « Autoriser Compliance sur cette machine » pour changer d\'avis.');
        }
        return decision === 'accepted';
    }
    function grantedPermissions(): Permissions {
        const allowed = hasMachineConsent(context.globalState.get<MachineConsent>(machineConsentKey));
        return { network: allowed, code_execution: allowed };
    }
    async function purgeSessions(reserve: number, extra: string[] = []): Promise<void> {
        const config = vscode.workspace.getConfiguration('compliance');
        const parsed = parseSessionKeep(applicationValue(config.inspect<number>('maxSessions'), 5));
        if (parsed.error) { output.appendLine(parsed.error); }
        const fallback = runsDirectory(source);
        const chosen = sessionDirectory(applicationValue(config.inspect<string>('sessionsDirectory'), ''), process.env.COMPLIANCE_SESSIONS_DIR, fallback);
        const protect = [reports.knownReference()?.runId, ...extra].filter((value): value is string => !!value);
        try {
            const lines = await new DaemonClient().purgeSessions(source, chosen, parsed.keep, protect, reserve);
            for (const line of lines) { output.appendLine(line); }
        } catch (error) {
            output.appendLine(`purge : ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    function hostPlatform(): string {
        const osName = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
        const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
        return `${osName}-${arch}`;
    }
    async function provisionTools(commands: string[], trigger: 'auto' | 'manual'): Promise<boolean> {
        const manifest = JSON.parse(await fs.readFile(path.join(source, '.config', 'runtime-manifest.json'), 'utf8'));
        const known = selectManifestTools(manifest, hostPlatform(), commands);
        const unknown = commands.filter(command => !known.some(tool => tool.command === command));
        if (unknown.length && trigger === 'manual') {
            await vscode.window.showErrorMessage(`${unknown.join(', ')} : absent du manifeste. L'extension ne propose ni pip ni Homebrew.`);
        }
        if (!known.length) { return false; }
        const allowed = hasMachineConsent(context.globalState.get<MachineConsent>(machineConsentKey)) || await ensureMachineConsent(trigger === 'manual');
        if (!allowed) {
            output.appendLine(`Installation non lancée (${known.map(tool => tool.command).join(', ')}) : autorisation machine absente.`);
            return false;
        }
        try {
            const client = new DaemonClient();
            const config = vscode.workspace.getConfiguration('compliance');
            const registryUrl = config.get<string>('registryUrl', '');
            const registryToken = config.get<string>('registryToken', '');
            output.appendLine(`Installation silencieuse : ${known.map(tool => tool.command).join(', ')}`);
            await client.syncTools(source, known.map(tool => tool.command), { registryUrl, registryToken });
            return true;
        } catch (error) {
            await vscode.window.showErrorMessage(classifyProvisionError(error instanceof Error ? error.message : String(error)).message);
            return false;
        }
    }
    async function provisionFromReport(directory: string): Promise<boolean> {
        try {
            return await provisionTools(missingToolCommands(JSON.parse(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8'))), 'auto');
        } catch (error) {
            output.appendLine(`Provisionnement non proposé : ${error instanceof Error ? error.message : String(error)}`);
            return false;
        }
    }
    async function launch(depth = 0): Promise<void> {
        if (!controller.canRun(vscode.workspace.isTrusted)) { await vscode.window.showWarningMessage('Target, source valide, preparation et autorisation requises avant l audit.'); return; }
        let rerun = false;
        try {
            await ensureMachineConsent();
            const state = controller.begin(vscode.workspace.isTrusted); update();
            tree.message = 'Nouvelle preparation avant audit.';
            output.appendLine(`Session ${state.runId}\nTarget : ${state.target}\nPipeline source : ${source}`);
            await purgeSessions(1, [state.runId]);
            const patterns = vscode.workspace.getConfiguration('compliance').get<string[]>('reportRedactionPatterns', []);
            for (const pattern of patterns) { new RegExp(pattern); }
            const directory = await audit(source, state, async () => grantedPermissions(), update, controller.abort!.signal, patterns.length ? patterns.map(pattern => `(?:${pattern})`).join('|') : undefined, undefined, line => output.appendLine(line));
            tree.message = `${state.status} ; session : ${directory}`; output.appendLine(tree.message);
            if (depth === 0) { rerun = await provisionFromReport(directory); }
            if (!rerun && state.reportPath) {
                const reference = { runId: state.runId, target: state.target, source };
                try { await reports.openSession(reference); }
                catch (error) {
                    try { await reports.open(path.join(directory, 'compliance-report.json'), reference, false); }
                    catch (fallback) { tree.message = `Rapport non ouvert : ${String(fallback)} ; dossier de session conserve.`; output.appendLine(`${String(error)} ; ${tree.message}`); await vscode.window.showErrorMessage(tree.message); }
                }
            }
        } catch (error) { controller.audit?.fail(String(error)); tree.message = String(error); output.appendLine(tree.message); await vscode.window.showErrorMessage(tree.message); }
        finally { await purgeSessions(0, [controller.audit?.runId || '']); controller.end(); update(); }
        if (rerun) {
            output.appendLine('Outils installés ; nouvel audit.');
            await launch(depth + 1);
        }
    }
    context.subscriptions.push(tree, output, view, reports, { dispose: () => { controller.cancel(); clearInterval(ticker); void shutdownComplianceDaemon(); } },
        sourceWatcher, sourceWatcher.onDidChange(invalidate), sourceWatcher.onDidCreate(invalidate), sourceWatcher.onDidDelete(invalidate),
        vscode.workspace.onDidGrantWorkspaceTrust(update),
        vscode.commands.registerCommand('compliance.showLogs', () => output.show()),
        vscode.commands.registerCommand('compliance.authorizeMachine', async () => {
            const allowed = await ensureMachineConsent(true);
            await vscode.window.showInformationMessage(allowed ? 'Compliance est autorisé sur cette machine. Les prochains audits ne redemanderont rien.' : 'Autorisation refusée. Les audits restent locaux, sans réseau ni exécution de code.');
        }),
        vscode.commands.registerCommand('compliance.reset', async () => {
            await shutdownComplianceDaemon();
            output.appendLine('Démon arrêté. Les sessions et rapports sont conservés.');
            await vscode.window.showInformationMessage('Démon Compliance arrêté. Les rapports sont conservés.');
        }),
        vscode.commands.registerCommand('compliance.refreshPlan', refresh),
        vscode.commands.registerCommand('compliance.runAudit', launch),
        vscode.commands.registerCommand('compliance.cancelAudit', () => { controller.cancel(); output.appendLine('Annulation demandee au backend.'); update(); }),
        vscode.commands.registerCommand('compliance.openLastReport', async (focus?: string) => {
            try {
                const state = controller.audit;
                if (state) {
                    if (!state.terminal || !state.reportPath) { throw new Error('Rapport de la session courante non disponible ; consulter ses journaux.'); }
                    await reports.openSession({ runId: state.runId, target: state.target, source }, focus);
                } else if (reports.knownReference()) { await reports.openSession(reports.knownReference(), focus, false); }
                else { await reports.openSession(undefined, focus, true); }
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
            const directory = path.join(runsDirectory(source), runId);
            await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(await sessionArtifact(directory, directory)));
        }),
        vscode.commands.registerCommand('compliance.openControlOutput', async (node: PlanNode) => {
            try {
                if (!controller.audit || !node?.output_path) { return; }
                const directory = path.join(runsDirectory(source), controller.audit.runId);
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
                await ensureMachineConsent();
                controller.select(target);
                await refresh();
            } catch (error) { await vscode.window.showErrorMessage(error instanceof Error ? error.message : String(error)); }
        }));
    update();
    void reports.restore().then(update);
    return { getNodes: () => tree.getChildren(), getReportHtml: () => reports.html() };
}
