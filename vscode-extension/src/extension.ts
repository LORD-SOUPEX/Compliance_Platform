import * as path from 'node:path';
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as vscode from 'vscode';
import { activeManifestPath, audit, DaemonClient, daemonLogPaths, Permissions, prepare, runsDirectory, sessionArtifact, SessionController, setAuditFilters, setDaemonLogger, setExpectedEngineVersion, shutdownComplianceDaemon, validateSource, validateTarget } from './daemonClient';
import { applicationValue, parseSessionKeep, sessionDirectory } from './localSettings';
import { classifyProvisionError, hasMachineConsent, machineConsentKey, machineConsentText, MachineConsent, missingToolCommands, selectManifestTools, shouldAskMachineConsent } from './toolProvision';
import { controlOutputText, paceNotice, PlanNode, projectPlan, VisualStatus } from './model';
import { ReportPanel } from './reportPanel';
import { daemonStreamLevel, errorMessage, Logger, relayDaemonEntry } from './logger';
import { DaemonSupervisor } from './daemonSupervisor';

const registryTokenKey = 'compliance.registryToken';
let activeSupervisor: DaemonSupervisor | undefined;

class PipelineTree implements vscode.TreeDataProvider<PlanNode> {
    private readonly changed = new vscode.EventEmitter<PlanNode | undefined>();
    readonly onDidChangeTreeData = this.changed.event;
    status: VisualStatus = 'Pending';
    message = 'Aucune Target sélectionnée.';
    constructor(readonly controller: SessionController) {}
    refresh(): void { this.changed.fire(undefined); }
    dispose(): void { this.changed.dispose(); }
    getChildren(node?: PlanNode): PlanNode[] {
        if (node) { return node.children; }
        const report = this.controller.preparation?.report;
        const session = this.controller.audit;
        return [
            { id: 'source', label: 'Pipeline source', description: this.controller.source, detail: report ? `Produit : ${report.metadata.platform_qualification_status || 'non qualifie'}\nCatalogue : ${report.metadata.catalog_sha256 || 'inconnu'}` : this.controller.source, children: [] },
            { id: 'target', label: 'Target', description: this.controller.target || 'Non sélectionnée', children: [] },
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
        if (node.output_path) { item.contextValue = 'complianceControlOutput'; item.command = { command: 'compliance.openLastReport', title: 'Ouvrir le contrôle dans le rapport', arguments: [node.id] }; }
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
    // LogOutputChannel: timestamps and levels; the user picks the level with "Developer: Set Log Level...".
    const channel = vscode.window.createOutputChannel('Compliance', { log: true });
    const log = new Logger(channel);
    setDaemonLogger(log);
    log.info('extension activée', { version: (context.extension.packageJSON as { version?: string }).version, platform: `${process.platform}-${process.arch}`, vscode: vscode.version, source });
    const supervisor = new DaemonSupervisor(source, log);
    activeSupervisor = supervisor;
    const showError = async (message: string, error?: unknown) => {
        const text = error === undefined ? message : `${message}${message ? ' : ' : ''}${errorMessage(error)}`;
        log.error(text);
        await vscode.window.showErrorMessage(text, 'Voir le journal').then(choice => { if (choice) { channel.show(true); } });
    };
    let provisionToolsRef: (commands: string[]) => Promise<boolean> = () => Promise.resolve(false);
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
            log.child({ runId: controller.audit.runId, controlId: control.id }).warn(notice);
        }
        tree.refresh();
    }, 1000);
    const sourceWatcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(source, '{.config/control-catalog.json,.tools/runtime/index.json,requirements-dev.lock}'));
    const invalidate = () => {
        controller.cancel(); controller.sourceValid = false; controller.preparation = undefined;
        tree.status = 'Blocked'; tree.message = 'Pipeline source modifiée ; actualiser la préparation.'; update();
    };
    async function refresh(): Promise<void> {
        if (controller.busy || !controller.target) { return; }
        await supervisor.track('préparation', refreshNow);
    }
    async function refreshNow(): Promise<void> {
        if (controller.busy || !controller.target) { return; }
        if (!vscode.workspace.isTrusted) { await vscode.window.showWarningMessage('Approuver le workspace avant de sonder les outils locaux.'); return; }
        controller.busy = true; controller.abort = new AbortController(); controller.preparation = undefined; controller.audit = undefined; controller.sourceValid = false;
        tree.status = 'Running';
        tree.message = 'Discovery, Matrix et Resolver ; aucun contrôle exécuté.';
        update();
        log.info('préparation', { source, target: controller.target });
        const stopFeed = await followDaemonLog();
        await purgeSessions(1);
        const started = Date.now();
        try {
            await supervisor.start();
            await validateSource(source);
            log.debug('source validée', { ms: Date.now() - started });
            const detected = Date.now();
            controller.preparation = await prepare(source, controller.target, undefined, controller.abort.signal, undefined, log);
            log.info('détection et plan', { ms: Date.now() - detected });
            controller.sourceValid = true;
            const renderStarted = Date.now();
            tree.status = controller.preparation.report.discovery.scan_complete ? 'Succeeded' : 'Blocked';
            const waiting = controller.preparation.report.execution_plan.controls.filter(control => control.reason_code === 'permission_denied');
            const authorized = hasMachineConsent(context.globalState.get<MachineConsent>(machineConsentKey));
            tree.message = waiting.length && !authorized
                ? `Plan préparé. ${waiting.length} contrôle(s) exigent l'autorisation machine, demandée une seule fois au lancement.`
                : `Plan préparé. Session : ${controller.preparation.directory}`;
            log.debug('rendu', { ms: Date.now() - renderStarted });
            log.info(tree.message, { ms: Date.now() - started });
        } catch (error) {
            tree.status = 'Error';
            tree.message = errorMessage(error);
            await showError('', error);
        } finally { stopFeed(); controller.end(); update(); }
    }
    async function ensureMachineConsent(force = false): Promise<boolean> {
        const memory = context.globalState.get<MachineConsent>(machineConsentKey);
        if (!force && hasMachineConsent(memory)) { return true; }
        if (!force && !shouldAskMachineConsent(memory)) { return false; }
        const choice = await vscode.window.showWarningMessage(machineConsentText(), { modal: true }, 'Autoriser', 'Refuser');
        const decision = choice === 'Autoriser' ? 'accepted' : 'refused';
        await context.globalState.update(machineConsentKey, { schema_version: 1, decision } satisfies MachineConsent);
        log.info('autorisation machine', { decision });
        if (decision === 'refused') {
            log.warn('Autorisation machine refusée. Les contrôles qui exigent le réseau ou l\'exécution de code restent non couverts. Relancez « Autoriser Compliance sur cette machine » pour changer d\'avis.');
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
        if (parsed.error) { log.warn(parsed.error); }
        const fallback = runsDirectory(source);
        const chosen = sessionDirectory(applicationValue(config.inspect<string>('sessionsDirectory'), ''), process.env.COMPLIANCE_SESSIONS_DIR, fallback);
        const protect = [reports.knownReference()?.runId, ...extra].filter((value): value is string => !!value);
        try {
            const lines = await new DaemonClient().purgeSessions(source, chosen, parsed.keep, protect, reserve);
            for (const line of lines) { log.info(`purge : ${line}`); }
        } catch (error) {
            log.warn('purge des sessions impossible', { error: errorMessage(error) });
        }
    }
    function hostPlatform(): string {
        const osName = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
        const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
        return `${osName}-${arch}`;
    }
    /** The manifest the running daemon selected, else the registry cache, else the copy in the VSIX. */
    async function manifestInUse(): Promise<string> {
        const fromDaemon = (await new DaemonClient().attach())?.registry?.manifest_path;
        return fromDaemon && fsSync.existsSync(fromDaemon) ? fromDaemon : activeManifestPath(source);
    }
    async function provisionTools(commands: string[], trigger: 'auto' | 'manual'): Promise<boolean> {
        const manifestPath = await manifestInUse();
        const manifest: unknown = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
        log.debug('manifeste actif', { manifest: manifestPath, platform: hostPlatform(), requested: commands.join(',') });
        const known = selectManifestTools(manifest, hostPlatform(), commands);
        const unknown = commands.filter(command => !known.some(tool => tool.command === command));
        if (unknown.length && trigger === 'manual') {
            await vscode.window.showErrorMessage(`${unknown.join(', ')} : absent du manifeste. L'extension ne propose ni pip ni Homebrew.`);
        }
        if (!known.length) { return false; }
        const allowed = hasMachineConsent(context.globalState.get<MachineConsent>(machineConsentKey)) || await ensureMachineConsent(trigger === 'manual');
        if (!allowed) {
            log.warn(`Installation non lancée (${known.map(tool => tool.command).join(', ')}) : autorisation machine absente.`);
            return false;
        }
        try {
            const client = new DaemonClient();
            const config = vscode.workspace.getConfiguration('compliance');
            const registryUrl = config.get<string>('registryUrl', '');
            const registryToken = await context.secrets.get(registryTokenKey) || '';
            log.info(`Installation silencieuse : ${known.map(tool => `${tool.command} ${tool.version}`).join(', ')}`, { registry: registryUrl || 'tools-v1' });
            const tools = known.map(tool => tool.command);
            await supervisor.track('installation des outils', () => vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Compliance : installation des outils'
            }, progress => client.syncTools(source, tools, {
                registryUrl, registryToken, log,
                onTool: (tool, index, total) => progress.report({ message: `${tool} (${index + 1}/${total})`, increment: index === 0 ? 0 : 100 / total })
            })));
            return true;
        } catch (error) {
            await showError(classifyProvisionError(errorMessage(error)).message);
            return false;
        }
    }
    async function provisionFromReport(directory: string): Promise<boolean> {
        try {
            return await provisionTools(missingToolCommands(JSON.parse(await fs.readFile(path.join(directory, 'compliance-report.json'), 'utf8'))), 'auto');
        } catch (error) {
            log.warn('Provisionnement non proposé', { error: errorMessage(error) });
            return false;
        }
    }
    /** Relays the daemon journal into the channel while a preparation or an audit runs. */
    async function followDaemonLog(): Promise<() => void> {
        const feed = new AbortController();
        try {
            const client = new DaemonClient();
            await client.ensureDaemon(source);
            const level = daemonStreamLevel(channel.logLevel);
            void client.streamLogs(level, entry => relayDaemonEntry(log, entry), feed.signal)
                .catch(error => log.debug('flux du journal du démon interrompu', { error: errorMessage(error) }));
        } catch (error) {
            log.debug('journal du démon non suivi', { error: errorMessage(error) });
        }
        return () => feed.abort();
    }
    /** Moves a token left in settings.json (synchronised by Settings Sync) to SecretStorage. */
    async function migrateRegistryToken(): Promise<void> {
        const config = vscode.workspace.getConfiguration('compliance');
        const legacy = config.inspect<string>('registryToken')?.globalValue;
        if (!legacy) { return; }
        await context.secrets.store(registryTokenKey, legacy);
        await config.update('registryToken', undefined, vscode.ConfigurationTarget.Global);
        log.info('jeton du registre déplacé de settings.json vers le stockage sécurisé de VS Code');
    }
    async function launch(depth = 0): Promise<void> {
        if (!controller.canRun(vscode.workspace.isTrusted)) { await vscode.window.showWarningMessage('Target, source valide, préparation et autorisation requises avant l\'audit.'); return; }
        await supervisor.track(depth ? 'nouvel audit' : 'audit', () => launchNow(depth));
    }
    async function launchNow(depth: number): Promise<void> {
        let rerun = false;
        let stopFeed = () => {};
        try {
            await ensureMachineConsent();
            await supervisor.start();
            const state = controller.begin(vscode.workspace.isTrusted); update();
            tree.message = 'Nouvelle préparation avant audit.';
            log.child({ runId: state.runId }).info('audit demandé', { target: state.target, source, depth });
            stopFeed = await followDaemonLog();
            await purgeSessions(1, [state.runId]);
            const patterns = vscode.workspace.getConfiguration('compliance').get<string[]>('reportRedactionPatterns', []);
            for (const pattern of patterns) { new RegExp(pattern); }
            const directory = await audit(source, state, () => Promise.resolve(grantedPermissions()), update, controller.abort!.signal, patterns.length ? patterns.map(pattern => `(?:${pattern})`).join('|') : undefined, undefined, log);
            tree.message = `${state.status} ; session : ${directory}`; log.child({ runId: state.runId }).info(tree.message);
            if (depth === 0) { rerun = await provisionFromReport(directory); }
            if (!rerun && state.reportPath) {
                const reference = { runId: state.runId, target: state.target, source };
                try { await reports.openSession(reference); }
                catch (error) {
                    try { await reports.open(path.join(directory, 'compliance-report.json'), reference, false); }
                    catch (fallback) { tree.message = `Rapport non ouvert : ${errorMessage(fallback)} ; dossier de session conservé.`; log.warn(errorMessage(error)); await showError(tree.message); }
                }
            }
        } catch (error) { controller.audit?.fail(errorMessage(error)); tree.message = errorMessage(error); await showError('Audit interrompu', error); }
        finally { stopFeed(); await purgeSessions(0, [controller.audit?.runId || '']); controller.end(); update(); }
        if (rerun) {
            log.info('Outils installés ; nouvel audit.');
            await launch(depth + 1);
        }
    }
    // The daemon is shared by every window: closing this one only unregisters it (deactivate);
    // the daemon stops itself once no window is left.
    context.subscriptions.push(tree, channel, view, reports, supervisor, { dispose: () => { controller.cancel(); clearInterval(ticker); } },
        sourceWatcher, sourceWatcher.onDidChange(invalidate), sourceWatcher.onDidCreate(invalidate), sourceWatcher.onDidDelete(invalidate),
        vscode.workspace.onDidGrantWorkspaceTrust(() => { update(); void supervisor.start().catch(() => undefined); }),
        vscode.commands.registerCommand('compliance.showLogs', () => channel.show()),
        vscode.commands.registerCommand('compliance.showDaemonLog', async () => {
            const { journal, console: consoleLog } = daemonLogPaths();
            const file = [journal, consoleLog].find(candidate => fsSync.existsSync(candidate));
            if (!file) { await vscode.window.showInformationMessage(`Aucun journal du démon dans ${path.dirname(journal)}.`); return; }
            await vscode.window.showTextDocument(vscode.Uri.file(file), { preview: true });
        }),
        vscode.commands.registerCommand('compliance.setRegistryToken', async () => {
            const value = await vscode.window.showInputBox({ title: 'Jeton du registre d\'outils', prompt: 'Jeton Bearer du miroir privé. Laisser vide pour l\'effacer.', password: true, ignoreFocusOut: true });
            if (value === undefined) { return; }
            if (value) { await context.secrets.store(registryTokenKey, value); } else { await context.secrets.delete(registryTokenKey); }
            log.info(value ? 'jeton du registre enregistré' : 'jeton du registre effacé');
        }),
        vscode.commands.registerCommand('compliance.authorizeMachine', async () => {
            const allowed = await ensureMachineConsent(true);
            await vscode.window.showInformationMessage(allowed ? 'Compliance est autorisé sur cette machine. Les prochains audits ne redemanderont rien.' : 'Autorisation refusée. Les audits restent locaux, sans réseau ni exécution de code.');
        }),
        vscode.commands.registerCommand('compliance.reset', async () => {
            await shutdownComplianceDaemon();
            supervisor.markStopped();
            log.info('Démon arrêté. Les sessions et rapports sont conservés.');
            await vscode.window.showInformationMessage('Démon Compliance arrêté. Les rapports sont conservés.');
        }),
        vscode.commands.registerCommand('compliance.refreshPlan', refresh),
        vscode.commands.registerCommand('compliance.runAudit', launch),
        vscode.commands.registerCommand('compliance.cancelAudit', () => { controller.cancel(); log.info('Annulation demandée au backend.'); update(); }),
        vscode.commands.registerCommand('compliance.openLastReport', async (focus?: string) => {
            try {
                const state = controller.audit;
                if (state) {
                    if (!state.terminal || !state.reportPath) { throw new Error('Rapport de la session courante non disponible ; consulter ses journaux.'); }
                    await reports.openSession({ runId: state.runId, target: state.target, source }, focus);
                } else if (reports.knownReference()) { await reports.openSession(reports.knownReference(), focus, false); }
                else { await reports.openSession(undefined, focus, true); }
            } catch (error) { await showError('Rapport non ouvert', error); }
        }),
        vscode.commands.registerCommand('compliance.openReportFile', async (selected?: vscode.Uri) => {
            try {
                const selection = selected ? [selected] : await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFolders: false, filters: { 'Rapport JSON': ['json'] }, openLabel: 'Ouvrir le rapport historique' });
                if (!selection?.length) { return; }
                if (selection[0].scheme !== 'file') { throw new Error('Choisir un rapport JSON local.'); }
                await reports.open(selection[0].fsPath);
            } catch (error) { await showError('Rapport non ouvert', error); }
        }),
        vscode.commands.registerCommand('compliance.refreshReport', async () => { try { await reports.refresh(); } catch (error) { await showError('Rapport non rechargé', error); } }),
        vscode.commands.registerCommand('compliance.openRawReport', async () => { try { await reports.raw(); } catch (error) { await showError('JSON brut non ouvert', error); } }),
        vscode.commands.registerCommand('compliance.openSessionFolder', async () => {
            const runId = controller.audit?.runId || reports.knownReference()?.runId;
            if (!runId) { return; }
            const directory = path.join(runsDirectory(source), runId);
            await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(await sessionArtifact(directory, directory)));
        }),
        vscode.commands.registerCommand('compliance.openControlOutput', async (node: PlanNode) => {
            try {
                if (!controller.audit || !node?.output_path) { return; }
                // output_path is the raw stdout/stderr capture; the structured result came with control_completed.
                const result = controller.audit.results.get(node.id);
                if (!result) { throw new Error('Sorties du contrôle absentes de cette session.'); }
                const content = controlOutputText(controller.audit.runId, node.id, result);
                await vscode.window.showTextDocument(await vscode.workspace.openTextDocument({ content, language: 'plaintext' }));
            } catch (error) { await showError('Sorties non ouvertes', error); }
        }),
        vscode.commands.registerCommand('compliance.selectTarget', async () => {
            if (controller.busy) { await vscode.window.showInformationMessage('Une session est déjà active.'); return; }
            if (!vscode.workspace.isTrusted) { await vscode.window.showWarningMessage('Approuver le workspace avant de preparer une Target.'); return; }
            const selection = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, canSelectMany: false, openLabel: 'Sélectionner la Target' });
            if (!selection?.length) { return; }
            if (selection[0].scheme !== 'file') { await vscode.window.showErrorMessage('Choisir un dossier local.'); return; }
            try {
                const target = await validateTarget(source, selection[0].fsPath);
                await ensureMachineConsent();
                controller.select(target);
                await refresh();
            } catch (error) { await showError('Target non préparée', error); }
        }));
    update();
    // Warm the engine without blocking activation; failures show in the status bar and the channel.
    if (vscode.workspace.isTrusted) { void supervisor.start().catch(() => undefined); }
    void migrateRegistryToken().catch(error => log.warn('migration du jeton du registre impossible', { error: errorMessage(error) }));
    void reports.restore().then(update, error => log.warn('dernière session non restaurée', { error: errorMessage(error) }));
    return { getNodes: () => tree.getChildren(), getReportHtml: () => reports.html() };
}

/** VS Code awaits this promise briefly on window close or reload. */
export async function deactivate(): Promise<void> {
    await activeSupervisor?.deactivate();
    activeSupervisor = undefined;
}
