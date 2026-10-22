import * as vscode from 'vscode';
import { DaemonClient, DaemonHealth } from './daemonClient';
import { errorMessage, Logger } from './logger';

export type SupervisorState = 'stopped' | 'starting' | 'ready' | 'busy' | 'failed';

const heartbeatMs = 60000;
const retryDelaysMs = [1000, 3000];

/**
 * One per window. Starts the daemon without blocking activation, retries a
 * failed start, registers the window with the daemon (which stops itself when
 * no window is left), and shows the engine state in the status bar.
 */
export class DaemonSupervisor implements vscode.Disposable {
    readonly clientId = `${vscode.env.sessionId}-${process.pid}`;
    private state: SupervisorState = 'stopped';
    private health?: DaemonHealth;
    private failure?: string;
    private activity?: string;
    private starting?: Promise<DaemonHealth>;
    private heartbeat?: NodeJS.Timeout;
    private readonly item = vscode.window.createStatusBarItem('compliance.status', vscode.StatusBarAlignment.Left, 10);

    constructor(private readonly source: string, private readonly log: Logger) {
        this.item.name = 'Compliance';
        this.item.command = 'compliance.showLogs';
        this.render();
        this.item.show();
    }

    /** Starts or joins the daemon. Concurrent callers share one attempt. */
    start(): Promise<DaemonHealth> {
        if (!this.starting) {
            this.starting = this.startWithRetries().finally(() => { this.starting = undefined; });
        }
        return this.starting;
    }

    private async startWithRetries(): Promise<DaemonHealth> {
        if (this.state !== 'ready' && this.state !== 'busy') { this.set('starting'); }
        let lastError: unknown;
        for (let attempt = 0; attempt <= retryDelaysMs.length; attempt++) {
            try {
                const client = new DaemonClient();
                const health = await client.ensureDaemon(this.source);
                await client.registerClient(this.clientId, `VS Code ${vscode.version}`).catch(error =>
                    this.log.debug('fenêtre non enregistrée auprès du démon', { error: errorMessage(error) }));
                this.accept(health);
                this.startHeartbeat();
                return health;
            } catch (error) {
                lastError = error;
                if (attempt < retryDelaysMs.length) {
                    this.log.warn(`démarrage du démon en échec, nouvel essai dans ${retryDelaysMs[attempt] / 1000} s`, { attempt: attempt + 1, error: errorMessage(error) });
                    await new Promise(resolve => setTimeout(resolve, retryDelaysMs[attempt]));
                }
            }
        }
        this.failure = errorMessage(lastError);
        this.set('failed');
        throw lastError instanceof Error ? lastError : new Error(this.failure);
    }

    private accept(health: DaemonHealth): void {
        this.health = health;
        this.failure = undefined;
        this.set(health.tools_upgrading?.length ? 'busy' : 'ready');
    }

    private startHeartbeat(): void {
        if (this.heartbeat) { return; }
        this.heartbeat = setInterval(() => { void this.beat(); }, heartbeatMs);
        this.heartbeat.unref?.();
    }

    /** Keeps the window registered and the status current. Never starts a daemon by itself. */
    private async beat(): Promise<void> {
        if (this.starting) { return; }
        const client = new DaemonClient();
        const health = await client.attach();
        if (!health) {
            if (this.state !== 'stopped' && this.state !== 'failed') { this.log.info('démon arrêté ; il sera relancé à la prochaine commande'); }
            this.health = undefined;
            this.set('stopped');
            return;
        }
        await client.registerClient(this.clientId, `VS Code ${vscode.version}`).catch(() => undefined);
        this.accept(health);
    }

    /** Shows label in the status bar while work runs, and in the window progress area. */
    async track<T>(label: string, work: () => Thenable<T>): Promise<T> {
        const previous = this.activity;
        this.activity = label;
        this.render();
        try {
            return await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: `ICP : ${label}` }, work);
        } finally {
            this.activity = previous;
            this.render();
        }
    }

    /** Called after "Réinitialiser le démon": the next command starts a fresh one. */
    markStopped(): void {
        this.health = undefined;
        this.set('stopped');
    }

    /** Unregisters this window. The daemon keeps serving other windows and stops once idle. */
    async deactivate(): Promise<void> {
        if (this.heartbeat) { clearInterval(this.heartbeat); this.heartbeat = undefined; }
        const client = new DaemonClient();
        if (await client.attach()) {
            await client.unregisterClient(this.clientId).catch(() => undefined);
        }
    }

    dispose(): void {
        if (this.heartbeat) { clearInterval(this.heartbeat); this.heartbeat = undefined; }
        this.item.dispose();
    }

    private set(state: SupervisorState): void {
        if (state !== this.state) { this.log.debug('état du moteur', { from: this.state, to: state }); }
        this.state = state;
        this.render();
    }

    private render(): void {
        const health = this.health;
        const engine = health ? `Moteur ${health.version} (pid ${health.pid}, port ${health.port})` : 'Moteur Compliance';
        const registry = health?.registry ? `\nRegistre : ${health.registry.source}${health.registry.refreshing ? ' (vérification en cours)' : ''}` : '';
        this.item.backgroundColor = undefined;
        if (this.activity) {
            this.item.text = `$(loading~spin) ICP : ${this.activity}`;
            this.item.tooltip = `${engine}\n${this.activity} en cours. Cliquer pour voir le journal.`;
            return;
        }
        switch (this.state) {
            case 'starting':
                this.item.text = '$(sync~spin) ICP';
                this.item.tooltip = 'Démarrage du moteur Compliance… Cliquer pour voir le journal.';
                break;
            case 'busy':
                this.item.text = `$(sync~spin) ICP : mise à jour de ${(health?.tools_upgrading || []).join(', ')}`;
                this.item.tooltip = `${engine}${registry}\nLes audits attendent la fin de la mise à jour des outils.`;
                break;
            case 'ready':
                this.item.text = '$(shield) ICP';
                this.item.tooltip = `${engine} prêt${registry}\nCliquer pour voir le journal.`;
                break;
            case 'failed':
                this.item.text = '$(warning) ICP';
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                this.item.tooltip = `Moteur indisponible : ${this.failure || 'erreur inconnue'}\nCliquer pour voir le journal.`;
                break;
            default:
                this.item.text = '$(circle-slash) ICP';
                this.item.tooltip = 'Moteur arrêté. Il démarre à la prochaine commande.';
        }
    }
}
