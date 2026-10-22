import * as http from 'node:http';
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFile, spawn, ChildProcess } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
    containsPath,
    isSameDirectory,
    parsePreparation,
    PlanNode,
    PreparationReport,
    projectPlan,
    Reason,
    VisualStatus
} from './model';
import { daemonBinaryDirectory, isOurDaemonImage } from './daemonLifecycle.js';
import { countsAsUnavailable, groupUnavailableLines } from './reportLayout';
import { engineVersionMismatch, expectedEngineVersion } from './engineVersion.js';
import { DaemonLogEntry, errorMessage, formatInvocation, InvocationRecord, Logger, silentLogger } from './logger';
import { SseEvent, SseParser } from './sse';

export { engineVersionMismatch, expectedEngineVersion, setExpectedEngineVersion } from './engineVersion.js';

let daemonLog: Logger = silentLogger;
/** Routes daemon lifecycle and child-process traces to the extension channel. */
export function setDaemonLogger(logger: Logger): void { daemonLog = logger; }

function defaultStateDir(): string {
    return process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance');
}

/** Exit code of `compliance daemon` when another instance holds the lock (server.ExitAlreadyRunning). */
export const exitAlreadyRunning = 3;

/** Journal written by the daemon (JSON lines) and console capture of its stdout and stderr. */
export function daemonLogPaths(stateDir = defaultStateDir()): { journal: string; console: string } {
    const logs = path.join(stateDir, 'logs');
    return { journal: path.join(logs, 'daemon.log'), console: path.join(logs, 'daemon-console.log') };
}

function registryAsset(name: string, fallback: string): string {
    const cached = path.join(os.homedir(), '.compliance', 'registry-cache', name);
    return fsSync.existsSync(cached) ? cached : fallback;
}

/** Manifest the daemon and `runtime sync` actually use: registry cache first, then the copy shipped in the VSIX. */
export function activeManifestPath(platformRoot: string): string {
    return registryAsset('runtime-manifest.json', path.join(platformRoot, '.config', 'runtime-manifest.json'));
}

/** Opens the console capture for append, rotating it past 5 MiB. Returns undefined when the folder is not writable. */
function openConsoleLog(file: string): number | undefined {
    try {
        fsSync.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
        try {
            if (fsSync.statSync(file).size > 5 * 1024 * 1024) { fsSync.renameSync(file, `${file}.1`); }
        } catch { /* absent, or still open by a previous daemon on Windows: keep appending */ }
        const fd = fsSync.openSync(file, 'a', 0o600);
        fsSync.writeSync(fd, `\n--- ${new Date().toISOString()} lancement par l'extension (pid ${process.pid}) ---\n`);
        return fd;
    } catch (error) {
        daemonLog.warn('journal console du démon indisponible', { file, error: errorMessage(error) });
        return undefined;
    }
}

/** Last lines of a text file, for error messages. Never throws. */
export async function tailFile(file: string, lines = 20): Promise<string> {
    try {
        const handle = await fs.open(file, 'r');
        try {
            const { size } = await handle.stat();
            const length = Math.min(size, 16 * 1024);
            const buffer = Buffer.alloc(length);
            await handle.read(buffer, 0, length, size - length);
            return buffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-lines).join('\n');
        } finally { await handle.close(); }
    } catch { return ''; }
}

interface DaemonConnection { port: number; token: string; health: DaemonHealth }
/** One start per state folder: concurrent callers (report restore, commands) share it instead of spawning twice. */
const startups = new Map<string, Promise<DaemonConnection>>();

export interface DaemonState {
    pid: number;
    port: number;
    host: string;
    token_path: string;
    state_dir: string;
    started_at: string;
    version: string;
}

export interface DaemonHealth {
    status: string;
    version: string;
    pid: number;
    port: number;
    started_at: string;
    phase?: string;
    registry?: DaemonRegistry;
    tools_upgrading?: string[];
    clients?: number;
    active_runs?: number;
}

/** Manifest and catalog the daemon actually uses (GET /api/v1/registry). */
export interface DaemonRegistry {
    source: string;
    manifest_path: string;
    catalog_path: string;
    sig_path: string;
    registry_url: string;
    refreshing: boolean;
}

/** Waits until pid is gone (process.kill(pid, 0) works the same on Windows, Linux and macOS). */
export async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try { process.kill(pid, 0); } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ESRCH') { return true; }
            if ((error as NodeJS.ErrnoException).code === 'EPERM') { /* alive, other user */ }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    return false;
}

/** Spawn deadline. The daemon now listens before any network access; a long
 * budget only matters on a first start scanned by an antivirus. */
export const daemonStartTimeoutMs = 60000;

export interface CreateRunOptions {
    runId?: string;
    outputDir?: string;
    planOnly?: boolean;
    controlID?: string;
    allowNetwork?: boolean;
    allowCodeExecution?: boolean;
    confirmApplyDestroy?: boolean;
    redactionPatterns?: string[];
}

export interface RunCreationResult {
    run_id: string;
    status: string;
    events_url: string;
    report_url: string;
}

export interface ControlLogs {
    run_id: string;
    control_id: string;
    status: string;
    exit_code: number | null;
    stdout: string;
    stderr: string;
    duration_ms: number;
    tool_version?: string;
}

export class DaemonClient {
    private port: number = 0;
    private token: string = '';
    private daemonProcess?: ChildProcess;

    constructor(private stateDir?: string) {
        if (!this.stateDir) {
            if (process.env.COMPLIANCE_STATE_DIR) {
                this.stateDir = process.env.COMPLIANCE_STATE_DIR;
            } else {
                const home = os.homedir();
                this.stateDir = path.join(home, '.compliance');
            }
        }
    }

    public isConfigured(): boolean {
        return this.port > 0 && this.token.length > 0;
    }

    public getProcess(): ChildProcess | undefined {
        return this.daemonProcess;
    }

    public getPort(): number {
        return this.port;
    }

    public setConnection(port: number, token: string): void {
        this.port = port;
        this.token = token;
    }

    public async ensureDaemon(platformRoot: string): Promise<DaemonHealth> {
        const key = path.resolve(this.stateDir!);
        let pending = startups.get(key);
        if (!pending) {
            pending = this.startOrAttach(platformRoot).finally(() => startups.delete(key));
            startups.set(key, pending);
        }
        const connection = await pending;
        this.port = connection.port;
        this.token = connection.token;
        return connection.health;
    }

    private async startOrAttach(platformRoot: string): Promise<DaemonConnection> {
        const started = Date.now();
        const connection = await this.startOrAttachUnlogged(platformRoot);
        daemonLog.debug('démon prêt', { version: connection.health.version, pid: connection.health.pid, port: connection.port, ms: Date.now() - started });
        return connection;
    }

    private async startOrAttachUnlogged(platformRoot: string): Promise<DaemonConnection> {
        if (process.platform === 'win32' && process.env.SystemRoot) {
            try {
                await fs.access(path.join(process.env.SystemRoot, 'System32'));
            } catch {
                throw new Error('Environnement Windows invalide (SystemRoot altéré).');
            }
        }

        const stateFile = path.join(this.stateDir!, 'daemon.json');
        try {
            const data = await fs.readFile(stateFile, 'utf8');
            const state: DaemonState = JSON.parse(data);
            const token = (await fs.readFile(state.token_path, 'utf8')).trim();
            this.port = state.port;
            this.token = token;

            const health = await this.getHealth();
            if (health && health.status === 'ok') {
                if (!engineVersionMismatch(health.version, expectedEngineVersion())) {
                    daemonLog.debug('démon existant réutilisé', { pid: health.pid, port: state.port, version: health.version });
                    return { port: this.port, token: this.token, health };
                }
                daemonLog.warn('démon d\'une autre version : remplacement', { running: health.version, expected: expectedEngineVersion(), pid: health.pid });
                await this.shutdown();
                // The old daemon holds the lock until it is really gone: spawning earlier made the new one exit at once.
                if (!(await waitForExit(health.pid, 5000))) { daemonLog.warn('ancien démon encore présent après 5 s', { pid: health.pid }); }
            }
        } catch (error) {
            daemonLog.debug('aucun démon joignable : lancement', { reason: errorMessage(error) });
        }

        const staged = await this.stagedRuntime(platformRoot);

        const args = ['daemon', '-state-dir', this.stateDir!, '-platform-root', staged.platformRoot];
        const journals = daemonLogPaths(this.stateDir);
        const consoleFd = openConsoleLog(journals.console);
        let spawnError: Error | undefined;
        let earlyExit: { code: number | null; signal: NodeJS.Signals | null } | undefined;
        let otherInstance = false;
        daemonLog.command('démon', staged.binary, args, staged.cwd);
        try {
            this.daemonProcess = spawn(staged.binary, args, {
                cwd: staged.cwd,
                detached: true,
                windowsHide: true,
                stdio: consoleFd === undefined ? 'ignore' : ['ignore', consoleFd, consoleFd]
            });
        } finally {
            // The child holds its own handle; the extension host must not keep the file open.
            if (consoleFd !== undefined) { try { fsSync.closeSync(consoleFd); } catch { /* already closed */ } }
        }
        this.daemonProcess.once('error', (error) => { spawnError = error; });
        this.daemonProcess.once('exit', (code, signal) => {
            if (code === exitAlreadyRunning) { otherInstance = true; return; }
            earlyExit = { code, signal };
        });
        this.daemonProcess.unref();
        daemonLog.debug('démon lancé', { pid: this.daemonProcess.pid });

        const deadline = Date.now() + daemonStartTimeoutMs;
        let announced = false;
        while (Date.now() < deadline) {
            if (spawnError || earlyExit) {
                throw await describeWithJournal(describeDaemonLaunchFailure(spawnError, earlyExit), journals);
            }
            if (otherInstance) {
                // Another window started the daemon first: wait for its daemon.json instead of failing.
                daemonLog.debug('verrou détenu par un autre démon : attente de son état');
                otherInstance = false;
            }
            if (!announced && Date.now() > deadline - daemonStartTimeoutMs + 5000) {
                announced = true;
                daemonLog.info('démarrage du démon plus long que prévu (analyse antivirus d\'un premier lancement ?)', { journal: journals.journal });
            }
            await new Promise(r => setTimeout(r, 200));
            try {
                const data = await fs.readFile(stateFile, 'utf8');
                const state: DaemonState = JSON.parse(data);
                const token = (await fs.readFile(state.token_path, 'utf8')).trim();
                this.port = state.port;
                this.token = token;

                const health = await this.getHealth();
                if (health && health.status === 'ok') {
                    if (engineVersionMismatch(health.version, expectedEngineVersion())) {
                        throw new Error(`Démon ${health.version} encore actif ; version attendue ${expectedEngineVersion()}.`);
                    }
                    return { port: this.port, token: this.token, health };
                }
            } catch {
                // daemon.json absent, stale, or still the replaced daemon while the new one starts: keep polling
            }
        }

        throw await describeWithJournal(describeDaemonLaunchFailure(spawnError, earlyExit), journals);
    }

    private async findComplianceBinary(platformRoot: string): Promise<string | null> {
        const exeName = process.platform === 'win32' ? 'compliance.exe' : 'compliance';
        const platformExe = process.platform === 'win32'
            ? (process.arch === 'arm64' ? 'compliance-windows-arm64.exe' : 'compliance-windows-amd64.exe')
            : (process.platform === 'darwin'
                ? (process.arch === 'arm64' ? 'compliance-darwin-arm64' : 'compliance-darwin-amd64')
                : (process.arch === 'arm64' ? 'compliance-linux-arm64' : 'compliance-linux-amd64'));

        const candidates = [
            path.join(__dirname, '..', 'bin', exeName),
            path.join(__dirname, '..', 'bin', platformExe),
            path.join(__dirname, '..', '..', 'bin', exeName),
            path.join(__dirname, '..', '..', 'bin', platformExe),
            path.join(platformRoot, 'vscode-extension', 'bin', exeName),
            path.join(platformRoot, 'vscode-extension', 'bin', platformExe),
            path.join(platformRoot, 'bin', exeName),
            path.join(platformRoot, 'bin', platformExe),
            path.join(platformRoot, '.tools', 'bin', exeName),
            path.join(platformRoot, 'core', exeName),
            path.join(platformRoot, 'core', 'cmd', 'compliance', exeName),
            exeName
        ];

        for (const candidate of candidates) {
            try {
                await fs.access(candidate);
                const binaryPath = path.resolve(candidate);
                await prepareComplianceBinary(binaryPath);
                return binaryPath;
            } catch {
                // Not found, check next
            }
        }
        return null;
    }

    private async stagedRuntime(platformRoot: string): Promise<{ binary: string; platformRoot: string; cwd: string }> {
        const sourceBin = await this.findComplianceBinary(platformRoot);
        if (!sourceBin) { throw new Error('Binaire "compliance" introuvable. Exécuter la compilation Go dans core/.'); }
        return stageDaemonRuntime(sourceBin, platformRoot);
    }

    public async purgeSessions(platformRoot: string, root: string, keep: number, protect: string[], reserve = 0): Promise<string[]> {
        const staged = await this.stagedRuntime(platformRoot);
        const bounded = Math.min(1000, Math.max(1, keep || 5));
        const args = ['sessions', 'purge', '-root', root, '-keep', String(bounded), '-reserve', String(reserve)];
        for (const name of protect) { if (name) { args.push('-protect', name); } }
        daemonLog.command('purge des sessions', staged.binary, args, staged.cwd);
        const started = Date.now();
        const output = await new Promise<string>((resolve, reject) => {
            execFile(staged.binary, args, { cwd: staged.cwd, windowsHide: true }, (error, stdout, stderr) => {
                if (error) {
                    daemonLog.warn('purge des sessions en échec', { exit: (error as NodeJS.ErrnoException & { code?: unknown }).code, stderr: String(stderr).trim() });
                    reject(new Error(String(stderr || error.message)));
                    return;
                }
                daemonLog.debug('purge des sessions terminée', { ms: Date.now() - started });
                resolve(String(stdout));
            });
        });
        return output.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    }

    public async installNodeToolchain(platformRoot: string, options?: SyncOptions): Promise<void> {
        await this.syncTools(platformRoot, ['node'], options);
    }

    public async syncTools(platformRoot: string, tools: string[], options?: SyncOptions): Promise<void> {
        const staged = await this.stagedRuntime(platformRoot);
        const manifest = registryAsset('runtime-manifest.json', path.join(staged.platformRoot, '.config', 'runtime-manifest.json'));
        const signature = registryAsset('runtime-manifest.json.sig', path.join(staged.platformRoot, '.config', 'runtime-manifest.json.sig'));
        const installed: string[] = [];
        const failed: string[] = [];
        const extraArgs: string[] = [];
        if (options?.registryUrl) {
            extraArgs.push('-registry-url', options.registryUrl);
        }
        const spawnEnv: NodeJS.ProcessEnv = { ...process.env };
        if (options?.registryToken) {
            spawnEnv.COMPLIANCE_REGISTRY_TOKEN = options.registryToken;
        }
        const log = options?.log || daemonLog;
        for (const [index, tool] of tools.entries()) {
            options?.onTool?.(tool, index, tools.length);
            const args = ['runtime', 'sync', '-manifest', manifest, '-sig', signature, '-tool', tool, ...extraArgs];
            const started = Date.now();
            log.command(`installation de ${tool}`, staged.binary, args, staged.cwd);
            try {
                await new Promise<void>((resolve, reject) => {
                    const child = spawn(staged.binary, args, { cwd: staged.cwd, env: spawnEnv, windowsHide: true });
                    let stderr = '';
                    relayLines(child.stdout, line => log.info(`${tool} : ${line}`));
                    relayLines(child.stderr, line => {
                        stderr += `${line}\n`;
                        log.write(/^\[(ERROR|WARN)/.test(line) ? 'warn' : 'info', `${tool} : ${line}`);
                    });
                    child.on('error', reject);
                    child.on('close', code => {
                        if (code === 0) { resolve(); }
                        else { reject(new Error(stderr.trim() || `runtime sync a quitté avec le code ${code}`)); }
                    });
                });
                installed.push(tool);
                log.info(`${tool} installé`, { ms: Date.now() - started });
            } catch (error) {
                const detail = errorMessage(error);
                log.error(`${tool} non installé`, { ms: Date.now() - started, error: detail });
                failed.push(`${tool} (${detail})`);
            }
        }
        if (installed.length) {
            // The daemon also watches the tools generation; this makes the next plan probe again at once.
            await this.ensureDaemon(platformRoot).then(() => this.invalidateTools())
                .catch(error => log.debug('cache des sondes non invalidé', { error: errorMessage(error) }));
        }
        if (failed.length) {
            throw new Error(`${installed.length} outil(s) installé(s), ${failed.length} échec : ${failed.join(' ; ')}`);
        }
    }

    /** Connects to a running daemon without ever starting one. */
    public async attach(): Promise<DaemonHealth | undefined> {
        try {
            const state = JSON.parse(await fs.readFile(path.join(this.stateDir!, 'daemon.json'), 'utf8')) as DaemonState;
            this.port = state.port;
            this.token = (await fs.readFile(state.token_path, 'utf8')).trim();
            const health = await this.getHealth();
            return health.status === 'ok' ? health : undefined;
        } catch { return undefined; }
    }

    /** Registers or refreshes this VS Code window; the daemon stops itself once no window is left. */
    public async registerClient(clientId: string, label: string): Promise<void> {
        await this.request('POST', '/api/v1/clients', { client_id: clientId, pid: process.pid, label }, 5000);
    }

    public async unregisterClient(clientId: string): Promise<void> {
        await this.request('DELETE', `/api/v1/clients/${encodeURIComponent(clientId)}`, undefined, 1500);
    }

    public async getRegistry(): Promise<DaemonRegistry> {
        return this.request<DaemonRegistry>('GET', '/api/v1/registry', undefined, 5000);
    }

    /** Forgets every cached tool probe (after an installation). */
    public async invalidateTools(): Promise<void> {
        await this.request('POST', '/api/v1/tools/invalidate', undefined, 5000);
    }

    public async getHealth(): Promise<DaemonHealth> {
        return this.request<DaemonHealth>('GET', '/api/v1/health', undefined, 3000);
    }

    public async approveWorkspace(workspacePath: string): Promise<void> {
        await this.request('POST', '/api/v1/workspaces/approve', { workspace_path: workspacePath });
    }

    /** Planning probes every candidate tool (Checkov alone may take 60 s): ten minutes before giving up. */
    public async getPlan(targetPath: string, options: { allowNetwork?: boolean; allowCodeExecution?: boolean; includeApplyDestroy?: boolean } = {}, signal?: AbortSignal): Promise<PreparationReport> {
        return this.request<PreparationReport>('POST', '/api/v1/plans', {
            target_path: targetPath,
            path: process.env.PATH || '',
            allow_network: options.allowNetwork ?? false,
            allow_code_execution: options.allowCodeExecution ?? false,
            include_apply_destroy: options.includeApplyDestroy ?? false
        }, 10 * 60 * 1000, signal);
    }

    public async createRun(targetPath: string, options: CreateRunOptions = {}): Promise<RunCreationResult> {
        return this.request<RunCreationResult>('POST', '/api/v1/runs', {
            target_path: targetPath,
            path: process.env.PATH || '',
            run_id: options.runId,
            output_dir: options.outputDir,
            plan_only: !!options.planOnly,
            control_id: options.controlID,
            allow_network: !!options.allowNetwork,
            allow_code_execution: !!options.allowCodeExecution,
            confirm_apply_destroy: !!options.confirmApplyDestroy,
            redaction_patterns: options.redactionPatterns || [],
            disabled_technologies: auditFilters.technologies,
            disabled_controls: auditFilters.controls
        });
    }

    /**
     * Session events until a terminal event. An exception thrown by onEvent rejects
     * the promise (it used to escape as an uncaught exception from the socket handler).
     */
    public streamEvents(runId: string, onEvent: (event: unknown) => void, signal?: AbortSignal, lastEventId?: string): Promise<void> {
        return this.openSse(`/api/v1/runs/${runId}/events`, event => {
            let parsed: Record<string, unknown>;
            try {
                const value: unknown = JSON.parse(event.data);
                if (!value || typeof value !== 'object' || Array.isArray(value)) { throw new Error('objet attendu'); }
                parsed = value as Record<string, unknown>;
            } catch (error) {
                daemonLog.warn('événement SSE illisible ignoré', { event: event.event, id: event.id, error: errorMessage(error) });
                return false;
            }
            if (event.event && !parsed.type) { parsed.type = event.event; }
            if (event.id && !parsed.id) { parsed.id = event.id; }
            onEvent(parsed);
            return parsed.type === 'session_completed' || parsed.type === 'session_cancelled' || parsed.type === 'session_failed';
        }, signal, lastEventId, 8000);
    }

    /** Live daemon journal from now on, until signal aborts. */
    public streamLogs(level: string, onEntry: (entry: DaemonLogEntry) => void, signal: AbortSignal): Promise<void> {
        return this.openSse(`/api/v1/logs/stream?level=${encodeURIComponent(level)}`, event => {
            if (event.event !== 'daemon_log') { return false; }
            try { onEntry(JSON.parse(event.data) as DaemonLogEntry); } catch { /* malformed record */ }
            return false;
        }, signal, undefined, 0);
    }

    /**
     * One SSE connection. handle returns true to close after a terminal event.
     * On abort, the connection stays open graceMs to receive the terminal event, then closes.
     */
    private openSse(urlPath: string, handle: (event: SseEvent) => boolean, signal: AbortSignal | undefined, lastEventId: string | undefined, graceMs: number): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            let settled = false;
            let graceTimer: NodeJS.Timeout | undefined;
            const finish = (error?: unknown) => {
                if (settled) { return; }
                settled = true;
                if (graceTimer) { clearTimeout(graceTimer); }
                signal?.removeEventListener('abort', onAbort);
                req.destroy();
                if (error) { reject(error instanceof Error ? error : new Error(String(error))); } else { resolve(); }
            };
            const onAbort = () => {
                if (graceMs <= 0) { finish(); return; }
                graceTimer = setTimeout(() => finish(), graceMs);
            };
            const headers: Record<string, string> = {
                'Host': `127.0.0.1:${this.port}`,
                'Authorization': `Bearer ${this.token}`,
                'Accept': 'text/event-stream'
            };
            if (lastEventId) { headers['Last-Event-ID'] = lastEventId; }

            const req = http.request({ hostname: '127.0.0.1', port: this.port, path: urlPath, method: 'GET', headers, agent: false }, (res) => {
                if (res.statusCode !== 200) {
                    res.resume();
                    finish(new Error(`Connexion SSE ${urlPath} rejetée avec statut ${res.statusCode}`));
                    return;
                }
                res.setEncoding('utf8');
                const parser = new SseParser();
                res.on('data', (chunk: string) => {
                    if (settled) { return; }
                    try {
                        for (const event of parser.feed(chunk)) {
                            if (handle(event)) { finish(); return; }
                        }
                    } catch (error) { finish(error); }
                });
                res.on('end', () => finish());
                res.on('error', error => finish(signal?.aborted ? undefined : error));
            });
            req.on('error', error => finish(signal?.aborted ? undefined : error));
            if (signal) {
                if (signal.aborted) { onAbort(); } else { signal.addEventListener('abort', onAbort, { once: true }); }
            }
            req.end();
        });
    }

    public async getReport(runId: string): Promise<Record<string, unknown>> {
        return this.request('GET', `/api/v1/runs/${runId}/report`, undefined, 120000);
    }

    public async cancelRun(runId: string): Promise<{ cancelled: boolean }> {
        return this.request('POST', `/api/v1/runs/${runId}/cancel`, undefined, 10000);
    }

    public async getLogs(runId: string, controlId: string): Promise<ControlLogs> {
        return this.request('GET', `/api/v1/runs/${runId}/logs/${encodeURIComponent(controlId)}`);
    }

    public async validateReport(reportData: Record<string, unknown>, reportSha256: string): Promise<unknown> {
        return this.request('POST', '/api/v1/reports/validate', {
            report: reportData,
            report_sha256: reportSha256
        }, 120000);
    }

    public async shutdown(): Promise<void> {
        await postShutdown(this.port, this.token);
        try {
            const state = JSON.parse(await fs.readFile(path.join(this.stateDir!, 'daemon.json'), 'utf8')) as DaemonState;
            await killDaemonPid(state.pid, true);
        } catch { /* état déjà retiré */ }
        await killStagedDaemons();
    }

    /** A request without an answer after timeoutMs fails instead of freezing the extension. */
    private request<T>(method: string, path: string, body?: unknown, timeoutMs = 30000, signal?: AbortSignal): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            if (signal?.aborted) { reject(new Error(`Requête ${method} ${path} annulée.`)); return; }
            const bodyData = body ? JSON.stringify(body) : undefined;
            const headers: Record<string, string> = {
                'Host': `127.0.0.1:${this.port}`,
                'Authorization': `Bearer ${this.token}`,
                'Accept': 'application/json'
            };
            if (bodyData) {
                headers['Content-Type'] = 'application/json';
                headers['Content-Length'] = String(Buffer.byteLength(bodyData));
            }

            const req = http.request({
                hostname: '127.0.0.1',
                port: this.port,
                path: path,
                method: method,
                headers: headers,
                agent: false
            }, (res) => {
                let responseBody = '';
                res.setEncoding('utf8');
                res.on('data', chunk => { responseBody += chunk; });
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        try {
                            const parsed = responseBody ? JSON.parse(responseBody) : {};
                            resolve(parsed as T);
                        } catch {
                            resolve({} as T);
                        }
                    } else {
                        reject(new Error(`Requête ${method} ${path} échouée (code ${res.statusCode}): ${responseBody}`));
                    }
                });
            });

            req.setTimeout(timeoutMs, () => req.destroy(new Error(`Requête ${method} ${path} sans réponse du démon après ${Math.round(timeoutMs / 1000)} s.`)));
            const onAbort = () => req.destroy(new Error(`Requête ${method} ${path} annulée.`));
            signal?.addEventListener('abort', onAbort, { once: true });
            req.on('close', () => signal?.removeEventListener('abort', onAbort));
            req.on('error', err => reject(err));
            if (bodyData) {
                req.write(bodyData);
            }
            req.end();
        });
    }
}

export interface SyncOptions { registryUrl?: string; registryToken?: string; log?: Logger; onTool?: (tool: string, index: number, total: number) => void }

/** Splits a child stream into lines across chunk boundaries (LF or CRLF). */
function relayLines(stream: NodeJS.ReadableStream | null | undefined, onLine: (line: string) => void): void {
    if (!stream) { return; }
    let pending = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
        pending += chunk;
        const lines = pending.split(/\r?\n/);
        pending = lines.pop() || '';
        for (const line of lines) { if (line.trim()) { onLine(line.trimEnd()); } }
    });
    stream.on('end', () => { if (pending.trim()) { onLine(pending.trimEnd()); } });
}

async function describeWithJournal(error: Error, journals: { journal: string; console: string }): Promise<Error> {
    const tail = await tailFile(journals.console, 15);
    daemonLog.error(error.message, { journal: journals.journal, console: journals.console });
    if (tail) { daemonLog.error(`dernières lignes de ${journals.console} :\n${tail}`); }
    return new Error(`${error.message} Journal : ${journals.journal}`);
}

const auditFilters = { technologies: [] as string[], controls: [] as string[] };
export function setAuditFilters(technologies: string[], controls: string[]): void {
    auditFilters.technologies = technologies;
    auditFilters.controls = controls;
}

export async function shutdownComplianceDaemon(stateDir?: string): Promise<void> {
    const dir = stateDir || process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance');
    const client = new DaemonClient(dir);
    let state: DaemonState | undefined;
    let token = '';
    try {
        state = JSON.parse(await fs.readFile(path.join(dir, 'daemon.json'), 'utf8')) as DaemonState;
        token = (await fs.readFile(state.token_path, 'utf8')).trim();
        client.setConnection(state.port, token);
    } catch { /* pas de démon enregistré */ }
    if (state) { await postShutdown(state.port, token); }
    if (state?.pid) { await killDaemonPid(state.pid, true); }
    await killStagedDaemons();
}

function postShutdown(port: number, token: string): Promise<void> {
    return new Promise(resolve => {
        if (!port || !token) { resolve(); return; }
        const req = http.request({
            hostname: '127.0.0.1', port, path: '/api/v1/shutdown', method: 'POST', timeout: 500,
            headers: { Host: `127.0.0.1:${port}`, Authorization: `Bearer ${token}` },
            agent: false
        }, response => { response.resume(); resolve(); });
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.on('error', () => resolve());
        req.end();
    });
}

async function stageDaemonRuntime(source: string, platformRoot: string): Promise<{ binary: string; platformRoot: string; cwd: string }> {
    const cwd = process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance');
    const dir = daemonBinaryDirectory(os.homedir(), expectedEngineVersion() || 'dev');
    await fs.mkdir(cwd, { recursive: true });
    await fs.mkdir(dir, { recursive: true });
    const dest = path.join(dir, path.basename(source));
    let current = false;
    try {
        const [from, to] = await Promise.all([fs.stat(source), fs.stat(dest)]);
        current = from.size === to.size && from.mtimeMs <= to.mtimeMs;
    } catch { current = false; }
    if (!current) { await fs.copyFile(source, dest); }
    await prepareComplianceBinary(dest);
    await copyConfig(configDirectory(platformRoot), path.join(dir, '.config'));
    return { binary: dest, platformRoot: dir, cwd };
}

function configDirectory(platformRoot: string): string | undefined {
    const candidates = [path.join(platformRoot, '.config'), path.join(__dirname, '..', '..', '.config'), path.join(__dirname, '..', '.config')];
    return candidates.find(candidate => fsSync.existsSync(path.join(candidate, 'control-catalog.json')));
}

async function copyConfig(source: string | undefined, destination: string): Promise<void> {
    if (!source) { return; }
    await fs.mkdir(destination, { recursive: true });
    for (const name of await fs.readdir(source)) {
        const from = path.join(source, name);
        const info = await fs.stat(from);
        if (!info.isFile()) { continue; }
        const to = path.join(destination, name);
        let same = false;
        try {
            const existing = await fs.stat(to);
            same = existing.size === info.size && existing.mtimeMs >= info.mtimeMs;
        } catch { same = false; }
        if (!same) { await fs.copyFile(from, to); }
    }
}

async function killDaemonPid(pid: number, force = false): Promise<void> {
    const image = await daemonImage(pid);
    if (image && !isOurDaemonImage(path.basename(image))) { return; }
    if (!image && !force) { return; }
    try { process.kill(pid); } catch { /* déjà arrêté */ }
}

async function killStagedDaemons(): Promise<void> {
    const home = (process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance')).toLowerCase();
    for (const row of await listedComplianceProcesses()) {
        const image = row.image.toLowerCase();
        const ours = isOurDaemonImage(path.basename(row.image));
        const staged = image.includes(home) || (image.includes('.vscode') && image.includes('compliance-platform'));
        if (ours && staged) {
            try { process.kill(row.pid); } catch { /* déjà arrêté */ }
        }
    }
}

async function listedComplianceProcesses(): Promise<Array<{ pid: number; image: string }>> {
    if (process.platform !== 'win32') { return []; }
    const text = await execText('powershell.exe', ['-NoProfile', '-Command', "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'compliance*.exe' } | ForEach-Object { $_.ProcessId.ToString() + '|' + $_.ExecutablePath }"]);
    return text.split(/\r?\n/).map(line => {
        const [pid, image] = line.split('|');
        return { pid: Number(pid), image: (image || '').trim() };
    }).filter(row => Number.isInteger(row.pid) && row.pid > 0 && row.image);
}

export async function daemonImage(pid: number): Promise<string> {
    if (process.platform === 'linux') {
        return fs.readlink(`/proc/${pid}/exe`).catch(() => '');
    }
    if (process.platform === 'darwin') {
        return execText('ps', ['-p', String(pid), '-o', 'comm=']);
    }
    return execText('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").ExecutablePath`]).then(text => text.trim());
}

function execText(command: string, args: string[]): Promise<string> {
    return new Promise(resolve => {
        const child = spawn(command, args, { windowsHide: true });
        let out = '';
        child.stdout?.on('data', chunk => { out += String(chunk); });
        child.on('error', () => resolve(''));
        child.on('close', () => resolve(out));
    });
}

// ---------------------------------------------------------------------------
// 2. Gestion de l'état, de la préparation et du session controller
// ---------------------------------------------------------------------------

export interface Preparation { report: PreparationReport; directory: string; target: string }
export interface Permissions { network: boolean; code_execution: boolean }
export type AskPermissions = (preparation: Preparation) => Promise<Permissions>;

export interface ProgressEvent {
    schema_version: number; run_id: string; sequence: number; timestamp: string; type: string;
    control_id?: string | null; technology?: string | null; root?: string | null; data: Record<string, unknown> | null;
}

const statuses: VisualStatus[] = ['Pending', 'Running', 'Succeeded', 'Failed', 'Error', 'Warning', 'Skipped', 'Blocked', 'Not applicable'];
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function reason(value: unknown): value is Reason { return record(value) && typeof value.code === 'string' && value.code.length > 0 && typeof value.message === 'string' && value.message.length > 0; }

export class AuditState {
    sequence = 0;
    status: VisualStatus = 'Running';
    reason?: Reason;
    terminal = false;
    reportPath?: string;
    snapshot?: PreparationReport;
    readonly controls = new Map<string, PlanNode>();
    readonly results = new Map<string, Record<string, unknown>>();
    constructor(readonly runId: string, readonly target: string) {}
    receive(value: unknown): void {
        if (!record(value) || value.schema_version !== 1 || value.run_id !== this.runId ||
            value.sequence !== this.sequence + 1 || typeof value.timestamp !== 'string' || !Number.isFinite(Date.parse(value.timestamp)) ||
            typeof value.type !== 'string' || this.terminal) { throw new Error('Evenement de session invalide, duplique ou hors sequence.'); }
        const event = value as unknown as ProgressEvent;
        this.sequence = event.sequence;
        if (event.sequence === 1 && event.type !== 'session_started') { throw new Error('Debut de session absent.'); }
        const data = event.data || {};
        switch (event.type) {
            case 'session_started': case 'preparation_started': case 'preparation_completed': case 'control_invocation': break;
            case 'plan_available': {
                this.snapshot = parsePreparation(JSON.stringify(data), this.target, true);
                if (this.snapshot.metadata.run_id !== this.runId) { throw new Error('Snapshot d une autre session.'); }
                for (const technology of projectPlan(this.snapshot)) {
                    for (const root of technology.children) { for (const control of root.children) { this.controls.set(control.id, control); } }
                }
                for (const control of this.snapshot.execution_plan.controls) {
                    if (!this.controls.has(control.id)) { this.controls.set(control.id, { id: control.id, label: control.name, status: 'Not applicable', reason: { code: control.reason_code || control.applicability, message: control.reason || 'Technologie absente.' }, children: [] }); }
                }
                break;
            }
            case 'control_started': {
                const control = this.controls.get(event.control_id || '');
                if (!control || control.status !== 'Pending' || typeof data.execution_start !== 'string' || !Number.isFinite(Date.parse(data.execution_start))) { throw new Error('Debut de controle invalide.'); }
                control.status = 'Running'; control.execution_start = data.execution_start; control.reason = undefined;
                break;
            }
            case 'control_completed': {
                const control = this.controls.get(event.control_id || '');
                if (!control || control.duration_ms !== undefined || !record(data.result) || data.result.control_id !== control.id ||
                    !['success', 'fail', 'error', 'skipped'].includes(String(data.result.status)) ||
                    typeof data.result.duration_ms !== 'number' || data.result.duration_ms < 0 || !Number.isFinite(data.result.duration_ms) ||
                    !statuses.includes(data.status as VisualStatus) || ['Pending', 'Running'].includes(String(data.status)) ||
                    (['Warning', 'Skipped', 'Blocked', 'Not applicable'].includes(String(data.status)) && !reason(data.reason)) ||
                    typeof data.output_path !== 'string') { throw new Error(`Fin de controle invalide : ${event.control_id}.`); }
                control.status = data.status as VisualStatus;
                control.duration_ms = data.result.duration_ms;
                control.reason = reason(data.reason) ? data.reason : undefined;
                control.output_path = data.output_path;
                this.results.set(control.id, data.result);
                break;
            }
            case 'report_available':
                if (typeof data.report_path !== 'string') { throw new Error('Chemin de rapport absent.'); }
                this.reportPath = data.report_path; break;
            case 'session_cancelling': this.reason = { code: 'session_interrupted', message: 'Annulation en cours.' }; break;
            case 'session_cancelled':
                this.status = 'Skipped'; this.reason = reason(data.reason) ? data.reason : { code: 'session_interrupted', message: 'Session annulee.' }; this.terminal = true; break;
            case 'session_failed':
                this.status = 'Error'; this.reason = reason(data.reason) ? data.reason : { code: 'preparation_error', message: 'Session backend en erreur.' }; this.terminal = true; break;
            case 'session_completed':
                if (!this.snapshot || !this.reportPath || [...this.controls.values()].some(control => control.duration_ms === undefined)) { throw new Error('Session terminee sans resultats complets.'); }
                this.status = data.verdict === 'FAIL' ? 'Failed' : data.verdict === 'PASS' && record(data.coverage) && data.coverage.complete === true ? 'Succeeded' : 'Warning';
                if (this.status === 'Warning') {
                    const reasons = Array.isArray(data.verdict_reasons) ? data.verdict_reasons.filter((item: unknown) => typeof item === 'string') : [];
                    this.reason = { code: data.verdict == null ? 'not_evaluated' : 'coverage_incomplete', message: String(reasons[0] || (data.verdict == null ? 'Non évalué : couverture nulle, aucun contrôle exécuté.' : 'Audit terminé avec une couverture partielle.')) };
                }
                this.terminal = true; break;
            default: this.reason = { code: 'unknown_event', message: `Evenement non reconnu : ${event.type}` }; break;
        }
    }
    fail(message: string): void {
        this.terminal = true; this.status = 'Error'; this.reason = { code: 'session_interrupted', message };
        for (const control of this.controls.values()) {
            if (control.status === 'Running') { control.status = 'Error'; control.reason = this.reason; }
            else if (control.status === 'Pending') { control.status = 'Blocked'; control.reason = this.reason; }
        }
    }
    verifyReport(value: unknown): void {
        if (!record(value) || value.schema_version !== 1 || !record(value.metadata) || value.metadata.run_id !== this.runId ||
            !isSameDirectory(String(value.repository), this.target) || !Array.isArray(value.execution_results) || !record(value.coverage) || !record(value.summary) ||
            !Array.isArray(value.findings) || !Array.isArray(value.diagnostics) || !Array.isArray(value.limitations) ||
            !['completed', 'blocked', 'error'].includes(String(value.execution_status)) || !['PASS', 'FAIL', null].includes(value.verdict as string | null)) { throw new Error('Rapport final invalide ou d une autre session.'); }
        const summary = value.summary as { success?: number; fail?: number; error?: number };
        if (value.verdict === 'PASS' && (summary.success || 0) + (summary.fail || 0) + (summary.error || 0) === 0) { throw new Error('PASS sans contrôle exécuté.'); }
        const ids = new Set<string>();
        for (const result of value.execution_results) {
            if (!record(result) || typeof result.control_id !== 'string' || ids.has(result.control_id) ||
                !['success', 'fail', 'error', 'skipped'].includes(String(result.status)) || typeof result.duration_ms !== 'number' || result.duration_ms < 0 ||
                !Array.isArray(result.diagnostics)) { throw new Error('Resultats du rapport invalides ou dupliques.'); }
            ids.add(result.control_id);
            const eventResult = this.results.get(result.control_id);
            if (eventResult && (eventResult.status !== result.status || eventResult.duration_ms !== result.duration_ms)) { throw new Error('Resultat different de son evenement terminal.'); }
        }
        if (this.status !== 'Error' && [...this.controls.keys()].some(id => !ids.has(id))) { throw new Error('Resultat absent du rapport final.'); }
        if (this.status === 'Skipped' && (value.coverage.complete || value.verdict === 'PASS')) { throw new Error('Annulation presentee comme reussie.'); }
    }
    nodes(): PlanNode[] {
        if (!this.snapshot) { return []; }
        return projectPlan(this.snapshot).map(technology => {
            for (const root of technology.children) {
                root.children = root.children.map(control => this.controls.get(control.id) || control);
                const priority: VisualStatus[] = ['Error', 'Failed', 'Blocked', 'Running', 'Pending', 'Warning', 'Skipped', 'Succeeded', 'Not applicable'];
                root.status = priority.find(status => root.children.some(control => control.status === status));
                if (root.status && ['Blocked', 'Warning', 'Skipped', 'Not applicable'].includes(root.status)) {
                    root.reason = root.children.find(control => control.status === root.status)?.reason;
                }
            }
            const incomplete = technology.children.some(root => root.children.some(control => ['Skipped', 'Blocked', 'Error', 'Warning'].includes(control.status || '')));
            if (incomplete && !technology.status) { technology.status = 'Warning'; technology.reason = { code: 'coverage_incomplete', message: 'Pipeline partiellement couverte.' }; }
            return technology;
        });
    }
}

export class SessionController {
    target?: string;
    preparation?: Preparation;
    approved = false;
    sourceValid = false;
    busy = false;
    abort?: AbortController;
    audit?: AuditState;
    constructor(readonly source: string) {}
    select(target: string): void {
        if (this.busy) { throw new Error('Une session est deja active.'); }
        this.target = target; this.approved = true; this.preparation = undefined; this.audit = undefined; this.sourceValid = false;
    }
    canRun(trusted: boolean): boolean { return trusted && this.approved && this.sourceValid && !!this.target && !!this.preparation?.report.discovery.scan_complete && !this.busy; }
    begin(trusted: boolean): AuditState {
        if (!this.canRun(trusted)) { throw new Error('Target, preparation valide, source et autorisation requises avant l audit.'); }
        this.busy = true; this.abort = new AbortController();
        this.audit = new AuditState(randomUUID().replace(/-/g, ''), this.target!);
        return this.audit;
    }
    cancel(): void { this.abort?.abort(); }
    end(): void { this.busy = false; this.abort = undefined; }
}

export function isInstalledExtensionSource(source: string): boolean {
    return fsSync.existsSync(path.join(source, '.config', 'control-catalog.json'))
        && !fsSync.existsSync(path.join(source, 'core', 'go.mod'))
        && !fsSync.existsSync(path.join(source, '.git'));
}

export function runsDirectory(source: string): string {
    if (process.env.COMPLIANCE_SESSIONS_DIR) { return process.env.COMPLIANCE_SESSIONS_DIR; }
    if (isInstalledExtensionSource(source)) {
        return path.join(os.homedir(), '.compliance', 'sessions', 'runs');
    }
    return path.join(source, '.tools', 'state', 'runs');
}

export async function stateRoot(source: string): Promise<string> {
    const directory = runsDirectory(source);
    const base = isInstalledExtensionSource(source) ? os.homedir() : source;
    const relative = path.relative(base, directory);
    let current = base;
    for (const segment of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, segment);
        try {
            const entry = await fs.lstat(current);
            if (entry.isSymbolicLink() || !entry.isDirectory()) { throw new Error('Le dossier d etat ne doit pas etre un lien ou un fichier.'); }
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { throw error; }
            await fs.mkdir(current);
        }
    }
    return directory;
}

/** POSIX execute bit and macOS quarantine removal, without blocking the extension host. */
async function prepareComplianceBinary(binaryPath: string): Promise<void> {
    if (process.platform !== 'win32') {
        await fs.chmod(binaryPath, 0o755);
    }
    if (process.platform === 'darwin') {
        // Attribute absent, or xattr unavailable: Gatekeeper is reported at spawn time.
        await new Promise<void>(resolve => execFile('xattr', ['-d', 'com.apple.quarantine', binaryPath], () => resolve()));
    }
}

function describeDaemonLaunchFailure(error?: Error, exit?: { code: number | null; signal: NodeJS.Signals | null }): Error {
    const errno = (error as NodeJS.ErrnoException | undefined)?.code;
    if (errno === 'EACCES' || errno === 'EPERM') {
        return new Error('Binaire compliance non exécutable (EACCES). Le mode 0755 n\'a pas pu être appliqué.');
    }
    if (exit?.signal === 'SIGKILL' || exit?.code === 137) {
        return new Error('Le binaire compliance a été tué (SIGKILL, signal 9). Sur macOS, Gatekeeper peut bloquer un exécutable non notarié même après le retrait de la quarantaine.');
    }
    if (error) {
        return new Error(`Démarrage du démon impossible : ${error.message}`);
    }
    if (exit) {
        return new Error(`Le démon s'est arrêté immédiatement (code ${exit.code ?? 'aucun'}, signal ${exit.signal ?? 'aucun'}).`);
    }
    return new Error('Délai dépassé lors du démarrage du démon local Compliance.');
}

export async function validateTarget(source: string, target: string): Promise<string> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await fs.realpath(target);
    if (!(await fs.stat(canonicalTarget)).isDirectory()) { throw new Error('La Target doit etre un dossier local.'); }
    if (containsPath(canonicalSource, canonicalTarget) || containsPath(canonicalTarget, canonicalSource)) {
        throw new Error('Choisir une Target externe, distincte de la Pipeline source et de ses dossiers parents.');
    }
    return canonicalTarget;
}

export async function prepare(source: string, target: string, client?: DaemonClient, signal?: AbortSignal, sessionDirectory?: string, log: Logger = silentLogger): Promise<Preparation> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await validateTarget(canonicalSource, target);
    const id = randomUUID();
    const directory = sessionDirectory || path.join(await stateRoot(canonicalSource), id);
    if (!sessionDirectory) { await fs.mkdir(directory); }
    const reportPath = path.join(directory, 'plan.json');
    if (!sessionDirectory) {
        await fs.writeFile(path.join(directory, 'session.json'), JSON.stringify({ id, source: canonicalSource, target: canonicalTarget, created_at: new Date().toISOString(), mode: 'PlanOnly' }, null, 2), 'utf8');
    }

    const daemon = client || new DaemonClient();
    try {
        const daemonStarted = Date.now();
        await daemon.ensureDaemon(canonicalSource);
        log.debug('démon disponible', { ms: Date.now() - daemonStarted });
        await daemon.approveWorkspace(canonicalTarget);
        const planStarted = Date.now();
        const plan = parsePreparation(JSON.stringify(await daemon.getPlan(canonicalTarget, {}, signal)), canonicalTarget, true);
        const body = JSON.stringify(plan);
        log.info('plan reçu', { ms: Date.now() - planStarted, bytes: Buffer.byteLength(body), controls: plan.execution_plan.controls.length });
        const writeStarted = Date.now();
        await fs.writeFile(reportPath, body, 'utf8');
        log.debug('plan.json écrit', { ms: Date.now() - writeStarted, file: reportPath });
        return { report: plan, directory, target: canonicalTarget };
    } catch (daemonErr) {
        const message = errorMessage(daemonErr);
        log.error('préparation en échec', { error: message, directory });
        await fs.appendFile(path.join(directory, 'preparation.log'), `\n${new Date().toISOString()} ${message}\n`, 'utf8')
            .catch(error => log.warn('preparation.log non écrit', { error: errorMessage(error) }));
        throw new Error(`Preparation impossible : ${message}. Journal : ${path.join(directory, 'preparation.log')}`);
    }
}

export async function validateSource(source: string, client?: DaemonClient): Promise<void> {
    const catalogPath = path.join(source, '.config/control-catalog.json');
    try {
        await fs.access(catalogPath);
    } catch {
        throw new Error('Catalogue de contrôles absent de la Pipeline source.');
    }
    const daemon = client || new DaemonClient();
    const health = await daemon.ensureDaemon(source);
    if (!health || health.status !== 'ok') {
        throw new Error('Démon compliance inaccessible ou non sain.');
    }
}

export async function sessionArtifact(directory: string, artifact: string): Promise<string> {
    const candidate = path.resolve(directory, artifact);
    const real = await fs.realpath(candidate);
    if (!containsPath(directory, real)) { throw new Error('Artefact de session redirige hors dossier.'); }
    return real;
}

async function atomicJson(file: string, value: unknown): Promise<void> {
    const temporary = `${file}.node.tmp`;
    await fs.writeFile(temporary, JSON.stringify(value, null, 2), 'utf8');
    await fs.rename(temporary, file);
}

function sessionHeadline(state: AuditState, cancelled: boolean): string {
    if (cancelled) { return 'annulée'; }
    if (state.status === 'Failed') { return 'terminée — Échec'; }
    if (state.status === 'Succeeded') { return 'terminée — Réussi'; }
    if (state.reason?.code === 'not_evaluated') { return `terminée — Non évalué${state.reason.message ? ` — ${state.reason.message}` : ''}`; }
    if (state.status === 'Warning') { return `terminée — Partiel${state.reason?.message ? ` — ${state.reason.message}` : ''}`; }
    return `terminée — ${state.status}`;
}

async function stream(
    source: string,
    target: string,
    state: AuditState,
    directory: string,
    permissions: Permissions,
    _hash: string,
    redaction: string | undefined,
    changed: () => void,
    signal: AbortSignal,
    daemon: DaemonClient,
    log: Logger
): Promise<void> {
    await daemon.ensureDaemon(source);
    await daemon.approveWorkspace(target);

    const redactionPatterns = redaction ? [redaction] : [];
    const run = await daemon.createRun(target, {
        runId: state.runId,
        outputDir: directory,
        planOnly: false,
        allowNetwork: permissions.network,
        allowCodeExecution: permissions.code_execution,
        redactionPatterns: redactionPatterns
    });

    const runLog = log.child({ runId: run.run_id });
    runLog.info('session lancée', { target, network: permissions.network, code_execution: permissions.code_execution, directory });
    const cancelHandler = () => {
        runLog.info('annulation demandée au démon');
        void daemon.cancelRun(run.run_id).catch(error => runLog.warn('annulation non transmise', { error: errorMessage(error) }));
    };
    signal.addEventListener('abort', cancelHandler, { once: true });

    try {
        const executed: string[] = [];
        const absent: string[] = [];
        const unavailable: string[] = [];
        await daemon.streamEvents(run.run_id, (ev) => {
            try {
                state.receive(ev);
                if (ev && typeof ev === 'object') {
                    const event = ev as { type?: string; control_id?: string; data?: Record<string, unknown> | null };
                    const data = event.data || {};
                    const result = data.result as { status?: string; duration_ms?: number; exit_code?: number | null } | undefined;
                    const reason = data.reason as { code?: string; message?: string } | undefined;
                    const id = event.control_id ?? '';
                    const controlLog = runLog.child({ controlId: id });
                    if (event.type === 'control_invocation') {
                        controlLog.debug(formatInvocation(data as InvocationRecord));
                    } else if (event.type === 'control_started') {
                        controlLog.info('exécution en cours');
                    } else if (event.type === 'control_completed') {
                        const code = reason?.code || '';
                        const technology = id.split('/')[0] || '';
                        const fields = { ms: result?.duration_ms, exit: result?.exit_code, output: data.output_path };
                        if (result?.status === 'success' || result?.status === 'fail' || result?.status === 'error') { executed.push(technology); }
                        if (result?.status === 'success') { controlLog.info('exécuté OK', fields); }
                        else if (result?.status === 'fail') { controlLog.info('exécuté KO', { ...fields, reason: reason?.message }); }
                        else if (result?.status === 'error') { controlLog.error('erreur', { ...fields, reason: reason?.message }); }
                        else if (code === 'technology_absent') { absent.push(technology); }
                        else if (countsAsUnavailable(code)) { unavailable.push(`${id} — ${reason?.message || 'indisponible'}`); }
                        else { controlLog.debug('non exécuté', { reason: code, message: reason?.message }); }
                    } else if (event.type === 'session_completed' || event.type === 'session_cancelled') {
                        const technologies = technologiesAbsentFromRun(executed, absent);
                        if (technologies.length) { runLog.info(`ignorés (technologie absente) : ${technologies.join(', ')}`); }
                        for (const line of groupUnavailableLines(unavailable)) { runLog.warn(`indisponible : ${line}`); }
                        runLog.info(`session ${sessionHeadline(state, event.type === 'session_cancelled')}`);
                    } else if (event.type === 'session_failed') {
                        runLog.error('session en échec côté démon', { error: data.error });
                    }
                }
                changed();
            } catch (error) {
                const message = errorMessage(error);
                if (message.includes('Controle du plan') || message.includes('Inventaire de technologies') || message.includes('plan v1')) { throw error; }
                runLog.warn('événement de session ignoré', { error: message });
            }
        }, signal);
    } finally {
        signal.removeEventListener('abort', cancelHandler);
    }

    try {
        const finalReport = await daemon.getReport(run.run_id);
        await fs.writeFile(path.join(directory, 'compliance-report.json'), JSON.stringify(finalReport, null, 2), 'utf8');
        if (!state.reportPath) {
            state.reportPath = path.join(directory, 'compliance-report.json');
        }
    } catch (error) {
        runLog.debug('rapport final non récupéré (session annulée ou en échec)', { error: errorMessage(error) });
    }
}

export async function audit(
    source: string,
    state: AuditState,
    ask: AskPermissions,
    changed: () => void,
    signal: AbortSignal,
    redaction?: string,
    client?: DaemonClient,
    log: Logger = silentLogger
): Promise<string> {
    const daemon = client || new DaemonClient();
    const target = await validateTarget(source, state.target);
    const directory = path.join(await stateRoot(source), state.runId);
    await fs.mkdir(directory);
    await fs.mkdir(path.join(directory, 'logs'));
    const metadata = {
        schema_version: 1,
        run_id: state.runId,
        target,
        pipeline_source: source,
        started_at: new Date().toISOString(),
        ended_at: null as string | null,
        state: 'preparing',
        permissions: { network: false, code_execution: false },
        catalog_sha256: '',
        report_path: path.join(directory, 'compliance-report.json')
    };
    await atomicJson(path.join(directory, 'session.json'), metadata);
    await fs.writeFile(path.join(directory, 'heartbeat'), '', 'utf8');
    const heartbeat = setInterval(() => { void fs.writeFile(path.join(directory, 'heartbeat'), '', 'utf8').catch(() => undefined); }, 1000);
    try {
        await validateSource(source, daemon);
        const fresh = await prepare(source, target, daemon, signal, directory, log);
        if (!fresh.report.discovery.scan_complete) { throw new Error('Discovery incomplete ; audit interdit.'); }
        const permissions = await ask(fresh);
        if (signal.aborted) {
            state.status = 'Skipped';
            state.reason = { code: 'session_interrupted', message: 'Session annulee avant execution.' };
            state.terminal = true;
            metadata.state = 'cancelled';
            return directory;
        }
        metadata.permissions = permissions;
        metadata.catalog_sha256 = fresh.report.metadata.catalog_sha256 || '';
        await atomicJson(path.join(directory, 'session.json'), metadata);
        await stream(source, target, state, directory, permissions, metadata.catalog_sha256, redaction, changed, signal, daemon, log);
        if (!state.reportPath) {
            const candidate = path.join(directory, 'compliance-report.json');
            try {
                await fs.access(candidate);
                state.reportPath = candidate;
            } catch {
                // Fichier absent
            }
        }
        if (state.reportPath) {
            const reportPath = await sessionArtifact(directory, state.reportPath);
            const report = JSON.parse(await fs.readFile(reportPath, 'utf8'));
            state.verifyReport(report);
            parsePreparation(JSON.stringify({ ...report, execution_status: 'planned', verdict: null, execution_results: [] }), target, true);
            if (!state.snapshot || JSON.stringify(report.execution_plan) !== JSON.stringify(state.snapshot.execution_plan)) {
                throw new Error('Rapport et snapshot divergent.');
            }
        } else if (state.status !== 'Error') {
            throw new Error('Rapport de session absent.');
        }
        return directory;
    } catch (error) {
        state.fail(error instanceof Error ? error.message : String(error));
        metadata.state = 'incomplete';
        throw error;
    } finally {
        clearInterval(heartbeat);
        if (!state.terminal) { state.fail('Session sans evenement terminal.'); metadata.state = 'incomplete'; }
        if (state.status === 'Skipped') { metadata.state = 'cancelled'; }
        else if (state.status === 'Error') { metadata.state = 'incomplete'; }
        else if (metadata.state === 'preparing') { metadata.state = 'completed'; }
        metadata.ended_at = new Date().toISOString();
        metadata.report_path = path.join(directory, 'compliance-report.json');
        await atomicJson(path.join(directory, 'session.json'), metadata);
        changed();
    }
}

// ---------------------------------------------------------------------------
// 3. Lecture, normalisation et validation de rapports (historiques et vivants)
// ---------------------------------------------------------------------------

/** Reports are not size-capped: a full audit of a large tree stays openable. Session metadata keeps its own limit. */
export const maximumReportBytes = Number.POSITIVE_INFINITY;
export type Fields = Record<string, unknown>;
export function fields(value: unknown): value is Fields { return value !== null && typeof value === 'object' && !Array.isArray(value); }
export function text(value: unknown): string { return value === null || value === undefined ? 'Non renseigne' : typeof value === 'string' ? value : JSON.stringify(value); }

export interface ReportControl {
    id: string; name: string; technology: string; root: string; status: VisualStatus; reason?: Reason;
    plan?: Fields; result?: Fields; findings: Fields[];
}

export interface LoadedReport {
    file: string; sha256: string; report: Fields; controls: ReportControl[]; historical: boolean;
    session?: Fields; directory?: string; target: string; runId: string;
}

export interface ReportReference { runId: string; target: string; source: string }
export type ReportMessage = { schema_version: 1; action: 'ready' | 'pick' | 'raw' | 'folder' | 'provision' } | { schema_version: 1; action: 'output' | 'files'; controlId: string } | { schema_version: 1; action: 'rows'; controlId: string; file: string } | { schema_version: 1; action: 'finding'; index: number };

export function reportMessage(value: unknown): ReportMessage {
    if (!fields(value) || value.schema_version !== 1 || typeof value.action !== 'string') { throw new Error('Message Webview invalide.'); }
    const keys = Object.keys(value).sort().join(',');
    if (['ready', 'pick', 'raw', 'folder', 'provision'].includes(value.action) && keys === 'action,schema_version') { return value as ReportMessage; }
    if ((value.action === 'output' || value.action === 'files') && keys === 'action,controlId,schema_version' && typeof value.controlId === 'string' && value.controlId.length > 0 && value.controlId.length <= 4096) { return value as ReportMessage; }
    if (value.action === 'rows' && keys === 'action,controlId,file,schema_version' && typeof value.controlId === 'string' && value.controlId.length > 0 && value.controlId.length <= 4096 && typeof value.file === 'string' && value.file.length > 0 && value.file.length <= 4096 && !value.file.includes('\0')) { return value as ReportMessage; }
    if (value.action === 'finding' && keys === 'action,index,schema_version' && Number.isSafeInteger(value.index) && Number(value.index) >= 0) { return value as ReportMessage; }
    throw new Error('Action ou arguments Webview non autorises.');
}

export async function noLinks(file: string): Promise<void> {
    let current = path.resolve(file);
    while (true) {
        const stat = await fs.lstat(current);
        if (stat.isSymbolicLink()) { throw new Error('Lien symbolique ou reanalyse refuse pour le lecteur.'); }
        const parent = path.dirname(current);
        if (parent === current) { return; }
        current = parent;
    }
}

export async function readStable(file: string, limit = maximumReportBytes): Promise<Buffer> {
    await noLinks(file);
    const handle = await fs.open(file, 'r');
    try {
        const before = await handle.stat();
        if (!before.isFile() || before.size === 0) { throw new Error('Fichier absent ou vide.'); }
        if (Number.isFinite(limit) && before.size > limit) { throw new Error('Fichier absent, vide ou trop volumineux.'); }
        const buffer = Buffer.alloc(before.size);
        let offset = 0;
        while (offset < buffer.length) {
            const read = await handle.read(buffer, offset, buffer.length - offset, offset);
            if (!read.bytesRead) { throw new Error('Fichier tronque pendant sa lecture.'); }
            offset += read.bytesRead;
        }
        const after = await handle.stat();
        const current = await fs.lstat(file);
        if (current.isSymbolicLink() || [after, current].some(stat => stat.size !== before.size || stat.mtimeMs !== before.mtimeMs || stat.ctimeMs !== before.ctimeMs || stat.ino !== before.ino)) {
            throw new Error('Fichier modifie pendant sa lecture ; actualiser le rapport.');
        }
        return buffer;
    } finally { await handle.close(); }
}

function json(bytes: Buffer): unknown { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/^\uFEFF/, '')); }
function objects(value: unknown, label: string): Fields[] {
    if (!Array.isArray(value) || !value.every(fields)) { throw new Error(`${label} doit etre un tableau d objets.`); }
    return value;
}

export function displayReport(value: unknown, presentations: unknown): { report: Fields; controls: ReportControl[] } {
    if (!fields(value) || value.schema_version !== 1 || !fields(value.metadata) || typeof value.metadata.run_id !== 'string' || !value.metadata.run_id ||
        typeof value.repository !== 'string' || !value.repository || !fields(value.execution_plan) || !fields(value.summary) || !fields(value.coverage) ||
        !fields(value.discovery) || !['PASS', 'FAIL', null].includes(value.verdict as string | null) ||
        !['planned', 'completed', 'blocked', 'error'].includes(String(value.execution_status))) { throw new Error('Rapport v1 invalide ou version non prise en charge.'); }
    const results = objects(value.execution_results, 'Resultats');
    const plan = objects(value.execution_plan.controls, 'Controles');
    const findings = objects(value.findings, 'Findings');
    objects(value.diagnostics, 'Diagnostics');
    if (!Array.isArray(value.limitations) || !Array.isArray(value.verdict_reasons) || plan.length > 5000 || results.length > 5001) { throw new Error('Rapport incomplet ou nombre de controles excessif.'); }
    const states = objects(presentations, 'Statuts backend');
    const byId = new Map<string, Fields>();
    const visual = new Map<string, Fields>();
    for (const result of results) {
        if (typeof result.control_id !== 'string' || byId.has(result.control_id) ||
            !['success', 'fail', 'error', 'skipped'].includes(String(result.status)) || typeof result.duration_ms !== 'number' || !Number.isFinite(result.duration_ms) || result.duration_ms < 0 ||
            typeof result.stdout !== 'string' || typeof result.stderr !== 'string' || !Array.isArray(result.diagnostics)) { throw new Error('Resultat invalide ou duplique.'); }
        byId.set(result.control_id, result);
    }
    for (const state of states) {
        if (typeof state.control_id !== 'string' || visual.has(state.control_id) ||
            !['Pending', 'Running', 'Succeeded', 'Failed', 'Error', 'Warning', 'Skipped', 'Blocked', 'Not applicable'].includes(String(state.status))) { throw new Error('Statut backend invalide.'); }
        if (['Warning', 'Skipped', 'Blocked', 'Not applicable'].includes(String(state.status)) &&
            (!fields(state.reason) || typeof state.reason.code !== 'string' || !state.reason.code || typeof state.reason.message !== 'string' || !state.reason.message)) { throw new Error('Motif structure absent.'); }
        visual.set(state.control_id, state);
    }
    const findingsByControl = new Map<string, Fields[]>();
    for (const finding of findings) {
        const id = typeof finding.control_id === 'string' ? finding.control_id : '';
        const bucket = findingsByControl.get(id);
        if (bucket) { bucket.push(finding); }
        else if (id) { findingsByControl.set(id, [finding]); }
    }
    const ids = new Set<string>();
    const planIds = new Set(plan.map(control => typeof control.id === 'string' ? control.id : String(control.control_id)));
    const controls = [...plan, ...results.filter(result => !planIds.has(String(result.control_id)))].map(control => {
        const id = typeof control.id === 'string' ? control.id : String(control.control_id);
        if (id === 'undefined' || !id || ids.has(id) || typeof control.technology !== 'string' || typeof control.root !== 'string') { throw new Error('Identite ou racine de controle invalide.'); }
        ids.add(id);
        const result = byId.get(id);
        const state = visual.get(id);
        if (!state || (!result && value.execution_status === 'completed' && value.discovery && (value.discovery as Fields).scan_complete !== false)) { throw new Error('Resultat ou presentation backend absent du rapport final.'); }
        return { id, name: text(control.name || id), technology: control.technology, root: control.root, status: state.status as VisualStatus,
            reason: fields(state.reason) ? state.reason as unknown as Reason : undefined, plan: planIds.has(id) ? control : undefined, result,
            findings: findingsByControl.get(id) || [] };
    });
    if (visual.size !== controls.length) { throw new Error('Presentations backend hors plan.'); }
    return { report: value, controls };
}

export async function readSession(source: string, reference: ReportReference): Promise<{ directory: string; session: Fields }> {
    if (!/^[a-f0-9]{32}$/.test(reference.runId) || path.relative(source, reference.source) !== '') { throw new Error('Reference de session invalide ou d une autre Pipeline source.'); }
    const directory = path.join(runsDirectory(source), reference.runId);
    const session = json(await readStable(path.join(directory, 'session.json'), 1024 * 1024));
    if (!fields(session) || session.schema_version !== 1 || session.run_id !== reference.runId || typeof session.target !== 'string' || !isSameDirectory(session.target, reference.target) ||
        typeof session.pipeline_source !== 'string' || !isSameDirectory(session.pipeline_source, source) ||
        !['completed', 'cancelled', 'failed', 'incomplete'].includes(String(session.state)) ||
        typeof session.report_path !== 'string' || !isSameDirectory(session.report_path, path.join(directory, 'compliance-report.json')) ||
        typeof session.started_at !== 'string' || !Number.isFinite(Date.parse(session.started_at)) ||
        !fields(session.permissions) || typeof session.permissions.network !== 'boolean' || typeof session.permissions.code_execution !== 'boolean') { throw new Error('Session non finalisee ou incoherente ; consulter ses journaux.'); }
    return { directory, session };
}

async function sessionNearReport(file: string): Promise<{ directory: string; session: Fields } | undefined> {
    const resolved = path.resolve(file);
    if (path.basename(resolved) !== 'compliance-report.json') { return undefined; }
    const directory = path.dirname(resolved);
    try {
        const session = json(await readStable(path.join(directory, 'session.json'), 1024 * 1024));
        if (!fields(session) || session.schema_version !== 1) { return undefined; }
        return { directory, session };
    } catch {
        return undefined;
    }
}

/** Validation only needs plan, results and discovery. Findings and captured stdout stay on disk. */
export function validationPayload(report: Fields): Fields {
    const results = Array.isArray(report.execution_results)
        ? report.execution_results.map(item => {
            if (!fields(item)) { return item; }
            const copy: Fields = { ...item };
            delete copy.stdout;
            delete copy.stderr;
            return copy;
        })
        : report.execution_results;
    return { ...report, findings: [], execution_results: results };
}

export async function loadReport(source: string, file: string, reference?: ReportReference, historical = !reference, client?: DaemonClient): Promise<LoadedReport> {
    const associated = reference ? await readSession(source, reference) : await sessionNearReport(file);
    if (associated && path.relative(path.join(associated.directory, 'compliance-report.json'), path.resolve(file)) !== '') { throw new Error('Rapport hors session attendue.'); }
    const before = await fs.lstat(file);
    const bytes = await readStable(file);
    const raw = json(bytes);
    if (!fields(raw) || raw.schema_version !== 1) { throw new Error('Rapport v1 invalide ou version inconnue.'); }
    const digest = createHash('sha256').update(bytes).digest('hex');
    const daemon = client || new DaemonClient();
    await daemon.ensureDaemon(source);
    const envelope = await daemon.validateReport(validationPayload(raw), digest);
    if (!fields(envelope) || envelope.schema_version !== 1 || envelope.report_sha256 !== digest) { throw new Error('Validation non rattachee aux octets du rapport.'); }
    const displayed = displayReport(raw, envelope.presentations);
    if (typeof envelope.total_duration_ms === 'number' && Number.isFinite(envelope.total_duration_ms) && envelope.total_duration_ms >= 0) {
        const metrics = fields(displayed.report.metrics) ? displayed.report.metrics : {};
        if (typeof metrics.total_duration_ms !== 'number') {
            metrics.total_duration_ms = envelope.total_duration_ms;
            displayed.report.metrics = metrics;
        }
    }
    if (reference && ((displayed.report.metadata as Fields).run_id !== reference.runId || !isSameDirectory(String(displayed.report.repository), reference.target))) { throw new Error('Identite run_id ou Target incoherente avec la session.'); }
    if (associated && fields(associated.session.permissions)) {
        const metadata = displayed.report.metadata as Fields;
        if (metadata.network_authorized !== associated.session.permissions.network || metadata.code_execution_authorized !== associated.session.permissions.code_execution) { throw new Error('Permissions du rapport incoherentes avec la session.'); }
    }
    if (associated && ['cancelled', 'incomplete'].includes(String(associated.session.state)) &&
        (displayed.report.verdict === 'PASS' || (displayed.report.coverage as Fields).complete === true)) { throw new Error('Rapport interrompu presente comme un PASS complet.'); }
    const after = await fs.lstat(file);
    if (after.isSymbolicLink() || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ino !== before.ino) { throw new Error('Rapport modifie pendant sa validation ; actualiser.'); }
    const directory = associated?.directory || (path.basename(path.resolve(file)) === 'compliance-report.json' ? path.dirname(path.resolve(file)) : undefined);
    return { ...displayed, file: path.resolve(file), sha256: digest, historical, session: associated?.session, directory,
        target: String(displayed.report.repository), runId: String((displayed.report.metadata as Fields).run_id) };
}

export function technologiesAbsentFromRun(executed: string[], absent: string[]): string[] {
    const ran = new Set(executed.filter(Boolean));
    return [...new Set(absent.filter(Boolean))].filter(name => !ran.has(name));
}

export function controlRelativeFile(root: string, file: string): string {
    let cleaned = file.replace(/\\/g, '/').trim();
    if (!/^[A-Za-z]:/.test(cleaned)) { cleaned = cleaned.replace(/^\/+/, ''); }
    const rootClean = root.replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/^\/+/, '');
    if (!rootClean || rootClean === '.' || cleaned.toLowerCase() === rootClean.toLowerCase() || cleaned.toLowerCase().startsWith(`${rootClean.toLowerCase()}/`)) {
        return cleaned;
    }
    return `${rootClean}/${cleaned}`;
}

export interface FindingLocation { file: string; line?: number; column?: number }
export function findingLocation(finding: Fields): FindingLocation | undefined {
    const diagnostic = Array.isArray(finding.diagnostics) ? finding.diagnostics.find(item => fields(item) && typeof item.file === 'string') : undefined;
    const record = typeof finding.file === 'string' ? finding : fields(diagnostic) ? diagnostic : undefined;
    if (!record || typeof record.file !== 'string' || !record.file || record.file.includes('\0') || /^(?:[a-z][a-z0-9+.-]*:)/i.test(record.file.replace(/^[A-Za-z]:[\\/]/, ''))) { return undefined; }
    return { file: record.file, line: Number.isInteger(record.line) && Number(record.line) > 0 ? Number(record.line) : undefined,
        column: Number.isInteger(record.column) && Number(record.column) > 0 ? Number(record.column) : undefined };
}

export async function targetFile(target: string, file: string): Promise<string> {
    if (!path.isAbsolute(target) || file.includes('\0') || /^(?:[a-z][a-z0-9+.-]*:)/i.test(file.replace(/^[A-Za-z]:[\\/]/, ''))) { throw new Error('Chemin local invalide.'); }
    const candidate = path.resolve(target, file);
    await noLinks(candidate);
    if (!containsPath(target, candidate) || !(await fs.stat(candidate)).isFile()) { throw new Error('Localisation hors Target ou non fichier.'); }
    return candidate;
}
