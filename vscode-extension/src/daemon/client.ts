// Local daemon: binary staging, start and shutdown, HTTP and SSE client, child-process journals.
import * as http from 'node:http';
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFile, spawn, ChildProcess } from 'node:child_process';
import { PreparationReport } from '../model';
import { daemonBinaryDirectory, isOurDaemonImage } from '../daemonLifecycle.js';
import { engineVersionMismatch, expectedEngineVersion } from '../engineVersion.js';
import { DaemonLogEntry, errorMessage, Logger, silentLogger } from '../logger';
import { SseEvent, SseParser } from '../sse';
export { engineVersionMismatch, expectedEngineVersion, setExpectedEngineVersion } from '../engineVersion.js';

export let daemonLog: Logger = silentLogger;
/** Routes daemon lifecycle and child-process traces to the extension channel. */
export function setDaemonLogger(logger: Logger): void {
    daemonLog = logger;
}

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
            if (fsSync.statSync(file).size > 5 * 1024 * 1024) {
                fsSync.renameSync(file, `${file}.1`);
            }
        } catch {
            /* absent, or still open by a previous daemon on Windows: keep appending */
        }
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
        } finally {
            await handle.close();
        }
    } catch {
        return '';
    }
}

interface DaemonConnection {
    port: number;
    token: string;
    health: DaemonHealth;
}
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
        try {
            process.kill(pid, 0);
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ESRCH') {
                return true;
            }
            if ((error as NodeJS.ErrnoException).code === 'EPERM') {
                /* alive, other user */
            }
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
            const state = JSON.parse(data) as DaemonState;
            const token = (await fs.readFile(state.token_path, 'utf8')).trim();
            this.port = state.port;
            this.token = token;

            const health = await this.getHealth();
            if (health && health.status === 'ok') {
                if (!engineVersionMismatch(health.version, expectedEngineVersion())) {
                    daemonLog.debug('démon existant réutilisé', { pid: health.pid, port: state.port, version: health.version });
                    return { port: this.port, token: this.token, health };
                }
                daemonLog.warn("démon d'une autre version : remplacement", { running: health.version, expected: expectedEngineVersion(), pid: health.pid });
                await this.shutdown();
                // The old daemon holds the lock until it is really gone: spawning earlier made the new one exit at once.
                if (!(await waitForExit(health.pid, 5000))) {
                    daemonLog.warn('ancien démon encore présent après 5 s', { pid: health.pid });
                }
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
            if (consoleFd !== undefined) {
                try {
                    fsSync.closeSync(consoleFd);
                } catch {
                    /* already closed */
                }
            }
        }
        this.daemonProcess.once('error', error => {
            spawnError = error;
        });
        this.daemonProcess.once('exit', (code, signal) => {
            if (code === exitAlreadyRunning) {
                otherInstance = true;
                return;
            }
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
                daemonLog.info("démarrage du démon plus long que prévu (analyse antivirus d'un premier lancement ?)", { journal: journals.journal });
            }
            await new Promise(r => setTimeout(r, 200));
            try {
                const data = await fs.readFile(stateFile, 'utf8');
                const state = JSON.parse(data) as DaemonState;
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
        const platformExe =
            process.platform === 'win32'
                ? process.arch === 'arm64'
                    ? 'compliance-windows-arm64.exe'
                    : 'compliance-windows-amd64.exe'
                : process.platform === 'darwin'
                  ? process.arch === 'arm64'
                      ? 'compliance-darwin-arm64'
                      : 'compliance-darwin-amd64'
                  : process.arch === 'arm64'
                    ? 'compliance-linux-arm64'
                    : 'compliance-linux-amd64';

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
        if (!sourceBin) {
            throw new Error('Binaire "compliance" introuvable. Exécuter la compilation Go dans core/.');
        }
        return stageDaemonRuntime(sourceBin, platformRoot);
    }

    public async purgeSessions(platformRoot: string, root: string, keep: number, protect: string[], reserve = 0): Promise<string[]> {
        const staged = await this.stagedRuntime(platformRoot);
        const bounded = Math.min(1000, Math.max(1, keep || 5));
        const args = ['sessions', 'purge', '-root', root, '-keep', String(bounded), '-reserve', String(reserve)];
        for (const name of protect) {
            if (name) {
                args.push('-protect', name);
            }
        }
        daemonLog.command('purge des sessions', staged.binary, args, staged.cwd);
        const started = Date.now();
        const output = await new Promise<string>((resolve, reject) => {
            execFile(staged.binary, args, { cwd: staged.cwd, windowsHide: true }, (error, stdout, stderr) => {
                if (error) {
                    daemonLog.warn('purge des sessions en échec', {
                        exit: (error as NodeJS.ErrnoException & { code?: unknown }).code,
                        stderr: String(stderr).trim()
                    });
                    reject(new Error(String(stderr || error.message)));
                    return;
                }
                daemonLog.debug('purge des sessions terminée', { ms: Date.now() - started });
                resolve(String(stdout));
            });
        });
        return output
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean);
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
                        if (code === 0) {
                            resolve();
                        } else {
                            reject(new Error(stderr.trim() || `runtime sync a quitté avec le code ${code}`));
                        }
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
            await this.ensureDaemon(platformRoot)
                .then(() => this.invalidateTools())
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
        } catch {
            return undefined;
        }
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
    public async getPlan(
        targetPath: string,
        options: { allowNetwork?: boolean; allowCodeExecution?: boolean; includeApplyDestroy?: boolean } = {},
        signal?: AbortSignal
    ): Promise<PreparationReport> {
        return this.request<PreparationReport>(
            'POST',
            '/api/v1/plans',
            {
                target_path: targetPath,
                path: process.env.PATH || '',
                allow_network: options.allowNetwork ?? false,
                allow_code_execution: options.allowCodeExecution ?? false,
                include_apply_destroy: options.includeApplyDestroy ?? false
            },
            10 * 60 * 1000,
            signal
        );
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
        return this.openSse(
            `/api/v1/runs/${runId}/events`,
            event => {
                let parsed: Record<string, unknown>;
                try {
                    const value: unknown = JSON.parse(event.data);
                    if (!value || typeof value !== 'object' || Array.isArray(value)) {
                        throw new Error('objet attendu');
                    }
                    parsed = value as Record<string, unknown>;
                } catch (error) {
                    daemonLog.warn('événement SSE illisible ignoré', { event: event.event, id: event.id, error: errorMessage(error) });
                    return false;
                }
                if (event.event && !parsed.type) {
                    parsed.type = event.event;
                }
                if (event.id && !parsed.id) {
                    parsed.id = event.id;
                }
                onEvent(parsed);
                return parsed.type === 'session_completed' || parsed.type === 'session_cancelled' || parsed.type === 'session_failed';
            },
            signal,
            lastEventId,
            8000
        );
    }

    /** Live daemon journal from now on, until signal aborts. */
    public streamLogs(level: string, onEntry: (entry: DaemonLogEntry) => void, signal: AbortSignal): Promise<void> {
        return this.openSse(
            `/api/v1/logs/stream?level=${encodeURIComponent(level)}`,
            event => {
                if (event.event !== 'daemon_log') {
                    return false;
                }
                try {
                    onEntry(JSON.parse(event.data) as DaemonLogEntry);
                } catch {
                    /* malformed record */
                }
                return false;
            },
            signal,
            undefined,
            0
        );
    }

    /**
     * One SSE connection. handle returns true to close after a terminal event.
     * On abort, the connection stays open graceMs to receive the terminal event, then closes.
     */
    private openSse(
        urlPath: string,
        handle: (event: SseEvent) => boolean,
        signal: AbortSignal | undefined,
        lastEventId: string | undefined,
        graceMs: number
    ): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            let settled = false;
            let graceTimer: NodeJS.Timeout | undefined;
            const finish = (error?: unknown) => {
                if (settled) {
                    return;
                }
                settled = true;
                if (graceTimer) {
                    clearTimeout(graceTimer);
                }
                signal?.removeEventListener('abort', onAbort);
                req.destroy();
                if (error) {
                    reject(error instanceof Error ? error : new Error(errorMessage(error)));
                } else {
                    resolve();
                }
            };
            const onAbort = () => {
                if (graceMs <= 0) {
                    finish();
                    return;
                }
                graceTimer = setTimeout(() => finish(), graceMs);
            };
            const headers: Record<string, string> = {
                Host: `127.0.0.1:${this.port}`,
                Authorization: `Bearer ${this.token}`,
                Accept: 'text/event-stream'
            };
            if (lastEventId) {
                headers['Last-Event-ID'] = lastEventId;
            }

            const req = http.request({ hostname: '127.0.0.1', port: this.port, path: urlPath, method: 'GET', headers, agent: false }, res => {
                if (res.statusCode !== 200) {
                    res.resume();
                    finish(new Error(`Connexion SSE ${urlPath} rejetée avec statut ${res.statusCode}`));
                    return;
                }
                res.setEncoding('utf8');
                const parser = new SseParser();
                res.on('data', (chunk: string) => {
                    if (settled) {
                        return;
                    }
                    try {
                        for (const event of parser.feed(chunk)) {
                            if (handle(event)) {
                                finish();
                                return;
                            }
                        }
                    } catch (error) {
                        finish(error);
                    }
                });
                res.on('end', () => finish());
                res.on('error', error => finish(signal?.aborted ? undefined : error));
            });
            req.on('error', error => finish(signal?.aborted ? undefined : error));
            if (signal) {
                if (signal.aborted) {
                    onAbort();
                } else {
                    signal.addEventListener('abort', onAbort, { once: true });
                }
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
        return this.request(
            'POST',
            '/api/v1/reports/validate',
            {
                report: reportData,
                report_sha256: reportSha256
            },
            120000
        );
    }

    public async shutdown(): Promise<void> {
        await postShutdown(this.port, this.token);
        try {
            const state = JSON.parse(await fs.readFile(path.join(this.stateDir!, 'daemon.json'), 'utf8')) as DaemonState;
            await killDaemonPid(state.pid, true);
        } catch {
            /* état déjà retiré */
        }
        await killStagedDaemons();
    }

    /** A request without an answer after timeoutMs fails instead of freezing the extension. */
    private request<T>(method: string, path: string, body?: unknown, timeoutMs = 30000, signal?: AbortSignal): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            if (signal?.aborted) {
                reject(new Error(`Requête ${method} ${path} annulée.`));
                return;
            }
            const bodyData = body ? JSON.stringify(body) : undefined;
            const headers: Record<string, string> = {
                Host: `127.0.0.1:${this.port}`,
                Authorization: `Bearer ${this.token}`,
                Accept: 'application/json'
            };
            if (bodyData) {
                headers['Content-Type'] = 'application/json';
                headers['Content-Length'] = String(Buffer.byteLength(bodyData));
            }

            const req = http.request(
                {
                    hostname: '127.0.0.1',
                    port: this.port,
                    path: path,
                    method: method,
                    headers: headers,
                    agent: false
                },
                res => {
                    let responseBody = '';
                    res.setEncoding('utf8');
                    res.on('data', chunk => {
                        responseBody += chunk;
                    });
                    res.on('end', () => {
                        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                            try {
                                const parsed: unknown = responseBody ? JSON.parse(responseBody) : {};
                                resolve(parsed as T);
                            } catch {
                                resolve({} as T);
                            }
                        } else {
                            reject(new Error(`Requête ${method} ${path} échouée (code ${res.statusCode}): ${responseBody}`));
                        }
                    });
                }
            );

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

export interface SyncOptions {
    registryUrl?: string;
    registryToken?: string;
    log?: Logger;
    onTool?: (tool: string, index: number, total: number) => void;
}

/** Splits a child stream into lines across chunk boundaries (LF or CRLF). */
function relayLines(stream: NodeJS.ReadableStream | null | undefined, onLine: (line: string) => void): void {
    if (!stream) {
        return;
    }
    let pending = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
        pending += chunk;
        const lines = pending.split(/\r?\n/);
        pending = lines.pop() || '';
        for (const line of lines) {
            if (line.trim()) {
                onLine(line.trimEnd());
            }
        }
    });
    stream.on('end', () => {
        if (pending.trim()) {
            onLine(pending.trimEnd());
        }
    });
}

async function describeWithJournal(error: Error, journals: { journal: string; console: string }): Promise<Error> {
    const tail = await tailFile(journals.console, 15);
    daemonLog.error(error.message, { journal: journals.journal, console: journals.console });
    if (tail) {
        daemonLog.error(`dernières lignes de ${journals.console} :\n${tail}`);
    }
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
    } catch {
        /* pas de démon enregistré */
    }
    if (state) {
        await postShutdown(state.port, token);
    }
    if (state?.pid) {
        await killDaemonPid(state.pid, true);
    }
    await killStagedDaemons();
}

function postShutdown(port: number, token: string): Promise<void> {
    return new Promise(resolve => {
        if (!port || !token) {
            resolve();
            return;
        }
        const req = http.request(
            {
                hostname: '127.0.0.1',
                port,
                path: '/api/v1/shutdown',
                method: 'POST',
                timeout: 500,
                headers: { Host: `127.0.0.1:${port}`, Authorization: `Bearer ${token}` },
                agent: false
            },
            response => {
                response.resume();
                resolve();
            }
        );
        req.on('timeout', () => {
            req.destroy();
            resolve();
        });
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
    let current: boolean;
    try {
        const [from, to] = await Promise.all([fs.stat(source), fs.stat(dest)]);
        current = from.size === to.size && from.mtimeMs <= to.mtimeMs;
    } catch {
        current = false;
    }
    if (!current) {
        await fs.copyFile(source, dest);
    }
    await prepareComplianceBinary(dest);
    await copyConfig(configDirectory(platformRoot), path.join(dir, '.config'));
    return { binary: dest, platformRoot: dir, cwd };
}

function configDirectory(platformRoot: string): string | undefined {
    const candidates = [path.join(platformRoot, '.config'), path.join(__dirname, '..', '..', '.config'), path.join(__dirname, '..', '.config')];
    return candidates.find(candidate => fsSync.existsSync(path.join(candidate, 'control-catalog.json')));
}

async function copyConfig(source: string | undefined, destination: string): Promise<void> {
    if (!source) {
        return;
    }
    await fs.mkdir(destination, { recursive: true });
    for (const name of await fs.readdir(source)) {
        const from = path.join(source, name);
        const info = await fs.stat(from);
        if (!info.isFile()) {
            continue;
        }
        const to = path.join(destination, name);
        let same: boolean;
        try {
            const existing = await fs.stat(to);
            same = existing.size === info.size && existing.mtimeMs >= info.mtimeMs;
        } catch {
            same = false;
        }
        if (!same) {
            await fs.copyFile(from, to);
        }
    }
}

async function killDaemonPid(pid: number, force = false): Promise<void> {
    const image = await daemonImage(pid);
    if (image && !isOurDaemonImage(path.basename(image))) {
        return;
    }
    if (!image && !force) {
        return;
    }
    try {
        process.kill(pid);
    } catch {
        /* déjà arrêté */
    }
}

async function killStagedDaemons(): Promise<void> {
    const home = (process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance')).toLowerCase();
    for (const row of await listedComplianceProcesses()) {
        const image = row.image.toLowerCase();
        const ours = isOurDaemonImage(path.basename(row.image));
        const staged = image.includes(home) || (image.includes('.vscode') && image.includes('compliance-platform'));
        if (ours && staged) {
            try {
                process.kill(row.pid);
            } catch {
                /* déjà arrêté */
            }
        }
    }
}

async function listedComplianceProcesses(): Promise<Array<{ pid: number; image: string }>> {
    if (process.platform !== 'win32') {
        return [];
    }
    const text = await execText('powershell.exe', [
        '-NoProfile',
        '-Command',
        "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'compliance*.exe' } | ForEach-Object { $_.ProcessId.ToString() + '|' + $_.ExecutablePath }"
    ]);
    return text
        .split(/\r?\n/)
        .map(line => {
            const [pid, image] = line.split('|');
            return { pid: Number(pid), image: (image || '').trim() };
        })
        .filter(row => Number.isInteger(row.pid) && row.pid > 0 && row.image);
}

export async function daemonImage(pid: number): Promise<string> {
    if (process.platform === 'linux') {
        return fs.readlink(`/proc/${pid}/exe`).catch(() => '');
    }
    if (process.platform === 'darwin') {
        return execText('ps', ['-p', String(pid), '-o', 'comm=']);
    }
    return execText('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").ExecutablePath`]).then(
        text => text.trim()
    );
}

function execText(command: string, args: string[]): Promise<string> {
    return new Promise(resolve => {
        const child = spawn(command, args, { windowsHide: true });
        let out = '';
        child.stdout?.on('data', chunk => {
            out += String(chunk);
        });
        child.on('error', () => resolve(''));
        child.on('close', () => resolve(out));
    });
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

function describeDaemonLaunchFailure(error?: NodeJS.ErrnoException, exit?: { code: number | null; signal: NodeJS.Signals | null }): Error {
    const errno = error?.code;
    if (errno === 'EACCES' || errno === 'EPERM') {
        return new Error("Binaire compliance non exécutable (EACCES). Le mode 0755 n'a pas pu être appliqué.");
    }
    if (exit?.signal === 'SIGKILL' || exit?.code === 137) {
        return new Error(
            'Le binaire compliance a été tué (SIGKILL, signal 9). Sur macOS, Gatekeeper peut bloquer un exécutable non notarié même après le retrait de la quarantaine.'
        );
    }
    if (error) {
        return new Error(`Démarrage du démon impossible : ${error.message}`);
    }
    if (exit) {
        return new Error(`Le démon s'est arrêté immédiatement (code ${exit.code ?? 'aucun'}, signal ${exit.signal ?? 'aucun'}).`);
    }
    return new Error('Délai dépassé lors du démarrage du démon local Compliance.');
}
