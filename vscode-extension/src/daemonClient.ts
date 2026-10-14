import * as http from 'node:http';
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFile, execFileSync, spawn, ChildProcess } from 'node:child_process';
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
import { groupUnavailableLines } from './reportLayout';
import { engineVersionMismatch, expectedEngineVersion } from './engineVersion.js';

export { engineVersionMismatch, expectedEngineVersion, setExpectedEngineVersion } from './engineVersion.js';

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
}

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
                    return health;
                }
                await this.shutdown();
            }
        } catch {
            // Daemon not running or invalid state file
        }

        const staged = await this.stagedRuntime(platformRoot);

        const args = ['daemon', '-state-dir', this.stateDir!, '-platform-root', staged.platformRoot];
        let spawnError: Error | undefined;
        let earlyExit: { code: number | null; signal: NodeJS.Signals | null } | undefined;
        this.daemonProcess = spawn(staged.binary, args, {
            cwd: staged.cwd,
            detached: true,
            windowsHide: true,
            stdio: 'ignore'
        });
        this.daemonProcess.once('error', (error) => { spawnError = error; });
        this.daemonProcess.once('exit', (code, signal) => { earlyExit = { code, signal }; });
        this.daemonProcess.unref();

        const deadline = Date.now() + 15000;
        while (Date.now() < deadline) {
            if (spawnError || earlyExit) {
                throw describeDaemonLaunchFailure(spawnError, earlyExit);
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
                    return health;
                }
            } catch {
                // Continue polling
            }
        }

        throw describeDaemonLaunchFailure(spawnError, earlyExit);
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
                prepareComplianceBinary(binaryPath);
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
        const output = await new Promise<string>((resolve, reject) => {
            execFile(staged.binary, args, { cwd: staged.cwd, windowsHide: true }, (error, stdout, stderr) => {
                if (error) { reject(new Error(String(stderr || error.message))); return; }
                resolve(String(stdout));
            });
        });
        return output.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    }

    public async installNodeToolchain(platformRoot: string): Promise<void> {
        const staged = await this.stagedRuntime(platformRoot);
        await new Promise<void>((resolve, reject) => {
            const child = spawn(staged.binary, ['runtime', 'node'], { cwd: staged.cwd, windowsHide: true });
            let stderr = '';
            child.stderr?.on('data', chunk => { stderr += String(chunk); });
            child.on('error', reject);
            child.on('close', code => {
                if (code === 0) { resolve(); }
                else { reject(new Error(stderr.trim() || `runtime node a quitté avec le code ${code}`)); }
            });
        });
    }

    public async syncTools(platformRoot: string, tools: string[]): Promise<void> {
        const staged = await this.stagedRuntime(platformRoot);
        const manifest = path.join(staged.platformRoot, '.config', 'runtime-manifest.json');
        const signature = path.join(staged.platformRoot, '.config', 'runtime-manifest.json.sig');
        const installed: string[] = [];
        const failed: string[] = [];
        for (const tool of tools) {
            try {
                await new Promise<void>((resolve, reject) => {
                    const child = spawn(staged.binary, ['runtime', 'sync', '-manifest', manifest, '-sig', signature, '-tool', tool], { cwd: staged.cwd, windowsHide: true });
                    let stderr = '';
                    child.stderr?.on('data', chunk => { stderr += String(chunk); });
                    child.on('error', reject);
                    child.on('close', code => {
                        if (code === 0) { resolve(); }
                        else { reject(new Error(stderr.trim() || `runtime sync a quitté avec le code ${code}`)); }
                    });
                });
                installed.push(tool);
            } catch (error) {
                const detail = error instanceof Error ? error.message : String(error);
                failed.push(`${tool} (${detail})`);
            }
        }
        if (failed.length) {
            throw new Error(`${installed.length} outil(s) installé(s), ${failed.length} échec : ${failed.join(' ; ')}`);
        }
    }

    public async getHealth(): Promise<DaemonHealth> {
        return this.request<DaemonHealth>('GET', '/api/v1/health');
    }

    public async approveWorkspace(workspacePath: string): Promise<void> {
        await this.request('POST', '/api/v1/workspaces/approve', { workspace_path: workspacePath });
    }

    public async getPlan(targetPath: string, options: { allowNetwork?: boolean; allowCodeExecution?: boolean; includeApplyDestroy?: boolean } = {}): Promise<PreparationReport> {
        return this.request<PreparationReport>('POST', '/api/v1/plans', {
            target_path: targetPath,
            allow_network: options.allowNetwork ?? false,
            allow_code_execution: options.allowCodeExecution ?? false,
            include_apply_destroy: options.includeApplyDestroy ?? false
        });
    }

    public async createRun(targetPath: string, options: CreateRunOptions = {}): Promise<RunCreationResult> {
        return this.request<RunCreationResult>('POST', '/api/v1/runs', {
            target_path: targetPath,
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

    public streamEvents(runId: string, onEvent: (event: any) => void, signal?: AbortSignal, lastEventId?: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            const headers: Record<string, string> = {
                'Host': `127.0.0.1:${this.port}`,
                'Authorization': `Bearer ${this.token}`,
                'Accept': 'text/event-stream'
            };
            if (lastEventId) {
                headers['Last-Event-ID'] = lastEventId;
            }

            const req = http.request({
                hostname: '127.0.0.1',
                port: this.port,
                path: `/api/v1/runs/${runId}/events`,
                method: 'GET',
                headers: headers,
                agent: false
            }, (res) => {
                if (res.statusCode !== 200) {
                    reject(new Error(`Connexion SSE rejetée avec statut ${res.statusCode}`));
                    return;
                }

                res.setEncoding('utf8');
                let buffer = '';

                res.on('data', (chunk: string) => {
                    buffer += chunk;
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';

                    let eventType = '';
                    let eventData = '';
                    let eventId = '';

                    for (const line of lines) {
                        const trimmed = line.trim();
                        if (trimmed === '') {
                            if (eventData) {
                                try {
                                    const parsed = JSON.parse(eventData);
                                    if (eventType && !parsed.type) {
                                        parsed.type = eventType;
                                    }
                                    if (eventId && !parsed.id) {
                                        parsed.id = eventId;
                                    }
                                    onEvent(parsed);
                                    if (parsed.type === 'session_completed' || parsed.type === 'session_cancelled' || parsed.type === 'session_failed') {
                                        req.destroy();
                                        resolve();
                                    }
                                } catch {
                                    // Parse error
                                }
                            }
                            eventType = '';
                            eventData = '';
                            eventId = '';
                        } else if (trimmed.startsWith('event:')) {
                            eventType = trimmed.substring(6).trim();
                        } else if (trimmed.startsWith('data:')) {
                            eventData = trimmed.substring(5).trim();
                        } else if (trimmed.startsWith('id:')) {
                            eventId = trimmed.substring(3).trim();
                        }
                    }
                });

                res.on('end', () => {
                    resolve();
                });

                res.on('error', (err) => {
                    reject(err);
                });
            });

            if (signal) {
                const onAbort = () => {
                    setTimeout(() => {
                        req.destroy();
                        resolve();
                    }, 8000);
                };
                if (signal.aborted) {
                    onAbort();
                } else {
                    signal.addEventListener('abort', onAbort, { once: true });
                }
            }

            req.on('error', (err) => {
                if (signal?.aborted) {
                    resolve();
                } else {
                    reject(err);
                }
            });

            req.end();
        });
    }

    public async getReport(runId: string): Promise<Record<string, unknown>> {
        return this.request('GET', `/api/v1/runs/${runId}/report`);
    }

    public async cancelRun(runId: string): Promise<{ cancelled: boolean }> {
        return this.request('POST', `/api/v1/runs/${runId}/cancel`);
    }

    public async getLogs(runId: string, controlId: string): Promise<ControlLogs> {
        return this.request('GET', `/api/v1/runs/${runId}/logs/${encodeURIComponent(controlId)}`);
    }

    public async validateReport(reportData: Record<string, unknown>, reportSha256: string): Promise<any> {
        return this.request('POST', '/api/v1/reports/validate', {
            report: reportData,
            report_sha256: reportSha256
        });
    }

    public async shutdown(): Promise<void> {
        await postShutdown(this.port, this.token);
        try {
            const state = JSON.parse(await fs.readFile(path.join(this.stateDir!, 'daemon.json'), 'utf8')) as DaemonState;
            await killDaemonPid(state.pid, true);
        } catch { /* état déjà retiré */ }
        await killStagedDaemons();
    }

    private request<T>(method: string, path: string, body?: any): Promise<T> {
        return new Promise<T>((resolve, reject) => {
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

            req.on('error', err => reject(err));
            if (bodyData) {
                req.write(bodyData);
            }
            req.end();
        });
    }
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
    prepareComplianceBinary(dest);
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
            case 'session_started': case 'preparation_started': case 'preparation_completed': break;
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

function prepareComplianceBinary(binaryPath: string): void {
    if (process.platform !== 'win32') {
        fsSync.chmodSync(binaryPath, 0o755);
    }
    if (process.platform === 'darwin') {
        try {
            execFileSync('xattr', ['-d', 'com.apple.quarantine', binaryPath], { stdio: 'ignore' });
        } catch {
            // Attribute absent, or xattr unavailable. Gatekeeper is reported at spawn time.
        }
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

export async function prepare(source: string, target: string, client?: DaemonClient, _signal?: AbortSignal, sessionDirectory?: string, log?: (line: string) => void): Promise<Preparation> {
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
        log?.(`demon : ${Date.now() - daemonStarted} ms`);
        await daemon.approveWorkspace(canonicalTarget);
        const planStarted = Date.now();
        const plan = await daemon.getPlan(canonicalTarget);
        const body = JSON.stringify(plan);
        log?.(`plan recu : ${Date.now() - planStarted} ms, ${Buffer.byteLength(body)} octets`);
        const writeStarted = Date.now();
        await fs.writeFile(reportPath, body, 'utf8');
        log?.(`ecriture plan.json : ${Date.now() - writeStarted} ms`);
        return { report: plan, directory, target: canonicalTarget };
    } catch (daemonErr) {
        const message = daemonErr instanceof Error ? daemonErr.message : String(daemonErr);
        await fs.appendFile(path.join(directory, 'preparation.log'), `\n${message}\n`, 'utf8').catch(() => {});
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
    log?: (line: string) => void
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

    const cancelHandler = () => {
        void daemon.cancelRun(run.run_id).catch(() => {});
    };
    signal.addEventListener('abort', cancelHandler, { once: true });

    try {
        const executed: string[] = [];
        const absent: string[] = [];
        const unavailable: string[] = [];
        await daemon.streamEvents(run.run_id, (ev) => {
            try {
                state.receive(ev);
                if (log && ev && typeof ev === 'object') {
                    const event = ev as { type?: string; control_id?: string; data?: Record<string, unknown> | null };
                    const data = event.data || {};
                    const result = data.result as { status?: string } | undefined;
                    const reason = data.reason as { code?: string; message?: string } | undefined;
                    if (event.type === 'control_started') {
                        log(`exécuté en cours : ${event.control_id ?? ''}`);
                    } else if (event.type === 'control_completed') {
                        const code = reason?.code || '';
                        const id = event.control_id ?? '';
                        const technology = id.split('/')[0] || '';
                        if (result?.status === 'success' || result?.status === 'fail' || result?.status === 'error') { executed.push(technology); }
                        if (result?.status === 'success') { log(`exécuté OK : ${id}`); }
                        else if (result?.status === 'fail') { log(`exécuté KO : ${id}`); }
                        else if (result?.status === 'error') { log(`erreur : ${id} — ${reason?.message || ''}`); }
                        else if (code === 'technology_absent') { absent.push(technology); }
                        else { unavailable.push(`${id} — ${reason?.message || 'indisponible'}`); }
                    } else if (event.type === 'session_completed' || event.type === 'session_cancelled') {
                        const technologies = technologiesAbsentFromRun(executed, absent);
                        if (technologies.length) { log(`ignorés (technologie absente) : ${technologies.join(', ')}`); }
                        for (const line of groupUnavailableLines(unavailable)) { log(`indisponible : ${line}`); }
                        log(`session ${sessionHeadline(state, event.type === 'session_cancelled')}`);
                    }
                }
                changed();
            } catch {
                // Ignorer les erreurs d'événement hors séquence en transit
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
    } catch {
        // Rapport non disponible si annulé ou échoué
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
    log?: (line: string) => void
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

export const maximumReportBytes = 32 * 1024 * 1024;
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
export type ReportMessage = { schema_version: 1; action: 'ready' | 'pick' | 'raw' | 'folder' | 'provision' } | { schema_version: 1; action: 'output'; controlId: string } | { schema_version: 1; action: 'finding'; index: number };

export function reportMessage(value: unknown): ReportMessage {
    if (!fields(value) || value.schema_version !== 1 || typeof value.action !== 'string') { throw new Error('Message Webview invalide.'); }
    const keys = Object.keys(value).sort().join(',');
    if (['ready', 'pick', 'raw', 'folder', 'provision'].includes(value.action) && keys === 'action,schema_version') { return value as ReportMessage; }
    if (value.action === 'output' && keys === 'action,controlId,schema_version' && typeof value.controlId === 'string' && value.controlId.length > 0 && value.controlId.length <= 4096) { return value as ReportMessage; }
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
        if (!before.isFile() || before.size === 0 || before.size > limit) { throw new Error('Fichier absent, vide ou trop volumineux.'); }
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
    const ids = new Set<string>();
    const controls = [...plan, ...results.filter(result => !plan.some(control => control.id === result.control_id))].map(control => {
        const id = typeof control.id === 'string' ? control.id : String(control.control_id);
        if (id === 'undefined' || !id || ids.has(id) || typeof control.technology !== 'string' || typeof control.root !== 'string') { throw new Error('Identite ou racine de controle invalide.'); }
        ids.add(id);
        const result = byId.get(id);
        const state = visual.get(id);
        if (!state || (!result && value.execution_status === 'completed' && value.discovery && (value.discovery as Fields).scan_complete !== false)) { throw new Error('Resultat ou presentation backend absent du rapport final.'); }
        return { id, name: text(control.name || id), technology: control.technology, root: control.root, status: state.status as VisualStatus,
            reason: fields(state.reason) ? state.reason as unknown as Reason : undefined, plan: plan.includes(control) ? control : undefined, result,
            findings: findings.filter(finding => finding.control_id === id) };
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

export async function loadReport(source: string, file: string, reference?: ReportReference, historical = !reference, client?: DaemonClient): Promise<LoadedReport> {
    const associated = reference ? await readSession(source, reference) : await sessionNearReport(file);
    if (associated && path.relative(path.join(associated.directory, 'compliance-report.json'), path.resolve(file)) !== '') { throw new Error('Rapport hors session attendue.'); }
    const bytes = await readStable(file);
    const raw = json(bytes);
    if (!fields(raw) || raw.schema_version !== 1) { throw new Error('Rapport v1 invalide ou version inconnue.'); }
    const stagingRoot = path.join(path.dirname(await stateRoot(source)), 'report-reader');
    await fs.mkdir(stagingRoot, { recursive: true }); await noLinks(stagingRoot);
    const staging = path.join(stagingRoot, randomUUID());
    await fs.mkdir(staging);
    try {
        const snapshot = path.join(staging, 'report.json'); await fs.writeFile(snapshot, bytes, { flag: 'wx' });
        const digest = createHash('sha256').update(bytes).digest('hex');

        const daemon = client || new DaemonClient();
        await daemon.ensureDaemon(source);
        const envelope = await daemon.validateReport(raw, digest);
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
        const after = createHash('sha256').update(await readStable(file)).digest('hex');
        if (after !== digest) { throw new Error('Rapport modifie pendant sa validation ; actualiser.'); }
        const directory = associated?.directory || (path.basename(path.resolve(file)) === 'compliance-report.json' ? path.dirname(path.resolve(file)) : undefined);
        return { ...displayed, file: path.resolve(file), sha256: digest, historical, session: associated?.session, directory,
            target: String(displayed.report.repository), runId: String((displayed.report.metadata as Fields).run_id) };
    } finally { await fs.rm(staging, { recursive: true, force: true }); }
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
