import * as http from 'node:http';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn, ChildProcess } from 'node:child_process';
import { PreparationReport } from './model';

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
            const home = os.homedir();
            this.stateDir = path.join(home, '.compliance');
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

    /**
     * Connects to an existing daemon or starts a new local compliance daemon process.
     */
    public async ensureDaemon(platformRoot: string): Promise<DaemonHealth> {
        if (process.platform === 'win32' && process.env.SystemRoot) {
            try {
                await fs.access(path.join(process.env.SystemRoot, 'System32'));
            } catch {
                throw new Error('Environnement Windows invalide (SystemRoot altéré).');
            }
        }

        // 1. Try reading existing state
        const stateFile = path.join(this.stateDir!, 'daemon.json');
        try {
            const data = await fs.readFile(stateFile, 'utf8');
            const state: DaemonState = JSON.parse(data);
            const token = (await fs.readFile(state.token_path, 'utf8')).trim();
            this.port = state.port;
            this.token = token;

            const health = await this.getHealth();
            if (health && health.status === 'ok') {
                return health;
            }
        } catch {
            // Daemon not running or invalid state file
        }

        // 2. Start daemon executable
        const complianceBin = await this.findComplianceBinary(platformRoot);
        if (!complianceBin) {
            throw new Error('Binaire "compliance" introuvable. Exécuter la compilation Go dans core/.');
        }

        const args = ['daemon', '-state-dir', this.stateDir!, '-platform-root', platformRoot];
        this.daemonProcess = spawn(complianceBin, args, {
            detached: true,
            windowsHide: true,
            stdio: 'ignore'
        });
        this.daemonProcess.unref();

        // 3. Wait for daemon to become healthy (polling up to 15 seconds)
        const deadline = Date.now() + 15000;
        while (Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 200));
            try {
                const data = await fs.readFile(stateFile, 'utf8');
                const state: DaemonState = JSON.parse(data);
                const token = (await fs.readFile(state.token_path, 'utf8')).trim();
                this.port = state.port;
                this.token = token;

                const health = await this.getHealth();
                if (health && health.status === 'ok') {
                    return health;
                }
            } catch {
                // Continue polling
            }
        }

        throw new Error('Délai dépassé lors du démarrage du démon local Compliance.');
    }

    private async findComplianceBinary(platformRoot: string): Promise<string | null> {
        const exeName = process.platform === 'win32' ? 'compliance.exe' : 'compliance';
        const platformExe = process.platform === 'win32' ? 'compliance-windows-amd64.exe'
            : (process.platform === 'darwin' ? (process.arch === 'arm64' ? 'compliance-darwin-arm64' : 'compliance-darwin-amd64')
            : 'compliance-linux-amd64');

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
                return path.resolve(candidate);
            } catch {
                // Not found, check next
            }
        }
        return null;
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
            allow_network: !!options.allowNetwork,
            allow_code_execution: !!options.allowCodeExecution,
            include_apply_destroy: !!options.includeApplyDestroy
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
            redaction_patterns: options.redactionPatterns || []
        });
    }

    public async cancelRun(runId: string): Promise<void> {
        await this.request('POST', `/api/v1/runs/${runId}/cancel`);
    }

    public async getReport(runId: string): Promise<any> {
        return this.request<any>('GET', `/api/v1/runs/${runId}/report`);
    }

    public async validateReport(reportData: any, reportSHA256?: string): Promise<{ schema_version: number; report_sha256: string; presentations: any[] }> {
        return this.request<{ schema_version: number; report_sha256: string; presentations: any[] }>('POST', '/api/v1/reports/validate', {
            report_sha256: reportSHA256,
            report: reportData
        });
    }

    public async getControlLogs(runId: string, controlId: string): Promise<ControlLogs> {
        return this.request<ControlLogs>('GET', `/api/v1/runs/${runId}/logs/${encodeURIComponent(controlId)}`);
    }

    /**
     * Connects to the SSE event stream for a given run and invokes onEvent for each parsed event.
     */
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
                            // Dispatch event if we have data
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
                let abortTimer: NodeJS.Timeout | undefined;
                const onAbort = () => {
                    // Laisser au démon le temps d'émettre le rapport et l'événement terminal d'annulation
                    abortTimer = setTimeout(() => {
                        req.destroy();
                        resolve();
                    }, 8000);
                };
                if (signal.aborted) {
                    onAbort();
                } else {
                    signal.addEventListener('abort', onAbort, { once: true });
                }
                const cleanup = () => {
                    if (abortTimer) {
                        clearTimeout(abortTimer);
                    }
                    signal.removeEventListener('abort', onAbort);
                };
                req.on('close', cleanup);
            }

            req.on('error', (err) => {
                reject(err);
            });

            req.end();
        });
    }

    public async shutdown(): Promise<void> {
        try {
            await this.request('POST', '/api/v1/shutdown');
        } catch {
            // Daemon already stopped
        }
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
