// Audit sessions: preparation, event stream, final report checks.
import * as fsSync from 'node:fs';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomUUID } from 'node:crypto';
import { containsPath, isSameDirectory, parsePreparation, PlanNode, PreparationReport, projectPlan, Reason, VisualStatus } from '../model';
import { countsAsUnavailable, groupUnavailableLines } from '../reportLayout';
import { errorMessage, formatInvocation, Logger, silentLogger } from '../logger';
import { DaemonClient } from '../daemon/client';
import type { Fields } from '../report/loader';

// ---------------------------------------------------------------------------
// 2. Gestion de l'état, de la préparation et du session controller
// ---------------------------------------------------------------------------

export interface Preparation {
    report: PreparationReport;
    directory: string;
    target: string;
}
export interface Permissions {
    network: boolean;
    code_execution: boolean;
}
export type AskPermissions = (preparation: Preparation) => Promise<Permissions>;

export interface ProgressEvent {
    schema_version: number;
    run_id: string;
    sequence: number;
    timestamp: string;
    type: string;
    control_id?: string | null;
    technology?: string | null;
    root?: string | null;
    data: Record<string, unknown> | null;
}

const statuses: VisualStatus[] = ['Pending', 'Running', 'Succeeded', 'Failed', 'Error', 'Warning', 'Skipped', 'Blocked', 'Not applicable'];
function record(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function reason(value: unknown): value is Reason {
    return record(value) && typeof value.code === 'string' && value.code.length > 0 && typeof value.message === 'string' && value.message.length > 0;
}

export class AuditState {
    sequence = 0;
    status: VisualStatus = 'Running';
    reason?: Reason;
    terminal = false;
    reportPath?: string;
    snapshot?: PreparationReport;
    readonly controls = new Map<string, PlanNode>();
    readonly results = new Map<string, Record<string, unknown>>();
    constructor(
        readonly runId: string,
        readonly target: string
    ) {}
    receive(value: unknown): void {
        if (
            !record(value) ||
            value.schema_version !== 1 ||
            value.run_id !== this.runId ||
            value.sequence !== this.sequence + 1 ||
            typeof value.timestamp !== 'string' ||
            !Number.isFinite(Date.parse(value.timestamp)) ||
            typeof value.type !== 'string' ||
            this.terminal
        ) {
            throw new Error('Événement de session invalide, dupliqué ou hors sequence.');
        }
        const event = value as unknown as ProgressEvent;
        this.sequence = event.sequence;
        if (event.sequence === 1 && event.type !== 'session_started') {
            throw new Error('Début de session absent.');
        }
        const data = event.data || {};
        switch (event.type) {
            case 'session_started':
            case 'preparation_started':
            case 'preparation_completed':
            case 'control_invocation':
                break;
            case 'plan_available': {
                this.snapshot = parsePreparation(JSON.stringify(data), this.target, true);
                if (this.snapshot.metadata.run_id !== this.runId) {
                    throw new Error("Snapshot d'une autre session.");
                }
                for (const technology of projectPlan(this.snapshot)) {
                    for (const root of technology.children) {
                        for (const control of root.children) {
                            this.controls.set(control.id, control);
                        }
                    }
                }
                for (const control of this.snapshot.execution_plan.controls) {
                    if (!this.controls.has(control.id)) {
                        this.controls.set(control.id, {
                            id: control.id,
                            label: control.name,
                            status: 'Not applicable',
                            reason: { code: control.reason_code || control.applicability, message: control.reason || 'Technologie absente.' },
                            children: []
                        });
                    }
                }
                break;
            }
            case 'control_started': {
                const control = this.controls.get(event.control_id || '');
                if (
                    !control ||
                    control.status !== 'Pending' ||
                    typeof data.execution_start !== 'string' ||
                    !Number.isFinite(Date.parse(data.execution_start))
                ) {
                    throw new Error('Début de contrôle invalide.');
                }
                control.status = 'Running';
                control.execution_start = data.execution_start;
                control.reason = undefined;
                break;
            }
            case 'control_completed': {
                const control = this.controls.get(event.control_id || '');
                if (
                    !control ||
                    control.duration_ms !== undefined ||
                    !record(data.result) ||
                    data.result.control_id !== control.id ||
                    !['success', 'fail', 'error', 'skipped'].includes(String(data.result.status)) ||
                    typeof data.result.duration_ms !== 'number' ||
                    data.result.duration_ms < 0 ||
                    !Number.isFinite(data.result.duration_ms) ||
                    !statuses.includes(data.status as VisualStatus) ||
                    ['Pending', 'Running'].includes(String(data.status)) ||
                    (['Warning', 'Skipped', 'Blocked', 'Not applicable'].includes(String(data.status)) && !reason(data.reason)) ||
                    typeof data.output_path !== 'string'
                ) {
                    throw new Error(`Fin de contrôle invalide : ${event.control_id}.`);
                }
                control.status = data.status as VisualStatus;
                control.duration_ms = data.result.duration_ms;
                control.reason = reason(data.reason) ? data.reason : undefined;
                control.output_path = data.output_path;
                this.results.set(control.id, data.result);
                break;
            }
            case 'report_available':
                if (typeof data.report_path !== 'string') {
                    throw new Error('Chemin de rapport absent.');
                }
                this.reportPath = data.report_path;
                break;
            case 'session_cancelling':
                this.reason = { code: 'session_interrupted', message: 'Annulation en cours.' };
                break;
            case 'session_cancelled':
                this.status = 'Skipped';
                this.reason = reason(data.reason) ? data.reason : { code: 'session_interrupted', message: 'Session annulée.' };
                this.terminal = true;
                break;
            case 'session_failed':
                this.status = 'Error';
                this.reason = reason(data.reason) ? data.reason : { code: 'preparation_error', message: 'Session backend en erreur.' };
                this.terminal = true;
                break;
            case 'session_completed':
                if (!this.snapshot || !this.reportPath || [...this.controls.values()].some(control => control.duration_ms === undefined)) {
                    throw new Error('Session terminée sans résultats complets.');
                }
                this.status =
                    data.verdict === 'FAIL'
                        ? 'Failed'
                        : data.verdict === 'PASS' && record(data.coverage) && data.coverage.complete === true
                          ? 'Succeeded'
                          : 'Warning';
                if (this.status === 'Warning') {
                    const reasons = Array.isArray(data.verdict_reasons) ? data.verdict_reasons.filter((item: unknown) => typeof item === 'string') : [];
                    this.reason = {
                        code: data.verdict == null ? 'not_evaluated' : 'coverage_incomplete',
                        message: String(
                            reasons[0] ||
                                (data.verdict == null
                                    ? 'Non évalué : couverture nulle, aucun contrôle exécuté.'
                                    : 'Audit terminé avec une couverture partielle.')
                        )
                    };
                }
                this.terminal = true;
                break;
            default:
                this.reason = { code: 'unknown_event', message: `Événement non reconnu : ${event.type}` };
                break;
        }
    }
    fail(message: string): void {
        this.terminal = true;
        this.status = 'Error';
        this.reason = { code: 'session_interrupted', message };
        for (const control of this.controls.values()) {
            if (control.status === 'Running') {
                control.status = 'Error';
                control.reason = this.reason;
            } else if (control.status === 'Pending') {
                control.status = 'Blocked';
                control.reason = this.reason;
            }
        }
    }
    verifyReport(value: unknown): void {
        if (
            !record(value) ||
            value.schema_version !== 1 ||
            !record(value.metadata) ||
            value.metadata.run_id !== this.runId ||
            !isSameDirectory(String(value.repository), this.target) ||
            !Array.isArray(value.execution_results) ||
            !record(value.coverage) ||
            !record(value.summary) ||
            !Array.isArray(value.findings) ||
            !Array.isArray(value.diagnostics) ||
            !Array.isArray(value.limitations) ||
            !['completed', 'blocked', 'error'].includes(String(value.execution_status)) ||
            !['PASS', 'FAIL', null].includes(value.verdict as string | null)
        ) {
            throw new Error("Rapport final invalide ou d'une autre session.");
        }
        const summary = value.summary as { success?: number; fail?: number; error?: number };
        if (value.verdict === 'PASS' && (summary.success || 0) + (summary.fail || 0) + (summary.error || 0) === 0) {
            throw new Error('PASS sans contrôle exécuté.');
        }
        const ids = new Set<string>();
        for (const result of value.execution_results) {
            if (
                !record(result) ||
                typeof result.control_id !== 'string' ||
                ids.has(result.control_id) ||
                !['success', 'fail', 'error', 'skipped'].includes(String(result.status)) ||
                typeof result.duration_ms !== 'number' ||
                result.duration_ms < 0 ||
                !Array.isArray(result.diagnostics)
            ) {
                throw new Error('Résultats du rapport invalides ou dupliqués.');
            }
            ids.add(result.control_id);
            const eventResult = this.results.get(result.control_id);
            if (eventResult && (eventResult.status !== result.status || eventResult.duration_ms !== result.duration_ms)) {
                throw new Error('Résultat différent de son événement terminal.');
            }
        }
        if (this.status !== 'Error' && [...this.controls.keys()].some(id => !ids.has(id))) {
            throw new Error('Résultat absent du rapport final.');
        }
        if (this.status === 'Skipped' && (value.coverage.complete || value.verdict === 'PASS')) {
            throw new Error('Annulation présentée comme réussie.');
        }
    }
    nodes(): PlanNode[] {
        if (!this.snapshot) {
            return [];
        }
        return projectPlan(this.snapshot).map(technology => {
            for (const root of technology.children) {
                root.children = root.children.map(control => this.controls.get(control.id) || control);
                const priority: VisualStatus[] = ['Error', 'Failed', 'Blocked', 'Running', 'Pending', 'Warning', 'Skipped', 'Succeeded', 'Not applicable'];
                root.status = priority.find(status => root.children.some(control => control.status === status));
                if (root.status && ['Blocked', 'Warning', 'Skipped', 'Not applicable'].includes(root.status)) {
                    root.reason = root.children.find(control => control.status === root.status)?.reason;
                }
            }
            const incomplete = technology.children.some(root =>
                root.children.some(control => ['Skipped', 'Blocked', 'Error', 'Warning'].includes(control.status || ''))
            );
            if (incomplete && !technology.status) {
                technology.status = 'Warning';
                technology.reason = { code: 'coverage_incomplete', message: 'Pipeline partiellement couverte.' };
            }
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
        if (this.busy) {
            throw new Error('Une session est déjà active.');
        }
        this.target = target;
        this.approved = true;
        this.preparation = undefined;
        this.audit = undefined;
        this.sourceValid = false;
    }
    canRun(trusted: boolean): boolean {
        return trusted && this.approved && this.sourceValid && !!this.target && !!this.preparation?.report.discovery.scan_complete && !this.busy;
    }
    begin(trusted: boolean): AuditState {
        if (!this.canRun(trusted)) {
            throw new Error("Target, préparation valide, source et autorisation requises avant l'audit.");
        }
        this.busy = true;
        this.abort = new AbortController();
        this.audit = new AuditState(randomUUID().replace(/-/g, ''), this.target!);
        return this.audit;
    }
    cancel(): void {
        this.abort?.abort();
    }
    end(): void {
        this.busy = false;
        this.abort = undefined;
    }
}

export function isInstalledExtensionSource(source: string): boolean {
    return (
        fsSync.existsSync(path.join(source, '.config', 'control-catalog.json')) &&
        !fsSync.existsSync(path.join(source, 'core', 'go.mod')) &&
        !fsSync.existsSync(path.join(source, '.git'))
    );
}

export function runsDirectory(source: string): string {
    if (process.env.COMPLIANCE_SESSIONS_DIR) {
        return process.env.COMPLIANCE_SESSIONS_DIR;
    }
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
            if (entry.isSymbolicLink() || !entry.isDirectory()) {
                throw new Error("Le dossier d'état ne doit pas être un lien ou un fichier.");
            }
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
                throw error;
            }
            await fs.mkdir(current);
        }
    }
    return directory;
}

export async function validateTarget(source: string, target: string): Promise<string> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await fs.realpath(target);
    if (!(await fs.stat(canonicalTarget)).isDirectory()) {
        throw new Error('La Target doit être un dossier local.');
    }
    if (containsPath(canonicalSource, canonicalTarget) || containsPath(canonicalTarget, canonicalSource)) {
        throw new Error('Choisir une Target externe, distincte de la Pipeline source et de ses dossiers parents.');
    }
    return canonicalTarget;
}

export async function prepare(
    source: string,
    target: string,
    client?: DaemonClient,
    signal?: AbortSignal,
    sessionDirectory?: string,
    log: Logger = silentLogger
): Promise<Preparation> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await validateTarget(canonicalSource, target);
    const id = randomUUID();
    const directory = sessionDirectory || path.join(await stateRoot(canonicalSource), id);
    if (!sessionDirectory) {
        await fs.mkdir(directory);
    }
    const reportPath = path.join(directory, 'plan.json');
    if (!sessionDirectory) {
        await fs.writeFile(
            path.join(directory, 'session.json'),
            JSON.stringify({ id, source: canonicalSource, target: canonicalTarget, created_at: new Date().toISOString(), mode: 'PlanOnly' }, null, 2),
            'utf8'
        );
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
        await fs
            .appendFile(path.join(directory, 'preparation.log'), `\n${new Date().toISOString()} ${message}\n`, 'utf8')
            .catch(error => log.warn('préparation.log non écrit', { error: errorMessage(error) }));
        throw new Error(`Préparation impossible : ${message}. Journal : ${path.join(directory, 'preparation.log')}`, { cause: daemonErr });
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
    if (!containsPath(directory, real)) {
        throw new Error('Artefact de session redirigé hors dossier.');
    }
    return real;
}

async function atomicJson(file: string, value: unknown): Promise<void> {
    const temporary = `${file}.node.tmp`;
    await fs.writeFile(temporary, JSON.stringify(value, null, 2), 'utf8');
    await fs.rename(temporary, file);
}

function sessionHeadline(state: AuditState, cancelled: boolean): string {
    if (cancelled) {
        return 'annulée';
    }
    if (state.status === 'Failed') {
        return 'terminée — Échec';
    }
    if (state.status === 'Succeeded') {
        return 'terminée — Réussi';
    }
    if (state.reason?.code === 'not_evaluated') {
        return `terminée — Non évalué${state.reason.message ? ` — ${state.reason.message}` : ''}`;
    }
    if (state.status === 'Warning') {
        return `terminée — Partiel${state.reason?.message ? ` — ${state.reason.message}` : ''}`;
    }
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
        await daemon.streamEvents(
            run.run_id,
            ev => {
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
                            controlLog.debug(formatInvocation(data));
                        } else if (event.type === 'control_started') {
                            controlLog.info('exécution en cours');
                        } else if (event.type === 'control_completed') {
                            const code = reason?.code || '';
                            const technology = id.split('/')[0] || '';
                            const fields = { ms: result?.duration_ms, exit: result?.exit_code, output: data.output_path };
                            if (result?.status === 'success' || result?.status === 'fail' || result?.status === 'error') {
                                executed.push(technology);
                            }
                            if (result?.status === 'success') {
                                controlLog.info('exécuté OK', fields);
                            } else if (result?.status === 'fail') {
                                controlLog.info('exécuté KO', { ...fields, reason: reason?.message });
                            } else if (result?.status === 'error') {
                                controlLog.error('erreur', { ...fields, reason: reason?.message });
                            } else if (code === 'technology_absent') {
                                absent.push(technology);
                            } else if (countsAsUnavailable(code)) {
                                unavailable.push(`${id} — ${reason?.message || 'indisponible'}`);
                            } else {
                                controlLog.debug('non exécuté', { reason: code, message: reason?.message });
                            }
                        } else if (event.type === 'session_completed' || event.type === 'session_cancelled') {
                            const technologies = technologiesAbsentFromRun(executed, absent);
                            if (technologies.length) {
                                runLog.info(`ignorés (technologie absente) : ${technologies.join(', ')}`);
                            }
                            for (const line of groupUnavailableLines(unavailable)) {
                                runLog.warn(`indisponible : ${line}`);
                            }
                            runLog.info(`session ${sessionHeadline(state, event.type === 'session_cancelled')}`);
                        } else if (event.type === 'session_failed') {
                            runLog.error('session en échec côté démon', { error: data.error });
                        }
                    }
                    changed();
                } catch (error) {
                    const message = errorMessage(error);
                    if (message.includes('Contrôle du plan') || message.includes('Inventaire de technologies') || message.includes('plan v1')) {
                        throw error;
                    }
                    runLog.warn('événement de session ignoré', { error: message });
                }
            },
            signal
        );
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
    const heartbeat = setInterval(() => {
        void fs.writeFile(path.join(directory, 'heartbeat'), '', 'utf8').catch(() => undefined);
    }, 1000);
    try {
        await validateSource(source, daemon);
        const fresh = await prepare(source, target, daemon, signal, directory, log);
        if (!fresh.report.discovery.scan_complete) {
            throw new Error('Discovery incomplète ; audit interdit.');
        }
        const permissions = await ask(fresh);
        if (signal.aborted) {
            state.status = 'Skipped';
            state.reason = { code: 'session_interrupted', message: 'Session annulée avant exécution.' };
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
            const report = JSON.parse(await fs.readFile(reportPath, 'utf8')) as Fields;
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
        if (!state.terminal) {
            state.fail('Session sans événement terminal.');
            metadata.state = 'incomplete';
        }
        if (state.status === 'Skipped') {
            metadata.state = 'cancelled';
        } else if (state.status === 'Error') {
            metadata.state = 'incomplete';
        } else if (metadata.state === 'preparing') {
            metadata.state = 'completed';
        }
        metadata.ended_at = new Date().toISOString();
        metadata.report_path = path.join(directory, 'compliance-report.json');
        await atomicJson(path.join(directory, 'session.json'), metadata);
        changed();
    }
}

export function technologiesAbsentFromRun(executed: string[], absent: string[]): string[] {
    const ran = new Set(executed.filter(Boolean));
    return [...new Set(absent.filter(Boolean))].filter(name => !ran.has(name));
}
