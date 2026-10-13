import { randomUUID } from 'node:crypto';
import { Preparation } from './backend';
import { isSameDirectory, parsePreparation, PlanNode, PreparationReport, projectPlan, Reason, VisualStatus } from './model';

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
                this.status = data.verdict === 'FAIL' ? 'Failed' : record(data.coverage) && data.coverage.complete === true ? 'Succeeded' : 'Warning';
                if (this.status === 'Warning') { this.reason = { code: 'coverage_incomplete', message: 'Audit termine avec couverture partielle.' }; }
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
            !['completed', 'blocked', 'error'].includes(String(value.execution_status)) || !['PASS', 'FAIL'].includes(String(value.verdict))) { throw new Error('Rapport final invalide ou d une autre session.'); }
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
