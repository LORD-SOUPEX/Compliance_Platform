import { createHash, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { planInvocation, Runner, runProcess, stateRoot } from './backend';
import { containsPath, Reason, VisualStatus } from './model';

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
export type ReportMessage = { schema_version: 1; action: 'ready' | 'refresh' | 'raw' | 'folder' } | { schema_version: 1; action: 'output'; controlId: string } | { schema_version: 1; action: 'finding'; index: number };
export function reportMessage(value: unknown): ReportMessage {
    if (!fields(value) || value.schema_version !== 1 || typeof value.action !== 'string') { throw new Error('Message Webview invalide.'); }
    const keys = Object.keys(value).sort().join(',');
    if (['ready', 'refresh', 'raw', 'folder'].includes(value.action) && keys === 'action,schema_version') { return value as ReportMessage; }
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
    const directory = path.join(source, '.tools/state/runs', reference.runId);
    const session = json(await readStable(path.join(directory, 'session.json'), 1024 * 1024));
    if (!fields(session) || session.schema_version !== 1 || session.run_id !== reference.runId || session.target !== reference.target ||
        typeof session.pipeline_source !== 'string' || path.relative(source, session.pipeline_source) !== '' ||
        !['completed', 'cancelled', 'failed', 'incomplete'].includes(String(session.state)) ||
        typeof session.report_path !== 'string' || path.relative(path.join(directory, 'compliance-report.json'), session.report_path) !== '' ||
        typeof session.started_at !== 'string' || !Number.isFinite(Date.parse(session.started_at)) ||
        !fields(session.permissions) || typeof session.permissions.network !== 'boolean' || typeof session.permissions.code_execution !== 'boolean') { throw new Error('Session non finalisee ou incoherente ; consulter ses journaux.'); }
    return { directory, session };
}

export async function loadReport(source: string, file: string, reference?: ReportReference, historical = !reference, runner: Runner = runProcess): Promise<LoadedReport> {
    const associated = reference ? await readSession(source, reference) : undefined;
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
        const invocation = planInvocation(source, source, snapshot);
        invocation.arguments = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(source, 'scripts/compliance-adapter.ps1'), '-ValidateReportPath', snapshot];
        const validation = await runner(invocation);
        if (validation.code !== 0) { throw new Error(`Rapport refuse par Test-ComplianceReport : ${validation.stderr.slice(0, 2000)}`); }
        const envelope: unknown = JSON.parse(validation.stdout.replace(/^\uFEFF/, ''));
        const digest = createHash('sha256').update(bytes).digest('hex');
        if (!fields(envelope) || envelope.schema_version !== 1 || envelope.report_sha256 !== digest) { throw new Error('Validation non rattachee aux octets du rapport.'); }
        const displayed = displayReport(raw, envelope.presentations);
        if (reference && ((displayed.report.metadata as Fields).run_id !== reference.runId || displayed.report.repository !== reference.target)) { throw new Error('Identite run_id ou Target incoherente avec la session.'); }
        if (associated && fields(associated.session.permissions)) {
            const metadata = displayed.report.metadata as Fields;
            if (metadata.network_authorized !== associated.session.permissions.network || metadata.code_execution_authorized !== associated.session.permissions.code_execution) { throw new Error('Permissions du rapport incoherentes avec la session.'); }
        }
        if (associated && ['cancelled', 'incomplete'].includes(String(associated.session.state)) &&
            (displayed.report.verdict === 'PASS' || (displayed.report.coverage as Fields).complete === true)) { throw new Error('Rapport interrompu presente comme un PASS complet.'); }
        const after = createHash('sha256').update(await readStable(file)).digest('hex');
        if (after !== digest) { throw new Error('Rapport modifie pendant sa validation ; actualiser.'); }
        return { ...displayed, file: path.resolve(file), sha256: digest, historical, session: associated?.session, directory: associated?.directory,
            target: String(displayed.report.repository), runId: String((displayed.report.metadata as Fields).run_id) };
    } finally { await fs.rm(staging, { recursive: true, force: true }); }
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
    if (!containsPath(target, candidate)) { throw new Error('Fichier hors Target refuse.'); }
    await noLinks(candidate);
    if (!containsPath(await fs.realpath(target), await fs.realpath(candidate)) || !(await fs.stat(candidate)).isFile()) { throw new Error('Localisation hors Target ou non fichier.'); }
    return candidate;
}
