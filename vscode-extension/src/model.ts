import * as fs from 'node:fs';
import * as path from 'node:path';

export type VisualStatus = 'Pending' | 'Running' | 'Succeeded' | 'Failed' | 'Error' | 'Warning' | 'Skipped' | 'Blocked' | 'Not applicable';
export interface Reason { code: string; message: string }
export interface Control {
    id: string;
    name: string;
    technology: string;
    capability: string;
    root: string;
    applicability: string;
    reason: string;
    reason_code?: string;
    permissions?: ('network' | 'code_execution')[];
    side_effect_level?: string;
    execution_order: number;
}
export interface Technology {
    technology: string;
    status: 'detected' | 'ambiguous' | 'absent';
    roots: string[];
    evidence: string[];
    ambiguities: string[];
}
export interface PreparationReport {
    schema_version: 1;
    repository: string;
    execution_status: 'planned';
    verdict: null;
    metadata: { run_id: string; source_adapter: string; catalog_sha256?: string; platform_qualification_status?: string };
    discovery: { technologies: Technology[]; scan_complete: boolean; scan_errors: { message: string }[] };
    execution_plan: { repository: string; permissions: { network: boolean; code_execution: boolean }; controls: Control[] };
    execution_results: [];
}
export interface PlanNode {
    id: string;
    label: string;
    description?: string;
    status?: VisualStatus;
    reason?: Reason;
    detail?: string;
    duration_ms?: number;
    execution_start?: string;
    output_path?: string;
    children: PlanNode[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function resolveExisting(input: string): string {
    const absolute = path.resolve(input);
    const read = (value: string): string => fs.realpathSync.native ? fs.realpathSync.native(value) : fs.realpathSync(value);
    try {
        return read(absolute);
    } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'ENOENT') { return absolute; }
    }
    let current = absolute;
    const missing: string[] = [];
    while (true) {
        try {
            const resolved = read(current);
            return missing.reduceRight((prefix, segment) => path.join(prefix, segment), resolved);
        } catch (error) {
            const code = (error as NodeJS.ErrnoException).code;
            if (code !== 'ENOENT') { return absolute; }
            const parent = path.dirname(current);
            if (parent === current) { return absolute; }
            missing.push(path.basename(current));
            current = parent;
        }
    }
}

export function containsPath(parent: string, candidate: string): boolean {
    const relative = path.relative(resolveExisting(parent), resolveExisting(candidate));
    return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function controlOutputText(runId: string, controlId: string, value: unknown): string {
    if (!isRecord(value) || value.control_id !== controlId || !['success', 'fail', 'error', 'skipped'].includes(String(value.status)) ||
        typeof value.stdout !== 'string' || typeof value.stderr !== 'string' || typeof value.duration_ms !== 'number') { throw new Error('Sorties invalides ou d un autre controle.'); }
    return `Session : ${runId}\nControle : ${controlId}\nStatut canonique : ${value.status}\nDuree : ${value.duration_ms} ms\n\nSTDOUT\n${value.stdout}\n\nSTDERR\n${value.stderr}\n\nDIAGNOSTICS\n${JSON.stringify(value.diagnostics, null, 2)}`;
}

export function isSameDirectory(a: string, b: string): boolean {
    if (path.relative(a, b) === '') { return true; }
    try {
        const ra = fs.realpathSync.native ? fs.realpathSync.native(a) : fs.realpathSync(a);
        const rb = fs.realpathSync.native ? fs.realpathSync.native(b) : fs.realpathSync(b);
        const rel = path.relative(ra, rb);
        if (rel === '') { return true; }
        if ((process.platform === 'win32' || process.platform === 'darwin') && rel.toLowerCase() === '') { return true; }
    } catch {
        return false;
    }
    return false;
}

export function parsePreparation(text: string, target: string, allowPermissions = false): PreparationReport {
    const report: unknown = JSON.parse(text.replace(/^\uFEFF/, ''));
    if (!isRecord(report) || report.schema_version !== 1 || report.execution_status !== 'planned' || report.verdict !== null ||
        typeof report.repository !== 'string' || !isSameDirectory(target, report.repository) ||
        !Array.isArray(report.execution_results) || report.execution_results.length !== 0 ||
        !isRecord(report.metadata) || report.metadata.source_adapter !== 'VSCode' || typeof report.metadata.run_id !== 'string' ||
        !isRecord(report.discovery) || typeof report.discovery.scan_complete !== 'boolean' ||
        !Array.isArray(report.discovery.scan_errors) || !Array.isArray(report.discovery.technologies) ||
        !isRecord(report.execution_plan) || report.execution_plan.repository !== report.repository ||
        !isRecord(report.execution_plan.permissions) || typeof report.execution_plan.permissions.network !== 'boolean' ||
        typeof report.execution_plan.permissions.code_execution !== 'boolean' ||
        (!allowPermissions && (report.execution_plan.permissions.network || report.execution_plan.permissions.code_execution)) || !Array.isArray(report.execution_plan.controls)) {
        throw new Error('Le backend ne fournit pas un plan v1 sans execution pour cette Target.');
    }
    const technologies = new Set<string>();
    for (const technology of report.discovery.technologies) {
        if (!isRecord(technology) || typeof technology.technology !== 'string' || technologies.has(technology.technology) ||
            !['detected', 'ambiguous', 'absent'].includes(String(technology.status)) ||
            !['roots', 'evidence', 'ambiguities'].every(field => Array.isArray(technology[field]) && technology[field].every((value: unknown) => typeof value === 'string'))) {
            throw new Error('Inventaire de technologies invalide.');
        }
        technologies.add(technology.technology);
    }
    const ids = new Set<string>();
    for (const control of report.execution_plan.controls) {
        if (!isRecord(control) || !['id', 'name', 'technology', 'capability', 'root', 'applicability', 'reason'].every(field => typeof control[field] === 'string') ||
            ids.has(String(control.id)) || !technologies.has(String(control.technology)) ||
            typeof control.execution_order !== 'number' || !Number.isInteger(control.execution_order) || control.execution_order < 1 ||
            !['applicable', 'not_applicable', 'capability_unavailable', 'tool_unavailable', 'technology_absent', 'ambiguous'].includes(String(control.applicability)) ||
            path.isAbsolute(String(control.root)) || !containsPath(target, path.resolve(target, String(control.root)))) {
            throw new Error('Controle du plan invalide ou hors Target.');
        }
        ids.add(String(control.id));
    }
    return report as unknown as PreparationReport;
}

export function projectPlan(report: PreparationReport): PlanNode[] {
    return report.discovery.technologies.filter(technology => technology.status !== 'absent').map(technology => {
        const controls = report.execution_plan.controls.filter(control => control.technology === technology.technology)
            .sort((first, second) => first.execution_order - second.execution_order);
        const roots = Array.from(new Set([...technology.roots, ...controls.map(control => control.root)]));
        const blocked = !report.discovery.scan_complete || technology.status === 'ambiguous';
        return {
            id: `technology/${technology.technology}`,
            label: technology.technology,
            description: technology.status,
            status: blocked ? 'Blocked' : undefined,
            reason: blocked ? {
                code: report.discovery.scan_complete ? 'ambiguous' : 'incomplete_scan',
                message: report.discovery.scan_complete ? technology.ambiguities.join('; ') || 'Technologie ambigue selon Discovery.' : 'Discovery incomplet ; aucune execution possible.'
            } : undefined,
            detail: technology.evidence.join('\n'),
            children: roots.map(root => ({
                id: `root/${technology.technology}/${root}`,
                label: root,
                children: controls.filter(control => control.root === root).map(control => {
                    const status: VisualStatus = !report.discovery.scan_complete ? 'Blocked' : control.applicability === 'applicable' ? 'Pending' : control.reason_code === 'permission_denied' ? 'Skipped' :
                        ['not_applicable', 'technology_absent'].includes(control.applicability) ? 'Not applicable' : 'Blocked';
                    return {
                        id: control.id,
                        label: control.name,
                        description: control.capability,
                        status,
                        reason: status === 'Pending' ? undefined : {
                            code: report.discovery.scan_complete ? control.reason_code || control.applicability : 'incomplete_scan',
                            message: report.discovery.scan_complete ? control.reason || 'Controle non executable selon le plan backend.' : 'Discovery incomplet ; aucun controle lance.'
                        },
                        detail: control.id,
                        children: []
                    };
                })
            }))
        };
    });
}
