export interface LayoutControl {
    id: string;
    name: string;
    technology: string;
    root: string;
    resultStatus: string;
    reasonCode: string;
    reasonMessage: string;
    durationMs?: number;
    stdout: string;
    stderr: string;
}

export interface LayoutTechnology {
    technology: string;
    status: string;
    evidence?: string[];
}

export interface ReportModel {
    verdict: { label: string; kind: string; detail: string };
    coverageText: string;
    executed: Array<LayoutControl & { compact: boolean; showOutput: boolean; label: string }>;
    gaps: string[];
    tools: string[];
    hiddenCount: number;
    showVerdictReasons: boolean;
    verdictReasons: string[];
    cards: { label: string; value: number; tone: string }[];
}

const hiddenCodes = new Set(['technology_absent', 'not_applicable', 'platform_unsupported', 'alternative_not_selected', 'ambiguous', 'user_disabled']);

function escapeHtml(value: string): string {
    return value.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character] || character));
}

const gapCodes = new Set(['tool_unavailable', 'capability_unavailable', 'repository_unconfigured', 'platform_unavailable']);

export function countsAsUnavailable(code: string): boolean {
    return code !== '' && !hiddenCodes.has(code);
}

export function coverageSentence(covered: number, detected: number, executed: number): string {
    if (detected <= 0) { return 'Aucune technologie détectée.'; }
    const text = `${covered} technologie(s) couverte(s) sur ${detected} détectée(s)`;
    if (covered === detected) { return `Couverture complète : ${text}.`; }
    if (executed <= 0) { return `Couverture nulle : ${text}.`; }
    return `Couverture partielle : ${text}.`;
}

export function nonApplicableMarkup(controls: LayoutControl[]): string {
    const executed = new Set(controls.filter(control => control.resultStatus === 'success' || control.resultStatus === 'fail' || control.resultStatus === 'error').map(control => control.technology));
    const hidden = controls.filter(control => isHidden(control) && !executed.has(control.technology));
    if (!hidden.length) { return ''; }
    const groups = new Map<string, LayoutControl[]>();
    for (const control of hidden) { groups.set(control.technology, [...(groups.get(control.technology) || []), control]); }
    const items = [...groups.entries()].map(([technology, rows]) => {
        const tools = [...new Set(rows.map(control => control.id.split('/')[2] || control.name))].join(', ');
        const reason = rows.every(control => control.reasonCode === 'technology_absent') ? 'technologie absente' : (rows[0].reasonMessage || 'non applicable');
        return `<li><strong>${escapeHtml(technology)}</strong> — ${escapeHtml(tools)} — ${escapeHtml(reason)}</li>`;
    }).join('');
    return `<section><h2>Contrôles non applicables</h2><ul>${items}</ul></section>`;
}

export function reportDurationMs(input: {
    metrics?: { total_duration_ms?: unknown; discovery_ms?: unknown; resolver_ms?: unknown; compliance_ms?: unknown; reporting_ms?: unknown };
    controls?: Array<{ resultStatus?: string; durationMs?: number }>;
    startedAt?: unknown;
    endedAt?: unknown;
}): number | undefined {
    const total = input.metrics?.total_duration_ms;
    if (typeof total === 'number' && Number.isFinite(total) && total >= 0) { return total; }
    const executed = (input.controls || []).filter(control => control.resultStatus === 'success' || control.resultStatus === 'fail' || control.resultStatus === 'error');
    if (executed.length) {
        return executed.reduce((sum, control) => sum + (typeof control.durationMs === 'number' && control.durationMs >= 0 ? control.durationMs : 0), 0);
    }
    const parts = [input.metrics?.discovery_ms, input.metrics?.resolver_ms, input.metrics?.compliance_ms, input.metrics?.reporting_ms];
    if (parts.length && parts.every(part => typeof part === 'number' && Number.isFinite(part) && part >= 0)) {
        return (parts as number[]).reduce((sum, part) => sum + part, 0);
    }
    if (typeof input.startedAt === 'string' && typeof input.endedAt === 'string') {
        const elapsed = Date.parse(input.endedAt) - Date.parse(input.startedAt);
        if (Number.isFinite(elapsed) && elapsed >= 0) { return elapsed; }
    }
    return undefined;
}

export function buildReportModel(input: {
    verdict: unknown;
    coverage: { complete?: unknown; executed_controls?: unknown; applicable_controls?: unknown; detected_technologies?: unknown; covered_technologies?: unknown; label?: unknown };
    verdictReasons?: unknown;
    technologies?: LayoutTechnology[];
    controls: LayoutControl[];
}): ReportModel {
    const reasons = Array.isArray(input.verdictReasons) ? input.verdictReasons.filter((item): item is string => typeof item === 'string' && item.trim() !== '') : [];
    const hidden = input.controls.filter(control => isHidden(control));
    const executed = input.controls.filter(control => isExecuted(control));
    const unavailable = input.controls.filter(control => isUnavailable(control));
    const applicable = executed.length + unavailable.length;
    const executedCount = executed.length;
    const complete = input.coverage.complete === true;
    const gaps = coverageGapLines(input.technologies || [], input.controls);
    const detected = typeof input.coverage.detected_technologies === 'number' ? input.coverage.detected_technologies : (input.technologies || []).filter(item => item.status === 'detected').length;
    const covered = typeof input.coverage.covered_technologies === 'number' ? input.coverage.covered_technologies : Math.max(0, detected - new Set(gaps.map(gap => gap.split(' : ')[0])).size);
    const coverageText = typeof input.coverage.label === 'string' && input.coverage.label ? input.coverage.label : coverageSentence(covered, detected, executedCount);
    return {
        verdict: verdictView(input.verdict, executedCount, complete),
        coverageText,
        executed: executed.map(control => ({
            ...control,
            compact: control.resultStatus === 'success',
            showOutput: true,
            label: control.resultStatus === 'success' ? 'Réussi' : control.resultStatus === 'fail' ? 'Échec' : 'Erreur'
        })),
        gaps,
        tools: uniqueTools(unavailable),
        hiddenCount: hidden.length,
        showVerdictReasons: reasons.length > 0,
        verdictReasons: reasons,
        cards: [
            { label: 'Applicables', value: applicable, tone: 'applicable' },
            { label: 'Exécutés', value: executedCount, tone: 'executed' },
            { label: 'Réussis', value: executed.filter(control => control.resultStatus === 'success').length, tone: 'passed' },
            { label: 'Échecs', value: executed.filter(control => control.resultStatus === 'fail' || control.resultStatus === 'error').length, tone: 'failed' },
            { label: 'Indisponibles', value: unavailable.length, tone: 'unavailable' }
        ]
    };
}

export function isExecuted(control: { resultStatus?: string }): boolean {
    return control.resultStatus === 'success' || control.resultStatus === 'fail' || control.resultStatus === 'error';
}

export function isUnavailable(control: LayoutControl): boolean {
    return !isExecuted(control) && countsAsUnavailable(control.reasonCode);
}

export function isHidden(control: LayoutControl): boolean {
    if (isExecuted(control)) { return false; }
    return !countsAsUnavailable(control.reasonCode);
}

export function verdictView(verdict: unknown, executed: number, complete: boolean): { label: string; kind: string; detail: string } {
    if (verdict === 'FAIL') { return { label: 'Échec', kind: 'fail', detail: 'Au moins un contrôle exécuté a échoué ou une erreur critique a interrompu l’évaluation.' }; }
    if (verdict === 'PASS' && complete && executed > 0) { return { label: 'Réussi', kind: 'pass', detail: 'Les contrôles applicables aux technologies détectées ont été exécutés sans écart.' }; }
    if (verdict === 'PASS' && executed > 0) { return { label: 'Partiel', kind: 'partial', detail: 'Des contrôles ont réussi, mais la couverture des technologies détectées est incomplète.' }; }
    return { label: 'Non évalué', kind: 'unevaluated', detail: 'Couverture nulle : aucun contrôle n’a été exécuté.' };
}

export function uniqueTools(controls: LayoutControl[]): string[] {
    const names = controls
        .filter(control => control.reasonCode === 'tool_unavailable')
        .map(control => {
            const command = control.id.split('/')[2];
            if (command) { return command; }
            const match = control.reasonMessage.match(/:\s*([A-Za-z0-9_.+-]+)\.?$/);
            return match ? match[1] : (control.reasonMessage || control.name);
        });
    return [...new Set(names)];
}

export function unavailableSummary(controls: LayoutControl[]): string[] {
    const groups = new Map<string, number>();
    for (const control of controls) {
        if (!isUnavailable(control)) { continue; }
        const parts = control.id.split('/');
        const tool = parts[2] || control.name;
        const reason = control.reasonMessage || control.reasonCode || 'indisponible';
        const key = `${control.technology} / ${tool} : ${reason}`;
        groups.set(key, (groups.get(key) || 0) + 1);
    }
    return [...groups.entries()].map(([key, count]) => count > 1 ? `${key} (${count} racines concernées)` : key);
}

function splitUnavailable(line: string): { id: string; reason: string } {
    const pattern = / (?:—|–|-) /g;
    let match: RegExpExecArray | null;
    let last: RegExpExecArray | null = null;
    while ((match = pattern.exec(line))) { last = match; }
    if (!last) { return { id: line, reason: 'indisponible' }; }
    return { id: line.slice(0, last.index), reason: line.slice(last.index + last[0].length) };
}

export function groupUnavailableLines(lines: string[]): string[] {
    const groups = new Map<string, number>();
    for (const line of lines) {
        const { id, reason } = splitUnavailable(line);
        const parts = id.split('/');
        const key = `${parts[0] || id} / ${parts[2] || parts[1] || id} : ${reason}`;
        groups.set(key, (groups.get(key) || 0) + 1);
    }
    return [...groups.entries()].map(([key, count]) => count > 1 ? `${key} (${count} racines concernées)` : key);
}

export function coverageGapLines(technologies: LayoutTechnology[], controls: LayoutControl[]): string[] {
    const lines: string[] = [];
    for (const tech of technologies) {
        if (tech.status !== 'detected') { continue; }
        const own = controls.filter(control => control.technology === tech.technology);
        if (own.length === 0) {
            lines.push(`${tech.technology} : détectée, aucun contrôle au catalogue`);
            continue;
        }
        const blocked = own.filter(control => gapCodes.has(control.reasonCode));
        if (blocked.length) {
            const messages = [...new Set(blocked.map(control => (control.reasonMessage || control.name).trim()).filter(Boolean))];
            lines.push(`${tech.technology} : ${messages.join(' ; ')}`);
        }
        if ((tech.evidence || []).some(file => file.toLowerCase().endsWith('.vue'))) {
            lines.push('vue : fichiers .vue détectés, pas de contrôle de types dédié');
        }
    }
    return [...new Set(lines)];
}
