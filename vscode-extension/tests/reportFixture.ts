import { randomUUID } from 'node:crypto';

export function reportFixture(target: string, runId = randomUUID().replace(/-/g, '')): Record<string, any> {
    const now = new Date().toISOString();
    const control = { id: 'future/lint/.', control_catalog_id: null, name: 'Future control', technology: 'future', capability: 'lint', root: '.', applicability: 'applicable', execution_order: 1, reason: '', tool: { name: 'Future tool', command: 'future' }, permissions: [] };
    const result = { control_id: control.id, control_catalog_id: null, name: control.name, technology: 'future', capability: 'lint', root: '.', severity: 'medium', status: 'success', execution_start: now, execution_end: now, duration_ms: 1234, tool_version: '1.0.0', stdout: 'sortie', stderr: '', exit_code: 0, output_truncated: false, critical: false, diagnostics: [] };
    return {
        schema_version: 1, engine_version: '0.1.0', generated_at: now,
        metadata: { run_id: runId, source_mode: 'Compliance', source_adapter: 'VSCode', platform: null, catalog_schema_version: 1, network_authorized: false, code_execution_authorized: false },
        repository: target, execution_status: 'completed', discovery: { scan_complete: true, scan_errors: [], technologies: [], ambiguities: [] }, matrix: [], resolver: [],
        execution_plan: { schema_version: 1, repository: target, budgets: {}, permissions: { network: false, code_execution: false }, controls: [control] }, execution_results: [result], findings: [], diagnostics: [],
        summary: { success: 1, fail: 0, error: 0, skipped: 0, critical_errors: 0 }, coverage: { complete: true, planned_controls: 1, executed_controls: 1, omitted_required_controls: 0, dependency_skips: 0, limitations: [] },
        limitations: [], verdict: 'PASS', verdict_reasons: [], advisory: true
    };
}
