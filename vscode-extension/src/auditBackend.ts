import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { prepare, Preparation, stateRoot, validateTarget } from './backend';
import { containsPath, parsePreparation } from './model';
import { AuditState } from './sessionController';
import { DaemonClient } from './daemonClient';

export interface Permissions { network: boolean; code_execution: boolean }
export type AskPermissions = (preparation: Preparation) => Promise<Permissions>;

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
    if (!containsPath(directory, candidate)) { throw new Error('Artefact hors dossier de session.'); }
    const real = await fs.realpath(candidate);
    if (!containsPath(await fs.realpath(directory), real)) { throw new Error('Artefact de session redirige hors dossier.'); }
    return real;
}

async function atomicJson(file: string, value: unknown): Promise<void> {
    const temporary = `${file}.node.tmp`;
    await fs.writeFile(temporary, JSON.stringify(value, null, 2), 'utf8');
    await fs.rename(temporary, file);
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
    daemon: DaemonClient
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
        await daemon.streamEvents(run.run_id, (ev) => {
            try {
                state.receive(ev);
                changed();
            } catch {
                // Ignorer les erreurs d'événement hors séquence en transit
            }
        }, signal);
    } finally {
        signal.removeEventListener('abort', cancelHandler);
    }

    // Récupérer et persister le rapport final
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
    client?: DaemonClient
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
        const fresh = await prepare(source, target, daemon, signal, directory);
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
        await stream(source, target, state, directory, permissions, metadata.catalog_sha256, redaction, changed, signal, daemon);
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
        if (metadata.state === 'incomplete' || metadata.state === 'cancelled') {
            metadata.ended_at = new Date().toISOString();
            await atomicJson(path.join(directory, 'session.json'), metadata);
        }
        changed();
    }
}
