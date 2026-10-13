import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { planInvocation, prepare, Preparation, stateRoot, validateTarget } from './backend';
import { containsPath, parsePreparation } from './model';
import { AuditState } from './sessionController';
import { DaemonClient } from './daemonClient';

export interface Permissions { network: boolean; code_execution: boolean }
export type AskPermissions = (preparation: Preparation) => Promise<Permissions>;

export async function validateSource(source: string): Promise<void> {
    if (process.platform !== 'win32') {
        // Sur Linux et macOS, la validation s'appuie sur le catalogue et les binaires multi-OS
        await fs.access(path.join(source, '.config/control-catalog.json'));
        return;
    }
    const index = JSON.parse((await fs.readFile(path.join(source, '.tools/runtime/index.json'), 'utf8')).replace(/^\uFEFF/, ''));
    const runtime = index.platforms?.['windows-x64'];
    if (index.schema_version !== 1 || runtime?.status !== 'qualified') { throw new Error('Runtime de la Pipeline source invalide.'); }
    await fs.access(path.join(source, 'src/Compliance.Session.psm1'));
    const lock = createHash('sha256').update(await fs.readFile(path.join(source, 'requirements-dev.lock'))).digest('hex');
    if (runtime.python?.dependency_lock_sha256 !== lock) { throw new Error('Lock runtime modifie ; Doctor requis.'); }
    const hashMatches = async (file: string, expected: unknown) => {
        if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/i.test(expected) ||
            createHash('sha256').update(await fs.readFile(file)).digest('hex') !== expected.toLowerCase()) { throw new Error('Integrite du runtime invalide ; Doctor requis.'); }
    };
    const pythonExecutable = (await fs.stat(runtime.python.executable).catch(() => null)) ?
        runtime.python.executable :
        path.join(source, '.tools/python', path.basename(runtime.python.executable));
    await hashMatches(pythonExecutable, runtime.python.executable_sha256);
    await hashMatches(path.join(source, '.venv/Scripts/python.exe'), runtime.python.environment_executable_sha256);
    if (!Array.isArray(runtime.tools) || !Array.isArray(runtime.powershell_modules)) { throw new Error('Inventaire runtime incomplet.'); }
    for (const tool of runtime.tools.filter((entry: { active: boolean }) => entry.active)) {
        const artifact = path.resolve(source, '.tools/runtime', tool.path);
        if (!containsPath(path.join(source, '.tools/runtime'), artifact) || tool.status !== 'qualified') { throw new Error('Artefact runtime hors cache ou non qualifie.'); }
        await hashMatches(artifact, tool.sha256);
        await hashMatches(path.join(source, '.tools/bin', path.basename(tool.path)), tool.sha256);
    }
    for (const module of runtime.powershell_modules) {
        const manifest = path.resolve(source, module.path, `${module.name}.psd1`);
        if (!containsPath(path.join(source, '.tools/powershell-modules'), manifest)) { throw new Error('Module runtime hors cache.'); }
        await hashMatches(manifest, module.manifest_sha256);
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

async function stream(source: string, target: string, state: AuditState, directory: string, permissions: Permissions, hash: string, redaction: string | undefined, changed: () => void, signal: AbortSignal): Promise<void> {
    // 1. Tenter le pilotage via le démon HTTP/SSE local
    try {
        const daemon = new DaemonClient();
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
        return;
    } catch (daemonErr) {
        if (process.platform !== 'win32') {
            throw new Error(`Démon compliance local requis sur ${process.platform} : ${daemonErr instanceof Error ? daemonErr.message : String(daemonErr)}`);
        }
        // Repli PowerShell sous Windows pendant la transition
    }

    const invocation = planInvocation(source, target, path.join(directory, 'compliance-report.json'));
    invocation.arguments.pop();
    invocation.arguments.push('-ProgressRunId', state.runId, '-ExpectedCatalogSha256', hash);
    if (permissions.network) { invocation.arguments.push('-AllowNetwork'); }
    if (permissions.code_execution) { invocation.arguments.push('-AllowCodeExecution'); }
    if (redaction) { invocation.arguments.push('-ReportRedactionPattern', redaction); }
    await new Promise<void>((resolve, reject) => {
        const child = spawn(invocation.executable, invocation.arguments, { cwd: source, shell: false, windowsHide: true });
        const decoder = new StringDecoder('utf8');
        let pending = ''; let stderr = ''; let failure: Error | undefined; let killTimer: NodeJS.Timeout | undefined;
        const cancel = () => {
            void fs.writeFile(path.join(directory, 'cancel'), '', 'utf8').catch(error => { failure = error; });
            if (!killTimer) { killTimer = setTimeout(() => {
                if (child.pid) {
                    const killer = spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true });
                    killer.on('error', () => child.kill());
                }
                failure = failure || new Error('Backend interrompu apres expiration du delai d annulation.');
            }, 10000); }
        };
        const accept = (line: string) => {
            if (!line.trim() || failure) { return; }
            try { state.receive(JSON.parse(line)); changed(); }
            catch (error) { failure = error instanceof Error ? error : new Error(String(error)); cancel(); }
        };
        signal.addEventListener('abort', cancel, { once: true });
        if (signal.aborted) { cancel(); }
        child.stdout.on('data', (chunk: Buffer) => {
            pending += decoder.write(chunk);
            if (pending.length > 16 * 1024 * 1024) { failure = new Error('Evenement superieur a 16 Mio.'); pending = ''; cancel(); return; }
            let newline: number;
            while ((newline = pending.indexOf('\n')) >= 0) { const line = pending.slice(0, newline); pending = pending.slice(newline + 1); accept(line); }
        });
        child.stderr.on('data', (chunk: Buffer) => { stderr = (stderr + chunk.toString('utf8')).slice(-65536); });
        const cleanup = () => { signal.removeEventListener('abort', cancel); if (killTimer) { clearTimeout(killTimer); } };
        child.on('error', error => { cleanup(); reject(error); });
        child.on('close', code => {
            cleanup(); pending += decoder.end();
            if (pending.trim()) { failure = failure || new Error('Evenement final tronque.'); }
            void fs.writeFile(path.join(directory, 'logs/backend.log'), stderr, 'utf8').then(() => {
                if (failure) { reject(failure); }
                else if (!state.terminal || ![0, 1, 2].includes(code ?? -1)) { reject(new Error(`Backend disparu sans fin fiable (code ${code}).`)); }
                else { resolve(); }
            }, reject);
        });
    });
}

export async function audit(source: string, state: AuditState, ask: AskPermissions, changed: () => void, signal: AbortSignal, redaction?: string): Promise<string> {
    await validateSource(source);
    const target = await validateTarget(source, state.target);
    const directory = path.join(await stateRoot(source), state.runId);
    await fs.mkdir(directory);
    await fs.mkdir(path.join(directory, 'logs'));
    const metadata = { schema_version: 1, run_id: state.runId, target, pipeline_source: source, started_at: new Date().toISOString(), ended_at: null as string | null,
        state: 'preparing', permissions: { network: false, code_execution: false }, catalog_sha256: '', report_path: path.join(directory, 'compliance-report.json') };
    await atomicJson(path.join(directory, 'session.json'), metadata);
    await fs.writeFile(path.join(directory, 'heartbeat'), '', 'utf8');
    const heartbeat = setInterval(() => { void fs.writeFile(path.join(directory, 'heartbeat'), '', 'utf8').catch(() => undefined); }, 1000);
    try {
        const fresh = await prepare(source, target, undefined, signal, directory);
        if (!fresh.report.discovery.scan_complete) { throw new Error('Discovery incomplete ; audit interdit.'); }
        const permissions = await ask(fresh);
        if (signal.aborted) { state.status = 'Skipped'; state.reason = { code: 'session_interrupted', message: 'Session annulee avant execution.' }; state.terminal = true; metadata.state = 'cancelled'; return directory; }
        metadata.permissions = permissions; metadata.catalog_sha256 = fresh.report.metadata.catalog_sha256 || '';
        await atomicJson(path.join(directory, 'session.json'), metadata);
        await stream(source, target, state, directory, permissions, metadata.catalog_sha256, redaction, changed, signal);
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
            if (!state.snapshot || JSON.stringify(report.execution_plan) !== JSON.stringify(state.snapshot.execution_plan)) { throw new Error('Rapport et snapshot divergent.'); }
        } else if (state.status !== 'Error') { throw new Error('Rapport de session absent.'); }
        return directory;
    } catch (error) {
        state.fail(error instanceof Error ? error.message : String(error));
        metadata.state = 'incomplete';
        throw error;
    } finally {
        clearInterval(heartbeat);
        if (!state.terminal) { state.fail('Session sans evenement terminal.'); metadata.state = 'incomplete'; }
        if (state.status === 'Skipped') { metadata.state = 'cancelled'; }
        if (metadata.state === 'incomplete' || metadata.state === 'cancelled') { metadata.ended_at = new Date().toISOString(); await atomicJson(path.join(directory, 'session.json'), metadata); }
        changed();
    }
}
