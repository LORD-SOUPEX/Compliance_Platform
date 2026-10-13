import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { containsPath, parsePreparation, PreparationReport } from './model';

export interface Invocation { executable: string; arguments: string[]; cwd: string }
export interface ProcessResult { code: number | null; stdout: string; stderr: string }
export type Runner = (invocation: Invocation, signal?: AbortSignal) => Promise<ProcessResult>;
export interface Preparation { report: PreparationReport; directory: string; target: string }

export async function stateRoot(source: string): Promise<string> {
    let directory = source;
    for (const segment of ['.tools', 'state', 'runs']) {
        directory = path.join(directory, segment);
        try {
            const entry = await fs.lstat(directory);
            if (entry.isSymbolicLink() || !entry.isDirectory()) { throw new Error('Le dossier d etat ne doit pas etre un lien ou un fichier.'); }
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { throw error; }
            await fs.mkdir(directory);
        }
    }
    return directory;
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

export function planInvocation(source: string, target: string, reportPath: string): Invocation {
    return {
        executable: path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        arguments: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(source, 'scripts', 'compliance-adapter.ps1'),
            '-Adapter', 'VSCode', '-RepositoryPath', target, '-ReportPath', reportPath, '-PlanOnly'],
        cwd: source
    };
}

export const runProcess: Runner = (invocation, signal) => new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('Preparation annulee.')); return; }
    const child = spawn(invocation.executable, invocation.arguments, { cwd: invocation.cwd, shell: false, windowsHide: true });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let failure: Error | undefined;
    const terminate = (message: string) => {
        if (failure) { return; }
        failure = new Error(message);
        if (child.pid && process.platform === 'win32') {
            const killer = spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true });
            killer.on('error', () => child.kill());
        } else { child.kill(); }
    };
    const aborted = () => terminate('Preparation annulee.');
    signal?.addEventListener('abort', aborted, { once: true });
    const timer = setTimeout(() => terminate('Preparation interrompue apres 120 secondes.'), 120000);
    const capture = (chunks: Buffer[], chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > 32 * 1024 * 1024) { terminate('Sorties de preparation superieures a 32 Mio.'); return; }
        chunks.push(chunk);
    };
    child.stdout.on('data', (chunk: Buffer) => capture(stdout, chunk));
    child.stderr.on('data', (chunk: Buffer) => capture(stderr, chunk));
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', aborted); };
    child.on('error', error => { cleanup(); reject(error); });
    child.on('close', code => {
        cleanup();
        if (failure) { reject(failure); }
        else { resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }); }
    });
});

import { DaemonClient } from './daemonClient';

export async function prepare(source: string, target: string, runner: Runner = runProcess, signal?: AbortSignal, sessionDirectory?: string): Promise<Preparation> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await validateTarget(canonicalSource, target);
    const id = randomUUID();
    const directory = sessionDirectory || path.join(await stateRoot(canonicalSource), id);
    if (!sessionDirectory) { await fs.mkdir(directory); }
    const reportPath = path.join(directory, 'plan.json');
    if (!sessionDirectory) { await fs.writeFile(path.join(directory, 'session.json'), JSON.stringify({ id, source: canonicalSource, target: canonicalTarget, created_at: new Date().toISOString(), mode: 'PlanOnly' }, null, 2), 'utf8'); }

    // 1. Tenter l'utilisation prioritaire du démon local Go (si aucun mock runner n'est fourni)
    if (runner === runProcess) {
        try {
            const daemon = new DaemonClient();
            await daemon.ensureDaemon(canonicalSource);
            await daemon.approveWorkspace(canonicalTarget);
            const plan = await daemon.getPlan(canonicalTarget);
            await fs.writeFile(reportPath, JSON.stringify(plan, null, 2), 'utf8');
            return { report: plan, directory, target: canonicalTarget };
        } catch (daemonErr) {
            // En cas d'indisponibilité du démon sous Windows, repli sur PowerShell
            if (process.platform !== 'win32') {
                throw new Error(`Démon compliance local requis sur ${process.platform} : ${daemonErr instanceof Error ? daemonErr.message : String(daemonErr)}`);
            }
        }
    }

    if (process.platform === 'win32') {
        await fs.access(path.join(canonicalSource, 'scripts', 'compliance-adapter.ps1'));
        await fs.access(path.join(canonicalSource, '.config', 'control-catalog.json'));
        try {
            const result = await runner(planInvocation(canonicalSource, canonicalTarget, reportPath), signal);
            await fs.writeFile(path.join(directory, 'preparation.log'), result.stderr, 'utf8');
            if (result.code !== 0 && result.code !== 2) { throw new Error(`Preparation backend en echec (code ${result.code}).`); }
            const report = parsePreparation(await fs.readFile(reportPath, 'utf8'), canonicalTarget);
            if (result.code === 2 && report.discovery.scan_complete) { throw new Error('Erreur technique de preparation ; plan non utilisable.'); }
            return { report, directory, target: canonicalTarget };
        } catch (error) {
            await fs.appendFile(path.join(directory, 'preparation.log'), `\n${error instanceof Error ? error.message : String(error)}\n`, 'utf8');
            throw new Error(`Preparation impossible : ${error instanceof Error ? error.message : String(error)}. Journal : ${path.join(directory, 'preparation.log')}`);
        }
    }
    throw new Error(`Exécution sur ${process.platform} non supportée sans démon Go.`);
}

