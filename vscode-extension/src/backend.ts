import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { containsPath, PreparationReport } from './model';
import { DaemonClient } from './daemonClient';

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

export async function prepare(source: string, target: string, client?: DaemonClient, _signal?: AbortSignal, sessionDirectory?: string): Promise<Preparation> {
    const canonicalSource = await fs.realpath(source);
    const canonicalTarget = await validateTarget(canonicalSource, target);
    const id = randomUUID();
    const directory = sessionDirectory || path.join(await stateRoot(canonicalSource), id);
    if (!sessionDirectory) { await fs.mkdir(directory); }
    const reportPath = path.join(directory, 'plan.json');
    if (!sessionDirectory) {
        await fs.writeFile(path.join(directory, 'session.json'), JSON.stringify({ id, source: canonicalSource, target: canonicalTarget, created_at: new Date().toISOString(), mode: 'PlanOnly' }, null, 2), 'utf8');
    }

    const daemon = client || new DaemonClient();
    try {
        await daemon.ensureDaemon(canonicalSource);
        await daemon.approveWorkspace(canonicalTarget);
        const plan = await daemon.getPlan(canonicalTarget);
        await fs.writeFile(reportPath, JSON.stringify(plan, null, 2), 'utf8');
        return { report: plan, directory, target: canonicalTarget };
    } catch (daemonErr) {
        const message = daemonErr instanceof Error ? daemonErr.message : String(daemonErr);
        await fs.appendFile(path.join(directory, 'preparation.log'), `\n${message}\n`, 'utf8').catch(() => {});
        throw new Error(`Preparation impossible : ${message}. Journal : ${path.join(directory, 'preparation.log')}`);
    }
}
