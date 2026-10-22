import * as path from 'node:path';

export function isOurDaemonImage(image: string): boolean {
    const base = path.basename(image).toLowerCase();
    return /^compliance(?:-[a-z0-9_]+)*(?:\.exe)?$/.test(base);
}

export function daemonBinaryDirectory(home: string, version: string): string {
    return path.join(home, '.compliance', 'bin', version);
}

export function residualExtensionDirectories(entries: string[], current: string): string[] {
    const currentResolved = path.resolve(current);
    return entries.filter(entry => {
        const base = path.basename(entry);
        return /compliance-platform\.compliance-pipelines/i.test(base) && path.resolve(entry) !== currentResolved;
    });
}

export function shouldReplaceDaemon(runningVersion: string | undefined, expectedVersion: string, image: string): boolean {
    if (!isOurDaemonImage(image) && image !== '') {
        return false;
    }
    return !runningVersion || runningVersion !== expectedVersion;
}
