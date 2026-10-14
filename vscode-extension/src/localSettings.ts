export interface Inspected<T> {
    globalValue?: T;
    workspaceValue?: T;
    workspaceFolderValue?: T;
}

export function applicationValue<T>(inspected: Inspected<T> | undefined, fallback: T): T {
    if (inspected && inspected.globalValue !== undefined) { return inspected.globalValue; }
    return fallback;
}

export function sessionDirectory(setting: string | undefined, envValue: string | undefined, fallback: string): string {
    const chosen = [setting, envValue, fallback].find(value => typeof value === 'string' && value.trim() !== '');
    return (chosen || fallback).trim();
}

export function parseSessionKeep(value: unknown): { keep: number; error?: string } {
    const number = typeof value === 'number' ? value : typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN;
    if (!Number.isInteger(number) || number < 1 || number > 1000) {
        return { keep: 5, error: `Nombre de sessions hors bornes (1 à 1000) : ${String(value)}. La valeur 5 est utilisée.` };
    }
    return { keep: number };
}
