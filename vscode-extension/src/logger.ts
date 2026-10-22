// Structured logging for the extension. This module does not import vscode:
// extension.ts hands it a LogOutputChannel, scripts/debug-check.js a plain sink.

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Record<string, unknown>;

/** The subset of vscode.LogOutputChannel the logger writes to. */
export interface LogSink {
    trace(message: string): void;
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
}

export interface LogContext { runId?: string; controlId?: string }

export const masked = '<masqué>';
const secretKey = '[A-Za-z0-9_.-]*(?:token|secret|password|passwd|passphrase|credential|api_?key|access_?key|private_?key|authorization)[A-Za-z0-9_.-]*';
const keyValue = new RegExp(`\\b(${secretKey})(\\s*[=:]\\s*)("[^"]*"|'[^']*'|[^\\s,;&]+)`, 'gi');
const bearer = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/g;
const userinfo = /([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/@\s]+@/g;
const secretFlag = new RegExp(`^-{1,2}${secretKey}$`, 'i');

/** Masks credentials in free text: key=value pairs, Bearer/Basic headers, URL user info. */
export function redact(text: string): string {
    // Bearer first: "Authorization: Bearer x" must not leave x behind once the key rule took "Bearer".
    return text.replace(bearer, `$1 ${masked}`).replace(keyValue, `$1$2${masked}`).replace(userinfo, `$1${masked}@`);
}

/** Masks the value that follows a sensitive flag ("-registry-token x" or "--token=x"). */
export function redactArgs(args: readonly string[]): string[] {
    const out: string[] = [];
    let hideNext = false;
    for (const arg of args) {
        if (hideNext) { out.push(masked); hideNext = false; continue; }
        const [name] = arg.split('=', 1);
        if (arg.startsWith('-') && secretFlag.test(name)) {
            if (arg.includes('=')) { out.push(`${name}=${masked}`); } else { out.push(arg); hideNext = true; }
            continue;
        }
        out.push(redact(arg));
    }
    return out;
}

/** Quotes an argument for display only; nothing is executed from this text. */
export function displayArg(arg: string): string {
    return /^[A-Za-z0-9_./\\:=@%+,-]+$/.test(arg) ? arg : `"${arg.replace(/"/g, '\\"')}"`;
}

export function commandLine(executable: string, args: readonly string[]): string {
    return [executable, ...redactArgs(args)].map(displayArg).join(' ');
}

function formatValue(value: unknown): string {
    if (value === undefined || value === null) { return 'null'; }
    if (value instanceof Error) { return displayArg(value.message); }
    if (typeof value === 'string') { return displayArg(value); }
    if (typeof value === 'number' || typeof value === 'boolean') { return String(value); }
    try { return JSON.stringify(value); } catch { return String(value); }
}

export function formatFields(fields?: LogFields): string {
    if (!fields) { return ''; }
    return Object.entries(fields).filter(([, value]) => value !== undefined).map(([key, value]) => `${key}=${formatValue(value)}`).join(' ');
}

export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

export class Logger {
    constructor(private readonly sink: LogSink, private readonly context: LogContext = {}) {}

    child(context: LogContext): Logger { return new Logger(this.sink, { ...this.context, ...context }); }

    trace(message: string, fields?: LogFields): void { this.write('trace', message, fields); }
    debug(message: string, fields?: LogFields): void { this.write('debug', message, fields); }
    info(message: string, fields?: LogFields): void { this.write('info', message, fields); }
    warn(message: string, fields?: LogFields): void { this.write('warn', message, fields); }
    error(message: string, fields?: LogFields): void { this.write('error', message, fields); }

    write(level: LogLevel, message: string, fields?: LogFields): void {
        const prefix = [this.context.runId ? `[run ${this.context.runId.slice(0, 8)}]` : '', this.context.controlId ? `[${this.context.controlId}]` : ''].filter(Boolean).join(' ');
        const text = redact([prefix, message, formatFields(fields)].filter(Boolean).join(' '));
        try { this.sink[level](text); } catch { /* channel disposed during shutdown */ }
    }

    /** Logs a process this extension launches itself. */
    command(label: string, executable: string, args: readonly string[], cwd?: string): void {
        this.debug(`exec ${label}`, { cmd: commandLine(executable, args), cwd });
    }
}

/** Swallows everything; default before activation and in unit tests. */
export const silentLogger = new Logger({ trace() {}, debug() {}, info() {}, warn() {}, error() {} });

/** One record of the daemon journal, as relayed by GET /api/v1/logs/stream. */
export interface DaemonLogEntry { time?: string; level?: string; msg?: string; attrs?: LogFields }

/**
 * Daemon records are shifted one level down so the channel's default (Info) shows
 * only extension summaries plus daemon warnings and errors.
 */
export function relayLevel(daemonLevel: string | undefined): LogLevel {
    switch (daemonLevel) {
        case 'error': return 'error';
        case 'warn': return 'warn';
        case 'info': return 'debug';
        default: return 'trace';
    }
}

/**
 * Lowest daemon level worth streaming for a VS Code log level
 * (vscode.LogLevel: Off=0, Trace=1, Debug=2, Info=3, Warning=4, Error=5).
 */
export function daemonStreamLevel(channelLevel: number): 'debug' | 'info' | 'warn' | 'error' {
    if (channelLevel <= 1) { return 'debug'; }
    if (channelLevel === 2) { return 'info'; }
    if (channelLevel === 5) { return 'error'; }
    return 'warn';
}

export function relayDaemonEntry(log: Logger, entry: DaemonLogEntry): void {
    const attrs = { ...(entry.attrs || {}) };
    const runId = typeof attrs.run_id === 'string' ? attrs.run_id : undefined;
    const controlId = typeof attrs.control_id === 'string' ? attrs.control_id : undefined;
    delete attrs.run_id;
    delete attrs.control_id;
    log.child({ runId, controlId }).write(relayLevel(entry.level), `démon ${entry.msg || ''}`.trim(), attrs);
}

/** Invocation record from the daemon (report.Invocation). */
export interface InvocationRecord {
    executable?: string; args?: string[]; raw_command_line?: string | null; cwd?: string;
    env_added?: Record<string, string>; env_removed?: string[] | null; timeout_ms?: number;
    stdout_path?: string | null; stderr_path?: string | null;
}

/** Multi-line text for the channel: command, cwd, environment delta, stream files. */
export function formatInvocation(record: InvocationRecord): string {
    const lines = [`exec ${record.raw_command_line || commandLine(record.executable || '?', record.args || [])}`];
    if (record.cwd) { lines.push(`    cwd    : ${record.cwd}`); }
    const added = Object.entries(record.env_added || {});
    if (added.length) { lines.push(`    env+   : ${added.map(([key, value]) => `${key}=${displayArg(value)}`).join(' ')}`); }
    if (record.env_removed?.length) { lines.push(`    env-   : ${record.env_removed.join(' ')}`); }
    if (record.timeout_ms) { lines.push(`    timeout: ${Math.round(record.timeout_ms / 1000)} s`); }
    if (record.stdout_path) { lines.push(`    sorties: ${record.stdout_path}, ${record.stderr_path || ''}`); }
    return lines.join('\n');
}
