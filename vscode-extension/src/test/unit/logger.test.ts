import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { daemonStreamLevel, formatInvocation, Logger, masked, redact, redactArgs, relayDaemonEntry, relayLevel } from '../../logger';

function capture(): { lines: string[]; logger: Logger } {
    const lines: string[] = [];
    const sink = (level: string) => (message: string) => { lines.push(`${level} ${message}`); };
    return { lines, logger: new Logger({ trace: sink('trace'), debug: sink('debug'), info: sink('info'), warn: sink('warn'), error: sink('error') }) };
}

test('redact masks key=value secrets, Bearer headers and URL credentials', () => {
    const text = redact('HTTPS_PROXY=http://me:pw@proxy:3128 token=abc Authorization: Bearer xyz');
    assert.ok(!/pw@|abc|xyz/.test(text), text);
    assert.ok(text.includes('proxy:3128'));
});

test('redactArgs masks the value of a sensitive flag in both forms', () => {
    assert.deepEqual(redactArgs(['-registry-token', 'abc', '--password=x', '-tool', 'ruff']), ['-registry-token', masked, `--password=${masked}`, '-tool', 'ruff']);
});

test('child loggers prefix run and control, and never print secrets', () => {
    const { lines, logger } = capture();
    logger.child({ runId: '0123456789abcdef', controlId: 'python/lint/ruff/.' }).info('exécuté OK', { ms: 12, api_key: 'zzz' });
    assert.equal(lines.length, 1);
    assert.ok(lines[0].startsWith('info [run 01234567] [python/lint/ruff/.] exécuté OK ms=12'), lines[0]);
    assert.ok(!lines[0].includes('zzz'));
});

test('daemon records are shifted one level down and keep their correlation', () => {
    assert.equal(relayLevel('info'), 'debug');
    assert.equal(relayLevel('debug'), 'trace');
    assert.equal(relayLevel('error'), 'error');
    assert.equal(daemonStreamLevel(1), 'debug');
    assert.equal(daemonStreamLevel(3), 'warn');
    const { lines, logger } = capture();
    relayDaemonEntry(logger, { level: 'warn', msg: 'tool_probe', attrs: { run_id: 'abcdef0123456789', command: 'trivy' } });
    assert.deepEqual(lines, ['warn [run abcdef01] démon tool_probe command=trivy']);
});

test('formatInvocation quotes arguments and lists the environment delta', () => {
    const text = formatInvocation({ executable: 'C:/tools/trivy.exe', args: ['config', 'my dir'], cwd: 'E:/t', env_added: { NO_COLOR: '1' }, env_removed: ['TRIVY_CONFIG'], timeout_ms: 300000, stdout_path: 'logs/a.stdout.log', stderr_path: 'logs/a.stderr.log' });
    assert.ok(text.startsWith('exec C:/tools/trivy.exe config "my dir"'), text);
    assert.ok(text.includes('env-   : TRIVY_CONFIG'));
    assert.ok(text.includes('timeout: 300 s'));
});
