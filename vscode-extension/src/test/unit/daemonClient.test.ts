import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { DaemonClient, tailFile, waitForExit } from '../../daemonClient';

async function serve(handler: http.RequestListener): Promise<{ client: DaemonClient; close: () => Promise<void> }> {
    const server = http.createServer(handler);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const client = new DaemonClient(await fs.mkdtemp(path.join(os.tmpdir(), 'icp-unit-')));
    client.setConnection((server.address() as AddressInfo).port, 'token');
    return {
        client,
        close: () =>
            new Promise<void>(resolve => {
                server.closeAllConnections();
                server.close(() => resolve());
            })
    };
}

function sse(res: http.ServerResponse, chunks: string[]): void {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    let index = 0;
    const next = () => {
        if (index >= chunks.length) {
            res.end();
            return;
        }
        res.write(chunks[index++]);
        setTimeout(next, 5);
    };
    next();
}

test('session events split across packets are delivered, and the stream stops on a terminal event', async () => {
    const { client, close } = await serve((_req, res) =>
        sse(res, [
            'id: 1\nevent: session_sta',
            'rted\ndata: {"sequence":1}\n\n',
            'id: 2\nevent: session_completed\ndata: {"sequence":2}\n\n',
            'id: 3\nevent: never\ndata: {"sequence":3}\n\n'
        ])
    );
    const seen: unknown[] = [];
    try {
        await client.streamEvents('run', event => {
            seen.push(event);
        });
        assert.deepEqual(seen, [
            { sequence: 1, type: 'session_started', id: '1' },
            { sequence: 2, type: 'session_completed', id: '2' }
        ]);
    } finally {
        await close();
    }
});

test('an exception raised by the event handler rejects the stream instead of escaping', async () => {
    const { client, close } = await serve((_req, res) => sse(res, ['data: {"type":"control_started"}\n\n', ': still open\n\n']));
    try {
        await assert.rejects(
            client.streamEvents('run', () => {
                throw new Error('Controle du plan invalide');
            }),
            /Controle du plan invalide/
        );
    } finally {
        await close();
    }
});

test('a daemon that never answers fails the request after its timeout', async () => {
    const { client, close } = await serve(() => {
        /* never answers */
    });
    try {
        const started = Date.now();
        await assert.rejects(client.getHealth(), /sans réponse du démon/);
        assert.ok(Date.now() - started < 10000);
    } finally {
        await close();
    }
});

test('waitForExit sees a process end on every OS', async () => {
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 200)']);
    assert.ok(child.pid);
    assert.equal(await waitForExit(child.pid, 10000), true);
    assert.equal(await waitForExit(2 ** 22 + 12345, 300), true);
});

test('tailFile returns the last lines and never throws', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'icp-tail-'));
    const file = path.join(dir, 'log.txt');
    await fs.writeFile(file, Array.from({ length: 30 }, (_, index) => `line ${index}`).join('\r\n'));
    assert.equal(await tailFile(file, 2), 'line 28\nline 29');
    assert.equal(await tailFile(path.join(dir, 'absent.txt')), '');
});
