import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { selectManifestTools } from '../../toolProvision';

const manifest = {
    platforms: {
        'windows-arm64': { tools: { rumdl: { version: 'arm', archive_url: 'arm.zip' } } },
        'windows-x64': { tools: { rumdl: { version: 'x64' }, ruff: { version: '0.16', archive_url: 'ruff.zip' } } },
        'linux-x64': { tools: { ruff: { version: 'linux' } } }
    }
};

test('Windows on ARM borrows x64 tools and keeps its own first', () => {
    const tools = selectManifestTools(manifest, 'windows-arm64', ['rumdl', 'ruff', 'trivy']);
    assert.deepEqual(tools, [
        { command: 'rumdl', version: 'arm', source: 'arm.zip' },
        { command: 'ruff', version: '0.16', source: 'ruff.zip' }
    ]);
});

test('other platforms only use their own entry', () => {
    assert.deepEqual(selectManifestTools(manifest, 'linux-arm64', ['ruff']), []);
    assert.equal(selectManifestTools(manifest, 'linux-x64', ['ruff'])[0].version, 'linux');
});
