const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const vsix = process.argv[2];
if (!vsix || !fs.existsSync(vsix)) {
    console.error('Usage: npm run reinstall -- chemin/du/fichier.vsix');
    process.exit(1);
}
require('./uninstall.js');
const code = process.env.VSCODE_CLI || 'code';
const id = 'compliance-platform.compliance-local-pipelines';
spawnSync(code, ['--uninstall-extension', id], { stdio: 'inherit' });
const extensions = path.join(process.env.USERPROFILE || os.homedir(), '.vscode', 'extensions');
if (fs.existsSync(extensions)) {
    for (const name of fs.readdirSync(extensions)) {
        if (/^compliance-platform\.compliance-local-pipelines/i.test(name)) {
            fs.rmSync(path.join(extensions, name), { recursive: true, force: true });
        }
    }
}
const installed = spawnSync(code, ['--install-extension', path.resolve(vsix), '--force'], { stdio: 'inherit' });
process.exit(installed.status || 0);
