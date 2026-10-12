import * as path from 'node:path';
import { runTests } from '@vscode/test-electron';

const extension = path.resolve(__dirname, '../..');
const source = path.resolve(extension, '..');
void runTests({
    vscodeExecutablePath: process.env.COMPLIANCE_VSCODE_EXECUTABLE,
    extensionDevelopmentPath: extension,
    extensionTestsPath: path.join(__dirname, 'host.js'),
    launchArgs: [source, '--user-data-dir', path.join(source, '.tools/state/extension-host-tests'), '--extensions-dir', path.join(source, '.tools/vscode-extension/host-extensions'), '--disable-workspace-trust', '--disable-extensions', '--skip-welcome', '--skip-release-notes']
}).catch(error => { console.error(error); process.exitCode = 1; });
