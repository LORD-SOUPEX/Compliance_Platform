const path = require('node:path');
const { runTests } = require('@vscode/test-electron');

process.env.COMPLIANCE_CDP_PORT = '9333';
process.env.COMPLIANCE_NODE = process.execPath;
runTests({
    extensionDevelopmentPath: path.join(__dirname, '..'),
    extensionTestsPath: path.join(__dirname, '..', '.extension-build', 'src', 'test', 'index.js'),
    launchArgs: ['--disable-extensions', '--remote-debugging-port=9333']
}).catch(error => {
    console.error(error);
    process.exit(1);
});
