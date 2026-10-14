const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const stateDir = process.env.COMPLIANCE_STATE_DIR || path.join(os.homedir(), '.compliance');
const stateFile = path.join(stateDir, 'daemon.json');

function imageOf(pid) {
    if (process.platform === 'linux') {
        try { return fs.readlinkSync(`/proc/${pid}/exe`); } catch { return ''; }
    }
    if (process.platform === 'darwin') {
        const result = spawnSync('ps', ['-p', String(pid), '-o', 'comm='], { encoding: 'utf8', windowsHide: true });
        return (result.stdout || '').trim();
    }
    const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").ExecutablePath`], { encoding: 'utf8', windowsHide: true });
    return (result.stdout || '').trim();
}

function ours(image) {
    return /^compliance(?:-[a-z0-9_]+)*(?:\.exe)?$/i.test(path.basename(image || ''));
}

function killPid(pid, force) {
    const image = imageOf(pid);
    if (image && !ours(image)) { return; }
    if (!image && !force) { return; }
    try { process.kill(pid); } catch { /* déjà arrêté */ }
}

function listed() {
    if (process.platform !== 'win32') { return []; }
    const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'compliance*.exe' } | ForEach-Object { $_.ProcessId.ToString() + '|' + $_.ExecutablePath }"], { encoding: 'utf8', windowsHide: true });
    return String(result.stdout || '').split(/\r?\n/).map(line => {
        const [pid, image] = line.split('|');
        return { pid: Number(pid), image: (image || '').trim() };
    }).filter(row => Number.isInteger(row.pid) && row.pid > 0 && row.image);
}

function requestShutdown(state) {
    return new Promise(resolve => {
        let token = '';
        try { token = fs.readFileSync(state.token_path, 'utf8').trim(); } catch { resolve(); return; }
        const request = http.request({ host: '127.0.0.1', port: state.port, path: '/api/v1/shutdown', method: 'POST', timeout: 500, headers: { Authorization: `Bearer ${token}` } }, response => { response.resume(); resolve(); });
        request.on('timeout', () => { request.destroy(); resolve(); });
        request.on('error', () => resolve());
        request.end();
    });
}

async function main() {
    try {
        const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        await requestShutdown(state);
        killPid(state.pid, true);
    } catch { /* pas de démon */ }

    const home = stateDir.toLowerCase();
    for (const row of listed()) {
        const image = row.image.toLowerCase();
        const staged = image.includes(home) || (image.includes('.vscode') && image.includes('compliance-platform'));
        if (ours(row.image) && staged) {
            try { process.kill(row.pid); } catch { /* déjà arrêté */ }
        }
    }

    fs.rmSync(path.join(stateDir, 'bin'), { recursive: true, force: true });
}

main();
