const port = process.env.COMPLIANCE_CDP_PORT || '9333';

async function main() {
    const version = await fetch(`http://127.0.0.1:${port}/json/version`).then(response => response.json());
    const socket = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, { once: true });
        socket.addEventListener('error', () => reject(new Error('browser websocket')), { once: true });
    });
    await call(socket, 'Target.setDiscoverTargets', { discover: true });
    const targets = await call(socket, 'Target.getTargets');
    const infos = targets.targetInfos || [];
    console.error(infos.map(item => `${item.type} ${item.url || item.title}`).join('\n'));
    let opened = false;
    let clicked = false;
    for (const info of infos) {
        if (!['page', 'iframe', 'webview', 'other'].includes(info.type)) { continue; }
        const attached = await call(socket, 'Target.attachToTarget', { targetId: info.targetId, flatten: true });
        const sessionId = attached.sessionId;
        let text = '';
        try {
            await call(socket, 'Runtime.enable', {}, sessionId);
            const probed = await call(socket, 'Runtime.evaluate', { expression: `(() => { const own = document.body ? document.body.innerText.slice(0, 400) : ''; const nested = [...document.querySelectorAll('iframe')].map(frame => { try { return frame.contentDocument && frame.contentDocument.body ? frame.contentDocument.body.innerText.slice(0, 400) : 'empty'; } catch (error) { return 'blocked'; } }).join(' || '); return own + ' ## ' + nested; })()`, returnByValue: true }, sessionId);
            text = String(probed.result?.value ?? '');
            console.error('probe', info.type, text.slice(0, 300));
        } catch (error) { console.error('probe-error', info.type, error.message); continue; }
        if (!text.includes('4 321 ms') && !text.includes('Contrôles exécutés') && !text.includes('JavaScript lint') && !text.includes('ICP COMPLIANCE')) { continue; }
        const inner = '[...document.querySelectorAll("iframe")].map(frame => frame.contentDocument).find(doc => doc && doc.body && doc.body.innerText.includes("4 321 ms"))';
        const fold = await call(socket, 'Runtime.evaluate', { expression: `(() => { const doc = ${inner}; if (!doc) return "missing"; if (doc.querySelector("h2") && [...doc.querySelectorAll("h2")].some(node => node.textContent.trim() === "Findings")) return "findings-section"; const node = doc.querySelector("details.file-node"); if (!node) return "none"; return node.open ? "open" : "closed"; })()`, returnByValue: true }, sessionId);
        if (fold.result?.value !== 'closed') { throw new Error('depliant fichier ' + fold.result?.value); }
        await call(socket, 'Runtime.evaluate', { expression: `(() => { const doc = ${inner}; const node = doc.querySelector("details.file-node"); node.querySelector("summary").click(); })()`, returnByValue: true }, sessionId);
        const after = await call(socket, 'Runtime.evaluate', { expression: `(() => { const doc = ${inner}; const node = doc.querySelector("details.file-node"); const hero = getComputedStyle(doc.querySelector(".hero")); const figure = getComputedStyle(doc.querySelector(".kpi strong")); const title = doc.querySelector("h1") ? doc.querySelector("h1").textContent : ""; return JSON.stringify({ open: node.open, title, display: figure.display, fontSize: figure.fontSize, background: hero.backgroundColor, file: node.querySelector("code") ? node.querySelector("code").textContent : "" }); })()`, returnByValue: true }, sessionId);
        const visual = JSON.parse(String(after.result?.value || '{}'));
        if (visual.open !== true || visual.title !== 'ICP COMPLIANCE' || visual.display !== 'block' || visual.fontSize !== '32px' || visual.background !== 'rgb(17, 22, 34)' || visual.file !== 'infra/vpc/main.tf') {
            throw new Error('rendu ' + JSON.stringify(visual));
        }
        opened = true;
        const outputs = await call(socket, 'Runtime.evaluate', { expression: `(() => { const doc = [...document.querySelectorAll("iframe")].map(frame => frame.contentDocument).find(item => item && item.querySelector(".control")); if (!doc) return "missing"; if (doc.body.innerText.includes("Actualiser")) return "actualiser"; if (!doc.body.innerText.includes("4 321 ms")) return "duration"; if (!doc.body.innerText.includes("ICP")) return "title"; const controls = [...doc.querySelectorAll(".control")]; const buttons = [...doc.querySelectorAll('.control button[data-action="output"]')]; const ids = buttons.map(button => button.getAttribute("data-control-id")); if (doc.querySelector("article.finding")) return "flat-findings"; if (controls.length < 2 || buttons.length !== controls.length || ids.some(id => !id) || new Set(ids).size !== ids.length) return "count " + buttons.length + "/" + controls.length; const finding = doc.querySelector('button[data-action="finding"]'); if (!finding) return "finding-missing"; finding.click(); buttons.forEach(button => button.click()); return "ok"; })()`, returnByValue: true }, sessionId);
        if (outputs.result?.value !== 'ok') { throw new Error('sorties ' + outputs.result?.value); }
        for (const action of ['pick', 'raw', 'folder']) {
            const result = await call(socket, 'Runtime.evaluate', { expression: `(() => { const doc = [...document.querySelectorAll("iframe")].map(frame => frame.contentDocument).find(item => item && item.querySelector(".control")); const button = doc && doc.querySelector('button[data-action="${action}"]'); if (!button) return false; button.click(); return true; })()`, returnByValue: true }, sessionId);
            if (result.result?.value !== true) { throw new Error('bouton absent ' + action); }
        }
        clicked = true;
        break;
    }
    if (!opened || !clicked) { throw new Error('page du rapport introuvable dans les cibles CDP'); }
    console.log('webview-clicks-ok');
    socket.close();
}

let seq = 0;
const pending = new Map();
let socketRef;

function call(socket, method, params, sessionId) {
    socketRef = socket;
    if (!socket.__listening) {
        socket.__listening = true;
        socket.addEventListener('message', event => {
            const message = JSON.parse(String(event.data));
            if (message.id && pending.has(message.id)) {
                pending.get(message.id)(message);
                pending.delete(message.id);
            }
        });
    }
    const id = ++seq;
    const body = { id, method, params };
    if (sessionId) { body.sessionId = sessionId; }
    socket.send(JSON.stringify(body));
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout ' + method)), 8000);
        pending.set(id, message => {
            clearTimeout(timer);
            if (message.error) { reject(new Error(message.error.message || method)); return; }
            resolve(message.result || {});
        });
    });
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
