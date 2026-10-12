declare function acquireVsCodeApi(): { postMessage(message: unknown): void };
const reportApi = acquireVsCodeApi();
document.addEventListener('click', event => {
    const element = event.target instanceof Element ? event.target.closest<HTMLButtonElement>('button[data-action]') : null;
    if (!element || element.disabled) { return; }
    const action = element.dataset.action;
    const message: Record<string, unknown> = { schema_version: 1, action };
    if (action === 'output') { message.controlId = element.dataset.controlId; }
    if (action === 'finding') { message.index = Number(element.dataset.findingIndex); }
    reportApi.postMessage(message);
});
window.addEventListener('message', event => {
    const message: unknown = event.data;
    if (!message || typeof message !== 'object' || !('type' in message) || message.type !== 'focus' || !('id' in message) || typeof message.id !== 'string') { return; }
    const target = document.getElementById(message.id);
    if (!target) { return; }
    let parent: HTMLElement | null = target;
    while (parent) { if (parent instanceof HTMLDetailsElement) { parent.open = true; } parent = parent.parentElement; }
    target.scrollIntoView({ block: 'start' });
});
reportApi.postMessage({ schema_version: 1, action: 'ready' });
