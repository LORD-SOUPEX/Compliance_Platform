export class Cdp {
    private id = 0;
    private readonly pending = new Map<number, (value: { result?: { result?: { value?: unknown } }; error?: { message?: string } }) => void>();
    readonly events: Array<{ method?: string; params?: unknown }> = [];
    private constructor(private readonly socket: WebSocket) {
        socket.addEventListener('message', event => {
            void Promise.resolve(event.data).then(async data => {
            const text = typeof data === 'string' ? data : await (data as Blob).text();
            const message = JSON.parse(text) as { id?: number; method?: string; params?: unknown; result?: { result?: { value?: unknown } }; error?: { message?: string } };
            if (message.id && this.pending.has(message.id)) {
                this.pending.get(message.id)!({ result: message.result, error: message.error });
                this.pending.delete(message.id);
            } else if (message.method) {
                this.events.push({ method: message.method, params: message.params });
            }
            });
        });
    }
    static async connect(webSocketUrl: string): Promise<Cdp> {
        const socket = new WebSocket(webSocketUrl);
        await new Promise<void>((resolve, reject) => {
            socket.addEventListener('open', () => resolve(), { once: true });
            socket.addEventListener('error', () => reject(new Error(`CDP websocket refusé : ${webSocketUrl}`)), { once: true });
        });
        return new Cdp(socket);
    }
    async send(method: string, params: Record<string, unknown> = {}): Promise<{ result?: { result?: { value?: unknown } } }> {
        const id = ++this.id;
        const response = new Promise<{ result?: { result?: { value?: unknown } }; error?: { message?: string } }>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`CDP ${method} sans réponse`)), 15000);
            this.pending.set(id, value => { clearTimeout(timer); resolve(value); });
        });
        this.socket.send(JSON.stringify({ id, method, params }));
        const settled = await response;
        if (settled.error) { throw new Error(settled.error.message || method); }
        return settled;
    }
    close(): void { this.socket.close(); }
}
