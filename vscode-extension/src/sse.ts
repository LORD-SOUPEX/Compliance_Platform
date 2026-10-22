/** One dispatched Server-Sent Event. */
export interface SseEvent {
    event: string;
    data: string;
    id?: string;
}

/**
 * Incremental parser for text/event-stream (WHATWG). Field state survives chunk
 * boundaries, multi-line `data:` fields are joined with "\n", and CRLF, CR and
 * LF line endings are all accepted, whatever OS the daemon runs on.
 */
export class SseParser {
    private buffer = '';
    private data: string[] = [];
    private event = '';
    private lastId?: string;

    feed(chunk: string): SseEvent[] {
        this.buffer += chunk;
        const events: SseEvent[] = [];
        for (;;) {
            const match = /\r\n|\r|\n/.exec(this.buffer);
            if (!match) {
                break;
            }
            // A trailing CR may be the first half of CRLF split across chunks.
            if (match[0] === '\r' && match.index === this.buffer.length - 1) {
                break;
            }
            const line = this.buffer.slice(0, match.index);
            this.buffer = this.buffer.slice(match.index + match[0].length);
            this.line(line, events);
        }
        return events;
    }

    private line(line: string, events: SseEvent[]): void {
        if (line === '') {
            if (this.data.length) {
                events.push({ event: this.event || 'message', data: this.data.join('\n'), id: this.lastId });
            }
            this.data = [];
            this.event = '';
            return;
        }
        if (line.startsWith(':')) {
            return;
        }
        const colon = line.indexOf(':');
        const field = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? '' : line.slice(colon + 1);
        if (value.startsWith(' ')) {
            value = value.slice(1);
        }
        if (field === 'data') {
            this.data.push(value);
        } else if (field === 'event') {
            this.event = value;
        } else if (field === 'id' && !value.includes('\0')) {
            this.lastId = value;
        }
    }
}
