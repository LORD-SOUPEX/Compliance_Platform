import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { SseParser } from '../../sse';

test('fields survive chunk boundaries and CRLF split in two', () => {
    const parser = new SseParser();
    const events = [
        ...parser.feed('id: 7\r\nevent: control_sta'),
        ...parser.feed('rted\r\ndata: {"a":'),
        ...parser.feed('1}\r'),
        ...parser.feed('\n\r\n')
    ];
    assert.deepEqual(events, [{ event: 'control_started', data: '{"a":1}', id: '7' }]);
});

test('multi-line data is joined, comments ignored, default event is message', () => {
    const parser = new SseParser();
    assert.deepEqual(parser.feed(': ping\n\ndata: x\ndata: y\n\n'), [{ event: 'message', data: 'x\ny', id: undefined }]);
});

test('an event without data is not dispatched and the id persists', () => {
    const parser = new SseParser();
    assert.deepEqual(parser.feed('id: 3\nevent: noop\n\ndata: z\n\n'), [{ event: 'message', data: 'z', id: '3' }]);
});
