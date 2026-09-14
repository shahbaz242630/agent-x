import { createLogger } from '@agentx/platform/observability';
import { findLeaks, LogCapture, SequentialIds } from '@agentx/testing';
import type { Socket } from 'node:net';
import { describe, expect, it } from 'vitest';

import { answerClientError, CLIENT_ERROR } from './client-errors.ts';
import { errorBody } from './errors.ts';
import { SECURITY_HEADERS } from './security-headers.ts';

const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const CRLF = String.fromCharCode(13, 10);

/** The parts of a socket the handler uses, recording what it does. */
function fakeSocket(state: { writable?: boolean; destroyed?: boolean } = {}) {
  const written: string[] = [];
  const destroyed: unknown[] = [];
  const socket = {
    writable: state.writable ?? true,
    destroyed: state.destroyed ?? false,
    write: (chunk: string) => written.push(chunk) > 0,
    destroy: (error?: unknown) => {
      destroyed.push(error);
    },
  };
  return { socket: socket as unknown as Socket, written, destroyed };
}

function setup() {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
    destination: capture,
  });
  return { logger, ids: new SequentialIds(), lines: () => capture.lines(), text: () => capture.text };
}

/** A Node parser error, as the server's clientError event gives it. */
const parserError = (code?: string): Error & { code?: string } =>
  Object.assign(new Error('Parse Error: Invalid method encountered'), code === undefined ? {} : { code });

/** The status line, the headers as an object, and the body. */
function parse(response: string) {
  const [head = '', body = ''] = response.split(CRLF + CRLF);
  const [statusLine, ...fields] = head.split(CRLF);
  const headers = Object.fromEntries(
    fields.map((field) => [field.slice(0, field.indexOf(':')), field.slice(field.indexOf(':') + 2)]),
  );
  return { statusLine, headers, body: JSON.parse(body) as unknown };
}

describe("SEC-WEB-02, SEC-DATA-04 a request Node can't parse gets the same plain answer as any error", () => {
  it.each([
    ['a malformed request', 'HPE_INVALID_METHOD', 'HTTP/1.1 400 Bad Request', 'BAD_REQUEST'],
    ['a parser error with no code', undefined, 'HTTP/1.1 400 Bad Request', 'BAD_REQUEST'],
    [
      'headers over the size limit',
      'HPE_HEADER_OVERFLOW',
      'HTTP/1.1 431 Request Header Fields Too Large',
      'HEADERS_TOO_LARGE',
    ],
    ['a request that took too long', 'ERR_HTTP_REQUEST_TIMEOUT', 'HTTP/1.1 408 Request Timeout', 'REQUEST_TIMEOUT'],
  ] as const)(
    'answers %s with the headers, a correlation ID and its reason code',
    (_what, code, statusLine, reason) => {
      const { logger, ids } = setup();
      const { socket, written, destroyed } = fakeSocket();
      const error = parserError(code);
      answerClientError(error, socket, logger, ids);
      expect(written).toHaveLength(1);
      const response = parse(written[0] ?? '');
      expect(response.statusLine).toBe(statusLine);
      expect(response.headers).toMatchObject({
        ...SECURITY_HEADERS,
        'x-correlation-id': FIRST_ID,
        'content-type': 'application/json; charset=utf-8',
        connection: 'close',
      });
      expect(response.body).toEqual(errorBody(reason, FIRST_ID));
      expect(Number(response.headers['content-length'])).toBe(Buffer.byteLength(JSON.stringify(response.body)));
      expect(destroyed).toEqual([error]);
    },
  );

  it('logs the refusal with its status and Node error, never the bytes received', () => {
    const { logger, ids, lines, text } = setup();
    const error = Object.assign(parserError('HPE_INVALID_METHOD'), {
      rawPacket: Buffer.from('POST /v1/x?token=plantedvalue HTTP/1.1'),
    });
    answerClientError(error, fakeSocket().socket, logger, ids);
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'info',
        event: CLIENT_ERROR,
        correlationId: FIRST_ID,
        status: 400,
        err: expect.objectContaining({ type: 'Error', code: 'HPE_INVALID_METHOD' }) as unknown,
      }),
    ]);
    expect(findLeaks(text(), ['plantedvalue', '/v1/x'])).toEqual([]);
  });

  it('writes nothing to a socket that no longer takes writes, and still closes and logs it', () => {
    const { logger, ids, lines } = setup();
    const { socket, written, destroyed } = fakeSocket({ writable: false });
    answerClientError(parserError('HPE_INVALID_METHOD'), socket, logger, ids);
    expect(written).toEqual([]);
    expect(destroyed).toHaveLength(1);
    expect(lines()).toHaveLength(1);
  });

  it.each([
    ['a connection the client reset', parserError('ECONNRESET'), {}],
    ['a socket already closed', parserError('HPE_INVALID_METHOD'), { destroyed: true }],
  ])('leaves %s alone: there is no one to answer', (_what, error, state) => {
    const { logger, ids, lines } = setup();
    const { socket, written, destroyed } = fakeSocket(state);
    answerClientError(error, socket, logger, ids);
    expect([written, destroyed, lines()]).toEqual([[], [], []]);
  });
});
