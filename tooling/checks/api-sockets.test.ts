// The API on a real socket, for what an in-process request can't reach: bytes
// Node's HTTP parser refuses, a client that hangs up, a request that arrives
// while the server stops, and a request with garbage after it in one packet.
// Product code can't open a socket (SEC-WEB-05), so these live here.
import net from 'node:net';

import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { buildServer } from '../../apps/api/src/server.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { LogCapture } from '../../packages/testing/src/log-scan.ts';
import { SequentialIds } from '../../packages/testing/src/ids.ts';

const CRLF = String.fromCharCode(13, 10);
const PUBLIC_ORIGIN = 'https://app.agentx.example';
/**
 * Test routes are open to anyone, read at most 1 KiB and answer `{ ok: true }`
 * (or a string, sent as it is): none of that is what these tests are about.
 */
const OPEN = {
  config: { access: ['public'] },
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
} as const;

type Server = Awaited<ReturnType<typeof buildServer>>;
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A listening server, with a slow route that answers when the test says so. */
async function listening() {
  const capture = new LogCapture();
  const config = {
    http: { host: '127.0.0.1', port: 0, publicOrigin: PUBLIC_ORIGIN, trustedProxies: [], rateLimitPerMinute: 100 },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
  });
  const app = await buildServer({ config, logger, ids: new SequentialIds(), healthChecks: [] });
  let release = (): void => undefined;
  let entered = (): void => undefined;
  const inHandler = new Promise<void>((resolve) => (entered = resolve));
  const slow = async () => {
    entered();
    await new Promise<void>((resolve) => (release = resolve));
    return { done: true };
  };
  const slowly = { ...OPEN, schema: { response: { 200: z.object({ done: z.literal(true) }) } } };
  app.get('/test/slow', slowly, slow);
  // A write whose body is read in full before the handler waits: the case Node doesn't call aborted.
  app.post('/test/slow', slowly, slow);
  app.get('/test/fail', OPEN, () => {
    throw new Error('failed on our side');
  });
  servers.push(app);
  await app.listen({ host: '127.0.0.1', port: 0 });
  const port = app.addresses()[0]?.port ?? 0;
  return {
    app,
    port,
    capture,
    inHandler,
    release: () => {
      release();
    },
  };
}

/** A request's text, with its lines joined by CRLF and the blank line after the headers. */
const request = (...lines: string[]): string => [...lines, '', ''].join(CRLF);

/** Opens a connection and collects everything the server sends until it closes it. */
function connect(port: number) {
  const socket = net.connect(port, '127.0.0.1');
  let received = '';
  socket.setEncoding('latin1');
  socket.on('data', (data: string) => (received += data));
  const closed = new Promise<void>((resolve) => {
    socket.on('close', () => {
      resolve();
    });
  });
  const opened = new Promise<void>((resolve) => {
    socket.on('connect', () => {
      resolve();
    });
  });
  return { socket, opened, closed, received: () => received };
}

/** Sends raw bytes and returns the whole answer once the server closes the connection. */
async function exchange(port: number, bytes: string): Promise<string> {
  const connection = connect(port);
  await connection.opened;
  connection.socket.write(bytes);
  await connection.closed;
  return connection.received();
}

/** Waits for `promise`, but fails after `ms` instead of waiting on a connection nobody closes. */
async function within<T>(promise: Promise<T>, ms: number, failure: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(failure));
    }, ms);
  });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}

const headerBlock = (response: string): string => (response.split(CRLF + CRLF)[0] ?? '').toLowerCase();
const bodyOf = (response: string): unknown => JSON.parse(response.slice(response.indexOf(CRLF + CRLF) + 4)) as unknown;

describe("SEC-WEB-02, SEC-DATA-04 bytes Node's parser refuses get our plain answer", () => {
  it.each([
    ['a malformed request line', request('GET /health HTTP/1.1 junk', 'Host: x'), '400', 'BAD_REQUEST'],
    ['a lower-case method', request('post /health HTTP/1.1', 'Host: x'), '400', 'BAD_REQUEST'],
    [
      'headers over 16 KiB',
      request('GET /health HTTP/1.1', 'Host: x', `X-Big: ${'a'.repeat(20_000)}`),
      '431',
      'HEADERS_TOO_LARGE',
    ],
  ])('%s', async (_what, bytes, status, code) => {
    const { port, capture } = await listening();
    const response = await exchange(port, bytes);
    expect(response.startsWith(`HTTP/1.1 ${status} `)).toBe(true);
    const head = headerBlock(response);
    expect(head).toContain("content-security-policy: default-src 'self'");
    expect(head).toContain('cache-control: no-store');
    expect(head).toMatch(/x-correlation-id: [0-9a-f-]{36}/);
    expect(bodyOf(response)).toMatchObject({ error: { code } });
    await vi.waitFor(() => {
      expect(capture.lines().some((line) => line.event === 'http.client_error')).toBe(true);
    });
  });

  it('a request with garbage after it in one packet makes no error line: its unreadable address gets a key, not a crash', async () => {
    const { port, capture } = await listening();
    for (let i = 0; i < 3; i += 1)
      await exchange(port, request('GET /health HTTP/1.1', 'Host: x') + 'GARBAGE' + CRLF + CRLF);
    await vi.waitFor(() => {
      expect(capture.lines().filter((line) => line.event === 'http.client_error')).toHaveLength(3);
    });
    expect(capture.lines().filter((line) => line.level === 'error')).toEqual([]);
  });
});

describe('ADR-011 §7 a client that hangs up before the answer still gets its line', () => {
  it('writes http.request_aborted, and no completed line', async () => {
    const { port, capture, inHandler, release } = await listening();
    const connection = connect(port);
    await connection.opened;
    connection.socket.write(request('GET /test/slow HTTP/1.1', 'Host: x'));
    await inHandler;
    connection.socket.destroy();
    await connection.closed;
    await vi.waitFor(() => {
      expect(capture.lines().filter((line) => line.event === 'http.request_aborted')).toEqual([
        expect.objectContaining({ method: 'GET', route: '/test/slow' }),
      ]);
    });
    // The handler then answers into a closed connection, which must not add a second line.
    release();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(capture.lines().filter((line) => line.event === 'http.request_completed')).toEqual([]);
  });
});

describe('ADR-011 §7 a client that hangs up on a write, after its body was read, still gets its line', () => {
  it('writes http.request_aborted', async () => {
    const { port, capture, inHandler, release } = await listening();
    const connection = connect(port);
    await connection.opened;
    const body = '{"amount":1}';
    connection.socket.write(
      request(
        'POST /test/slow HTTP/1.1',
        'Host: x',
        `Origin: ${PUBLIC_ORIGIN}`,
        'Content-Type: application/json',
        `Content-Length: ${String(body.length)}`,
      ) + body,
    );
    await inHandler;
    connection.socket.destroy();
    await connection.closed;
    await vi.waitFor(() => {
      expect(capture.lines().filter((line) => line.event === 'http.request_aborted')).toEqual([
        expect.objectContaining({ method: 'POST', route: '/test/slow' }),
      ]);
    });
    release();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(capture.lines().filter((line) => line.event === 'http.request_completed')).toEqual([]);
  });
});

describe('SEC-WEB-02 a request that arrives while the server stops is answered as usual', () => {
  it('with our headers, not a bare 503', async () => {
    const { app, port, inHandler, release } = await listening();
    const connection = connect(port);
    await connection.opened;
    connection.socket.write(request('GET /test/slow HTTP/1.1', 'Host: x'));
    await inHandler;
    const closing = app.close();
    await vi.waitFor(() => {
      expect(app.server.listening).toBe(false);
    });
    // A second request on the connection still open, as SIGTERM finds one.
    connection.socket.write(request('GET /health HTTP/1.1', 'Host: x'));
    release();
    await connection.closed;
    await closing;
    const second = connection.received().slice(connection.received().indexOf('HTTP/1.1', 10));
    expect(second.startsWith('HTTP/1.1 200 ')).toBe(true);
    expect(headerBlock(second)).toContain("content-security-policy: default-src 'self'");
    expect(headerBlock(second)).toContain('connection: close');
  });

  it('an error answer while stopping still closes the connection, so the stop is not held up', async () => {
    const { app, port, inHandler, release } = await listening();
    const connection = connect(port);
    await connection.opened;
    connection.socket.write(request('GET /test/slow HTTP/1.1', 'Host: x'));
    await inHandler;
    const closing = app.close();
    await vi.waitFor(() => {
      expect(app.server.listening).toBe(false);
    });
    connection.socket.write(request('GET /test/fail HTTP/1.1', 'Host: x'));
    release();
    // The server ends the connection itself; the test never destroys the socket.
    await within(connection.closed, 5_000, 'the server kept the connection open, holding the stop up');
    await closing;
    const second = connection.received().slice(connection.received().indexOf('HTTP/1.1', 10));
    expect(second.startsWith('HTTP/1.1 500 ')).toBe(true);
    expect(headerBlock(second)).toContain('connection: close');
  });
});

describe('SEC-WEB-01 Origin, as Node joins it', () => {
  it('refuses two Origin headers, even both ours: Node joins them into one value that matches nothing', async () => {
    const { port } = await listening();
    const response = await exchange(
      port,
      request(
        'POST /health HTTP/1.1',
        'Host: x',
        `Origin: ${PUBLIC_ORIGIN}`,
        `Origin: ${PUBLIC_ORIGIN}`,
        'Content-Length: 0',
        'Connection: close',
      ),
    );
    expect(response.startsWith('HTTP/1.1 403 ')).toBe(true);
  });
});
