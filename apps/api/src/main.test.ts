import { EventEmitter } from 'node:events';

import type { Output } from '@agentx/platform/observability';
import { findLeaks, LogCapture } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type ApiProcess, runApi } from './main.ts';
import type { buildServer } from './server.ts';

/** Every server runApi builds, including one it closes itself after a failed start. */
const built = vi.hoisted((): FastifyInstance[] => []);

vi.mock('./server.ts', async (importOriginal) => {
  const actual = await importOriginal<{ buildServer: typeof buildServer }>();
  return {
    ...actual,
    buildServer: async (...args: Parameters<typeof buildServer>) => {
      const server = await actual.buildServer(...args);
      built.push(server);
      return server;
    },
  };
});

/** Plain words standing in for a secret put in the wrong setting, so secret scanners ignore it. */
const MISPLACED = 'value that must never be printed';

/** A test run: any free port, on this machine only. */
const ENV = { AGENTX_ENV: 'test', AGENTX_HTTP_PORT: '0' };

class FakeProcess extends EventEmitter implements ApiProcess {
  readonly written: string[] = [];
  readonly stdout: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  readonly stderr: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  readonly exits: number[] = [];
  exitCode: number | string | null | undefined = undefined;

  exit(code: number): void {
    this.exits.push(code);
  }
}

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(env: Readonly<Record<string, string>> = ENV) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const server = await runApi(host, { env, destination: capture });
  if (server !== undefined) servers.push(server);
  return { host, server, capture, events: () => capture.lines().map((line) => line.event) };
}

describe('SEC-AV-03 the API refuses to start on a bad config', () => {
  it('says why, naming each setting and never its value, and exits with a failure', async () => {
    const { host, server, capture } = await start({ AGENTX_ENV: MISPLACED, AGENTX_HTTP_PORT: 'eighty' });
    expect(server).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        env: 'unconfigured',
        event: 'api.start_refused',
        problems: [
          'AGENTX_ENV: must be one of: development, test, staging, production',
          'AGENTX_HTTP_PORT: must be a whole number, written in digits only',
        ],
      }),
    ]);
    expect(findLeaks(capture.text, [MISPLACED])).toEqual([]);
  });

  it('logs an unexpected error while reading the config as a refusal too', async () => {
    const env = Object.defineProperty({}, 'AGENTX_ENV', {
      enumerable: true,
      get: () => {
        throw new Error('environment unreadable');
      },
    });
    const host = new FakeProcess();
    const capture = new LogCapture();
    expect(await runApi(host, { env, destination: capture })).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        event: 'api.start_refused',
        err: expect.objectContaining({ type: 'Error', message: 'environment unreadable' }) as unknown,
      }),
    ]);
  });

  it('guards stdout and stderr before anything else', async () => {
    const { host } = await start({ AGENTX_ENV: MISPLACED });
    host.stdout.write('stray text from someone@example.com\n');
    host.stderr.write('stray error from 192.0.2.44\n');
    expect(host.written).toEqual(['stray text from [email]\n', 'stray error from [ip]\n']);
  });
});

describe('SEC-OPS-05 the API logs its config fingerprint and starts listening', () => {
  it('logs the fingerprint, listens on the port it was given, and answers', async () => {
    const { server, capture } = await start();
    const [starting, listening] = capture.lines().filter((line) => String(line.event).startsWith('api.'));
    expect(starting).toEqual(
      expect.objectContaining({
        event: 'api.starting',
        configHash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/) as unknown,
        watchedVariables: [],
        nodeFlags: expect.any(Array) as unknown,
      }),
    );
    expect(listening).toEqual(
      expect.objectContaining({ event: 'api.listening', ports: server?.addresses().map((address) => address.port) }),
    );
    expect(listening?.ports).toEqual([expect.any(Number)]);
    expect((await server?.inject('/health'))?.json()).toEqual({ status: 'ok' });
  });

  it('names the watched variables that are set, never their values', async () => {
    const { capture } = await start({ ...ENV, NODE_EXTRA_CA_CERTS: '/etc/ssl/bank-ca.pem' });
    expect(capture.lines()[0]).toEqual(expect.objectContaining({ watchedVariables: ['NODE_EXTRA_CA_CERTS'] }));
    expect(capture.text).not.toContain('bank-ca');
  });

  it('logs a failure to listen, closes what it built, and exits with a failure', async () => {
    const first = await start();
    const port = String(first.server?.addresses()[0]?.port);
    const { host, server, events } = await start({ ...ENV, AGENTX_HTTP_PORT: port });
    expect(server).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(events()).toContain('api.listen_failed');
    await expect(built.at(-1)?.inject('/health')).rejects.toThrow();
  });
});

describe('the API stops cleanly on a signal', () => {
  it.each(['SIGTERM', 'SIGINT'] as const)(
    'on %s: stops listening, writes the held-back counts, exits 0',
    async (signal) => {
      const { host, server, events } = await start();
      host.emit(signal, signal);
      await vi.waitFor(() => {
        expect(host.exits).toEqual([0]);
      });
      expect(events().slice(-2)).toEqual(['api.stopping', 'api.stopped']);
      expect(server?.server.listening).toBe(false);
    },
  );

  it.each([
    ['the same signal twice', ['SIGTERM', 'SIGTERM']],
    ['two different signals', ['SIGTERM', 'SIGINT']],
  ] as const)('stops once for %s, and keeps listening for more', async (_what, signals) => {
    const { host, events } = await start();
    for (const signal of signals) host.emit(signal, signal);
    await vi.waitFor(() => {
      expect(host.exits).toEqual([0]);
    });
    expect(events().filter((event) => event === 'api.stopping')).toHaveLength(1);
    // Still listening, so Node's default (ending the process at once) never takes over.
    expect([host.listenerCount('SIGTERM'), host.listenerCount('SIGINT')]).toEqual([1, 1]);
  });

  it('logs a failure to stop and exits with a failure', async () => {
    const { host, server, events } = await start();
    if (server === undefined) throw new Error('the server should have started');
    const close = server.close.bind(server);
    Object.assign(server, { close: () => Promise.reject(new Error('close failed')) });
    try {
      host.emit('SIGTERM', 'SIGTERM');
      await vi.waitFor(() => {
        expect(host.exits).toEqual([1]);
      });
      expect(events()).toContain('api.stop_failed');
    } finally {
      Object.assign(server, { close });
    }
  });
});

describe('the API stops within its deadline', () => {
  /** Replaces the server's close for one test, with a fake clock for the deadline. */
  async function withClose(
    close: () => Promise<undefined>,
    run: (host: FakeProcess, events: () => unknown[]) => Promise<void>,
  ) {
    const { host, server, events } = await start();
    if (server === undefined) throw new Error('the server should have started');
    const realClose = server.close.bind(server);
    Object.assign(server, { close });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await run(host, events);
    } finally {
      vi.useRealTimers();
      Object.assign(server, { close: realClose });
    }
  }

  it('gives up when stopping hangs: logs it, writes the counts and exits 1 after 25 seconds', async () => {
    await withClose(
      () => new Promise<undefined>(() => undefined),
      async (host, events) => {
        host.emit('SIGTERM', 'SIGTERM');
        await vi.advanceTimersByTimeAsync(24_999);
        expect(host.exits).toEqual([]);
        await vi.advanceTimersByTimeAsync(1);
        expect(host.exits).toEqual([1]);
        expect(events()).toContain('api.stop_timed_out');
      },
    );
  });

  it('clears the deadline once stopped, so a clean stop never becomes a failed one', async () => {
    await withClose(
      () => Promise.resolve(undefined),
      async (host, events) => {
        host.emit('SIGTERM', 'SIGTERM');
        await vi.advanceTimersByTimeAsync(60_000);
        expect(host.exits).toEqual([0]);
        expect(events()).not.toContain('api.stop_timed_out');
      },
    );
  });
});

describe('the API logs a crash before it exits', () => {
  it('logs the error and where it came from, then exits 1', async () => {
    const { host, capture } = await start();
    host.emit('uncaughtException', new TypeError('bad state for someone@example.com'), 'unhandledRejection');
    expect(host.exits).toEqual([1]);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        level: 'error',
        event: 'api.crashed',
        origin: 'unhandledRejection',
        err: expect.objectContaining({ type: 'TypeError', message: 'bad state for [email]' }) as unknown,
      }),
    );
  });
});
