import { EventEmitter } from 'node:events';

import type { DatabaseConnectionOptions } from '@agentx/platform/db';
import type { Output } from '@agentx/platform/observability';
import { findLeaks, LogCapture } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

/**
 * A stand-in for the pool: these tests are about the process around it (order,
 * exits, log lines); main.db.test.ts runs the real one. `destroy` is what the
 * process calls at shutdown; `roleCheck` is what assertRuntimeRole does.
 */
class FakeDatabase {
  readonly options: DatabaseConnectionOptions;
  destroyed = false;
  destroy = (): Promise<void> => fake.destroy(this);

  constructor(options: DatabaseConnectionOptions) {
    this.options = options;
  }
}

const closePool = (database: FakeDatabase): Promise<void> => {
  database.destroyed = true;
  fake.steps.push('pool closed');
  return Promise.resolve();
};

const fake = vi.hoisted(() => ({
  created: [] as FakeDatabase[],
  /** What happens at each step, in order, so a test can check the order. */
  steps: [] as string[],
  roleCheck: (_database: FakeDatabase): Promise<void> => Promise.resolve(),
  destroy: (_database: FakeDatabase): Promise<void> => Promise.resolve(),
}));

vi.mock('@agentx/platform/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/db')>();
  return {
    ...actual,
    createDatabase: (options: DatabaseConnectionOptions) => {
      const database = new FakeDatabase(options);
      fake.created.push(database);
      return database;
    },
    assertRuntimeRole: (database: FakeDatabase) => {
      fake.steps.push('role checked');
      return fake.roleCheck(database);
    },
  };
});

/** Plain words standing in for a secret put in the wrong setting, so secret scanners ignore it. */
const MISPLACED = 'value that must never be printed';
/** Plain words standing in for the database login. */
const DB_LOGIN = 'stand-in login for these tests';

/** A test run: any free port, on this machine only. */
const ENV = { AGENTX_ENV: 'test', AGENTX_HTTP_PORT: '0', AGENTX_DB_HOST: 'db', AGENTX_DB_PASSWORD: DB_LOGIN };

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

beforeEach(() => {
  fake.created.length = 0;
  fake.steps.length = 0;
  fake.roleCheck = () => Promise.resolve();
  fake.destroy = closePool;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(env: Readonly<Record<string, string>> = ENV) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const server = await runApi(host, { env, destination: capture });
  if (server !== undefined) servers.push(server);
  return {
    host,
    server,
    capture,
    /** The process's own events, without the framework's lines. */
    events: () =>
      capture
        .lines()
        .map((line) => String(line.event))
        .filter((event) => event.startsWith('api.')),
  };
}

describe('SEC-AV-03 the API refuses to start on a bad config', () => {
  it('says why, naming each setting and never its value, and exits with a failure', async () => {
    const { host, server, capture } = await start({ ...ENV, AGENTX_ENV: MISPLACED, AGENTX_HTTP_PORT: 'eighty' });
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
    expect(fake.created).toEqual([]);
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

describe('APP-02 the API opens its database as its own role, and checks that role before it listens', () => {
  it('connects with the database settings, named agentx-api, with the configured pool size', async () => {
    const { server } = await start({
      ...ENV,
      AGENTX_DB_PORT: '6432',
      AGENTX_DB_NAME: 'agentx_t',
      AGENTX_DB_POOL_MAX: '3',
    });
    expect(server).toBeDefined();
    expect(fake.created.map((database) => database.options)).toEqual([
      {
        host: 'db',
        port: 6432,
        database: 'agentx_t',
        user: 'agentx_app',
        password: DB_LOGIN,
        tls: 'verify-full',
        maxConnections: 3,
        applicationName: 'agentx-api',
      },
    ]);
  });

  it('checks the role, logs that the database is ready, and only then listens', async () => {
    const { events, capture } = await start();
    expect(fake.steps).toEqual(['role checked']);
    expect(events()).toEqual(['api.starting', 'api.database_connected', 'api.listening']);
    expect(capture.lines()[1]).toEqual(
      expect.objectContaining({ event: 'api.database_connected', role: 'agentx_app' }),
    );
  });

  it('refuses to start as a role that could bypass the tenant walls, naming the reasons, and closes the pool', async () => {
    const { UnsafeDatabaseRole } = await import('@agentx/platform/db');
    fake.roleCheck = () => Promise.reject(new UnsafeDatabaseRole(['it has BYPASSRLS', 'it owns the database']));
    const serversBefore = built.length;
    const { host, server, capture } = await start();
    expect(server).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        level: 'error',
        event: 'api.start_refused',
        problems: ['it has BYPASSRLS', 'it owns the database'],
      }),
    );
    expect(fake.created.map((database) => database.destroyed)).toEqual([true]);
    // Nothing was built to listen: the refusal comes before the server.
    expect(built.length).toBe(serversBefore);
  });

  it('logs a database it cannot reach, redacted, closes the pool and exits with a failure', async () => {
    fake.roleCheck = () => Promise.reject(new Error('connect ECONNREFUSED 10.0.0.5:5432'));
    const { host, server, capture } = await start();
    expect(server).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        level: 'error',
        event: 'api.database_unavailable',
        err: expect.objectContaining({ type: 'Error', message: 'connect ECONNREFUSED [ip]:5432' }) as unknown,
      }),
    );
    expect(fake.created.map((database) => database.destroyed)).toEqual([true]);
  });

  it('never writes the database login to the log, started or refused', async () => {
    const { capture: started } = await start();
    fake.roleCheck = () => Promise.reject(new Error('password authentication failed for user "agentx_app"'));
    const { capture: refused } = await start();
    expect(findLeaks(started.text + refused.text, [DB_LOGIN])).toEqual([]);
  });
});

describe('SEC-OPS-05 the API logs its config fingerprint and starts listening', () => {
  it('logs the fingerprint, listens on the port it was given, and answers', async () => {
    const { server, capture } = await start();
    const [starting, , listening] = capture.lines().filter((line) => String(line.event).startsWith('api.'));
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

  it('logs a failure to listen, closes what it built and the pool, and exits with a failure', async () => {
    const first = await start();
    const port = String(first.server?.addresses()[0]?.port);
    const { host, server, events } = await start({ ...ENV, AGENTX_HTTP_PORT: port });
    expect(server).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(events()).toContain('api.listen_failed');
    await expect(built.at(-1)?.inject('/health')).rejects.toThrow();
    expect(fake.created.map((database) => database.destroyed)).toEqual([false, true]);
  });
});

describe('the API stops cleanly on a signal', () => {
  it.each(['SIGTERM', 'SIGINT'] as const)(
    'on %s: logs the signal, stops listening, then closes the pool, exits 0',
    async (signal) => {
      const { host, server, events, capture } = await start();
      host.emit(signal, signal);
      await vi.waitFor(() => {
        expect(host.exits).toEqual([0]);
      });
      expect(events().slice(-2)).toEqual(['api.stopping', 'api.stopped']);
      expect(capture.lines().find((line) => line.event === 'api.stopping')).toEqual(
        expect.objectContaining({ event: 'api.stopping', signal }),
      );
      expect(server?.server.listening).toBe(false);
      expect(fake.steps).toEqual(['role checked', 'pool closed']);
    },
  );

  it('closes the pool only after HTTP has stopped, so requests in flight still have it', async () => {
    const { host, server } = await start();
    if (server === undefined) throw new Error('the server should have started');
    const close = server.close.bind(server);
    Object.assign(server, {
      close: async () => {
        fake.steps.push('http closing');
        await close();
        fake.steps.push('http closed');
      },
    });
    host.emit('SIGTERM', 'SIGTERM');
    await vi.waitFor(() => {
      expect(host.exits).toEqual([0]);
    });
    expect(fake.steps).toEqual(['role checked', 'http closing', 'http closed', 'pool closed']);
  });

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
    expect(fake.steps.filter((step) => step === 'pool closed')).toHaveLength(1);
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

  it('logs a pool that fails to close and exits with a failure', async () => {
    const { host, capture } = await start();
    fake.destroy = () => Promise.reject(new Error('pool would not close'));
    host.emit('SIGTERM', 'SIGTERM');
    await vi.waitFor(() => {
      expect(host.exits).toEqual([1]);
    });
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        event: 'api.stop_failed',
        err: expect.objectContaining({ message: 'pool would not close' }) as unknown,
      }),
    );
  });
});

describe('the API stops within its deadline', () => {
  /** Replaces the server's close for one test, with a fake clock for the deadline. */
  async function withClose(
    close: () => Promise<undefined>,
    run: (host: FakeProcess, events: () => unknown[], capture: LogCapture) => Promise<void>,
  ) {
    const { host, server, events, capture } = await start();
    if (server === undefined) throw new Error('the server should have started');
    const realClose = server.close.bind(server);
    Object.assign(server, { close });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await run(host, events, capture);
    } finally {
      vi.useRealTimers();
      Object.assign(server, { close: realClose });
    }
  }

  it('gives up when stopping hangs: logs it, writes the counts and exits 1 after 25 seconds', async () => {
    await withClose(
      () => new Promise<undefined>(() => undefined),
      async (host, events, capture) => {
        host.emit('SIGTERM', 'SIGTERM');
        await vi.advanceTimersByTimeAsync(24_999);
        expect(host.exits).toEqual([]);
        await vi.advanceTimersByTimeAsync(1);
        expect(host.exits).toEqual([1]);
        expect(events()).toContain('api.stop_timed_out');
        expect(capture.lines().at(-1)).toEqual(
          expect.objectContaining({ event: 'api.stop_timed_out', deadlineMs: 25_000 }),
        );
      },
    );
  });

  it('gives up the same way when the pool will not close', async () => {
    fake.destroy = () => new Promise<void>(() => undefined);
    await withClose(
      () => Promise.resolve(undefined),
      async (host, events) => {
        host.emit('SIGTERM', 'SIGTERM');
        await vi.advanceTimersByTimeAsync(25_000);
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

describe("every exit writes the log's held-back counts first", () => {
  /** A cap the request lines soon exceed, with the rate limit at half of it, as the config requires. */
  const CAPPED = { ...ENV, AGENTX_LOG_EVENT_CAP_PER_MINUTE: '20', AGENTX_RATE_LIMIT_PER_MINUTE: '10' };

  /** Starts, then makes more requests than the cap, so lines of one event are being held back. */
  async function startWithHeldBackLines() {
    const started = await start(CAPPED);
    if (started.server === undefined) throw new Error('the server should have started');
    for (let request = 0; request < 45; request += 1) await started.server.inject('/health');
    expect(started.capture.lines().some((line) => line.event === 'log.suppressed')).toBe(false);
    return started;
  }

  /** The counts the logger wrote out: 10 requests answered, 20 refusals written, the other 15 held back. */
  const heldBack = (capture: LogCapture) =>
    capture
      .lines()
      .filter((line) => line.event === 'log.suppressed')
      .map((line) => line.suppressedCount);

  it('on a clean stop', async () => {
    const { host, capture } = await startWithHeldBackLines();
    host.emit('SIGTERM', 'SIGTERM');
    await vi.waitFor(() => {
      expect(host.exits).toEqual([0]);
    });
    expect(heldBack(capture)).toEqual([15]);
  });

  it('on a stop that failed', async () => {
    const { host, server, capture } = await startWithHeldBackLines();
    if (server === undefined) throw new Error('the server should have started');
    const close = server.close.bind(server);
    Object.assign(server, { close: () => Promise.reject(new Error('close failed')) });
    try {
      host.emit('SIGTERM', 'SIGTERM');
      await vi.waitFor(() => {
        expect(host.exits).toEqual([1]);
      });
      expect(heldBack(capture)).toEqual([15]);
    } finally {
      Object.assign(server, { close });
    }
  });

  it('on a crash', async () => {
    const { host, capture } = await startWithHeldBackLines();
    host.emit('uncaughtException', new Error('bad state'), 'uncaughtException');
    expect(host.exits).toEqual([1]);
    expect(heldBack(capture)).toEqual([15]);
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
