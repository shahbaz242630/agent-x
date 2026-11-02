// The API as it really runs: `node apps/api/src/main.ts` in its own process,
// with Node stripping the TypeScript itself, real sockets, a real database and
// the real stdout. The unit tests run the same code in-process through Vitest;
// this proves the entry point starts on plain Node, connects as the app role,
// writes only clean JSON lines, and answers with the protections in place.
// (Stopping on a signal is tested in-process: Windows can't send one a process
// can catch.)
import { type ChildProcess, spawn } from 'node:child_process';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { PURPOSES } from '../../packages/platform/src/keys/purposes.ts';
import { createTestDatabase, type TestDatabase } from '../../packages/testing/src/db/test-database.ts';
import { writeTestKeys } from '../../packages/testing/src/keys.ts';
import { findLeaks } from '../../packages/testing/src/log-scan.ts';

const MAIN = path.resolve('apps/api/src/main.ts');
const PUBLIC_ORIGIN = 'http://localhost:8080';
const server = inject('postgres');
const keys = writeTestKeys(PURPOSES);

/** The parent's environment without any AGENTX_ or PG setting, plus a test run's, against the test database. */
function childEnv(database: TestDatabase): NodeJS.ProcessEnv {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !/^(?:AGENTX_|PG)/.test(name.toUpperCase())),
  );
  const connection = database.connection('app');
  return {
    ...inherited,
    AGENTX_ENV: 'test',
    AGENTX_HTTP_PORT: '0',
    AGENTX_PUBLIC_ORIGIN: PUBLIC_ORIGIN,
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_USER: connection.user,
    AGENTX_DB_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    AGENTX_KEYS_DIR: keys.directory,
  };
}

interface Line {
  event?: string;
  correlationId?: string;
  runId?: string;
  ports?: number[];
  configHash?: string;
  status?: number;
}

let database: TestDatabase;
let child: ChildProcess;
let stdout = '';
let stderr = '';
let port = 0;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  child = spawn(process.execPath, [MAIN], { env: childEnv(database), stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout?.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr?.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`the API did not start in time.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    }, 30_000);
    const poll = setInterval(() => {
      const listening = lines().find((line) => line.event === 'api.listening')?.ports?.[0];
      if (listening !== undefined) {
        clearTimeout(timer);
        clearInterval(poll);
        resolve(listening);
      }
    }, 50);
    child.once('exit', (code) => {
      clearTimeout(timer);
      clearInterval(poll);
      reject(new Error(`the API exited with ${String(code)}.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    });
  });
});

afterAll(async () => {
  child.kill();
  await new Promise((resolve) => child.once('exit', resolve));
  await database.drop();
  keys.remove();
});

function lines(): Line[] {
  return stdout
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as Line);
}

/** Lines of the process itself once it listens, no request's and no run's: what it says of itself, and the logger's and the requests' sums. */
const PROCESS_LINES = /^(api\.|log\.|http\.minute$)/;

describe(`the API process (Postgres ${server.version})`, () => {
  it('SEC-OPS-05 logs its config fingerprint, connects as the app role, records the start, then listens', async () => {
    // The jobs' lines follow api.listening, which is all beforeAll waits for: wait for them, not the first read
    // (a flake twice in a week, S60 and S61).
    await vi.waitFor(
      () => {
        const events = lines()
          .map((line) => String(line.event))
          .filter((event) => event.startsWith('api.'));
        expect(events).toEqual([
          'api.starting',
          'api.partner',
          'api.database_connected',
          'api.start_recorded',
          'api.listening',
          'api.notices',
          'api.idp_events',
          'api.contact_fill',
          'api.factor_resets',
          'api.handoff',
          'api.payment_checks',
          'api.background_downloads',
        ]);
      },
      { timeout: 10_000, interval: 50 },
    );
    expect(lines().find((line) => line.event === 'api.starting')?.configHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('4D2e D: `jobs` on plain Node stays up with nothing listening, its timers letting go only of what they may', async () => {
    const jobsLines: Line[] = [];
    const jobs = spawn(process.execPath, [MAIN], {
      env: { ...childEnv(database), AGENTX_ROLE: 'jobs' },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    jobs.stdout.setEncoding('utf8').on('data', (chunk: string) => {
      for (const line of chunk.split('\n')) if (line.startsWith('{')) jobsLines.push(JSON.parse(line) as Line);
    });
    try {
      await vi.waitFor(
        () => {
          expect(jobsLines.map((line) => line.event)).toContain('api.background_downloads');
        },
        { timeout: 30_000, interval: 100 },
      );
      // Past every first run's quick end: a process holding nothing open would have exited by now.
      await new Promise((resolve) => setTimeout(resolve, 3_000));
      expect(jobs.exitCode).toBeNull();
      expect(jobsLines.map((line) => line.event)).not.toContain('api.listening');
    } finally {
      jobs.kill();
      await new Promise((resolve) => jobs.once('exit', resolve));
    }
  }, 60_000);

  it('SEC-WEB-02 answers the health check, with the security headers and a correlation ID', async () => {
    const response = await fetch(`http://127.0.0.1:${port}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok' });
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('x-correlation-id')).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('SEC-WEB-01 refuses a write from another site', async () => {
    const response = await fetch(`http://127.0.0.1:${port}/health`, {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: 'ORIGIN_REFUSED' } });
  });

  it('4D2e Stage F level 4: every line a request or a job writes says which, on real sockets, a body read too', async () => {
    const seen = lines().length;
    await fetch(`http://127.0.0.1:${port}/health`);
    await fetch(`http://127.0.0.1:${port}/v1/spend-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer not-a-key' },
      body: JSON.stringify({ any: 'body' }),
    });
    await vi.waitFor(() => {
      expect(lines().length).toBeGreaterThanOrEqual(seen + 2);
    });
    // Before it listens a process is starting up, which is neither.
    const listening = lines().findIndex((line) => line.event === 'api.listening');
    const unclaimed = lines()
      .slice(listening)
      .filter(
        (line) =>
          line.correlationId === undefined && line.runId === undefined && !PROCESS_LINES.test(String(line.event)),
      );
    expect(unclaimed.map((line) => line.event)).toEqual([]);
    // The jobs' first runs have written by now, each under its own run's ID.
    expect(lines().some((line) => line.runId !== undefined)).toBe(true);
  });

  it('SEC-DATA-01 writes only JSON lines to stdout, with no client address, query or database login in them', async () => {
    await fetch(`http://127.0.0.1:${port}/nothing-here?note=plantedqueryvalue`);
    await vi.waitFor(() => {
      expect(lines().some((line) => line.event === 'http.request_completed' && line.status === 404)).toBe(true);
    });
    const written = stdout.split('\n').filter((line) => line !== '');
    expect(written.filter((line) => !line.startsWith('{'))).toEqual([]);
    expect(stderr).toBe('');
    expect(
      findLeaks(stdout, ['127.0.0.1', 'plantedqueryvalue', 'nothing-here', database.connection('app').password]),
    ).toEqual([]);
  });
});
