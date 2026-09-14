// The API as it really runs: `node apps/api/src/main.ts` in its own process,
// with Node stripping the TypeScript itself, real sockets and the real stdout.
// The unit tests run the same code in-process through Vitest; this proves the
// entry point starts on plain Node, writes only clean JSON lines, and answers
// with the protections in place. (Stopping on a signal is tested in-process:
// Windows can't send one a process can catch.)
import { type ChildProcess, spawn } from 'node:child_process';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { findLeaks } from '../../packages/testing/src/log-scan.ts';

const MAIN = path.resolve('apps/api/src/main.ts');
const PUBLIC_ORIGIN = 'http://localhost:8080';

/** The parent's environment without any AGENTX_ setting, plus a test run's. */
function childEnv(): NodeJS.ProcessEnv {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith('AGENTX_')),
  );
  return { ...inherited, AGENTX_ENV: 'test', AGENTX_HTTP_PORT: '0', AGENTX_PUBLIC_ORIGIN: PUBLIC_ORIGIN };
}

interface Line {
  event?: string;
  ports?: number[];
  configHash?: string;
  status?: number;
}

let child: ChildProcess;
let stdout = '';
let stderr = '';
let port = 0;

beforeAll(async () => {
  child = spawn(process.execPath, [MAIN], { env: childEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
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

afterAll(() => {
  child.kill();
});

function lines(): Line[] {
  return stdout
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as Line);
}

describe('the API process', () => {
  it('SEC-OPS-05 logs its config fingerprint, then listens', () => {
    const events = lines().map((line) => line.event);
    expect(events.indexOf('api.starting')).toBeLessThan(events.indexOf('api.listening'));
    expect(lines().find((line) => line.event === 'api.starting')?.configHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

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

  it('SEC-DATA-01 writes only JSON lines to stdout, with no client address or query in them', async () => {
    await fetch(`http://127.0.0.1:${port}/nothing-here?note=plantedqueryvalue`);
    await vi.waitFor(() => {
      expect(lines().some((line) => line.event === 'http.request_completed' && line.status === 404)).toBe(true);
    });
    const written = stdout.split('\n').filter((line) => line !== '');
    expect(written.filter((line) => !line.startsWith('{'))).toEqual([]);
    expect(findLeaks(stdout, ['127.0.0.1', 'plantedqueryvalue', 'nothing-here'])).toEqual([]);
  });
});
