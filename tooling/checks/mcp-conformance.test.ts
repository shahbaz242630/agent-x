// 6E2 (MCP-Guide §7, early warning): the official MCP conformance suite
// (`@modelcontextprotocol/conformance`, pinned) against the API's MCP endpoint
// on a real socket, for each protocol revision we serve. A revision's own
// requirement set must pass (2026-07-28 and 2025-11-25: blocking), less the
// checks baselined in mcp-conformance.<revision>.yml with their reasons: the
// suite's fixture tools, and the prompts, resources, elicitation and sampling
// this server deliberately doesn't have. A baselined check that starts passing
// fails the run too, so the baseline never goes stale. The draft suite runs too, reported and never failing: it says
// what the next revision would break before it ships.
//
// The suite can't send a header, so a small proxy in front adds the agent's key,
// as an agent's client does. The use cases are left out: the protocol is under
// test, not what a tool does (mcp.test.ts holds that).
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, request as forward, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildServer } from '../../apps/api/src/server.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { SequentialIds } from '../../packages/testing/src/ids.ts';
import { LogCapture } from '../../packages/testing/src/log-scan.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const AGENT = {
  orgId: '0199a0f0-0000-7000-8000-00000000abcd',
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes: ['requests:write', 'requests:read', 'sources:read', 'suppliers:read'] as const,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
};
/** The suite's own command line, as the pinned package installs it. */
const CLI = createRequire(import.meta.url).resolve('@modelcontextprotocol/conformance/dist/index.js');
/** A revision's baseline: what its requirement set checks that we deliberately don't do, each with its reason. */
const baselineOf = (revision: string) => path.resolve(`tooling/checks/mcp-conformance.${revision}.yml`);

let api: Awaited<ReturnType<typeof buildServer>>;
let proxy: Server;
let url = '';
const outputs = process.env.MCP_CONFORMANCE_OUT ?? mkdtempSync(path.join(tmpdir(), 'mcp-conformance-'));

beforeAll(async () => {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 10_000,
      rateLimitPerUserPerMinute: 10_000,
      rateLimitPerAgentPerMinute: 10_000,
      rateLimitPerOrganisationPerMinute: 100_000,
      webCopies: 1,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  api = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    checkAgentKey: (text) =>
      Promise.resolve(text === KEY ? { outcome: 'accepted', key: AGENT } : { outcome: 'refused' }),
  });
  await api.listen({ host: '127.0.0.1', port: 0 });
  const target = api.server.address() as AddressInfo;
  // The agent's key on every request, as its client sends it; everything else as the suite sent it.
  proxy = createServer((incoming, outgoing) => {
    const upstream = forward(
      {
        host: '127.0.0.1',
        port: target.port,
        method: incoming.method,
        path: incoming.url,
        headers: { ...incoming.headers, authorization: `Bearer ${KEY}` },
      },
      (answer) => {
        outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
        answer.pipe(outgoing);
      },
    );
    upstream.on('error', () => outgoing.destroy());
    incoming.pipe(upstream);
  });
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${String((proxy.address() as AddressInfo).port)}/v1/mcp`;
}, 60_000);

afterAll(async () => {
  await new Promise<void>((resolve) =>
    proxy.close(() => {
      resolve();
    }),
  );
  await api.close();
  if (process.env.MCP_CONFORMANCE_OUT === undefined) rmSync(outputs, { recursive: true, force: true });
});

/** Runs the suite with these arguments: its exit code, and what it printed. */
function conformance(...args: readonly string[]): Promise<{ readonly code: number | null; readonly output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'server', '--url', url, '--output-dir', outputs, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, output });
    });
  });
}

describe('the MCP endpoint passes the official conformance suite (6E2, MCP-Guide §7)', () => {
  it.each(['2026-07-28', '2025-11-25'])(
    "passes revision %s's requirement set, less the baselined fixtures",
    async (revision) => {
      const { code, output } = await conformance(
        '--requirements',
        revision,
        '--expected-failures',
        baselineOf(revision),
      );
      expect(code, output).toBe(0);
    },
  );

  it('runs the draft suite and reports it, never failing: what the next revision would break', async () => {
    const { code, output } = await conformance('--suite', 'draft');
    // Reported only (MCP-Guide §7): a red draft is a warning to read, not a broken build.
    console.info(`MCP conformance, draft suite (exit ${String(code)}):\n${output.slice(-4000)}`);
    expect(code === null || typeof code === 'number').toBe(true);
  });
});
