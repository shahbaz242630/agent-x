// 6E4: the TS canaries (canary.ts) against the API's MCP endpoint on a real
// socket, as staging's daily run reaches it: each real client, pinned, lists
// the seven tools and reads get_agent's typed answer, and the judge passes it.
// The positive controls: a wrong key, and an address with no MCP server, each
// turn every canary red, never green. The use cases are left out: get_agent
// answers from the key alone (mcp-conformance.test.ts does the same).
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { buildServer } from '../../apps/api/src/server.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { SequentialIds } from '../../packages/testing/src/ids.ts';
import { LogCapture } from '../../packages/testing/src/log-scan.ts';
import { EXPECTED_TOOLS, judgeCanary } from './canary-judge.ts';
import { CANARIES, main } from './canary.ts';

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const WRONG_KEY = `axk_${'c'.repeat(32)}_${'d'.repeat(43)}`;
const AGENT = {
  orgId: '0199a0f0-0000-7000-8000-00000000abcd',
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes: ['sources:read', 'suppliers:read'] as const,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
};

let api: Awaited<ReturnType<typeof buildServer>>;
let url = '';

beforeAll(async () => {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: 'https://app.agentx.example',
      trustedProxies: [],
      rateLimitPerMinute: 10_000,
      rateLimitPerUserPerMinute: 10_000,
      rateLimitPerAgentPerMinute: 10_000,
      rateLimitPerOrganisationPerMinute: 100_000,
      webCopies: 1,
      mcpOauth: false,
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
  url = `http://127.0.0.1:${String((api.server.address() as AddressInfo).port)}/v1/mcp`;
}, 60_000);

afterAll(async () => {
  await api.close();
});

describe('the TS canaries against a real MCP endpoint (6E4)', () => {
  it.each(Object.keys(CANARIES))('%s lists the seven tools and reads get_agent, and passes', async (name) => {
    const seen = await CANARIES[name]?.({ url, key: KEY, allowHttp: true });
    expect(seen?.failed).toBeUndefined();
    expect(seen?.tools?.toSorted()).toEqual([...EXPECTED_TOOLS].sort());
    expect(seen?.agent).toMatchObject({
      isError: false,
      structuredContent: { agentId: AGENT.agentId, organizationId: AGENT.orgId, scopes: [...AGENT.scopes] },
    });
    expect(seen?.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(judgeCanary(seen ?? { canary: name, client: '?', version: '?' }).errors).toEqual([]);
  });

  it('speaks each era it claims: the 2025 handshake and the 2026-07-28 revision', async () => {
    const legacy = await CANARIES['ts-legacy']?.({ url, key: KEY });
    const modern = await CANARIES['ts-modern']?.({ url, key: KEY });
    expect(legacy?.protocol).toMatch(/^2025-/);
    expect(modern?.protocol).toBe('2026-07-28');
  });

  // The positive controls: a canary that can't get in, or reaches no MCP server, is red, and never shows the key.
  it.each(Object.keys(CANARIES))('%s goes red with a key staging refuses, naming no key', async (name) => {
    const seen = await CANARIES[name]?.({ url, key: WRONG_KEY, allowHttp: true });
    expect(seen?.failed?.step).toBe('connect');
    const { errors } = judgeCanary(seen ?? { canary: name, client: '?', version: '?' });
    expect(errors).toHaveLength(1);
    expect(errors.join('')).not.toContain(WRONG_KEY.slice(4));
  });

  it('runs from the command line: red when staging is out of reach or the secrets are missing, its usage otherwise', async () => {
    const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    // An https address nothing listens on: the client can't connect, so the canary is red.
    expect(await main(['ts-legacy'], { AGENTX_MCP_ORIGIN: 'https://127.0.0.1:1', AGENTX_MCP_KEY: KEY })).toBe(1);
    expect(out).toHaveBeenCalledWith(
      expect.stringMatching(/^::error::The ts-legacy canary, @modelcontextprotocol\/client \d/),
    );
    // The bridge too, on an https address as staging's (no --allow-http).
    expect(await main(['mcp-remote'], { AGENTX_MCP_ORIGIN: 'https://127.0.0.1:1', AGENTX_MCP_KEY: KEY })).toBe(1);
    expect(await main(['ts-legacy'], {})).toBe(1);
    expect(await main(['nothing'], {})).toBe(2);
    expect(await main([], {})).toBe(2);
    vi.restoreAllMocks();
  });

  it.each(Object.keys(CANARIES))('%s goes red where no MCP server answers', async (name) => {
    const seen = await CANARIES[name]?.({ url: url.replace('/v1/mcp', '/v1/none'), key: KEY, allowHttp: true });
    expect(seen?.failed).toBeDefined();
    expect(judgeCanary(seen ?? { canary: name, client: '?', version: '?' }).errors).toHaveLength(1);
  });
});
