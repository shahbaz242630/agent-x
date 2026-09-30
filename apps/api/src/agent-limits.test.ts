// C2-2: each AI agent's own rate limit, beside its address's (SEC-AG-06,
// ADR-011 §4), and an agent's answers allowlisted: nothing a route doesn't
// name reaches an agent (SEC-AG-05), with the key check stood in for.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { errorBody } from './errors.ts';
import { REQUEST_RATE_LIMITED } from './request-log.ts';
import type { SecurityEventNote } from './security-recorder.ts';
import { buildServer } from './server.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const OTHER_AGENT = '0199a0f0-0000-7000-8000-0000000000a2';
const KEY_TEXT = (letter: string) => `axk_${letter.repeat(32)}_${'b'.repeat(43)}`;
/** Two keys of one agent, as through a rotation's overlap, and one of another agent. */
const KEYS: ReadonlyMap<string, AcceptedKey> = new Map(
  [
    ['a', AGENT_ID, '0199a0f0-0000-7000-8000-0000000000b1'],
    ['c', AGENT_ID, '0199a0f0-0000-7000-8000-0000000000b2'],
    ['d', OTHER_AGENT, '0199a0f0-0000-7000-8000-0000000000b3'],
  ].map(([letter = '', agentId = '', keyId = '']) => [
    KEY_TEXT(letter),
    {
      orgId: '0199a0f0-0000-7000-8000-00000000abcd',
      agentId,
      keyId,
      scopes: ['requests:read'],
      expiresAt: new Date('2026-12-28T09:00:00.000Z'),
    },
  ]),
);

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server({ perAddress = 100, perAgent = 10 } = {}) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: 'https://app.agentx.example',
      trustedProxies: [],
      rateLimitPerMinute: perAddress,
      rateLimitPerUserPerMinute: 100,
      rateLimitPerAgentPerMinute: perAgent,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
  });
  const noted: SecurityEventNote[] = [];
  const checked: string[] = [];
  const app = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    securityEvents: { note: (event) => noted.push(event) },
    checkAgentKey: (text) => {
      checked.push(text);
      const key = KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
  });
  servers.push(app);
  const answer: RouteShorthandOptions = {
    config: { access: ['agent'], agentScopes: [] },
    schema: { response: { 200: z.object({ supplierId: z.uuid(), name: z.string() }) } },
  };
  // A route asking for a scope no key here holds: every request refused once the agent is known.
  app.get('/test/payments', { ...answer, config: { access: ['agent'], agentScopes: ['requests:write'] } }, () => ({
    supplierId: '0199a0f0-0000-7000-8000-0000000000e1',
    name: 'Gulf Supplies LLC',
  }));
  app.get('/test/supplier', answer, () => ({
    supplierId: '0199a0f0-0000-7000-8000-0000000000e1',
    name: 'Gulf Supplies LLC',
    // What an agent must never see: a bank detail a careless route read along with the rest.
    iban: `AE07${'0'.repeat(19)}`,
  }));
  await app.ready();
  return { app, noted, checked, lines: () => capture.lines() };
}

const asAgent = (letter: string, remoteAddress = '198.51.100.1') => ({
  url: '/v1/agent',
  headers: { authorization: `Bearer ${KEY_TEXT(letter)}` },
  remoteAddress,
});

describe("SEC-AG-06 C2-2 each agent's own rate limit, beside its address's", () => {
  it('refuses an agent past its own limit, whichever addresses it sends from', async () => {
    const { app } = await server();
    const statuses = [];
    for (let i = 0; i < 10; i += 1)
      statuses.push((await app.inject(asAgent('a', `198.51.100.${String(i)}`))).statusCode);
    const refused = await app.inject(asAgent('a', '198.51.100.99'));

    expect(statuses).toEqual(Array.from({ length: 10 }, () => 200));
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toEqual(errorBody('RATE_LIMITED', refused.headers['x-correlation-id'] as string));
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
    expect(refused.headers).toMatchObject({ 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '0' });
  });

  it('counts the agent, not the key: its two keys through a rotation share one limit', async () => {
    const { app } = await server();
    for (let i = 0; i < 10; i += 1) await app.inject(asAgent(i % 2 === 0 ? 'a' : 'c'));

    expect((await app.inject(asAgent('c'))).statusCode).toBe(429);
    expect((await app.inject(asAgent('a'))).statusCode).toBe(429);
  });

  it('counts an agent refused for a scope it lacks, then answers RATE_LIMITED past its limit (the S68 audit)', async () => {
    const { app } = await server();
    const statuses = [];
    for (let i = 0; i < 11; i += 1) {
      statuses.push(
        (await app.inject({ ...asAgent('a', `198.51.100.${String(i)}`), url: '/test/payments' })).statusCode,
      );
    }

    expect(statuses).toEqual([...Array.from({ length: 10 }, () => 403), 429]);
    // One count: the refusals used the agent's minute up, for its allowed requests too.
    expect((await app.inject(asAgent('a'))).statusCode).toBe(429);
  });

  it('counts each agent on its own', async () => {
    const { app } = await server();
    for (let i = 0; i < 11; i += 1) await app.inject(asAgent('a'));

    expect((await app.inject(asAgent('d'))).statusCode).toBe(200);
  });

  it("says the address's limit on every answer before the refusal", async () => {
    const { app } = await server();
    const first = await app.inject(asAgent('a'));

    expect(first.headers).toMatchObject({ 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '99' });
    expect(first.headers).not.toHaveProperty('retry-after');
  });

  it('notes each refusal as a security event with the address, and names the agent on its line', async () => {
    const { app, noted, lines } = await server();
    for (let i = 0; i < 10; i += 1) await app.inject(asAgent('a'));
    expect(noted).toEqual([]);

    await app.inject(asAgent('a', '203.0.113.9'));

    expect(noted).toEqual([{ kind: 'rate_limited', reason: 'per_agent', ip: '203.0.113.9' }]);
    expect(lines().filter((line) => line.event === REQUEST_RATE_LIMITED)).toEqual([
      expect.objectContaining({ status: 429, agentId: AGENT_ID, agentKeyId: '0199a0f0-0000-7000-8000-0000000000b1' }),
    ]);
  });

  it('counts no refused key against any agent: it is held by its address alone', async () => {
    const { app, noted } = await server();
    for (let i = 0; i < 20; i += 1) expect((await app.inject(asAgent('e'))).statusCode).toBe(401);

    expect((await app.inject(asAgent('a'))).statusCode).toBe(200);
    expect(noted).toEqual([]);
  });

  it("leaves the address's own limit first: a refused address checks no key", async () => {
    const { app, noted, checked } = await server({ perAddress: 10, perAgent: 100 });
    for (let i = 0; i < 11; i += 1) await app.inject(asAgent('a'));

    expect(checked).toHaveLength(10);
    expect(noted).toEqual([{ kind: 'rate_limited', reason: 'per_address', ip: '198.51.100.1' }]);
  });
});

describe("SEC-AG-05 C2-2 an agent's answers are allowlisted", () => {
  it('sends an agent only the fields its route names, whatever else the route returned', async () => {
    const { app } = await server();
    const response = await app.inject({
      url: '/test/supplier',
      headers: { authorization: `Bearer ${KEY_TEXT('a')}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ supplierId: '0199a0f0-0000-7000-8000-0000000000e1', name: 'Gulf Supplies LLC' });
    expect(response.body).not.toContain('AE07');
  });
});
