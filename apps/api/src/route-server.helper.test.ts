// The routes' HTTP tests' shared server (S90's simplify review): the config,
// logger, ids and console sign-in each route test built alike, around the
// routes and the member it hands over. A helper, not a test: Vitest leaves
// `*.helper.test.ts` out (vitest.config.ts), and the name keeps it with the
// tests, which alone may import @agentx/testing.
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';

import { buildServer, type ServerOptions } from './server.ts';

export const PUBLIC_ORIGIN = 'https://app.agentx.example';
/** The console session's cookie the tests send. */
export const COOKIE = 'S'.repeat(43);
/** The organisation the signed-in person is a member of. */
export const ORG = '0199a0f0-0000-7000-8000-00000000abcd';

const CONFIG = {
  http: {
    host: '127.0.0.1',
    port: 0,
    publicOrigin: PUBLIC_ORIGIN,
    trustedProxies: [],
    rateLimitPerMinute: 1000,
    rateLimitPerUserPerMinute: 1000,
    rateLimitPerAgentPerMinute: 1000,
  },
  log: { level: 'info' as const, eventCapPerMinute: 10_000 },
};

const servers: FastifyInstance[] = [];

/** Closes every server started since it last ran: each test file's afterEach. */
export const closeServers = async (): Promise<void> => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
};

/** The console's sign-in with COOKIE as the session given; nothing else is in these tests. */
const signedIn = (live: LiveSession): SignIn => ({
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(undefined),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? live : undefined),
});

/**
 * A ready server with the routes given: COOKIE signs in as `live`, a `member`
 * of ORG and of no other organisation (none at all when not given), never
 * restricted. A route's own membership check replaces that one.
 */
export async function routeServer({
  live,
  member,
  ...routes
}: {
  readonly live: LiveSession;
  readonly member?: MembershipCheck;
} & Partial<ServerOptions>): Promise<FastifyInstance> {
  const app = await buildServer({
    config: CONFIG,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...CONFIG },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: signedIn(live), sessionSeconds: 43_200 },
    restrictedUntil: () => Promise.resolve(undefined),
    findMembership: (orgId) =>
      Promise.resolve(member !== undefined && orgId.toLowerCase() === ORG ? member : ({ outcome: 'none' } as const)),
    ...routes,
  });
  servers.push(app);
  await app.ready();
  return app;
}
