// ADR-011 §4, SEC-AV-07: the rate limit per client address, counted for every
// request, including 404s, refusals and malformed addresses; and, beside it,
// each signed-in person's own (B2-5c), each agent's and each organisation's.
//
// It counts with the plugin's `createRateLimit`, not its `rateLimit` hook. That
// hook marks each request as counted, which would stop any route's own limit
// from running, such as the per-agent limits in Phase 1.
//
// Every count is this process's own, in memory. With several `web` copies
// (AGENTX_WEB_COPIES, 4D2e D12) each allows its share, the limit / copies
// rounded up (`shareOfCopies`). The trade: a balancer sending one caller more
// to one copy than another refuses it a little under its limit, and rounding up
// lets it through at most copies - 1 over in a window. No count is shared
// between copies (a shared counter is left out, Stage D's design).
//
// The client address comes from the raw request, with the server's own trust
// rule, not from `request.ip`: Fastify builds the request for a malformed
// address without its proxy rule, so behind a proxy every such request would
// count as the proxy's.
import proxyAddr from '@fastify/proxy-addr';
import rateLimit, { type CreateRateLimitOptions, normalizeIP } from '@fastify/rate-limit';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

/** Which addresses are trusted proxies, compiled once. The server uses the same rule for `request.ip`. */
export type ProxyTrust = (address: string, hop: number) => boolean;

/** The setting counts requests per minute. */
const WINDOW_MS = 60_000;

/**
 * The callers each counter remembers, about 230 bytes each (measured on the plugin's store), so about 23 MB a counter
 * when full; the plugin's own default is 5,000. Not a limit on callers: past it, the one longest unheard from is
 * forgotten and starts a fresh count. That frees a caller from its limit only if 100,000 others are heard from
 * between two of its requests; copies divide the callers between them, so each remembers further.
 */
const CALLERS_REMEMBERED = 100_000;

/** One copy's share of a limit across all `web` copies: rounded up, so never none. */
export const shareOfCopies = (limit: number, copies: number): number => Math.ceil(limit / copies);

/** IPv6 clients usually hold a whole /64, so it counts as one address (the plugin's default). */
const IPV6_PREFIX = 64;

/** The one bucket for requests whose address can't be read, such as one whose connection already closed. */
export const UNREADABLE_ADDRESS = 'unreadable-address';

/** The headers the counter sets, which an error response keeps. */
export const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'retry-after',
] as const;

const ipAddress = z.union([z.ipv4(), z.ipv6()]);

/** Some proxies write `address:port` in `X-Forwarded-For`; the port changes with every connection. */
const IPV4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/;
const BRACKETED_IPV6 = /^\[([0-9A-Fa-f:.]{2,45})\](?::\d{1,5})?$/;

/**
 * The client's address without a port or brackets, or undefined if it isn't a
 * plain IP address. It never throws. The address is undefined when the
 * connection closed before it was read. The security events keep this whole
 * address (B2-5b); the rate limit counts it per /64 (`clientKey`).
 */
export function clientAddress(ip: string | undefined): string | undefined {
  if (ip === undefined) return undefined;
  const address = IPV4_WITH_PORT.exec(ip)?.[1] ?? BRACKETED_IPV6.exec(ip)?.[1] ?? ip;
  return ipAddress.safeParse(address).success ? address : undefined;
}

/** The key a request is counted under: its client address, per /64 for IPv6. It never throws. */
export function clientKey(ip: string | undefined): string {
  const address = clientAddress(ip);
  return address === undefined ? UNREADABLE_ADDRESS : normalizeIP(address, IPV6_PREFIX);
}

/** An IPv6 network a registration counts under (6F1 G4): a site's whole allocation, usually a /48. */
const IPV6_NETWORK_PREFIX = 48;

/**
 * The network a request is counted under where one network's many addresses must count as one (6F1 G4, the OAuth
 * registrations' day): an IPv4 address's /24 (`192.0.2.0`), an IPv6 address's /48. It never throws.
 */
export function clientNetwork(ip: string | undefined): string {
  const address = clientAddress(ip);
  if (address === undefined) return UNREADABLE_ADDRESS;
  const network = normalizeIP(address, IPV6_NETWORK_PREFIX);
  // normalizeIP gives an IPv4 address, or an IPv6 address written as one (::ffff:a.b.c.d), as plain IPv4.
  return network.includes(':') ? network : network.replace(/\.\d+$/, '.0');
}

/**
 * The network an OAuth flow is counted under beside its source (AG8): an IPv4 address alone, as its source is, or an
 * IPv6 address's /48, the whole site a /64 source sits in. It never throws.
 */
export function clientSite(ip: string | undefined): string {
  const address = clientAddress(ip);
  // normalizeIP gives an IPv4 address, or an IPv6 address written as one (::ffff:a.b.c.d), as plain IPv4.
  return address === undefined ? UNREADABLE_ADDRESS : normalizeIP(address, IPV6_NETWORK_PREFIX);
}

/** The client's address as the trust rule reads it from the connection and its proxies' headers. */
export function rawClientIp(request: FastifyRequest, trust: ProxyTrust): string | undefined {
  // eslint-disable-next-line no-restricted-properties -- the connection's address, read and never written to
  return proxyAddr(request.raw, trust);
}

class RateLimited extends Error {
  readonly statusCode = 429;
}

/** The trust rule for a list of proxy addresses and ranges; an empty list trusts none. */
export function proxyTrust(trustedProxies: readonly string[]): ProxyTrust {
  return proxyAddr.compile([...trustedProxies]);
}

/** Registers the plugin with the limit per client address. `createCounter`'s hook then works on the app's requests. */
export async function registerRateLimit(app: FastifyInstance, perMinute: number, trust: ProxyTrust): Promise<void> {
  await app.register(rateLimit, {
    global: false,
    max: perMinute,
    timeWindow: WINDOW_MS,
    cache: CALLERS_REMEMBERED,
    keyGenerator: (request) => clientKey(rawClientIp(request, trust)),
  });
}

/** Counts a request against a limit: `createCounter`'s and `createPersonCounter`'s hooks. */
export type CountRequest = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

/** One limit's counter, from the plugin's `createRateLimit`. */
type Limiter = ReturnType<FastifyInstance['createRateLimit']>;

/**
 * A limit's counter of its own, keyed by `key`. The plugin's store takes `cache` from these options (its `child`),
 * though its type for them leaves it out; rate-limit.test.ts holds it to remembering past the plugin's default.
 */
function counterOf(
  app: FastifyInstance,
  perMinute: number,
  key: (request: FastifyRequest) => string,
  windowMs = WINDOW_MS,
): Limiter {
  const options: CreateRateLimitOptions & { readonly cache: number } = {
    max: perMinute,
    timeWindow: windowMs,
    cache: CALLERS_REMEMBERED,
    keyGenerator: key,
  };
  return app.createRateLimit(options);
}

/**
 * The part of an address's limit its agents can never use (S219): a fifth, at least one. An agent on its people's own
 * laptop or office network shares their address; flooding, it used the whole limit and refused their Suspend press
 * (S219's timed kill-switch test on staging). So the console and the brakes always keep this much.
 */
export const reservedForPeople = (perMinute: number): number => Math.max(1, Math.ceil(perMinute / 5));

/**
 * An agent's tools' request, as the access hook tells it (access.ts): any Authorization header; none on the MCP
 * endpoint (`toolCalls`); and an OAuth client's own calls, keyless by nature: discovery (`/.well-known/…`) and the
 * token, revoke, register and device endpoints (`oauthClient`). Not `/v1/oauth/authorize`: that is the person's browser.
 */
const fromAgentSide = (request: FastifyRequest): boolean => {
  const { config, url } = request.routeOptions;
  return (
    request.headers.authorization !== undefined ||
    config.toolCalls === true ||
    config.oauthClient === true ||
    (config.oauth === true && url?.startsWith('/.well-known/') === true)
  );
};

/**
 * The hook that counts each request against its address's limit and sets the
 * limit headers. Over the limit, it tells `limited` the client's address and
 * which limit, then throws a 429 error, which the error handler answers with `RATE_LIMITED`.
 *
 * An agent's request is refused, uncounted, once the address's own count this minute has reached the agents' share
 * (`perMinute` less `reservedForPeople`), read from the same count, so the same window: agents can never take the
 * last fifth, and its people (the console, the brakes) always have it (S219). A second count of agents' own would run
 * its own window, and agents past it near one window's end got a second share in the address's next (S219 review).
 * The read and the count are two awaited steps, and requests pipelined on one connection start in the same tick: so
 * each address's agents' requests read but not yet counted are held here (`inFlight`, synchronous) and added to what
 * is read; without it one pipelined burst took the whole limit (S219 review). Held twice for a moment, they can only
 * refuse a little early. The address's total stays `perMinute`, so its request lines still can't fill the log (rateLimitProblems).
 * `perMinute` is this copy's share, as registered. A rogue agent sending keyless requests to people's routes counts as
 * people: no split by headers can tell, so this holds against an agent flooding by mistake, not one aimed at the brakes.
 */
export function createCounter(
  trust: ProxyTrust,
  perMinute: number,
  limited: (ip: string | undefined, reason: 'per_address' | 'per_address_agents') => void,
): CountRequest {
  const agentsShare = Math.max(1, perMinute - reservedForPeople(perMinute));
  /** Per address key: its agents' requests read and not yet counted. An entry lives only while one is. */
  const inFlight = new Map<string, number>();
  const overAddress = async (address: Limiter, request: FastifyRequest, reply: FastifyReply) => {
    if (await overLimit(address, request, reply, 'always')) {
      limited(rawClientIp(request, trust), 'per_address');
      throw new RateLimited('rate limit exceeded');
    }
  };
  return async (request, reply) => {
    // The address's limit is the plugin's own, set at registration.
    const address = request.server.createRateLimit();
    if (!fromAgentSide(request)) {
      await overAddress(address, request, reply);
      return;
    }
    const key = clientKey(rawClientIp(request, trust));
    const others = inFlight.get(key) ?? 0;
    inFlight.set(key, others + 1);
    try {
      const seen = await address(request, { increment: false });
      if (!seen.isAllowed && seen.max - seen.remaining + others >= agentsShare) {
        void reply.headers({
          'x-ratelimit-limit': agentsShare,
          'x-ratelimit-remaining': 0,
          'x-ratelimit-reset': seen.ttlInSeconds,
          'retry-after': seen.ttlInSeconds,
        });
        limited(rawClientIp(request, trust), 'per_address_agents');
        throw new RateLimited('rate limit exceeded');
      }
      await overAddress(address, request, reply);
    } finally {
      const left = (inFlight.get(key) ?? 1) - 1;
      if (left > 0) inFlight.set(key, left);
      else inFlight.delete(key);
    }
  };
}

/**
 * The hook that counts each signed-in person's requests against their own
 * limit (ADR-011 §4, B2-5c), beside their address's: a person's session used
 * from many addresses is still one person. It runs after the access hook, and
 * counts only a request it found a person for. Over the limit, it tells
 * `limited` the client's address and the person, sets the limit headers to
 * the person's, since theirs is the one refusing, and throws the same 429.
 *
 * The counter is made here, once: each `createRateLimit` with options of its
 * own starts a count of its own.
 */
export function createPersonCounter(
  app: FastifyInstance,
  perMinute: number,
  trust: ProxyTrust,
  /** `orgId`: the organisation their membership was found active in for this request (6E1b); null for none. */
  limited: (ip: string | undefined, userId: string, orgId: string | null) => void,
): CountRequest {
  // Only called for a request with a person: the hook below looks first.
  const limiter = counterOf(app, perMinute, (request) => request.person?.userId ?? UNREADABLE_ADDRESS);
  return async (request, reply) => {
    const person = request.person;
    if (person === null) return;
    if (await overLimit(limiter, request, reply, 'when-refused')) {
      limited(rawClientIp(request, trust), person.userId, request.verifiedOrg);
      throw new RateLimited('rate limit exceeded');
    }
  };
}

/**
 * The hook that counts each AI agent's requests against its own limit
 * (ADR-011 §4, SEC-AG-06; C2-2), beside its address's: by the agent, not the
 * key, so an agent holding two keys through a rotation's overlap, or sending
 * from many addresses, is still one agent. It runs after the access hook, and
 * counts only a request whose key it accepted; a refused key is held by its
 * address's limit alone. Over the limit, it tells `limited` the client's
 * address and the agent, sets the limit headers to the agent's, and throws
 * the same 429. The request's line names the agent (request-log.ts).
 */
export function createAgentCounter(
  app: FastifyInstance,
  perMinute: number,
  trust: ProxyTrust,
  limited: (ip: string | undefined, agent: { readonly agentId: string; readonly orgId: string }) => void,
): CountRequest {
  // Only called for a request with an agent: the hook below looks first.
  const limiter = counterOf(app, perMinute, (request) => request.agent?.agentId ?? UNREADABLE_ADDRESS);
  return async (request, reply) => {
    const agent = request.agent;
    if (agent === null) return;
    if (await overLimit(limiter, request, reply, 'when-refused')) {
      limited(rawClientIp(request, trust), agent);
      throw new RateLimited('rate limit exceeded');
    }
  };
}

/**
 * The hook that counts each organisation's agents' requests against its own
 * limit (4D2d, PL-63), beside each agent's: what they send together can't take
 * another organisation's room, and it only ever refuses the organisation that
 * hit it. Never its people's: runaway agents using the count up would lock an
 * admin out of the brakes (the review, S166), and each person has their own limit.
 * It runs after the access hook. Over the limit, it tells `limited` the client's address, sets
 * the limit headers to the organisation's, and throws the same 429.
 */
export function createOrganisationCounter(
  app: FastifyInstance,
  perMinute: number,
  trust: ProxyTrust,
  limited: (ip: string | undefined, agent: { readonly agentId: string; readonly orgId: string }) => void,
): CountRequest {
  // Only called for a request with an agent: the hook below looks first.
  const limiter = counterOf(app, perMinute, (request) => request.agent?.orgId ?? UNREADABLE_ADDRESS);
  return async (request, reply) => {
    const agent = request.agent;
    if (agent === null) return;
    if (await overLimit(limiter, request, reply, 'when-refused')) {
      limited(rawClientIp(request, trust), agent);
      throw new RateLimited('rate limit exceeded');
    }
  };
}

/**
 * A route's own limit per client address (6E3a: the OAuth endpoints'), beside the address's limit for every route,
 * in a window of its own (`windowMs`): an hour for registering a client, a minute for the rest. A count of its own
 * for each counter made. Over it, the limit headers are its own, and the same 429. `keyOf` groups the addresses
 * counted as one: `clientKey` (an IPv6 /64) unless the route's own pool groups them otherwise (sign-ins: `clientSite`).
 */
export function createAddressCounter(
  app: FastifyInstance,
  { most, windowMs }: { readonly most: number; readonly windowMs: number },
  trust: ProxyTrust,
  keyOf: (ip: string | undefined) => string = clientKey,
): CountRequest {
  const limiter = counterOf(app, most, (request) => keyOf(rawClientIp(request, trust)), windowMs);
  return async (request, reply) => {
    if (await overLimit(limiter, request, reply, 'when-refused')) throw new RateLimited('rate limit exceeded');
  };
}

/**
 * A route's own limit per signed-in person (6E3c: a device's user code typed, 5 a minute), beside every other, in a
 * window of its own. Added after the access hook (a `preHandler`) on a person's route, which the access hook lets
 * through only with a person. Over it, the limit headers are its own, and the same 429.
 */
export function createRoutePersonCounter(
  app: FastifyInstance,
  { most, windowMs }: { readonly most: number; readonly windowMs: number },
): CountRequest {
  const limiter = counterOf(app, most, (request) => request.person?.userId ?? UNREADABLE_ADDRESS, windowMs);
  return async (request, reply) => {
    if (await overLimit(limiter, request, reply, 'when-refused')) throw new RateLimited('rate limit exceeded');
  };
}

/**
 * Counts the request and says whether it is over the limit. The limit headers
 * are set on every counted response (`always`), or only when this limit
 * refuses the request (`when-refused`), so the address's headers stand
 * otherwise.
 */
async function overLimit(
  limiter: Limiter,
  request: FastifyRequest,
  reply: FastifyReply,
  headers: 'always' | 'when-refused',
): Promise<boolean> {
  const result = await limiter(request);
  // Only an allow list lets a request through uncounted, and none is set. The
  // check is here for TypeScript, which sees the counted fields only after it.
  if (result.isAllowed) return false;
  if (headers === 'when-refused' && !result.isExceeded) return false;
  void reply.headers({
    'x-ratelimit-limit': result.max,
    'x-ratelimit-remaining': result.remaining,
    'x-ratelimit-reset': result.ttlInSeconds,
  });
  if (!result.isExceeded) return false;
  void reply.header('retry-after', result.ttlInSeconds);
  return true;
}
