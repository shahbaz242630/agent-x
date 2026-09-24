// ADR-011 §4, SEC-AV-07: the rate limit per client address, counted for every
// request, including 404s, refusals and malformed addresses; and, beside it,
// each signed-in person's own (B2-5c).
//
// It counts with the plugin's `createRateLimit`, not its `rateLimit` hook. That
// hook marks each request as counted, which would stop any route's own limit
// from running, such as the per-agent limits in Phase 1.
//
// The client address comes from the raw request, with the server's own trust
// rule, not from `request.ip`: Fastify builds the request for a malformed
// address without its proxy rule, so behind a proxy every such request would
// count as the proxy's.
import proxyAddr from '@fastify/proxy-addr';
import rateLimit, { normalizeIP } from '@fastify/rate-limit';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

/** Which addresses are trusted proxies, compiled once. The server uses the same rule for `request.ip`. */
export type ProxyTrust = (address: string, hop: number) => boolean;

/** The setting counts requests per minute. */
const WINDOW_MS = 60_000;

/** IPv6 clients usually hold a whole /64, so it counts as one address (the plugin's default). */
const IPV6_PREFIX = 64;

/** The one bucket for requests whose address can't be read, such as one whose connection already closed. */
export const UNREADABLE_ADDRESS = 'unreadable-address';

/** The headers the counter sets, which an error response keeps. */
export const RATE_LIMIT_HEADERS = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'retry-after'];

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

/** The client's address as the trust rule reads it from the connection and its proxies' headers. */
function rawClientIp(request: FastifyRequest, trust: ProxyTrust): string | undefined {
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
    keyGenerator: (request) => clientKey(rawClientIp(request, trust)),
  });
}

/** Counts a request against a limit: `createCounter`'s and `createPersonCounter`'s hooks. */
export type CountRequest = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

/** One limit's counter, from the plugin's `createRateLimit`. */
type Limiter = ReturnType<FastifyInstance['createRateLimit']>;

/**
 * The hook that counts each request against its address's limit and sets the
 * limit headers. Over the limit, it tells `limited` the client's address, then
 * throws a 429 error, which the error handler answers with `RATE_LIMITED`.
 */
export function createCounter(trust: ProxyTrust, limited: (ip: string | undefined) => void): CountRequest {
  return async (request, reply) => {
    // The address's limit is the plugin's own, set at registration.
    if (await overLimit(request.server.createRateLimit(), request, reply, 'always')) {
      limited(rawClientIp(request, trust));
      throw new RateLimited('rate limit exceeded');
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
  limited: (ip: string | undefined, userId: string) => void,
): CountRequest {
  const limiter = app.createRateLimit({
    max: perMinute,
    timeWindow: WINDOW_MS,
    // Only called for a request with a person: the hook below looks first.
    keyGenerator: (request) => request.person?.userId ?? UNREADABLE_ADDRESS,
  });
  return async (request, reply) => {
    const person = request.person;
    if (person === null) return;
    if (await overLimit(limiter, request, reply, 'when-refused')) {
      limited(rawClientIp(request, trust), person.userId);
      throw new RateLimited('rate limit exceeded');
    }
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
