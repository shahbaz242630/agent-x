// ADR-011 §4, SEC-AV-07: the rate limit per client address, counted for every
// request, including 404s, refusals and malformed addresses.
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
 * The key a request is counted under: its client address without a port, per
 * /64 for IPv6. It never throws. The address is undefined when the connection
 * closed before it was read.
 */
export function clientKey(ip: string | undefined): string {
  if (ip === undefined) return UNREADABLE_ADDRESS;
  const address = IPV4_WITH_PORT.exec(ip)?.[1] ?? BRACKETED_IPV6.exec(ip)?.[1] ?? ip;
  return ipAddress.safeParse(address).success ? normalizeIP(address, IPV6_PREFIX) : UNREADABLE_ADDRESS;
}

class RateLimited extends Error {
  readonly statusCode = 429;
}

/** The trust rule for a list of proxy addresses and ranges; an empty list trusts none. */
export function proxyTrust(trustedProxies: readonly string[]): ProxyTrust {
  return proxyAddr.compile([...trustedProxies]);
}

/** Registers the plugin with the limit per client address. `countRequest` then works on the app's requests. */
export async function registerRateLimit(app: FastifyInstance, perMinute: number, trust: ProxyTrust): Promise<void> {
  await app.register(rateLimit, {
    global: false,
    max: perMinute,
    timeWindow: WINDOW_MS,
    // eslint-disable-next-line no-restricted-properties -- the connection's address, read and never written to
    keyGenerator: (request) => clientKey(proxyAddr(request.raw, trust)),
  });
}

/**
 * Counts the request against its address's limit and sets the limit headers.
 * Over the limit, it throws a 429 error, which the error handler answers with
 * `RATE_LIMITED`.
 */
export async function countRequest(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const result = await request.server.createRateLimit()(request);
  // Only an allow list lets a request through uncounted, and none is set. The
  // check is here for TypeScript, which sees the counted fields only after it.
  if (result.isAllowed) return;
  void reply.headers({
    'x-ratelimit-limit': result.max,
    'x-ratelimit-remaining': result.remaining,
    'x-ratelimit-reset': result.ttlInSeconds,
  });
  if (result.isExceeded) {
    void reply.header('retry-after', result.ttlInSeconds);
    throw new RateLimited('rate limit exceeded');
  }
}
