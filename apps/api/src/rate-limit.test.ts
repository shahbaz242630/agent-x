import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  clientAddress,
  clientKey,
  createCounter,
  createOrganisationCounter,
  proxyTrust,
  registerRateLimit,
  shareOfCopies,
  UNREADABLE_ADDRESS,
} from './rate-limit.ts';

describe('SEC-AV-07 the key a request is counted under', () => {
  it.each([
    ['an IPv4 address', '203.0.113.9', '203.0.113.9'],
    ['an IPv4 address with a port', '203.0.113.9:40001', '203.0.113.9'],
    ['an IPv4-mapped address, as a dual-stack server sees IPv4 clients', '::ffff:203.0.113.9', '203.0.113.9'],
    ['an IPv6 address, counted per /64', '2001:db8:1:2:aaaa:bbbb:cccc:dddd', '2001:db8:1:2::'],
    ['another address in the same /64', '2001:db8:1:2::7', '2001:db8:1:2::'],
    ['a bracketed IPv6 address with a port', '[2001:db8:1:2::7]:443', '2001:db8:1:2::'],
    ['a bracketed IPv6 address without one', '[2001:db8:1:2::7]', '2001:db8:1:2::'],
  ])('keys %s by the address', (_what, ip, expected) => {
    expect(clientKey(ip)).toBe(expected);
  });

  it.each([
    ["a request whose connection closed first, so Node can't give its address", undefined],
    ['text that is no address', 'unknown'],
    ['an empty value', ''],
    ['an IPv4 address with a port too big', '203.0.113.9:999999'],
    ['an IPv6 address with a zone', 'fe80::1%eth0'],
  ])('puts %s in one shared bucket, and never throws', (_what, ip) => {
    expect(clientKey(ip)).toBe(UNREADABLE_ADDRESS);
  });
});

describe('SEC-AV-07 the client address the security events keep', () => {
  it.each([
    ['an IPv4 address', '203.0.113.9', '203.0.113.9'],
    ['an IPv4 address with a port', '203.0.113.9:40001', '203.0.113.9'],
    ['an IPv4-mapped address', '::ffff:203.0.113.9', '::ffff:203.0.113.9'],
    ['an IPv6 address, whole, never per /64', '2001:db8:1:2:aaaa:bbbb:cccc:dddd', '2001:db8:1:2:aaaa:bbbb:cccc:dddd'],
    ['a bracketed IPv6 address with a port', '[2001:db8:1:2::7]:443', '2001:db8:1:2::7'],
    ['a bracketed IPv6 address without one', '[2001:db8:1:2::7]', '2001:db8:1:2::7'],
  ])('keeps %s without its port or brackets', (_what, ip, expected) => {
    expect(clientAddress(ip)).toBe(expected);
  });

  it.each([
    ['a request whose connection closed first', undefined],
    ['text that is no address', 'unknown'],
    ['an empty value', ''],
    ['an IPv4 address with a port too big', '203.0.113.9:999999'],
    ['an IPv6 address with a zone', 'fe80::1%eth0'],
    ['text that passes a URL parse as a bracketed host', '::1]/x'],
  ])('has none for %s, and never throws', (_what, ip) => {
    expect(clientAddress(ip)).toBeUndefined();
  });
});

describe("one copy's share of a limit across several web copies (4D2e D12)", () => {
  it.each([
    [300, 1, 300],
    [300, 3, 100],
    [10, 3, 4],
    [10, 1000, 1],
  ])('is %i over %i copies at %i each, rounded up so never none', (limit, copies, share) => {
    expect(shareOfCopies(limit, copies)).toBe(share);
  });
});

describe('the callers a counter remembers', () => {
  /** Past the plugin's own default of 5,000, which would forget the first caller. */
  const OTHERS = 6000;
  const reply = { headers: () => reply, header: () => reply } as unknown as FastifyReply;
  const requestFrom = (app: ReturnType<typeof Fastify>, address: string, orgId: string) =>
    ({
      server: app,
      agent: { orgId },
      routeOptions: { config: {} },
      raw: { headers: {}, socket: { remoteAddress: address } },
    }) as unknown as FastifyRequest;
  const refused = async (
    count: (request: FastifyRequest, reply: FastifyReply) => Promise<void>,
    request: FastifyRequest,
  ) =>
    count(request, reply).then(
      () => false,
      () => true,
    );

  it('still counts the first caller once thousands more have been heard from, by address and by organisation', async () => {
    const app = Fastify();
    const trust = proxyTrust([]);
    await registerRateLimit(app, 1, trust);
    const byAddress = createCounter(trust, () => undefined);
    const byOrganisation = createOrganisationCounter(app, 1, trust, () => undefined);
    const first = requestFrom(app, '198.51.100.1', 'org-first');
    expect(await refused(byAddress, first)).toBe(false);
    expect(await refused(byOrganisation, first)).toBe(false);
    for (let other = 0; other < OTHERS; other += 1) {
      const request = requestFrom(app, `10.${String(other >> 8)}.${String(other & 255)}.1`, `org-${String(other)}`);
      await byAddress(request, reply);
      await byOrganisation(request, reply);
    }
    expect(await refused(byAddress, first)).toBe(true);
    expect(await refused(byOrganisation, first)).toBe(true);
    await app.close();
  });
});
