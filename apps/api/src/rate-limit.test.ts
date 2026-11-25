import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  clientAddress,
  clientKey,
  clientNetwork,
  clientSite,
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

describe('6F1 G4 the network an OAuth registration is counted under', () => {
  it.each([
    ['an IPv4 address, by its /24', '203.0.113.9', '203.0.113.0'],
    ['another address in the same /24', '203.0.113.250:40001', '203.0.113.0'],
    ['an IPv4-mapped address', '::ffff:198.51.100.7', '198.51.100.0'],
    ['an IPv6 address, by its /48', '2001:db8:1:2:aaaa::1', '2001:db8:1::'],
    ['another /64 of the same /48', '[2001:db8:1:ffff::7]:443', '2001:db8:1::'],
  ])('keys %s', (_what, ip, expected) => {
    expect(clientNetwork(ip)).toBe(expected);
  });

  it('puts an address it can’t read in the one shared bucket', () => {
    expect(clientNetwork(undefined)).toBe(UNREADABLE_ADDRESS);
    expect(clientNetwork('unknown')).toBe(UNREADABLE_ADDRESS);
  });
});

describe('AG8 the network an OAuth flow is counted under beside its source', () => {
  it.each([
    ['an IPv4 address, alone: its own source', '203.0.113.9', '203.0.113.9'],
    ['an IPv4-mapped address', '::ffff:198.51.100.7', '198.51.100.7'],
    ['an IPv6 address, by its /48', '2001:db8:1:2:aaaa::1', '2001:db8:1::'],
    ['another /64 of the same /48', '[2001:db8:1:ffff::7]:443', '2001:db8:1::'],
  ])('keys %s', (_what, ip, expected) => {
    expect(clientSite(ip)).toBe(expected);
  });

  it('puts an address it can’t read in the one shared bucket', () => {
    expect(clientSite(undefined)).toBe(UNREADABLE_ADDRESS);
    expect(clientSite('unknown')).toBe(UNREADABLE_ADDRESS);
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
  const requestFrom = (app: FastifyInstance, address: string, orgId: string) =>
    ({
      server: app,
      headers: {},
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
    const byAddress = createCounter(trust, 1, () => undefined);
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

describe("S219 an address's agents never take its people's fifth, across windows", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('keeps the people their fifth when the agents start sending late in a minute and flood on into the next', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: 1_000_000 });
    const app = Fastify();
    const trust = proxyTrust([]);
    await registerRateLimit(app, 10, trust);
    const notes: string[] = [];
    app.addHook(
      'onRequest',
      createCounter(trust, 10, (_ip, reason) => notes.push(reason)),
    );
    app.get('/p', () => 'ok');
    await app.ready();
    const from = { remoteAddress: '198.51.100.1' };
    const statuses = async (times: number, agent: boolean) => {
      const answers: number[] = [];
      for (let i = 0; i < times; i += 1) {
        const headers = agent ? { authorization: 'Bearer x' } : {};
        answers.push((await app.inject({ url: '/p', headers, ...from })).statusCode);
      }
      return answers;
    };

    expect(await statuses(1, false)).toEqual([200]);
    vi.advanceTimersByTime(10_000);
    expect(await statuses(1, true)).toEqual([200]);
    vi.advanceTimersByTime(55_000);
    // The address's new minute: agents get 8 of 10.
    expect((await statuses(10, true)).filter((status) => status === 200)).toHaveLength(8);
    vi.advanceTimersByTime(5_000);
    expect((await statuses(10, true)).filter((status) => status === 200)).toHaveLength(0);
    vi.advanceTimersByTime(1_000);
    // The Suspend press, and one more: the people's fifth.
    expect(await statuses(2, false)).toEqual([200, 200]);
    expect(await statuses(1, false)).toEqual([429]);
    expect(notes.filter((reason) => reason === 'per_address')).toEqual(['per_address']);
    await app.close();
  });
  it("counts an OAuth client's keyless calls as its agents', and the person's authorize as theirs", async () => {
    const app = Fastify();
    const trust = proxyTrust([]);
    await registerRateLimit(app, 10, trust);
    app.addHook(
      'onRequest',
      createCounter(trust, 10, () => undefined),
    );
    app.get('/.well-known/oauth-protected-resource', { config: { oauth: true } }, () => 'ok');
    app.get('/v1/oauth/token', { config: { oauth: true, oauthClient: true } }, () => 'ok');
    app.get('/v1/oauth/authorize', { config: { oauth: true } }, () => 'ok');
    await app.ready();
    const ask = async (url: string) => (await app.inject({ url, remoteAddress: '198.51.100.1' })).statusCode;
    const clients: number[] = [];
    for (let i = 0; i < 5; i += 1)
      clients.push(await ask('/.well-known/oauth-protected-resource'), await ask('/v1/oauth/token'));

    expect(clients.filter((status) => status === 200)).toHaveLength(8);
    expect(await ask('/v1/oauth/authorize')).toBe(200);
    expect(await ask('/v1/oauth/authorize')).toBe(200);
    expect(await ask('/v1/oauth/authorize')).toBe(429);
    await app.close();
  });
});
