// S88 (Shannon AUTH-VULN-01): ending a person's sessions at the login service
// when they sign out, against a stand-in for Zitadel's session API: what is
// asked, what is ended, and every way it fails.
import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { createLoginSessions, LoginSessionsUnavailable } from './login-sessions.ts';
import { LoginTokenRefused } from './zitadel-call.ts';

const ISSUER = 'https://auth.example.test';
// Plain words, built at run time, as every stand-in for a secret here.
const WORDS = ['session', 'ending', 'words'].join('-');
const WHO = { issuer: ISSUER, subject: '312000000000000042' };
const SESSIONS = ['312000000000000302', '312000000000000301'];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const found = (ids: readonly string[]) => ({ details: {}, sessions: ids.map((id) => ({ id })) });

/**
 * A stand-in for Zitadel's session API: a search answers `answered`, each
 * deletion 200, unless `answer` says otherwise for a call. Keeps what was asked.
 */
function zitadel(
  answered: unknown = found(SESSIONS),
  answer: (method: string, path: string) => Response | Error | undefined = () => undefined,
) {
  const asked: { url: string; method: string; init: RequestInit }[] = [];
  const fetch: OutboundFetch = (url, init = {}) => {
    const method = init.method ?? 'GET';
    asked.push({ url: String(url), method, init });
    const { pathname } = new URL(String(url));
    const given = answer(method, pathname);
    if (given instanceof Error) return Promise.reject(given);
    if (given !== undefined) return Promise.resolve(given);
    if (method === 'POST' && pathname === '/v2/sessions/search') return Promise.resolve(json(answered));
    if (method === 'DELETE') return Promise.resolve(json({ details: {} }));
    return Promise.resolve(json({ message: 'no such route' }, 404));
  };
  const ended = () => asked.filter(({ method }) => method === 'DELETE').map(({ url }) => url);
  return { asked, ended, fetch };
}

const sessionsWith = (fetch: OutboundFetch, now?: () => number) =>
  createLoginSessions({ issuer: ISSUER, internalOrigin: undefined, token: WORDS, fetch, now });

describe('ending the sessions at the login service', () => {
  it("searches the person's sessions newest first with the token, then ends each, and says how many", async () => {
    const stub = zitadel();

    expect(await sessionsWith(stub.fetch).endAll(WHO)).toBe(2);

    const [search] = stub.asked;
    expect(search?.url).toBe(`${ISSUER}/v2/sessions/search`);
    expect(search?.method).toBe('POST');
    expect(JSON.parse(search?.init.body as string)).toEqual({
      query: { limit: 100, asc: false },
      sortingColumn: 'SESSION_FIELD_NAME_CREATION_DATE',
      queries: [{ userIdQuery: { id: WHO.subject } }],
    });
    expect(new Headers(search?.init.headers).get('authorization')).toBe(`Bearer ${WORDS}`);
    expect(stub.ended()).toEqual(SESSIONS.map((id) => `${ISSUER}/v2/sessions/${id}`));
  });

  it('ends nothing when the person has none: Zitadel leaves an empty list out', async () => {
    const stub = zitadel({ details: {} });

    expect(await sessionsWith(stub.fetch).endAll(WHO)).toBe(0);
    expect(stub.asked).toHaveLength(1);
  });

  it('asks nothing for a person of another login service: their ID could name someone else here', async () => {
    const stub = zitadel();

    expect(await sessionsWith(stub.fetch).endAll({ ...WHO, issuer: 'https://other.example.test' })).toBe(0);
    expect(stub.asked).toEqual([]);
  });

  it('takes a session already gone (404) as ended', async () => {
    const stub = zitadel(undefined, (method) => (method === 'DELETE' ? json({}, 404) : undefined));

    expect(await sessionsWith(stub.fetch).endAll(WHO)).toBe(2);
  });

  it('ends the newest hundred, then throws, as any older are left', async () => {
    const ids = Array.from({ length: 100 }, (_, index) => `3120000000000010${String(index).padStart(2, '0')}`);
    const stub = zitadel(found(ids));

    await expect(sessionsWith(stub.fetch).endAll(WHO)).rejects.toThrow(
      new LoginSessionsUnavailable('reading the sessions: 100 or more, any older left'),
    );
    expect(stub.ended()).toHaveLength(100);
  });

  it('stops once out of time, so a slow login service holds no sign-out long', async () => {
    let clock = 0;
    const stub = zitadel(undefined, (method) => {
      if (method === 'DELETE') clock += 10_001;
      return undefined;
    });

    await expect(sessionsWith(stub.fetch, () => clock).endAll(WHO)).rejects.toThrow(
      new LoginSessionsUnavailable('ending the sessions: out of time'),
    );
    expect(stub.ended()).toHaveLength(1);
  });

  it('throws when an ending is refused, naming the step', async () => {
    const stub = zitadel(undefined, (method) => (method === 'DELETE' ? json({}, 500) : undefined));

    await expect(sessionsWith(stub.fetch).endAll(WHO)).rejects.toThrow(
      new LoginSessionsUnavailable('ending a session: it answered 500'),
    );
  });

  it.each([
    ['a failed search', zitadel(undefined, () => json({}, 500)), 'reading the sessions: it answered 500'],
    [
      'a call that fails',
      zitadel(undefined, () => new TypeError('fetch failed')),
      'reading the sessions: the call failed',
    ],
    ['no list', zitadel({ sessions: 'all' }), 'reading the sessions: the answer holds no list of at most 100'],
    [
      'a list past the most',
      zitadel(found(Array.from({ length: 101 }, () => '312000000000000301'))),
      'reading the sessions: the answer holds no list of at most 100',
    ],
    ['an ID that is not one', zitadel(found(['../users/1'])), 'reading the sessions: an ID is not one'],
    ['a session with no ID', zitadel({ sessions: [{}] }), 'reading the sessions: an ID is not one'],
    ['an ID that is a number', zitadel({ sessions: [{ id: 312 }] }), 'reading the sessions: an ID is not one'],
  ])('throws on %s, ending nothing', async (_, stub, message) => {
    await expect(sessionsWith(stub.fetch).endAll(WHO)).rejects.toThrow(new LoginSessionsUnavailable(message));
    expect(stub.ended()).toEqual([]);
  });

  it.each([401, 403])('throws LoginTokenRefused for a refused token (%i), which the alert counts', async (status) => {
    const stub = zitadel(undefined, () => json({}, status));

    await expect(sessionsWith(stub.fetch).endAll(WHO)).rejects.toThrow(
      new LoginTokenRefused(`the login service refused the token: it answered ${String(status)}`),
    );
  });

  it("refuses a subject that isn't the login service's user ID, asking nothing", async () => {
    const stub = zitadel();

    await expect(sessionsWith(stub.fetch).endAll({ ...WHO, subject: '../sessions' })).rejects.toThrow(RangeError);
    expect(stub.asked).toEqual([]);
  });
});
