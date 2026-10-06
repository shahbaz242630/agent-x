// S88 (Shannon AUTH-VULN-01): ending a person's sessions at the login service
// when they sign out, against a stand-in for Zitadel's session API: what is
// asked, what is ended, and every way it fails.
import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { createLoginSessions, LoginSessionsUnavailable } from './login-sessions.ts';

const ISSUER = 'https://auth.example.test';
// Plain words, built at run time, as every stand-in for a secret here.
const WORDS = ['session', 'ending', 'words'].join('-');
const SUBJECT = '312000000000000042';
const SESSIONS = ['312000000000000301', '312000000000000302'];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/**
 * A stand-in for Zitadel's session API: a search answers `found`, each
 * deletion 200, unless `answer` says otherwise for a call. Keeps what was asked.
 */
function zitadel(
  found: unknown = { details: {}, sessions: SESSIONS.map((id) => ({ id })) },
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
    if (method === 'POST' && pathname === '/v2/sessions/search') return Promise.resolve(json(found));
    if (method === 'DELETE') return Promise.resolve(json({ details: {} }));
    return Promise.resolve(json({ message: 'no such route' }, 404));
  };
  return { asked, fetch };
}

const sessionsWith = (fetch: OutboundFetch) =>
  createLoginSessions({ issuer: ISSUER, internalOrigin: undefined, token: WORDS, fetch });

describe('ending the sessions at the login service', () => {
  it("searches the person's sessions with the token, then ends each, and says how many", async () => {
    const stub = zitadel();

    expect(await sessionsWith(stub.fetch).endAll(SUBJECT)).toBe(2);

    const [search, ...ends] = stub.asked;
    expect(search?.url).toBe(`${ISSUER}/v2/sessions/search`);
    expect(search?.method).toBe('POST');
    expect(JSON.parse(search?.init.body as string)).toEqual({
      query: { limit: 100 },
      queries: [{ userIdQuery: { id: SUBJECT } }],
    });
    expect(new Headers(search?.init.headers).get('authorization')).toBe(`Bearer ${WORDS}`);
    expect(ends.map(({ url, method }) => [method, url])).toEqual(
      SESSIONS.map((id) => ['DELETE', `${ISSUER}/v2/sessions/${id}`]),
    );
  });

  it('ends nothing when the person has none: Zitadel leaves an empty list out', async () => {
    const stub = zitadel({ details: {} });

    expect(await sessionsWith(stub.fetch).endAll(SUBJECT)).toBe(0);
    expect(stub.asked).toHaveLength(1);
  });

  it('takes a session already gone (404) as ended', async () => {
    const stub = zitadel(undefined, (method) => (method === 'DELETE' ? json({}, 404) : undefined));

    expect(await sessionsWith(stub.fetch).endAll(SUBJECT)).toBe(2);
  });

  it('throws when an ending is refused, naming the step', async () => {
    const stub = zitadel(undefined, (method) => (method === 'DELETE' ? json({}, 403) : undefined));

    await expect(sessionsWith(stub.fetch).endAll(SUBJECT)).rejects.toThrow(
      new LoginSessionsUnavailable('ending a session: it answered 403'),
    );
  });

  it.each([
    ['a refused search', zitadel(undefined, () => json({}, 403)), 'reading the sessions: it answered 403'],
    [
      'a call that fails',
      zitadel(undefined, () => new TypeError('fetch failed')),
      'reading the sessions: the call failed',
    ],
    ['no list', zitadel({ sessions: 'all' }), 'reading the sessions: the answer holds no list of at most 100'],
    [
      'a list past the most',
      zitadel({ sessions: Array.from({ length: 101 }, () => ({ id: SESSIONS[0] })) }),
      'reading the sessions: the answer holds no list of at most 100',
    ],
    ['an ID that is not one', zitadel({ sessions: [{ id: '../users/1' }] }), 'reading the sessions: an ID is not one'],
    ['a session with no ID', zitadel({ sessions: [{}] }), 'reading the sessions: an ID is not one'],
  ])('throws on %s, ending nothing', async (_, stub, message) => {
    await expect(sessionsWith(stub.fetch).endAll(SUBJECT)).rejects.toThrow(new LoginSessionsUnavailable(message));
    expect(stub.asked.filter(({ method }) => method === 'DELETE')).toEqual([]);
  });

  it("refuses a subject that isn't the login service's user ID, asking nothing", async () => {
    const stub = zitadel();

    await expect(sessionsWith(stub.fetch).endAll('../sessions')).rejects.toThrow(RangeError);
    expect(stub.asked).toEqual([]);
  });
});
