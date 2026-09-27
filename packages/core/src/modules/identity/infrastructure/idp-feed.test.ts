// B6-2b: the login service's event feed, against a stand-in for Zitadel's
// event search: what is asked, how the answer is read, and every way it fails.
import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { WATCHED_IDP_EVENTS } from '../domain/idp-event.ts';
import { createIdpEventFeed, IdpFeedUnavailable, MOST_EVENTS_A_PAGE } from './idp-feed.ts';

const ISSUER = 'https://auth.example.test';
// Plain words, built at run time, as every stand-in for a secret here.
const WORDS = ['feed', 'reading', 'words'].join('-');
const SINCE = new Date('2026-09-27T08:00:00.000Z');
const UNTIL = new Date('2026-09-27T09:00:00.000Z');

const EVENT = {
  editor: { userId: '312000000000000001', displayName: 'Break Glass', service: 'zitadel.admin.v1.AdminService' },
  aggregate: {
    id: '312000000000000042',
    type: { type: 'user', localized: { key: 'x', localizedMessage: 'User' } },
    resourceOwner: '312000000000000007',
  },
  sequence: '14',
  creationDate: '2026-09-27T08:30:00.123456Z',
  payload: { email: 'sara@example.test' },
  type: { type: 'user.human.mfa.otp.removed', localized: { key: 'x', localizedMessage: 'OTP removed' } },
};

/** A stand-in for Zitadel: answers each call with `answer`, and keeps what was asked. */
function zitadel(answer: () => Response | Error) {
  const asked: { url: string; init: RequestInit }[] = [];
  const fetch: OutboundFetch = (url, init) => {
    asked.push({ url: String(url), init: init ?? {} });
    const found = answer();
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return { asked, fetch };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const feedWith = (fetch: OutboundFetch, internalOrigin?: string) =>
  createIdpEventFeed({ issuer: ISSUER, internalOrigin, token: WORDS, fetch });

describe('the login service’s event feed (B6-2b)', () => {
  it('asks the event search for the types we copy, in the span, oldest first, with the token', async () => {
    const { asked, fetch } = zitadel(() => json({ events: [] }));

    await feedWith(fetch).eventsBetween(SINCE, UNTIL, 50);

    expect(asked).toHaveLength(1);
    const [call] = asked;
    expect(call?.url).toBe(`${ISSUER}/admin/v1/events/_search`);
    expect(call?.init.method).toBe('POST');
    expect(new Headers(call?.init.headers).get('authorization')).toBe(`Bearer ${WORDS}`);
    expect(JSON.parse(call?.init.body as string)).toEqual({
      asc: true,
      limit: 50,
      event_types: Object.keys(WATCHED_IDP_EVENTS),
      range: { since: SINCE.toISOString(), until: UNTIL.toISOString() },
    });
  });

  it('goes through the internal origin, naming the issuer’s host, as sign-in does', async () => {
    const { asked, fetch } = zitadel(() => json({ events: [] }));

    await feedWith(fetch, 'http://zitadel.internal:8080').eventsBetween(SINCE, UNTIL, 1);

    expect(asked[0]?.url).toBe('http://zitadel.internal:8080/admin/v1/events/_search');
    expect(new Headers(asked[0]?.init.headers).get('x-zitadel-instance-host')).toBe('auth.example.test');
  });

  it('reads each event’s type, what it is about, its place, its time and who made it, and never its payload', async () => {
    const { fetch } = zitadel(() =>
      json({
        events: [
          EVENT,
          { ...EVENT, sequence: 15, editor: { userId: '' }, type: { type: 'user.locked' } },
          {
            ...EVENT,
            aggregate: { ...EVENT.aggregate, type: { type: 'instance' } },
            type: { type: 'instance.member.added' },
          },
        ],
      }),
    );

    const events = await feedWith(fetch).eventsBetween(SINCE, UNTIL, 10);

    expect(events).toEqual([
      {
        type: 'user.human.mfa.otp.removed',
        eventClass: 'second_factor_removed',
        aggregateType: 'user',
        aggregateId: '312000000000000042',
        sequence: '14',
        createdAt: new Date('2026-09-27T08:30:00.123Z'),
        editorUserId: '312000000000000001',
      },
      expect.objectContaining({
        type: 'user.locked',
        eventClass: 'sign_in_blocked',
        sequence: '15',
        editorUserId: null,
      }),
      expect.objectContaining({ aggregateType: 'instance', eventClass: 'rights_changed' }),
    ]);
    expect(JSON.stringify(events)).not.toContain('sara');
  });

  it('reads an answer with no events as none', async () => {
    const { fetch } = zitadel(() => json({}));

    expect(await feedWith(fetch).eventsBetween(SINCE, UNTIL, 10)).toEqual([]);
  });

  it.each([
    ['a type we don’t copy', { ...EVENT, type: { type: 'user.human.password.check.succeeded' } }],
    ['no type', { ...EVENT, type: {} }],
    ['an aggregate we don’t know', { ...EVENT, aggregate: { ...EVENT.aggregate, type: { type: 'project' } } }],
    ['an aggregate ID that isn’t one', { ...EVENT, aggregate: { ...EVENT.aggregate, id: 'a b' } }],
    ['a sequence that isn’t a whole number', { ...EVENT, sequence: '1.5' }],
    ['a sequence past a safe number, as a number', { ...EVENT, sequence: 2 ** 60 }],
    ['a time that isn’t one', { ...EVENT, creationDate: 'yesterday' }],
    ['no time', { ...EVENT, creationDate: undefined }],
    ['an editor that isn’t an ID', { ...EVENT, editor: { userId: 'a;b' } }],
  ])('refuses the whole page for an event with %s', async (_what, event) => {
    const { fetch } = zitadel(() => json({ events: [EVENT, event] }));

    await expect(feedWith(fetch).eventsBetween(SINCE, UNTIL, 10)).rejects.toThrow(IdpFeedUnavailable);
  });

  it.each([
    ['an answer that is not a list', () => json({ events: { a: 1 } }), 'the answer holds no list of events'],
    ['more events than asked for', () => json({ events: [EVENT, EVENT] }), 'the answer holds no list of events'],
    ['an answer that is not JSON', () => new Response('<html>', { status: 200 }), 'the answer is not JSON'],
    ['a refused token', () => json({ code: 7 }, 403), 'it answered 403'],
    ['the login service away', () => new Error('socket hang up'), 'the call failed'],
    [
      'an answer larger than the bound',
      () => new Response('x'.repeat(2 * 1024 * 1024 + 1), { status: 200 }),
      'the answer was larger than',
    ],
  ])('fails as unavailable for %s, naming the step', async (_what, answer, step) => {
    const { fetch } = zitadel(answer);

    const failed = feedWith(fetch).eventsBetween(SINCE, UNTIL, 1);

    await expect(failed).rejects.toThrow(IdpFeedUnavailable);
    await expect(failed).rejects.toThrow(step);
  });

  it('refuses a page size out of bounds, an issuer that isn’t an origin, and a token that isn’t one', async () => {
    const { fetch } = zitadel(() => json({ events: [] }));

    await expect(feedWith(fetch).eventsBetween(SINCE, UNTIL, 0)).rejects.toThrow(RangeError);
    await expect(feedWith(fetch).eventsBetween(SINCE, UNTIL, MOST_EVENTS_A_PAGE + 1)).rejects.toThrow(RangeError);
    expect(() =>
      createIdpEventFeed({ issuer: `${ISSUER}/path`, internalOrigin: undefined, token: WORDS, fetch }),
    ).toThrow(RangeError);
    expect(() => createIdpEventFeed({ issuer: ISSUER, internalOrigin: undefined, token: 'a b', fetch })).toThrow(
      RangeError,
    );
  });
});
