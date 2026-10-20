// The activity log's rows as an organisation is shown them (L5, decision 26):
// the clock where each was made, with its offset, and nothing made up for a
// zone this runtime doesn't know; each sealed by the day it was written (L6).
import { describe, expect, it } from 'vitest';

import { type ActivityRow, v7Floor } from '../../activity/index.ts';

import { activityShown, localTimeOf } from './activity-shown.ts';

const ROW: ActivityRow = {
  id: '0199a0f0-0000-7000-8000-0000000a15a1',
  recordedAt: new Date('2026-10-19T13:39:12.123Z'),
  actor: { type: 'user', id: '0199a0f0-0000-7000-8000-000000000011' },
  method: 'GET',
  route: '/v1/members',
  pathIds: [],
  status: 200,
  reason: null,
  correlationId: '0199a0f0-0000-7000-8000-0000000a15c0',
  durationMs: 3,
  client: { ip: '94.200.1.7', place: { country: 'AE', city: undefined }, timeZone: undefined },
};

describe('localTimeOf (decision 26: each row in its person’s own time)', () => {
  it.each([
    ['Asia/Dubai', '2026-10-19T17:39:12.123+04:00'],
    ['UTC', '2026-10-19T13:39:12.123+00:00'],
    ['America/New_York', '2026-10-19T09:39:12.123-04:00'],
    ['Asia/Kolkata', '2026-10-19T19:09:12.123+05:30'],
    ['Asia/Kathmandu', '2026-10-19T19:24:12.123+05:45'],
  ])('reads 13:39:12.123 UTC in %s as %s', (zone, local) => {
    expect(localTimeOf(new Date('2026-10-19T13:39:12.123Z'), zone)).toBe(local);
  });

  it('crosses midnight into the next day, and keeps a whole second’s zeros', () => {
    expect(localTimeOf(new Date('2026-12-31T22:00:00.007Z'), 'Asia/Dubai')).toBe('2027-01-01T02:00:00.007+04:00');
  });

  it('answers null for a zone this runtime doesn’t know', () => {
    expect(localTimeOf(new Date('2026-10-19T13:39:12.123Z'), 'Mars/Olympus_Mons')).toBeNull();
  });
});

describe('activityShown (decision 26: clues labelled, the place credited)', () => {
  it('shows a country with no city, credited to DB-IP, and no local time without a zone', () => {
    expect(activityShown(ROW, new Map(), null).client).toEqual({
      ip: '94.200.1.7',
      place: { country: 'AE', city: null, approximate: true, by: 'IP Geolocation by DB-IP', link: 'https://db-ip.com' },
      timeZone: null,
    });
    expect(activityShown(ROW, new Map(), null).localTime).toBeNull();
  });

  it('shows the time in the row’s own zone, its actor named', () => {
    const shown = activityShown(
      { ...ROW, client: { ip: undefined, place: undefined, timeZone: { name: 'Asia/Dubai', from: 'browser' } } },
      new Map([[`user:${ROW.actor.id}`, { name: 'Sara Khan', email: null, shownFrom: 'kept_copy' as const }]]),
      null,
    );

    expect(shown).toMatchObject({
      localTime: '2026-10-19T17:39:12.123+04:00',
      actor: { ...ROW.actor, name: 'Sara Khan', shownFrom: 'kept_copy' },
      client: { ip: null, place: null, timeZone: { name: 'Asia/Dubai', from: 'browser' } },
    });
  });
});

describe('activityShown: sealed (L6, a day is the UTC day a row was written, by its UUIDv7)', () => {
  const at = (iso: string) => `${v7Floor(Date.parse(iso)).slice(0, 14)}7000-8000-0000000a15a1`;
  const sealed = (id: string, sealedDay: string | null) => activityShown({ ...ROW, id }, new Map(), sealedDay).sealed;

  it('is sealed when written on or before the newest day sealed, to its last millisecond', () => {
    expect(sealed(at('2026-10-19T23:59:59.999Z'), '2026-10-19')).toBe(true);
    expect(sealed(at('2026-10-01T00:00:00.000Z'), '2026-10-19')).toBe(true);
  });

  it('is not sealed when written after it, from the next day’s first millisecond, or with none sealed', () => {
    expect(sealed(at('2026-10-20T00:00:00.000Z'), '2026-10-19')).toBe(false);
    expect(sealed(at('2026-10-19T12:00:00.000Z'), '2026-10-18')).toBe(false);
    expect(sealed(at('2026-10-19T12:00:00.000Z'), null)).toBe(false);
  });

  it('reads an ID in capitals as the database lists it, in lower case', () => {
    expect(sealed(at('2026-10-19T23:59:59.999Z').toUpperCase(), '2026-10-19')).toBe(true);
    expect(sealed(at('2026-10-20T10:00:00.000Z').toUpperCase(), '2026-10-19')).toBe(false);
  });
});
