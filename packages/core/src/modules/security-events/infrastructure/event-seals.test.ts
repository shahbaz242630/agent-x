// S206 V6: the security events' MACs and the seal check's rules, without a
// database: a MAC holds over every column and for no change to any; an
// address reads alike however it was written; a row without a MAC is believed
// never; and a page of seals is held to its days, gaps
// between them and the retention.
import { createKeyProvider } from '@agentx/platform/keys';
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { v7Floor } from '../../activity/index.ts';
import {
  brokenSecuritySeal,
  eventMac,
  eventMacHolds,
  type EventFacts,
  firstCheckableDay,
  ipForm,
  SECURITY_SEAL_FORM,
  securityLogAlarm,
} from './event-seals.ts';

const material = (fill: number) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, fill)]]) });
const keys = createKeyProvider({ 'session-mac': material(3) }, ['session-mac']);
const otherKeys = createKeyProvider({ 'session-mac': material(4) }, ['session-mac']);

/** A UUIDv7 of the instant `ms`. */
const idOf = (ms: number) => `${v7Floor(ms).slice(0, 14)}7000-8000-000000000001`;

const AFTER = Date.parse('2026-12-11T00:00:00.000Z');
const ORG = '0199a0f0-0000-7000-8000-00000000a0a0';

const facts = (change: Partial<EventFacts> = {}): EventFacts => ({
  id: idOf(AFTER),
  orgId: null,
  kind: 'sign_in_failed',
  reason: 'state_mismatch',
  ip: '203.0.113.7',
  userId: '0199a0f0-0000-7000-8000-0000000b25a1',
  agentId: null,
  windowStart: new Date(AFTER - 60_000),
  count: 3,
  createdAt: new Date(AFTER),
  ...change,
});

const holds = (made: EventFacts, read: EventFacts, by = keys) => eventMacHolds(by, read, eventMac(keys, made));

describe('SEC-DB-18 a security event’s MAC (S206 V6)', () => {
  it('holds over the row as written, and as Postgres gives it back', () => {
    expect(holds(facts(), facts())).toBe(true);
    // An IPv6 address the API had in capitals and in full reads back compressed, in lower case.
    expect(holds(facts({ ip: '2001:DB8:0:0:0:0:0:1' }), facts({ ip: '2001:db8::1' }))).toBe(true);
    expect(holds(facts({ ip: '::ffff:1.2.3.4' }), facts({ ip: '::ffff:102:304' }))).toBe(true);
    expect(holds(facts({ userId: facts().userId?.toUpperCase() ?? null }), facts())).toBe(true);
    expect(holds(facts({ orgId: ORG.toUpperCase(), agentId: ORG }), facts({ orgId: ORG, agentId: ORG }))).toBe(true);
  });

  it.each([
    ['its ID', { id: idOf(AFTER + 1) }],
    ['its organisation', { orgId: ORG }],
    ['its kind', { kind: 'rate_limited' }],
    ['its reason', { reason: 'callback_incomplete' }],
    ['its address', { ip: '203.0.113.8' }],
    ['its address blanked', { ip: null }],
    ['its person', { userId: null }],
    ['its agent', { agentId: ORG }],
    ['its window', { windowStart: new Date(AFTER - 120_000) }],
    ['its count', { count: 1 }],
    ['when it was written', { createdAt: new Date(AFTER + 1) }],
  ] satisfies [string, Partial<EventFacts>][])('fails once %s is changed', (_what, change) => {
    expect(holds(facts(), facts(change))).toBe(false);
  });

  it('fails with another key, a made-up version, a MAC of the wrong shape, or half a pair', () => {
    expect(holds(facts(), facts(), otherKeys)).toBe(false);
    const { mac } = eventMac(keys, facts());
    expect(eventMacHolds(keys, facts(), { mac, mac_key_version: 7 })).toBe(false);
    expect(eventMacHolds(keys, facts(), { mac: mac.toString('hex'), mac_key_version: 1 })).toBe(false);
    expect(eventMacHolds(keys, facts(), { mac, mac_key_version: 1.5 })).toBe(false);
    expect(eventMacHolds(keys, facts(), { mac: null, mac_key_version: 1 })).toBe(false);
  });

  it('never believes a row with none, however old its ID', () => {
    const none = { mac: null, mac_key_version: null };
    expect(eventMacHolds(keys, facts({ id: idOf(0) }), none)).toBe(false);
    expect(eventMacHolds(keys, facts(), none)).toBe(false);
  });

  it('reads an address in one form', () => {
    expect(ipForm('203.0.113.7')).toBe('203.0.113.7');
    expect(ipForm('2001:DB8::0:1')).toBe('[2001:db8::1]');
  });
});

describe('SEC-DB-18 the seal check’s rules (S206 V6)', () => {
  const sealOf = (day: string, digest = `digest-${day}`) => ({
    day,
    requests: 1,
    digest,
    idFrom: 'a',
    idTo: 'b',
    form: SECURITY_SEAL_FORM,
  });
  const digest = (day: string) =>
    Promise.resolve({ day, requests: 1, digest: `digest-${day}`, idFrom: 'a', idTo: 'b', misdated: null });
  const asked: [string, string][] = [];
  const rules = (rowsIn: readonly string[] = [], checkableFrom = '2027-01-01') => ({
    digest,
    between: (older: string, newer: string) => {
      asked.push([older, newer]);
      return Promise.resolve(rowsIn.some((day) => day > older && day < newer));
    },
    checkableFrom,
  });

  it('holds a page whose days digest as sealed, a day between two seals asked only where one lies', async () => {
    asked.length = 0;
    const page = [sealOf('2027-01-20'), sealOf('2027-01-19'), sealOf('2027-01-15')];
    expect(await brokenSecuritySeal(page, rules())).toBeUndefined();
    expect(asked).toEqual([['2027-01-15', '2027-01-19']]);
  });

  it('finds a day digested otherwise, a row in a day between two seals, or a seal naming no day', async () => {
    expect(await brokenSecuritySeal([sealOf('2027-01-20', 'other')], rules())).toEqual({
      day: '2027-01-20',
      why: 'digest',
    });
    expect(await brokenSecuritySeal([sealOf('2027-01-20'), sealOf('2027-01-15')], rules(['2027-01-17']))).toEqual({
      day: '2027-01-16',
      why: 'unsealed_day',
    });
    expect(await brokenSecuritySeal([{ ...sealOf('x'), day: 7 }], rules())).toEqual({ day: 'unnamed', why: 'digest' });
  });

  it('checks no seal past the retention, nor any older than it', async () => {
    const page = [sealOf('2027-01-20'), sealOf('2027-01-10', 'other'), sealOf('2027-01-05', 'other')];
    expect(await brokenSecuritySeal(page, rules(['2027-01-12'], '2027-01-11'))).toBeUndefined();
  });

  it('the first checkable day: two after the one the sweep is in', () => {
    expect(firstCheckableDay(new Date('2027-02-10T12:00:00.000Z'), 30)).toBe('2027-01-13');
    expect(firstCheckableDay(new Date('2027-02-10T00:00:00.000Z'), 30)).toBe('2027-01-13');
  });

  it('raises the alarm naming the chain, the day, the organisation and the row where known', () => {
    const capture = new LogCapture();
    const logger = testLogger(capture);
    securityLogAlarm(logger, 'global', 'digest', '2027-01-20');
    securityLogAlarm(logger, { orgId: ORG.toUpperCase() }, 'mac', '2027-01-20', idOf(AFTER));
    expect(
      capture.lines().map(({ event, chain, check, reason, day, orgId, rowId }) => ({
        event,
        chain,
        check,
        reason,
        day,
        orgId,
        rowId,
      })),
    ).toEqual([
      {
        event: 'audit.integrity_failed',
        chain: 'platform',
        check: 'security_event',
        reason: 'digest',
        day: '2027-01-20',
        orgId: undefined,
        rowId: undefined,
      },
      {
        event: 'audit.integrity_failed',
        chain: 'organisation',
        check: 'security_event',
        reason: 'mac',
        day: '2027-01-20',
        orgId: ORG,
        rowId: idOf(AFTER),
      },
    ]);
  });
});
