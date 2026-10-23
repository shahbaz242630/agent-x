// The fake partner's messages (Phase 4 E1b; SEC-PTR-01, -03, -06): signed
// over the raw body and the time sent; checked signature first, then the
// time, then the body; normalised to what it names, keyed by its body's
// SHA-256 (the rail's messages carry no ID).
import { createHash, createHmac, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { FAKE_SIGNATURE_HEADER, signFakeMessage, verifyFakeMessage } from './fake-events.ts';
import { createMemoryRecords } from './fake-records.ts';

const KEY = randomBytes(32);
const NOW = new Date('2026-10-23T10:00:00.000Z');
const INSTRUCTION = '0193b1e2-7c4a-7d3e-9f10-2a3b4c5d6e7f';
const CONSENT = 'aani-consent-1';

/** A message the fake sends, naming our instruction unless `consentOnly`. */
const signed = (consentOnly = false) =>
  signFakeMessage(
    KEY,
    { eventType: 'payment.status', consentId: CONSENT, ...(!consentOnly && { instructionId: INSTRUCTION }) },
    NOW,
  );

/** Any body, signed as the fake signs, under a time given as it is written: for shapes it never sends itself. */
const signedBody = (body: string, sentAt = NOW.toISOString()) => {
  const raw = Buffer.from(body, 'utf8');
  const mac = createHmac('sha256', KEY).update(`${sentAt}.`).update(raw).digest('hex');
  return { body: raw, headers: { [FAKE_SIGNATURE_HEADER]: `t=${sentAt},v1=${mac}` } };
};

describe('the fake partner’s messages (E1b)', () => {
  it('verifies one naming our instruction, keyed by its body’s SHA-256, the same for a replay', () => {
    const { body, headers } = signed();

    const check = verifyFakeMessage(KEY, body, headers, NOW);

    expect(check).toEqual({
      kind: 'verified',
      event: {
        partner: 'fake',
        dedupeKey: createHash('sha256').update(body).digest('hex'),
        eventType: 'payment.status',
        reference: { kind: 'instruction', instructionId: INSTRUCTION },
      },
    });
    expect(verifyFakeMessage(KEY, body, headers, NOW)).toEqual(check);
  });

  it('verifies one naming the consent alone (rail map §1.8)', () => {
    const { body, headers } = signed(true);

    expect(verifyFakeMessage(KEY, body, headers, NOW)).toMatchObject({
      kind: 'verified',
      event: { reference: { kind: 'consent', consentId: CONSENT } },
    });
  });

  it.each([
    ['its body changed', (m: ReturnType<typeof signed>) => ({ ...m, body: Buffer.concat([m.body, Buffer.from(' ')]) })],
    [
      'its signature changed',
      (m: ReturnType<typeof signed>) => ({
        ...m,
        headers: {
          ...m.headers,
          [FAKE_SIGNATURE_HEADER]:
            m.headers[FAKE_SIGNATURE_HEADER]?.replace(/.$/, (c) => (c === '0' ? '1' : '0')) ?? '',
        },
      }),
    ],
    [
      'its time changed',
      (m: ReturnType<typeof signed>) => ({
        ...m,
        headers: {
          ...m.headers,
          [FAKE_SIGNATURE_HEADER]: m.headers[FAKE_SIGNATURE_HEADER]?.replace('10:00:00', '10:00:01') ?? '',
        },
      }),
    ],
    ['no signature', (m: ReturnType<typeof signed>) => ({ ...m, headers: { 'content-type': 'application/json' } })],
    ['a garbled one', (m: ReturnType<typeof signed>) => ({ ...m, headers: { [FAKE_SIGNATURE_HEADER]: 'v1=abc' } })],
    [
      'two of them',
      (m: ReturnType<typeof signed>) => ({
        ...m,
        headers: {
          [FAKE_SIGNATURE_HEADER]: [m.headers[FAKE_SIGNATURE_HEADER] ?? '', m.headers[FAKE_SIGNATURE_HEADER] ?? ''],
        },
      }),
    ],
  ] as const)('refuses one with %s: signature (SEC-PTR-01)', (_name, change) => {
    const { body, headers } = change(signed());

    expect(verifyFakeMessage(KEY, body, headers, NOW)).toEqual({ kind: 'refused', reason: 'signature' });
  });

  it('refuses one signed with another key', () => {
    const { body, headers } = signFakeMessage(randomBytes(32), { eventType: 'x', consentId: CONSENT }, NOW);

    expect(verifyFakeMessage(KEY, body, headers, NOW)).toEqual({ kind: 'refused', reason: 'signature' });
  });

  it.each([
    ['5 minutes on: still within', 5 * 60_000, 'verified'],
    ['past 5 minutes on', 5 * 60_000 + 1, 'refused'],
    ['5 minutes before: still within', -5 * 60_000, 'verified'],
    ['past 5 minutes before', -5 * 60_000 - 1, 'refused'],
  ] as const)('holds the signed time to a 5-minute window (SEC-PTR-03): %s', (_name, by, kind) => {
    const { body, headers } = signed();

    const check = verifyFakeMessage(KEY, body, headers, new Date(NOW.getTime() + by));

    expect(check.kind).toBe(kind);
    if (check.kind === 'refused') expect(check.reason).toBe('stale');
  });

  it('refuses a signed time that is no time at all: stale', () => {
    const { body, headers } = signedBody(`{"Meta":{"EventType":"x","ConsentId":"${CONSENT}"}}`, 'soon');

    expect(verifyFakeMessage(KEY, body, headers, NOW)).toEqual({ kind: 'refused', reason: 'stale' });
  });

  it.each([
    ['not JSON', 'not json'],
    ['not an object', '"text"'],
    ['null', 'null'],
    ['no Meta', '{"Data":{}}'],
    ['no event type', `{"Meta":{"ConsentId":"${CONSENT}"}}`],
    ['an event type too long', `{"Meta":{"EventType":"${'x'.repeat(101)}","ConsentId":"${CONSENT}"}}`],
    ['no consent', '{"Meta":{"EventType":"x"}}'],
    ['an empty consent', '{"Meta":{"EventType":"x","ConsentId":""}}'],
    ['Data that names no instruction', `{"Meta":{"EventType":"x","ConsentId":"${CONSENT}"},"Data":{}}`],
    [
      'an instruction that is no ID of ours',
      `{"Meta":{"EventType":"x","ConsentId":"${CONSENT}"},"Data":{"InstructionId":"pay-1"}}`,
    ],
    ['Data that is not an object', `{"Meta":{"EventType":"x","ConsentId":"${CONSENT}"},"Data":"x"}`],
  ] as const)('refuses a signed body that is %s: malformed (SEC-PTR-06)', (_name, body) => {
    const message = signedBody(body);

    expect(verifyFakeMessage(KEY, message.body, message.headers, NOW)).toEqual({
      kind: 'refused',
      reason: 'malformed',
    });
  });

  it('keeps one key a store: the same each time it is asked for', async () => {
    const records = createMemoryRecords();

    const first = await records.eventKey();

    expect(first).toHaveLength(32);
    expect(await records.eventKey()).toEqual(first);
    expect(await createMemoryRecords().eventKey()).not.toEqual(first);
  });
});
