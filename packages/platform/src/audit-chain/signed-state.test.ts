import { createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider, type PurposeKeys } from '../keys/key-provider.ts';
import { encodeMessage } from '../keys/message.ts';
import { byPurpose, type KeyPurpose, PURPOSES } from '../keys/purposes.ts';
import { sealState, type StateFacts, stateSealDetails, stateSealIn, stateSealMatches } from './signed-state.ts';

const key = (fill: number): Buffer => Buffer.alloc(32, fill);
const AUDIT_MAC = PURPOSES.indexOf('audit-mac') + 1;

function provider(changes: Partial<Record<KeyPurpose, PurposeKeys>> = {}): KeyProvider {
  const material: KeyMaterial = byPurpose(
    (purpose) => changes[purpose] ?? { current: 1, versions: new Map([[1, key(PURPOSES.indexOf(purpose) + 1)]]) },
  );
  return createKeyProvider(material);
}

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const FACTS: StateFacts = {
  orgId: ORG,
  subject: { type: 'agent', id: AGENT, version: 3 },
  fields: [
    ['status', 'SUSPENDED'],
    ['expires_at', null],
  ],
};

describe('ADR-012 §2 a state seal', () => {
  const keys = provider();

  it('is an HMAC with the audit key over the labelled organisation, object, version and each field by name', () => {
    const seal = sealState(keys, FACTS);
    const expected = createHmac('sha256', key(AUDIT_MAC))
      .update(
        encodeMessage([
          'signed-state',
          ORG,
          'agent',
          AGENT,
          '3',
          'field',
          'status',
          'value',
          'SUSPENDED',
          'field',
          'expires_at',
          'null',
        ]),
      )
      .digest();

    expect(seal).toEqual({ fingerprint: expected, keyVersion: 1 });
    expect(Object.isFrozen(seal)).toBe(true);
  });

  it('matches the state it was made for, IDs in any case', () => {
    const seal = sealState(keys, FACTS);
    const shouted = { ...FACTS, orgId: ORG.toUpperCase(), subject: { ...FACTS.subject, id: AGENT.toUpperCase() } };

    expect(stateSealMatches(keys, FACTS, seal)).toBe(true);
    expect(stateSealMatches(keys, shouted, seal)).toBe(true);
  });

  it.each<[string, StateFacts]>([
    ['another organisation', { ...FACTS, orgId: '0199a0f0-0000-7000-8000-000000000002' }],
    ['another type of object', { ...FACTS, subject: { ...FACTS.subject, type: 'agent_key' } }],
    ['another object', { ...FACTS, subject: { ...FACTS.subject, id: '0199a0f0-0000-7000-8000-0000000000a2' } }],
    [
      'an older version: the row pointed back at an earlier state',
      { ...FACTS, subject: { ...FACTS.subject, version: 2 } },
    ],
    [
      'a field changed',
      {
        ...FACTS,
        fields: [
          ['status', 'ACTIVE'],
          ['expires_at', null],
        ],
      },
    ],
    [
      'a field given a value',
      {
        ...FACTS,
        fields: [
          ['status', 'SUSPENDED'],
          ['expires_at', '1790000000000000'],
        ],
      },
    ],
    [
      'the text "null" for no value',
      {
        ...FACTS,
        fields: [
          ['status', 'SUSPENDED'],
          ['expires_at', 'null'],
        ],
      },
    ],
    [
      'values moved to other fields',
      {
        ...FACTS,
        fields: [
          ['expires_at', 'SUSPENDED'],
          ['status', null],
        ],
      },
    ],
    [
      'a field renamed',
      {
        ...FACTS,
        fields: [
          ['state', 'SUSPENDED'],
          ['expires_at', null],
        ],
      },
    ],
    ['a field left out', { ...FACTS, fields: [['status', 'SUSPENDED']] }],
    ['a field added', { ...FACTS, fields: [...FACTS.fields, ['role', 'admin']] }],
  ])("doesn't match %s", (_change, changed) => {
    expect(stateSealMatches(keys, changed, sealState(keys, FACTS))).toBe(false);
  });

  it.each([
    ['another fingerprint', { fingerprint: Buffer.alloc(32, 7), keyVersion: 1 }],
    ['a fingerprint of the wrong length', { fingerprint: Buffer.alloc(31, 7), keyVersion: 1 }],
    ['a key version the app does not hold', { fingerprint: Buffer.alloc(32, 7), keyVersion: 9 }],
  ])("doesn't match %s, and doesn't throw", (_change, seal) => {
    expect(stateSealMatches(keys, FACTS, seal)).toBe(false);
  });

  it('is made with the current key, and checked with its own version after a rotation', () => {
    const rotated = provider({
      'audit-mac': {
        current: 2,
        versions: new Map([
          [1, key(AUDIT_MAC)],
          [2, key(99)],
        ]),
      },
    });
    const old = sealState(keys, FACTS);

    expect(sealState(rotated, FACTS).keyVersion).toBe(2);
    expect(stateSealMatches(rotated, FACTS, old)).toBe(true);
    expect(stateSealMatches(rotated, FACTS, { ...old, keyVersion: 2 })).toBe(false);
  });

  it.each<[string, StateFacts]>([
    ['no fields, which would match any row', { ...FACTS, fields: [] }],
    ['version 0', { ...FACTS, subject: { ...FACTS.subject, version: 0 } }],
    ['a version that is not whole', { ...FACTS, subject: { ...FACTS.subject, version: 1.5 } }],
  ])('refuses to seal %s, and never matches it', (_what, facts) => {
    expect(() => sealState(keys, facts)).toThrow(
      new RangeError('A state seal needs at least one field and a version from 1'),
    );
    expect(stateSealMatches(keys, facts, sealState(keys, FACTS))).toBe(false);
  });
});

describe("the seal in an event's details", () => {
  const keys = provider();
  const seal = sealState(keys, FACTS);

  it('is written as 64 lower-case hex digits and the key version, and read back the same', () => {
    const details = stateSealDetails(seal);

    expect(details).toEqual({ stateFingerprint: seal.fingerprint.toString('hex'), stateKeyVersion: 1 });
    expect(details.stateFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(stateSealIn({ step: 1, ...details })).toEqual(seal);
  });

  it('is absent from details that carry none', () => {
    expect(stateSealIn({})).toBeUndefined();
    expect(stateSealIn({ status: 'ACTIVE' })).toBeUndefined();
  });

  it.each([
    ['only the fingerprint', { stateFingerprint: 'ab'.repeat(32) }],
    ['only the key version', { stateKeyVersion: 1 }],
    ['a fingerprint in capitals', { stateFingerprint: 'AB'.repeat(32), stateKeyVersion: 1 }],
    ['a fingerprint too short', { stateFingerprint: 'ab'.repeat(31), stateKeyVersion: 1 }],
    ['a fingerprint that is not hex', { stateFingerprint: 'zz'.repeat(32), stateKeyVersion: 1 }],
    ['a fingerprint that is not text', { stateFingerprint: 1, stateKeyVersion: 1 }],
    ['a key version of 0', { stateFingerprint: 'ab'.repeat(32), stateKeyVersion: 0 }],
    ['a key version that is not whole', { stateFingerprint: 'ab'.repeat(32), stateKeyVersion: 1.5 }],
    ['a key version as text', { stateFingerprint: 'ab'.repeat(32), stateKeyVersion: '1' }],
    ['a fingerprint of null', { stateFingerprint: null, stateKeyVersion: 1 }],
  ])('is malformed with %s', (_what, details) => {
    expect(stateSealIn(details)).toBe('malformed');
  });

  it("reads only the details' own fields, never inherited ones", () => {
    const inherited = Object.create({ stateFingerprint: 'ab'.repeat(32), stateKeyVersion: 1 }) as Record<
      string,
      unknown
    >;

    expect(stateSealIn(inherited)).toBeUndefined();
  });
});
