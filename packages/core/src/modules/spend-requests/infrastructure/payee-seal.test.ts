// Phase 2 E1b: a decision's payee seal, a keyed hash of its payee key, which
// the holdings check compares each claim's and reservation's key against.
import { createKeyProvider } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import { payeeAsSealed, sealPayee } from './payee-seal.ts';

/** The decision key alone, in two versions, `current` in use, so a seal made with the first still verifies once rotated. */
const keysAt = (current: number) =>
  createKeyProvider(
    {
      'decision-hash': {
        current,
        versions: new Map([
          [1, Buffer.alloc(32, 1)],
          [2, Buffer.alloc(32, 2)],
        ]),
      },
    },
    ['decision-hash'],
  );
const keys = keysAt(1);

const ORG = '0199a0f0-0000-7000-8000-00000000e1b1';
const REQUEST = '0199a0f0-0000-7000-8000-00000000e1b2';
const PAYEE = 'pf1.3f2a';

const asSealed = (seal: Parameters<typeof payeeAsSealed>[1], payeeKey: string | null, at = { ORG, REQUEST }) =>
  payeeAsSealed(keys, seal, { orgId: at.ORG, requestId: at.REQUEST, payeeKey });

describe('the payee seal (E1b)', () => {
  it('holds for the payee key sealed alone: another key, or none, is told apart', () => {
    const seal = sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: PAYEE });

    expect(seal.mac).toMatch(/^[0-9a-f]{64}$/);
    expect(seal.keyVersion).toBe(1);
    expect(asSealed(seal, PAYEE)).toBe(true);
    expect(asSealed(seal, null)).toBe(false);
    expect(asSealed(seal, 'pf1.3f2b')).toBe(false);
    // The organisation and the request are sealed with it, in any case as written.
    expect(asSealed(seal, PAYEE, { ORG: ORG.toUpperCase(), REQUEST: REQUEST.toUpperCase() })).toBe(true);
    expect(asSealed(seal, PAYEE, { ORG, REQUEST: ORG })).toBe(false);
    expect(asSealed(seal, PAYEE, { ORG: REQUEST, REQUEST })).toBe(false);
  });

  it('seals a request with no payee key as none, which a key added past the app breaks', () => {
    const seal = sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: null });

    expect(asSealed(seal, null)).toBe(true);
    expect(asSealed(seal, PAYEE)).toBe(false);
    // No key is a shape of its own, so a key of '' (a reservation's column has no check against it) is told apart.
    expect(asSealed(seal, '')).toBe(false);
    expect(asSealed(sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: '' }), null)).toBe(false);
  });

  it('verifies with the version it was sealed with, after the key is rotated', () => {
    const old = sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: PAYEE });
    const rotated = keysAt(2);
    const seal = sealPayee(rotated, { orgId: ORG, requestId: REQUEST, payeeKey: PAYEE });

    expect(seal.keyVersion).toBe(2);
    expect(seal.mac).not.toBe(old.mac);
    for (const each of [old, seal]) {
      expect(payeeAsSealed(rotated, each, { orgId: ORG, requestId: REQUEST, payeeKey: PAYEE })).toBe(true);
    }
    expect(asSealed({ ...old, keyVersion: 2 }, PAYEE)).toBe(false);
  });

  it('is a payee seal alone: never the same hash as anything else the decision key makes of these parts', () => {
    const seal = sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: PAYEE });
    const decision = keys.mac('decision-hash', ['spend-request-decision', ORG, REQUEST, 'key', PAYEE]);

    expect(Buffer.from(decision.mac).toString('hex')).not.toBe(seal.mac);
  });

  it('passes a decision made before E1b, which sealed none, and fails one whose seal is not whole', () => {
    expect(asSealed('none', PAYEE)).toBe(true);
    expect(asSealed('none', null)).toBe(true);
    expect(asSealed('unreadable', PAYEE)).toBe(false);
  });
});
