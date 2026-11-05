import { describe, expect, it } from 'vitest';

import { createKeyProvider, KeyError, type KeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import { OPERATOR_ID, operatorSignature, sealedSigned } from './operator-signature.ts';

const keys: KeyProvider = createKeyProvider(
  byPurpose((purpose) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]) })),
);

const ORG: Chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-0000000000a1' };
const OTHER_ORG: Chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-0000000000a2' };

/** An event row with every sealed column, as a store reads it, the operator's by default. */
const ROW = {
  seq: 5n,
  id: '0199a0f0-0000-7000-8000-000000000005',
  recorded_at: new Date('2026-11-04T08:00:00.123Z'),
  whole_ms: true,
  prev_hash: Buffer.alloc(32, 1),
  hash: Buffer.alloc(32, 2),
  mac: Buffer.alloc(32, 3),
  mac_key_version: 1,
  actor_id: OPERATOR_ID,
};

/** The row with its signature, made by `by` on `chain`, and signing started at `from`. */
const signedRow = (chain = ORG, by = keys, from: bigint | null = 1n) => {
  const signed = operatorSignature(by, chain, OPERATOR_ID, { seq: ROW.seq, id: ROW.id, hash: ROW.hash });
  return { ...ROW, signature: signed?.signature, signature_key_version: signed?.keyVersion, signed_from: from };
};

const unsigned = (from: bigint | null) => ({ ...ROW, signature: null, signature_key_version: null, signed_from: from });

/** Whether sealedSigned keeps the row's MAC: believed, or taken as missing. */
const believed = (row: Readonly<Record<string, unknown>>, chain = ORG): boolean | undefined => {
  const sealed = sealedSigned(keys, chain, row);
  return sealed === undefined ? undefined : sealed.mac.length > 0;
};

describe("the operator's signature on its events (PL-57)", () => {
  it("signs only the operator's events, and a process without its key can't sign one", () => {
    expect(operatorSignature(keys, ORG, 'api', ROW)).toBeUndefined();
    expect(operatorSignature(keys, ORG, OPERATOR_ID, ROW)).toMatchObject({ keyVersion: 1 });
    const held = PURPOSES.filter((purpose) => purpose !== 'operator-signing');
    const withoutIt = createKeyProvider(
      Object.fromEntries(
        held.map((purpose) => [
          purpose,
          { current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]) },
        ]),
      ),
      held,
    );
    expect(() => operatorSignature(withoutIt, ORG, OPERATOR_ID, ROW)).toThrow(KeyError);
  });

  it("believes another actor's event without a signature, and an operator's with its own", () => {
    expect(believed({ ...ROW, actor_id: 'api' })).toBe(true);
    expect(believed(signedRow())).toBe(true);
    expect(sealedSigned(keys, ORG, { ...ROW, seq: 'five' })).toBeUndefined();
  });

  it('believes an unsigned operator event only before signing started on its chain', () => {
    expect(believed(unsigned(6n))).toBe(true);
    expect(believed(unsigned(5n))).toBe(false);
    expect(believed(unsigned(null))).toBe(false);
    // Read without the signature's columns at all: nothing to show.
    expect(believed(ROW)).toBe(false);
  });

  it("refuses a signature from another chain, another key, of the wrong shape, or a version it can't check", () => {
    expect(believed(signedRow(OTHER_ORG))).toBe(false);
    expect(believed(signedRow(ORG), OTHER_ORG)).toBe(false);
    const forger = createKeyProvider(
      { 'operator-signing': { current: 1, versions: new Map([[1, Buffer.alloc(32, 0xf0)]]) } },
      ['operator-signing'],
    );
    expect(believed(signedRow(ORG, forger))).toBe(false);
    expect(believed({ ...signedRow(), signature: 'not bytes' })).toBe(false);
    expect(believed({ ...signedRow(), signature_key_version: '1' })).toBe(false);
    expect(believed({ ...signedRow(), signature_key_version: 2 })).toBe(false);
  });

  it('lets any other failure of the check through', () => {
    const failing: KeyProvider = {
      ...keys,
      verifySignature: () => {
        throw new RangeError('the key store is gone');
      },
    };
    expect(() => sealedSigned(failing, ORG, signedRow())).toThrow(RangeError);
  });
});
