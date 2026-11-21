import type { Chain, ChainWitness, WitnessClass } from '@agentx/platform/audit-chain';
import { afterEach, describe, expect, it } from 'vitest';

import {
  chainWitness,
  headWrittenIn,
  noteAgainOnCommit,
  noteCommitted,
  nowChainsOf,
  waitWitnessed,
  witnessedWrite,
  witnessWith,
  wroteTo,
} from './witnessing.ts';

const ORG: Chain = { kind: 'organisation', orgId: '0199A0F0-0000-7000-8000-000000000001' };
const PLATFORM: Chain = { kind: 'platform' };
const head = (seq: bigint) => ({ seq, hash: Buffer.alloc(32, Number(seq)) });

/** A witness log that records what it was told. */
function recording() {
  const notes: [string, bigint, WitnessClass][] = [];
  const waited: Chain[][] = [];
  const witness: ChainWitness = {
    note: (chain, { seq }, klass) => notes.push([chain.kind, seq, klass]),
    settled: (chains) => {
      waited.push([...chains]);
      return Promise.resolve();
    },
    pending: () => [],
  };
  return { witness, notes, waited };
}

afterEach(() => {
  witnessWith(undefined);
});

describe('TR-1 each transaction’s chain heads to the witness log', () => {
  it('notes a transaction’s highest head once, `now` if any of its writes there is', () => {
    const { witness, notes } = recording();
    witnessWith(witness);
    expect(chainWitness()).toBe(witness);
    const tx = {};
    witnessedWrite(tx, ORG, 'soon');
    wroteTo(tx, ORG, head(5n));
    witnessedWrite(tx, { kind: 'organisation', orgId: ORG.orgId.toLowerCase() }, 'now');
    wroteTo(tx, ORG, head(7n));
    wroteTo(tx, ORG, head(6n));
    // The first write's hook: not the highest, nothing; the second's: the highest, as `now`.
    noteCommitted(tx, ORG, head(5n));
    noteCommitted(tx, ORG, head(7n));
    expect(notes).toEqual([['organisation', 7n, 'now']]);
    expect(nowChainsOf(tx)).toEqual([ORG]);
    // The highest head, its hash with it: what the hand-off's gate witnesses (TR-1 F.5); none for a chain not written.
    expect(headWrittenIn(tx, ORG)).toEqual(head(7n));
    expect(headWrittenIn(tx, PLATFORM)).toBeUndefined();
  });

  it('notes nothing without a witness log, for a head it never wrote, or for a transaction it never saw', () => {
    const tx = {};
    witnessedWrite(tx, PLATFORM, 'now');
    wroteTo(tx, PLATFORM, head(3n));
    noteCommitted(tx, PLATFORM, head(3n));
    const { witness, notes } = recording();
    witnessWith(witness);
    noteCommitted(tx, PLATFORM, undefined);
    noteCommitted({}, PLATFORM, head(3n));
    noteCommitted(tx, ORG, head(3n));
    expect(notes).toEqual([]);
    // A chain whose writes were all `soon` asks for no wait.
    const soon = {};
    witnessedWrite(soon, ORG, 'soon');
    expect(nowChainsOf(soon)).toEqual([]);
    expect(nowChainsOf({})).toEqual([]);
  });

  it('TR-3 notes a head again on commit only where a witness log is given and the transaction wrote there', async () => {
    // A stand-in for a transaction on another driver: afterCommit keeps no hook there (the DB test runs the real one).
    const tx = { isTransaction: false } as unknown as Parameters<typeof noteAgainOnCommit>[0];
    await expect(noteAgainOnCommit(tx, ORG)).resolves.toBeUndefined();
    const { witness, notes } = recording();
    witnessWith(witness);
    await noteAgainOnCommit(tx, ORG);
    witnessedWrite(tx, ORG, 'now');
    wroteTo(tx, ORG, head(4n));
    await noteAgainOnCommit(tx, ORG);
    expect(notes).toEqual([]);
  });

  it('waits for the chains given, and for none without a witness log or chains', async () => {
    await expect(waitWitnessed([ORG])).resolves.toBeUndefined();
    const { witness, waited } = recording();
    witnessWith(witness);
    await waitWitnessed([]);
    await waitWitnessed([ORG, PLATFORM]);
    expect(waited).toEqual([[ORG, PLATFORM]]);
  });
});
