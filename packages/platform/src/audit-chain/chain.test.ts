import { createHash, createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider, type PurposeKeys } from '../keys/key-provider.ts';
import { encodeMessage, type Message } from '../keys/message.ts';
import { byPurpose, type KeyPurpose, PURPOSES } from '../keys/purposes.ts';
import {
  type Chain,
  type ChainEntry,
  type ChainHead,
  ChainSealError,
  createChainVerifier,
  GENESIS_HASH,
  genesisHead,
  headIsSealed,
  linkHash,
  sealNext,
  type StoredEntry,
} from './chain.ts';

const key = (fill: number): Buffer => Buffer.alloc(32, fill);
const AUDIT_MAC = PURPOSES.indexOf('audit-mac') + 1;

function provider(changes: Partial<Record<KeyPurpose, PurposeKeys>> = {}): KeyProvider {
  const material: KeyMaterial = byPurpose(
    (purpose) => changes[purpose] ?? { current: 1, versions: new Map([[1, key(PURPOSES.indexOf(purpose) + 1)]]) },
  );
  return createKeyProvider(material);
}

/** The audit MAC key at version 1, and version 2 made current: a rotation half-way through. */
const rotatedMacKey = (): PurposeKeys => ({
  current: 2,
  versions: new Map([
    [1, key(AUDIT_MAC)],
    [2, key(99)],
  ]),
});

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const CHAIN: Chain = { kind: 'organisation', orgId: ORG };
const RECORDED_AT = new Date('2026-09-19T08:00:00.123Z');

function entry(seq: bigint, content: Message = ['action', `step.${seq.toString()}`]): ChainEntry {
  return { seq, id: `0199a0f0-0000-7000-8000-${seq.toString().padStart(12, '0')}`, recordedAt: RECORDED_AT, content };
}

/** A chain of `count` events sealed one after another, and its head. */
function sealedChain(
  keys: KeyProvider,
  count: number,
  chain: Chain = CHAIN,
): { events: StoredEntry[]; head: ChainHead } {
  let head = genesisHead(keys, chain);
  const events: StoredEntry[] = [];
  for (let seq = 1n; seq <= BigInt(count); seq += 1n) {
    const next = entry(seq);
    const sealed = sealNext(keys, chain, head, next);
    events.push({ ...next, ...sealed.link });
    head = sealed.head;
  }
  return { events, head };
}

/** The item at `index`, which the test knows is there. */
function nth<T>(list: readonly T[], index: number): T {
  const item = list[index];
  if (item === undefined) throw new Error(`The test expected an item at ${index}`);
  return item;
}

/** Checks `events` as a store holding exactly them would give them: its last number is theirs. */
function verify(keys: KeyProvider, head: ChainHead, events: readonly StoredEntry[], chain: Chain = CHAIN) {
  const verifier = createChainVerifier(keys, chain, { head, lastSeq: events.at(-1)?.seq ?? 0n });
  for (const event of events) verifier.check(event);
  return verifier.finish();
}

describe('the link hash (ADR-011 §3)', () => {
  it('is SHA-256 of the labelled chain, previous hash and event, as documented, so anyone can recompute it', () => {
    const next = entry(1n, ['action', 'organisation.created']);
    const expected = createHash('sha256')
      .update(
        encodeMessage([
          'audit-link',
          `organisation:${ORG}`,
          GENESIS_HASH,
          '1',
          next.id,
          '2026-09-19T08:00:00.123Z',
          'action',
          'organisation.created',
        ]),
      )
      .digest();

    expect(linkHash(CHAIN, GENESIS_HASH, next)).toEqual(expected);
  });

  it.each([
    ['the chain', () => linkHash({ kind: 'organisation', orgId: OTHER_ORG }, GENESIS_HASH, entry(1n))],
    ['the platform chain', () => linkHash({ kind: 'platform' }, GENESIS_HASH, entry(1n))],
    ['the previous hash', () => linkHash(CHAIN, Buffer.alloc(32, 1), entry(1n))],
    ['the place', () => linkHash(CHAIN, GENESIS_HASH, { ...entry(1n), seq: 2n })],
    ['the ID', () => linkHash(CHAIN, GENESIS_HASH, { ...entry(1n), id: entry(2n).id })],
    [
      'the time',
      () => linkHash(CHAIN, GENESIS_HASH, { ...entry(1n), recordedAt: new Date(RECORDED_AT.getTime() + 1) }),
    ],
    ['the content', () => linkHash(CHAIN, GENESIS_HASH, entry(1n, ['action', 'step.2']))],
  ])('changes with %s', (_part, changed) => {
    expect(changed()).not.toEqual(linkHash(CHAIN, GENESIS_HASH, entry(1n)));
  });
});

describe('sealing (ADR-012 §2: a MAC on every event and on the head)', () => {
  it('links the event to the head, MACs it with the audit key as documented, and moves the head on', () => {
    const keys = provider();
    const start = genesisHead(keys, CHAIN);
    const next = entry(1n);
    const { link, head } = sealNext(keys, CHAIN, start, next);
    const hash = linkHash(CHAIN, GENESIS_HASH, next);
    const mac = (message: Message): Buffer =>
      createHmac('sha256', key(AUDIT_MAC)).update(encodeMessage(message)).digest();

    expect(link).toEqual({
      prevHash: GENESIS_HASH,
      hash,
      mac: mac(['audit-event', `organisation:${ORG}`, '1', next.id, hash]),
      macKeyVersion: 1,
    });
    expect(head).toEqual({
      seq: 1n,
      hash,
      mac: mac(['audit-head', `organisation:${ORG}`, '1', hash]),
      macKeyVersion: 1,
    });
  });

  it('starts a chain at 0 and the genesis hash, with a sealed head', () => {
    const keys = provider();
    const head = genesisHead(keys, CHAIN);

    expect(head.seq).toBe(0n);
    expect(head.hash).toEqual(GENESIS_HASH);
    expect(headIsSealed(keys, CHAIN, head)).toBe(true);
  });

  it.each([0n, 2n, 5n])(
    'refuses an event numbered %s after an empty chain: only the next place can be sealed',
    (seq) => {
      const keys = provider();

      expect(() => sealNext(keys, CHAIN, genesisHead(keys, CHAIN), entry(seq))).toThrow(
        new ChainSealError(`the event is numbered ${seq.toString()}, but the next place after the head is 1`),
      );
    },
  );

  it('seals with the current key version, so a rotation reaches new events and heads', () => {
    const keys = provider({ 'audit-mac': rotatedMacKey() });
    const { link, head } = sealNext(keys, CHAIN, genesisHead(keys, CHAIN), entry(1n));

    expect(link.macKeyVersion).toBe(2);
    expect(head.macKeyVersion).toBe(2);
  });
});

describe('the head check', () => {
  const keys = provider();
  const { head } = sealedChain(keys, 2);

  it('accepts the head as sealed', () => {
    expect(headIsSealed(keys, CHAIN, head)).toBe(true);
  });

  it.each([
    ['wound back', { ...head, seq: 1n }],
    ['pointed at another hash', { ...head, hash: Buffer.alloc(32, 7) }],
    ['given a MAC of the wrong length', { ...head, mac: head.mac.subarray(0, 31) }],
    ['given another MAC', { ...head, mac: Buffer.alloc(32, 7) }],
    ['given a key version the app does not hold', { ...head, macKeyVersion: 9 }],
  ])('refuses a head %s', (_change, changed) => {
    expect(headIsSealed(keys, CHAIN, changed)).toBe(false);
  });

  it("refuses another chain's head", () => {
    expect(headIsSealed(keys, { kind: 'organisation', orgId: OTHER_ORG }, head)).toBe(false);
    expect(headIsSealed(keys, { kind: 'platform' }, head)).toBe(false);
  });
});

describe('SEC-EVD-02 the chain check', () => {
  const keys = provider();
  const { events, head } = sealedChain(keys, 4);

  it('passes an untouched chain, up to its head', () => {
    expect(verify(keys, head, events)).toEqual({ ok: true, seq: 4n, hash: head.hash });
  });

  it('passes an empty chain', () => {
    expect(verify(keys, genesisHead(keys, CHAIN), [])).toEqual({ ok: true, seq: 0n, hash: GENESIS_HASH });
  });

  it('passes events sealed before a key rotation, and after it', () => {
    const before = sealedChain(keys, 2);
    const rotated = provider({ 'audit-mac': rotatedMacKey() });
    const next = entry(3n);
    const after = sealNext(rotated, CHAIN, before.head, next);

    expect(verify(rotated, after.head, [...before.events, { ...next, ...after.link }])).toEqual({
      ok: true,
      seq: 3n,
      hash: after.head.hash,
    });
  });

  it.each([
    ['the first event deleted', () => events.slice(1), 'gap', 1n],
    ['a mid-chain event deleted', () => [events[0], events[2], events[3]], 'gap', 2n],
    ['an event pointed at another previous hash', () => replace(1, { prevHash: Buffer.alloc(32, 5) }), 'link', 2n],
    ['an event edited', () => replace(2, { content: ['action', 'step.edited'] }), 'hash', 3n],
    ['an event moved in time', () => replace(0, { recordedAt: new Date(0) }), 'hash', 1n],
    ['an event given another ID', () => replace(3, { id: entry(9n).id }), 'hash', 4n],
    ['a MAC changed', () => replace(1, { mac: Buffer.alloc(32, 3) }), 'mac', 2n],
    ['a MAC cut short', () => replace(1, { mac: Buffer.alloc(0) }), 'mac', 2n],
    ['a MAC key version the app does not hold', () => replace(2, { macKeyVersion: 2 }), 'mac', 3n],
    ['the tail deleted, the head left', () => events.slice(0, 3), 'head', 4n],
  ] as const)('finds %s', (_change, changed, reason, seq) => {
    expect(verify(keys, head, changed() as StoredEntry[])).toEqual({ ok: false, problem: { reason, seq } });
  });

  it('finds an event edited by someone who recomputed every hash after it, but holds no key', () => {
    // FX-TAMPER: the database owner can compute SHA-256, not the MAC.
    const forged = events.map((event) => ({ ...event }));
    forged[1] = { ...nth(events, 1), content: ['action', 'step.forged'] };
    for (let index = 1; index < forged.length; index += 1) {
      const prevHash = nth(forged, index - 1).hash;
      forged[index] = { ...nth(forged, index), prevHash, hash: linkHash(CHAIN, prevHash, nth(forged, index)) };
    }
    const last = nth(forged, forged.length - 1);

    expect(verify(keys, { ...head, hash: last.hash }, forged)).toEqual({
      ok: false,
      problem: { reason: 'head', seq: 4n },
    });
    // Even with a head that happened to verify, the edited event's own MAC fails first.
    expect(verify(keys, head, forged)).toEqual({ ok: false, problem: { reason: 'mac', seq: 2n } });
  });

  it('finds a correctly chained event appended with no valid MAC (FX-TAMPER)', () => {
    const next = entry(5n);
    const hash = linkHash(CHAIN, head.hash, next);
    const appended: StoredEntry = { ...next, prevHash: head.hash, hash, mac: Buffer.alloc(32), macKeyVersion: 1 };

    expect(verify(keys, { ...head, seq: 5n, hash }, [...events, appended])).toEqual({
      ok: false,
      problem: { reason: 'head', seq: 5n },
    });
    expect(verify(keys, head, [...events, appended])).toEqual({ ok: false, problem: { reason: 'head', seq: 4n } });
  });

  it("finds another organisation's events copied in, with their MACs and head", () => {
    const other = sealedChain(keys, 4, { kind: 'organisation', orgId: OTHER_ORG });

    expect(verify(keys, head, other.events)).toEqual({ ok: false, problem: { reason: 'hash', seq: 1n } });
    expect(verify(keys, other.head, other.events)).toEqual({ ok: false, problem: { reason: 'head', seq: 4n } });
  });

  it('finds an event added past the head, with the head left where it was', () => {
    const next = entry(5n);
    const sealed = sealNext(keys, CHAIN, head, next);

    expect(verify(keys, head, [...events, { ...next, ...sealed.link }])).toEqual({
      ok: false,
      problem: { reason: 'head', seq: 4n },
    });
  });

  it('finds a head wound back to an earlier valid head only past its events: the anchor check catches the rest', () => {
    const earlier = sealedChain(keys, 2);

    expect(verify(keys, earlier.head, events.slice(0, 2))).toEqual({ ok: true, seq: 2n, hash: earlier.head.hash });
    expect(verify(keys, earlier.head, events)).toEqual({ ok: false, problem: { reason: 'head', seq: 2n } });
  });

  it('stops at the first problem and keeps reporting it', () => {
    const verifier = createChainVerifier(keys, CHAIN, { head, lastSeq: 4n });

    expect(verifier.check(nth(events, 1))).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.check(nth(events, 0))).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.unreadable()).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.finish()).toEqual({ ok: false, problem: { reason: 'gap', seq: 1n } });
  });

  it('reports a row that cannot be read at its place', () => {
    const verifier = createChainVerifier(keys, CHAIN, { head, lastSeq: 4n });
    verifier.check(nth(events, 0));

    expect(verifier.unreadable()).toEqual({ reason: 'unreadable', seq: 2n });
    expect(verifier.finish()).toEqual({ ok: false, problem: { reason: 'unreadable', seq: 2n } });
  });

  it('reports a head whose MAC is wrong before reading any event', () => {
    const verifier = createChainVerifier(keys, CHAIN, { head: { ...head, mac: Buffer.alloc(32) }, lastSeq: 4n });

    expect(verifier.check(nth(events, 0))).toEqual({ reason: 'head', seq: 4n });
  });

  it('reports a head that has events past it, or is past its events, before reading any', () => {
    expect(createChainVerifier(keys, CHAIN, { head, lastSeq: 5n }).check(nth(events, 0))).toEqual({
      reason: 'head',
      seq: 4n,
    });
    expect(createChainVerifier(keys, CHAIN, { head, lastSeq: 3n }).finish()).toEqual({
      ok: false,
      problem: { reason: 'head', seq: 4n },
    });
  });

  it('reports a head the events stop short of', () => {
    expect(createChainVerifier(keys, CHAIN, { head, lastSeq: 4n }).finish()).toEqual({
      ok: false,
      problem: { reason: 'head', seq: 4n },
    });
  });

  it("reports a sealed head from a fork of the chain, whose hash isn't the last event's", () => {
    const fork = sealNext(keys, CHAIN, sealedChain(keys, 3).head, entry(4n, ['action', 'forked'])).head;

    expect(verify(keys, fork, events)).toEqual({ ok: false, problem: { reason: 'head', seq: 4n } });
  });

  function replace(index: number, change: Partial<StoredEntry>): StoredEntry[] {
    return events.map((event, at) => (at === index ? { ...event, ...change } : event));
  }
});
