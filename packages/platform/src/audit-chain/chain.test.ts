import { createHash, createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  createKeyProvider,
  KeyError,
  type KeyMaterial,
  type KeyProvider,
  type PurposeKeys,
} from '../keys/key-provider.ts';
import { encodeMessage, type Message } from '../keys/message.ts';
import { byPurpose, type KeyPurpose, PURPOSES } from '../keys/purposes.ts';
import {
  type Chain,
  type ChainEntry,
  type ChainHead,
  ChainSealError,
  createChainVerifier,
  entryIsSealed,
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

/** Checks `events` as a store holding exactly them would give them. */
function verify(keys: KeyProvider, head: ChainHead, events: readonly StoredEntry[], chain: Chain = CHAIN) {
  const verifier = createChainVerifier(keys, chain, { head, stored: BigInt(events.length) });
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

describe('one event checked on its own (entryIsSealed)', () => {
  const keys = provider();
  const { events } = sealedChain(keys, 3);
  const middle = nth(events, 1);

  it('accepts a sealed event, wherever it is in its chain', () => {
    expect(events.every((event) => entryIsSealed(keys, CHAIN, event))).toBe(true);
  });

  it.each([
    ['its content edited', { ...middle, content: ['action', 'step.9'] as const }],
    ['its time edited', { ...middle, recordedAt: new Date(RECORDED_AT.getTime() + 1) }],
    ['its ID edited', { ...middle, id: nth(events, 0).id }],
    ['moved to another place', { ...middle, seq: 7n }],
    [
      'pointed at another previous hash, its hash recomputed without the key',
      { ...middle, prevHash: Buffer.alloc(32, 7) },
    ],
    ['given another MAC', { ...middle, mac: Buffer.alloc(32, 7) }],
    ['given a MAC of the wrong length', { ...middle, mac: middle.mac.subarray(0, 31) }],
    ['given a key version the app does not hold', { ...middle, macKeyVersion: 9 }],
  ])('refuses an event %s', (_change, changed) => {
    expect(entryIsSealed(keys, CHAIN, changed)).toBe(false);
  });

  it('refuses an event whose hash was recomputed over new content by someone without the key (FX-TAMPER)', () => {
    const content = ['action', 'step.forged'] as const;
    const forged = { ...middle, content, hash: linkHash(CHAIN, middle.prevHash, { ...middle, content }) };

    expect(entryIsSealed(keys, CHAIN, forged)).toBe(false);
  });

  it("refuses another chain's event, MAC and all", () => {
    expect(entryIsSealed(keys, { kind: 'organisation', orgId: OTHER_ORG }, middle)).toBe(false);
    expect(entryIsSealed(keys, { kind: 'platform' }, middle)).toBe(false);
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

  it("finds an event sealed with an older key version than one before it: a rotated-out key can't add events", () => {
    const rotated = provider({ 'audit-mac': rotatedMacKey() });
    const newer = sealedChain(rotated, 2);
    // Made with version 1, which the app still holds to check older events: a copy of it is all an attacker needs.
    const next = entry(3n);
    const hash = linkHash(CHAIN, newer.head.hash, next);
    const mac = createHmac('sha256', key(AUDIT_MAC))
      .update(encodeMessage(['audit-event', `organisation:${ORG}`, '3', next.id, hash]))
      .digest();
    const forged: StoredEntry = { ...next, prevHash: newer.head.hash, hash, mac, macKeyVersion: 1 };

    expect(verify(rotated, newer.head, [...newer.events, forged])).toEqual({
      ok: false,
      problem: { reason: 'mac', seq: 3n },
    });
  });

  it("seals with the chain's newer version when this process's current one is older: a rollback raises no alarm", () => {
    const newer = sealedChain(provider({ 'audit-mac': rotatedMacKey() }), 2);
    const rolledBack = provider({ 'audit-mac': { ...rotatedMacKey(), current: 1 } });
    const next = entry(3n);
    const after = sealNext(rolledBack, CHAIN, newer.head, next);

    expect(after.link.macKeyVersion).toBe(2);
    expect(after.head.macKeyVersion).toBe(2);
    expect(verify(rolledBack, after.head, [...newer.events, { ...next, ...after.link }])).toMatchObject({ ok: true });
  });

  it("refuses to seal where the chain has reached a version this process doesn't hold", () => {
    const newer = sealedChain(provider({ 'audit-mac': rotatedMacKey() }), 2);

    expect(() => sealNext(provider(), CHAIN, newer.head, entry(3n))).toThrow(
      new KeyError('audit-mac has no version 2'),
    );
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
    // With the head left where it was, the event is still read here, and its own MAC fails.
    expect(verify(keys, head, [...events, appended])).toEqual({ ok: false, problem: { reason: 'mac', seq: 5n } });
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
    const verifier = createChainVerifier(keys, CHAIN, { head, stored: 4n });

    expect(verifier.check(nth(events, 1))).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.check(nth(events, 0))).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.unreadable()).toEqual({ reason: 'gap', seq: 1n });
    expect(verifier.finish()).toEqual({ ok: false, problem: { reason: 'gap', seq: 1n } });
  });

  it('reports a row that cannot be read at its place', () => {
    const verifier = createChainVerifier(keys, CHAIN, { head, stored: 4n });
    verifier.check(nth(events, 0));

    expect(verifier.unreadable()).toEqual({ reason: 'unreadable', seq: 2n });
    expect(verifier.finish()).toEqual({ ok: false, problem: { reason: 'unreadable', seq: 2n } });
  });

  it('reports a head whose MAC is wrong before reading any event', () => {
    const verifier = createChainVerifier(keys, CHAIN, { head: { ...head, mac: Buffer.alloc(32) }, stored: 4n });

    expect(verifier.check(nth(events, 0))).toEqual({ reason: 'head', seq: 4n });
  });

  it('reports a store holding more events than the head counts, once its events all check out', () => {
    // An event at a number the check never reads (0, say, or a second event 4) is still counted.
    const verifier = createChainVerifier(keys, CHAIN, { head, stored: 5n });
    for (const event of events) expect(verifier.check(event)).toBeUndefined();

    expect(verifier.finish()).toEqual({ ok: false, problem: { reason: 'head', seq: 4n } });
  });

  it('reports a head the events stop short of', () => {
    expect(createChainVerifier(keys, CHAIN, { head, stored: 4n }).finish()).toEqual({
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

describe('SEC-DB-11 the chain against its last anchor (ADR-012 §2)', () => {
  const keys = provider();
  const { events, head } = sealedChain(keys, 4);
  const anchorAt = (seq: number) => ({ seq: BigInt(seq), hash: nth(events, seq - 1).hash });
  const against = (chainHead: ChainHead, stored: readonly StoredEntry[], anchor: { seq: bigint; hash: Buffer }) => {
    const verifier = createChainVerifier(keys, CHAIN, { head: chainHead, stored: BigInt(stored.length), anchor });
    for (const event of stored) verifier.check(event);
    return verifier.finish();
  };

  it('passes a chain that still holds its anchor, at its head or grown past it', () => {
    expect(against(head, events, anchorAt(4))).toEqual({ ok: true, seq: 4n, hash: head.hash });
    expect(against(head, events, anchorAt(2))).toEqual({ ok: true, seq: 4n, hash: head.hash });
  });

  it('finds a chain wound back to an earlier sealed head, its tail deleted: the chain alone looks whole', () => {
    const earlier = sealedChain(keys, 2);

    expect(verify(keys, earlier.head, events.slice(0, 2))).toMatchObject({ ok: true });
    expect(against(earlier.head, events.slice(0, 2), anchorAt(4))).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 4n },
    });
  });

  it('finds a chain grown again on a wound-back head: sealed and whole, but not the event anchored', () => {
    // Wound back to event 2, and then the app went on recording, as it would on a head that checks out.
    const earlier = sealedChain(keys, 2);
    const regrown = [...events.slice(0, 2)];
    let regrownHead = earlier.head;
    for (const seq of [3n, 4n, 5n]) {
      const next = entry(seq, ['action', `regrown.${seq.toString()}`]);
      const sealed = sealNext(keys, CHAIN, regrownHead, next);
      regrown.push({ ...next, ...sealed.link });
      regrownHead = sealed.head;
    }

    expect(verify(keys, regrownHead, regrown)).toMatchObject({ ok: true, seq: 5n });
    expect(against(regrownHead, regrown, anchorAt(3))).toEqual({ ok: false, problem: { reason: 'anchor', seq: 3n } });
  });

  it('reports the first problem it meets, even when the head is also behind the anchor', () => {
    const earlier = sealedChain(keys, 2);

    expect(against(earlier.head, events.slice(1, 2), anchorAt(4))).toEqual({
      ok: false,
      problem: { reason: 'gap', seq: 1n },
    });
  });

  it('passes an empty chain anchored when it was empty', () => {
    expect(against(genesisHead(keys, CHAIN), [], { seq: 0n, hash: GENESIS_HASH })).toMatchObject({ ok: true, seq: 0n });
  });
});
