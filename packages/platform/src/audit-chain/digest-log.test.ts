import { gunzipSync, gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import {
  createDigestLog,
  type DigestAnchors,
  headCutBelow,
  headHeldTo,
  heldThrough,
  MOST_WITNESSED,
  placesOf,
  raiseWritten,
} from './digest-log.ts';
import { bodyHash } from './shards.ts';
import { subjectKey } from './state-digest.ts';

const keyMaterial = (fill: number): KeyMaterial =>
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
  })) satisfies KeyMaterial;
const keys = createKeyProvider(keyMaterial(1));
/** Someone else's signing key: their files read as ours, signed wrongly. */
const otherKeys = createKeyProvider(keyMaterial(50));

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const CHAIN: Chain = { kind: 'organisation', orgId: ORG };
const OTHER: Chain = { kind: 'organisation', orgId: OTHER_ORG };
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY = '0199a0f0-0000-7000-8000-0000000000b1';
const START = new Date('2026-11-20T09:00:00.000Z');
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const seen = (...entries: readonly (readonly [string, string, bigint])[]): ReadonlyMap<string, bigint> =>
  new Map(entries.map(([type, id, seq]) => [subjectKey(type, id), seq]));

/** A clock the test moves. */
function clock(at = START.getTime()) {
  const held = { at };
  return { now: () => new Date(held.at), held };
}

/** The anchors' log as the digest asks it: rebases by chain, and shards held. */
function anchorsWith(rebases = new Map<string, Date>(), letGo = new Set<string>()): DigestAnchors {
  const name = (chain: Chain) => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  return {
    rebasedAfter: (chain, at) => {
      const rebase = rebases.get(name(chain));
      return rebase !== undefined && rebase > at;
    },
    holds: (chain) => !letGo.has(name(chain)),
  };
}

function digestOn(
  fake = createFakeWriteOnceStore(),
  {
    time = clock(),
    anchors = anchorsWith(),
    capture = new LogCapture(),
    mostBytes = 64 * 1024 * 1024,
    mostFileBytes = undefined as number | undefined,
    signing = keys,
    forget = undefined as number | undefined,
    forgetSessions = undefined as number | undefined,
  } = {},
) {
  const log = createDigestLog({
    store: fake.store,
    keys: signing,
    logger: testLogger(capture),
    now: time.now,
    epoch: 1,
    anchors,
    alertAfterMs: 15 * MINUTE,
    mostBytes,
    ...(mostFileBytes === undefined ? {} : { mostFileBytes }),
    forgetRequestsAfterMs: forget,
    forgetSessionEndsAfterMs: forgetSessions,
  });
  return { log, fake, time, capture };
}

const namesUnder = (files: ReadonlyMap<string, Buffer>, kind: string): string[] =>
  [...files.keys()].filter((name) => name.startsWith(`e1/digests/${kind}/`)).toSorted();

/** A file's lines, opened. */
const linesOf = (bytes: Buffer): string[] => gunzipSync(bytes).toString('utf8').split('\n');

/** A file closed for `name` by `signing`, of the lines given. */
function closedFile(name: string, lines: readonly string[], signing = keys): Buffer {
  const body = bodyHash();
  for (const line of lines) body.add(line);
  const { signature, keyVersion } = signing.sign('audit-anchor', [
    'audit-digest-file',
    name,
    '1',
    String(body.lines),
    body.digest(),
  ]);
  const closing = JSON.stringify({ k: 'z', lines: body.lines, kv: keyVersion, sig: signature.toString('base64') });
  return gzipSync([...lines, closing].join('\n'));
}

describe('the signed states’ digest in memory alone (no store)', () => {
  it('keeps the highest place each object was seen at, says nothing of others, and stands for every chain', async () => {
    const log = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    expect(log.state()).toBe('read');
    expect(log.covers(CHAIN, 0n)).toBe(true);
    log.record(CHAIN, seen(['agent', AGENT, 5n], ['agent_key', KEY, 3n]), START);
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    log.record(CHAIN, seen(['agent', AGENT.toUpperCase(), 9n]), START);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(9n);
    expect(log.latest(CHAIN, 'agent_key', KEY)).toBe(3n);
    expect(log.latest(CHAIN, 'agent', KEY)).toBeUndefined();
    expect(log.latest(OTHER, 'agent', AGENT)).toBeUndefined();
    await log.read();
    await log.flush();
    expect(log.memoryHeld()).toMatchObject({ chains: 1, objects: 2 });
  });

  it('a place that is not a safe count is refused, as no chain reaches it', () => {
    const log = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      alertAfterMs: 1,
      mostBytes: 1e6,
    });
    expect(() => {
      log.record(CHAIN, seen(['agent', AGENT, 0n]), START);
    }).toThrow(RangeError);
    expect(() => {
      log.record(CHAIN, seen(['agent', AGENT, 2n ** 53n]), START);
    }).toThrow(RangeError);
  });

  it('holds thousands of objects a chain, each where it was seen last', () => {
    const log = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      alertAfterMs: 1,
      mostBytes: 1e8,
    });
    const ids = Array.from({ length: 5000 }, (_, at) => `0199a0f0-0000-7000-8000-${at.toString(16).padStart(12, '0')}`);
    log.record(CHAIN, new Map(ids.map((id, at) => [subjectKey('spend_request', id), BigInt(at + 1)])), START);
    expect(ids.every((id, at) => log.latest(CHAIN, 'spend_request', id) === BigInt(at + 1))).toBe(true);
    expect(log.memoryHeld().objects).toBe(5000);
  });
});

describe('the digest kept in the write-once store (AT13)', () => {
  it('is unknown until its first read has ended whole, and an empty store reads as nothing known', async () => {
    const { log } = digestOn();
    expect(log.state()).toBe('unread');
    expect(log.covers(CHAIN, 0n)).toBe(false);
    await log.read();
    expect(log.state()).toBe('read');
    expect(log.covers(CHAIN, 0n)).toBe(true);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
  });

  it('writes what moved as a delta, closed for its own name, and a restart reads it back', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 7n]), START);
    log.record(OTHER, seen(['agent_key', KEY, 2n]), START);
    await log.flush();
    const [delta] = namesUnder(fake.files, 'deltas');
    expect(delta).toMatch(/^e1\/digests\/deltas\/\d{13}-[0-9a-f-]{36}$/);
    // Nothing moved: nothing written but the hour's snapshot, which came with it.
    await log.flush();
    expect(namesUnder(fake.files, 'deltas')).toHaveLength(1);

    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(7n);
    expect(restarted.log.latest(OTHER, 'agent_key', KEY)).toBe(2n);
  });

  it('writes the whole hourly where something moved, and a start reads the newest snapshot and the deltas since', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 7n]), START);
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);
    time.held.at += 10 * MINUTE;
    log.record(CHAIN, seen(['agent', AGENT, 9n], ['agent_key', KEY, 8n]), time.now());
    await log.flush();
    // Within the hour: a delta, no snapshot.
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);
    time.held.at += HOUR;
    log.record(OTHER, seen(['agent', AGENT, 3n]), time.now());
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(2);

    const restarted = digestOn(fake, { time });
    const gets = fake.calls.smallGets;
    await restarted.log.read();
    // The newest snapshot, and the one delta named since it (the one before it is older than the clocks' margin).
    expect(fake.calls.smallGets - gets).toBe(2);
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(9n);
    expect(restarted.log.latest(CHAIN, 'agent_key', KEY)).toBe(8n);
    expect(restarted.log.latest(OTHER, 'agent', AGENT)).toBe(3n);
  });

  it('a later read takes another process’s deltas since its last, once each', async () => {
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const writer = digestOn(fake, { time });
    const reader = digestOn(fake, { time });
    await writer.log.read();
    await reader.log.read();
    writer.log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await writer.log.flush();
    time.held.at += MINUTE;
    await reader.log.read();
    expect(reader.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    const gets = fake.calls.smallGets;
    await reader.log.read();
    expect(fake.calls.smallGets).toBe(gets);
  });

  it('a delta signed with another key, edited, or copied under a new name counts for nothing, and is the alarm', async () => {
    const { log, fake, time, capture } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    const [written] = namesUnder(fake.files, 'deltas');
    if (written === undefined) throw new Error('A delta was written');
    const lines = linesOf(fake.files.get(written) ?? Buffer.alloc(0));
    const body = lines.slice(0, -1);
    const forged = JSON.stringify({
      c: `organisation:${ORG}`,
      t: START.toISOString(),
      e: Buffer.concat([Buffer.alloc(8, 7), Buffer.from([0, 0, 0, 0, 0, 0, 0, 99])]).toString('base64'),
    });
    const at = (minutes: number) => String(9_999_999_999_999 - (START.getTime() + minutes * MINUTE)).padStart(13, '0');
    const named = (minutes: number, id: string) => `e1/digests/deltas/${at(minutes)}-${id}`;
    const other = named(1, '0199a0f0-0000-7000-8000-00000000f001');
    const edited = named(2, '0199a0f0-0000-7000-8000-00000000f002');
    const copied = named(3, '0199a0f0-0000-7000-8000-00000000f003');
    const junk = named(4, '0199a0f0-0000-7000-8000-00000000f004');
    fake.files.set(other, closedFile(other, [forged], otherKeys));
    fake.files.set(edited, gzipSync([forged, ...lines.slice(1)].join('\n')));
    fake.files.set(copied, fake.files.get(written) ?? Buffer.alloc(0));
    fake.files.set(junk, Buffer.from('not gzip'));
    // A file whose lines don't read as ours, closed properly: still nothing taken.
    const unreadable = named(5, '0199a0f0-0000-7000-8000-00000000f005');
    fake.files.set(unreadable, closedFile(unreadable, ['{"c":"organisation:nope","t":"x","e":""}']));
    expect(body).toHaveLength(1);

    time.held.at += 6 * MINUTE;
    const restarted = digestOn(fake, { time, capture });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    expect(
      capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.check === 'digest_store'),
    ).toHaveLength(5);
    expect(restarted.log.memoryHeld().objects).toBe(1);
  });

  it('a spoiled snapshot is passed over for the one before it, and with none sound every delta is read: nothing lost', async () => {
    const { log, fake, time, capture } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    time.held.at += 2 * HOUR;
    log.record(CHAIN, seen(['agent_key', KEY, 6n]), time.now());
    await log.flush();
    const snapshots = namesUnder(fake.files, 'snapshots');
    expect(snapshots).toHaveLength(2);
    // The newest snapshot spoiled: its bytes replaced by another's, so it fails its own name.
    const [newest, older] = snapshots;
    if (newest === undefined || older === undefined) throw new Error('Two snapshots were written');
    fake.files.set(newest, fake.files.get(older) ?? Buffer.alloc(0));

    const restarted = digestOn(fake, { time, capture });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    expect(restarted.log.latest(CHAIN, 'agent_key', KEY)).toBe(6n);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.integrity_failed', check: 'digest_store', kind: 'snapshots' }),
    );

    // Every snapshot spoiled: the deltas alone hold every fact.
    fake.files.set(older, Buffer.from('spoiled'));
    const again = digestOn(fake, { time });
    await again.log.read();
    expect(again.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    expect(again.log.latest(CHAIN, 'agent_key', KEY)).toBe(6n);
  });

  it('past a day of spoiled snapshots it stops looking back and reads every delta', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    for (let hour = 1; hour <= 25; hour += 1) {
      const name = `e1/digests/snapshots/${String(9_999_999_999_999 - (START.getTime() + hour * MINUTE)).padStart(13, '0')}-0199a0f0-0000-7000-8000-${hour.toString(16).padStart(12, '0')}`;
      fake.files.set(name, Buffer.from('spoiled'));
    }
    time.held.at += HOUR;
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
  });

  it('a name dated past the clock is the alarm and passed over', async () => {
    const { fake, time, capture } = digestOn();
    const ahead = String(9_999_999_999_999 - (START.getTime() + HOUR)).padStart(13, '0');
    const name = `e1/digests/deltas/${ahead}-0199a0f0-0000-7000-8000-00000000f00a`;
    fake.files.set(name, closedFile(name, []));
    fake.files.set('e1/digests/deltas/not-ours', Buffer.from('x'));
    const restarted = digestOn(fake, { time, capture });
    await restarted.log.read();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.integrity_failed', check: 'digest_store', reason: 'future' }),
    );
  });

  it('a rebase sets the chain’s facts from before it aside, in memory and as read; facts after it stand', async () => {
    const rebases = new Map<string, Date>();
    const anchors = anchorsWith(rebases);
    const { log, fake, time } = digestOn(undefined, { anchors });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START);
    log.record(OTHER, seen(['agent', AGENT, 9n]), START);
    await log.flush();
    rebases.set(ORG, new Date(START.getTime() + MINUTE));
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(log.latest(OTHER, 'agent', AGENT)).toBe(9n);
    time.held.at += 2 * MINUTE;
    log.record(CHAIN, seen(['agent', AGENT, 3n]), time.now());
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    await log.flush();

    const restarted = digestOn(fake, { time, anchors });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    expect(restarted.log.latest(OTHER, 'agent', AGENT)).toBe(9n);
  });

  it('says nothing of a chain whose anchors’ shard is let go, and stands for none of it', async () => {
    const letGo = new Set<string>();
    const { log } = digestOn(undefined, { anchors: anchorsWith(new Map(), letGo) });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START);
    letGo.add(ORG);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(log.covers(CHAIN, 0n)).toBe(false);
    expect(log.covers(OTHER, 0n)).toBe(true);
    letGo.delete(ORG);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(9n);
  });

  it('a write that fails keeps what moved for the next, a warning, and past the alert time the alert', async () => {
    const { log, fake, time, capture } = digestOn();
    await log.read();
    fake.instead.put = () => Promise.reject(new Error('store away'));
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.state_digest_store_failed', what: 'write' }),
    );
    time.held.at += 20 * MINUTE;
    await log.flush();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.state_digest_store_failing', what: 'write' }),
    );
    delete fake.instead.put;
    await log.flush();
    // Kept as a delta, not only in the hour's snapshot: a snapshot is never the one copy of a fact.
    expect(namesUnder(fake.files, 'deltas')).toHaveLength(1);
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
  });

  it('writes no snapshot before a whole read, as it would stand for the whole: only the delta', async () => {
    const { log, fake } = digestOn();
    fake.instead.list = () => Promise.reject(new Error('store away'));
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    expect(namesUnder(fake.files, 'deltas')).toHaveLength(1);
    expect(namesUnder(fake.files, 'snapshots')).toEqual([]);
  });

  it('a read that fails leaves it unknown, a warning, and tries again whole next time', async () => {
    const { log, fake, capture } = digestOn();
    fake.instead.list = () => Promise.reject(new Error('store away'));
    await log.read();
    expect(log.state()).toBe('unread');
    expect(log.covers(CHAIN, 0n)).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.state_digest_store_failed', what: 'read' }),
    );
    delete fake.instead.list;
    await log.read();
    expect(log.state()).toBe('read');
  });

  it('a file listed and gone is the store failing, never a file passed over', async () => {
    const { log, fake } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), START);
    await log.flush();
    fake.instead.getAtMost = () => Promise.resolve('missing');
    const restarted = digestOn(fake);
    await restarted.log.read();
    expect(restarted.log.state()).toBe('unread');
  });

  it('joins a read or a write under way rather than start a second', async () => {
    const { log } = digestOn();
    const [one, two] = [log.read(), log.read()];
    expect(one).toBe(two);
    await one;
    const [three, four] = [log.flush(), log.flush()];
    expect(three).toBe(four);
    await three;
  });

  it('writes a chain of many objects over lines of at most 2,048 each, and reads every one back', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    const ids = Array.from({ length: 5000 }, (_, at) => `0199a0f0-0000-7000-8000-${at.toString(16).padStart(12, '0')}`);
    log.record(CHAIN, new Map(ids.map((id, at) => [subjectKey('spend_request', id), BigInt(at + 1)])), START);
    await log.flush();
    const [delta] = namesUnder(fake.files, 'deltas');
    expect(linesOf(fake.files.get(delta ?? '') ?? Buffer.alloc(0))).toHaveLength(4);
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(ids.every((id, at) => restarted.log.latest(CHAIN, 'spend_request', id) === BigInt(at + 1))).toBe(true);
  });
});

/** A place of the chain, as a walk's report gives it. */
const point = (seq: bigint) => ({ seq, hash: Buffer.alloc(32, Number(seq % 200n)), macKeyVersion: 1 });
/** A stretch a walk read whole, after `from` up to `to`. */
const stretch = (from: bigint, to: bigint) => ({ from, to: point(to) });

/** `count` spend requests' facts, from the `from`th. */
const requests = (count: number, from = 0) =>
  new Map(
    Array.from({ length: count }, (_, at) => [
      subjectKey('spend_request', `0199a0f0-0000-7000-8000-${(from + at).toString(16).padStart(12, '0')}`),
      BigInt(from + at + 1),
    ]),
  );

describe('the digest’s coverage: Tx A goes on a chain only as far as its walks join up from its first event (AT13)', () => {
  it('covers a chain to where its stretches join from the start; a gap leaves it uncovered until filled', async () => {
    const { log } = digestOn();
    await log.read();
    expect(log.covers(CHAIN, 0n)).toBe(true);
    expect(log.covers(CHAIN, 1n)).toBe(false);
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 5n));
    expect(log.covers(CHAIN, 5n)).toBe(true);
    expect(log.covers(CHAIN, 6n)).toBe(false);
    expect(log.coverage(CHAIN)).toEqual(point(5n));
    // Read whole from 8 to 12, with 5 to 8 never read: not covered past 5.
    log.record(CHAIN, new Map(), START, stretch(8n, 12n));
    expect(log.covers(CHAIN, 12n)).toBe(false);
    // The gap read: joined up to 12 at once.
    log.record(CHAIN, new Map(), START, stretch(5n, 8n));
    expect(log.covers(CHAIN, 12n)).toBe(true);
    expect(log.coverage(CHAIN)).toEqual(point(12n));
    // A stretch inside what is covered moves nothing back.
    log.record(CHAIN, new Map(), START, stretch(0n, 2n));
    expect(log.coverage(CHAIN)).toEqual(point(12n));
  });

  it('keeps at most a few stretches beyond a gap, the nearest first', async () => {
    const { log } = digestOn();
    await log.read();
    for (let far = 20n; far >= 2n; far -= 1n) log.record(CHAIN, new Map(), START, stretch(far * 10n, far * 10n + 5n));
    log.record(CHAIN, new Map(), START, stretch(0n, 20n));
    // The nearest far side kept joins at once: the farthest were let go, and later walks bring them again.
    expect(log.coverage(CHAIN)).toEqual(point(25n));
  });

  it('writes the stretches with the facts and reads them back: a restart covers what was covered', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 5n));
    log.record(CHAIN, new Map(), START, stretch(5n, 9n));
    await log.flush();
    const restarted = digestOn(fake, { time });
    expect(restarted.log.covers(CHAIN, 0n)).toBe(false);
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 9n)).toBe(true);
    expect(restarted.log.coverage(CHAIN)).toEqual(point(9n));
  });

  it('an anchor written and the digest’s delta lost: a restart leaves the chain uncovered past what was written', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 5n));
    await log.flush();
    // The next walk's delta never reaches the store: the process stops before its write.
    log.record(CHAIN, seen(['agent', AGENT, 7n]), START, stretch(5n, 9n));
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 5n)).toBe(true);
    expect(restarted.log.covers(CHAIN, 9n)).toBe(false);
    expect(restarted.log.coverage(CHAIN)).toEqual(point(5n));
  });

  it('a spoiled delta breaks coverage at its stretch: facts after it never stand for the chain whole', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    log.record(CHAIN, new Map(), START, stretch(0n, 5n));
    await log.flush();
    time.held.at += MINUTE;
    log.record(CHAIN, seen(['agent', AGENT, 7n]), time.now(), stretch(5n, 9n));
    await log.flush();
    time.held.at += MINUTE;
    log.record(CHAIN, new Map(), time.now(), stretch(9n, 12n));
    await log.flush();
    const [, middle] = namesUnder(fake.files, 'deltas');
    if (middle === undefined) throw new Error('Three deltas were written');
    fake.files.set(middle, Buffer.from('spoiled'));
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 5n)).toBe(true);
    expect(restarted.log.covers(CHAIN, 12n)).toBe(false);
  });

  it('a rebase sets the chain’s coverage aside with its facts, until walks read it again from its first event', async () => {
    const rebases = new Map<string, Date>();
    const { log } = digestOn(undefined, { anchors: anchorsWith(rebases) });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    rebases.set(ORG, new Date(START.getTime() + MINUTE));
    expect(log.covers(CHAIN, 10n)).toBe(false);
    expect(log.coverage(CHAIN)).toBeUndefined();
    // A walk that began before the rebase read the chain as it was: nothing of it counts.
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    expect(log.covers(CHAIN, 10n)).toBe(false);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    log.record(CHAIN, seen(['agent', AGENT, 4n]), new Date(START.getTime() + 2 * MINUTE), stretch(0n, 6n));
    expect(log.covers(CHAIN, 6n)).toBe(true);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
  });
});

describe('the digest within its memory: one organisation’s growth never stops another’s (AT13; S165, S170)', () => {
  it('the largest chain gives way, its payments first, then all of it, each with its own alarm; the small one keeps all', async () => {
    const capture = new LogCapture();
    const { log, fake, time } = digestOn(undefined, { capture, mostBytes: 12_000 });
    await log.read();
    log.record(OTHER, seen(['agent', AGENT, 2n]), START, stretch(0n, 2n));
    log.record(CHAIN, seen(['agent', AGENT, 3n], ['agent_key', KEY, 4n]), START, stretch(0n, 4n));
    expect(capture.lines()).toEqual([]);
    // The busy organisation's requests outgrow what may be held: its payments give way.
    log.record(CHAIN, requests(400), START, stretch(4n, 500n));
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({
        level: 'error',
        event: 'audit.state_digest_chain_gave_way',
        orgId: ORG,
        what: 'payments',
      }),
    );
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-000000000000')).toBeUndefined();
    // Its authority is still held to the digest, and both chains still go on.
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    expect(log.latest(OTHER, 'agent', AGENT)).toBe(2n);
    expect(log.covers(CHAIN, 500n)).toBe(true);
    expect(log.covers(OTHER, 2n)).toBe(true);
    expect(log.memoryHeld().bytes).toBeLessThanOrEqual(12_000);
    expect(log.bytesHeld()).toBe(log.memoryHeld().bytes);
    // More payments of it are kept no more.
    log.record(CHAIN, requests(10, 1000), START);
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-0000000003e8')).toBeUndefined();

    // Its authority alone outgrowing it too: the whole chain gives way, read as before the digest, never a stop.
    const agents = new Map(
      Array.from({ length: 600 }, (_, at) => [
        subjectKey('agent', `0199a0f0-0000-7000-8000-${(5000 + at).toString(16).padStart(12, '0')}`),
        BigInt(at + 600),
      ]),
    );
    log.record(CHAIN, agents, START, stretch(500n, 1200n));
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.state_digest_chain_gave_way', orgId: ORG, what: 'chain' }),
    );
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(log.covers(CHAIN, 99_999n)).toBe(true);
    expect(log.latest(OTHER, 'agent', AGENT)).toBe(2n);
    expect(log.covers(OTHER, 2n)).toBe(true);

    // A restart holds the chain as given way at once: today's checks, never a wait for a walk from its first event.
    time.held.at += 2 * HOUR;
    log.record(OTHER, seen(['agent', KEY, 3n]), time.now(), stretch(2n, 3n));
    await log.flush();
    const again = new LogCapture();
    const restarted = digestOn(fake, { time, mostBytes: 1024 * 1024, capture: again });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 99_999n)).toBe(true);
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(restarted.log.covers(OTHER, 3n)).toBe(true);
    expect(again.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.state_digest_chain_gave_way', orgId: ORG, what: 'chain' }),
    );
  });

  it('a chain whose payments gave way keeps its coverage and its state across a restart: no wait, payments as before', async () => {
    const { log, fake, time } = digestOn(undefined, { mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 4n));
    await log.flush();
    log.record(CHAIN, requests(400), START);
    // A walk after it gave way: its coverage is written, as a payment's fact missing only loses protection.
    log.record(CHAIN, new Map(), START, stretch(0n, 600n));
    expect(log.covers(CHAIN, 600n)).toBe(true);
    // Within the hour: no snapshot, so the delta alone carries how far it gave way.
    time.held.at += 10 * MINUTE;
    await log.flush();
    const restarted = digestOn(fake, { time, mostBytes: 1024 * 1024 });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 600n)).toBe(true);
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    // Its payments still given way, though there is room now: what was let go is not all in the store's files.
    expect(restarted.log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-000000000000')).toBeUndefined();
    restarted.log.record(CHAIN, requests(1, 2000), START);
    expect(restarted.log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-0000000007d0')).toBeUndefined();
  });

  it('a snapshot alone carries how far a chain gave way, and its coverage where only its payments did', async () => {
    const { log, fake, time } = digestOn(undefined, { mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 4n));
    log.record(CHAIN, requests(400), START, stretch(4n, 600n));
    time.held.at += 2 * HOUR;
    await log.flush();
    for (const name of namesUnder(fake.files, 'deltas')) fake.files.delete(name);
    const again = new LogCapture();
    const restarted = digestOn(fake, { time, mostBytes: 1024 * 1024, capture: again });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 600n)).toBe(true);
    expect(again.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.state_digest_chain_gave_way', orgId: ORG, what: 'payments' }),
    );
  });

  it('says it is past half, once', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { capture, mostBytes: 16_000 });
    await log.read();
    log.record(CHAIN, requests(300), START);
    log.record(CHAIN, requests(10, 1000), START);
    expect(capture.lines().filter((line) => line.event === 'audit.state_digest_near_memory')).toHaveLength(1);
    expect(capture.lines().filter((line) => line.event === 'audit.state_digest_chain_gave_way')).toEqual([]);
  });

  it('writes no snapshot larger than a start fetches: the deltas are read instead', async () => {
    const capture = new LogCapture();
    const { log, fake, time } = digestOn(undefined, { capture, mostFileBytes: 1500 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 1n]), START);
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);
    // Small deltas over the hour, and the hour's snapshot of all of them past what a start fetches.
    for (let delta = 0; delta < 5; delta += 1) {
      time.held.at += 13 * MINUTE;
      log.record(CHAIN, requests(30, delta * 100), time.now());
      await log.flush();
    }
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'audit.state_digest_snapshot_too_large' }));
    const restarted = digestOn(fake, { time, mostFileBytes: 1500 });
    await restarted.log.read();
    expect(restarted.log.memoryHeld().objects).toBe(151);
  });
});

describe('the digest in a process that loses the lease (AT13, TR-1 A)', () => {
  it('keeps its heads and facts when the lease goes, reads the store as a web copy does, writes nothing until it leads', async () => {
    const leads = { now: true };
    const rebases = new Map<string, Date>();
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const log = createDigestLog({
      store: fake.store,
      keys,
      logger: testLogger(),
      now: time.now,
      epoch: 1,
      anchors: anchorsWith(rebases),
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await log.flush();
    log.heads(CHAIN)?.saw(headAt(12n));
    // Recorded while it led, not yet written as the lease goes.
    log.record(OTHER, seen(['agent', AGENT, 4n]), START);
    const written = fake.files.size;

    leads.now = false;
    // Every answer as while it led: the facts, the coverage and the head seen above it, none forgotten.
    expect(log.state()).toBe('read');
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(9n);
    expect(log.covers(CHAIN, 10n)).toBe(true);
    expect(log.coverage(CHAIN)?.seq).toBe(10n);
    expect(log.owed(CHAIN, 10n)).toBe(false);
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(12n));
    // A head a read finds while it follows is held to as well.
    log.heads(CHAIN)?.saw(headAt(14n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(14n));
    // It writes nothing: a walk isn't recorded, and what waits isn't written.
    log.record(CHAIN, seen(['agent_key', KEY, 3n]), START, stretch(10n, 13n));
    expect(log.latest(CHAIN, 'agent_key', KEY)).toBeUndefined();
    time.held.at += MINUTE;
    await log.flush();
    expect(fake.files.size).toBe(written);

    // The copy leading walks and writes; this one reads it, as a web copy does.
    const { log: leader } = digestOn(fake, { time });
    await leader.read();
    leader.record(CHAIN, seen(['agent_key', KEY, 11n]), time.now(), stretch(10n, 13n));
    await leader.flush();
    await log.read();
    expect(log.latest(CHAIN, 'agent_key', KEY)).toBe(11n);
    expect(log.coverage(CHAIN)?.seq).toBe(13n);
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(14n));

    // A rebase its anchors' log reads while it follows sets the chain aside, heads and facts, as at a leader.
    rebases.set(ORG, new Date(time.held.at));
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();

    // Leading again, it writes what it held back: a start reads it.
    leads.now = true;
    const before = fake.files.size;
    time.held.at += MINUTE;
    await log.flush();
    expect(fake.files.size).toBe(before + 1);
    const { log: restarted } = digestOn(fake, { time });
    await restarted.read();
    expect(restarted.latest(OTHER, 'agent', AGENT)).toBe(4n);
  });

  it('leading again, writes no snapshot until a read while it leads has ended whole: the leader’s deltas never hidden', async () => {
    const leads = { now: true };
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const log = createDigestLog({
      store: fake.store,
      keys,
      logger: testLogger(),
      now: time.now,
      epoch: 1,
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);

    // It follows; the copy leading writes a delta this one never reads, its reads failing.
    leads.now = false;
    time.held.at += MINUTE;
    const { log: leader } = digestOn(fake, { time });
    await leader.read();
    leader.record(OTHER, seen(['agent_key', KEY, 5n]), time.now());
    await leader.flush();
    fake.instead.list = () => Promise.reject(new Error('the store is away'));
    await log.read();

    // It leads again an hour on, a snapshot due, its reads still failing: deltas go, no snapshot.
    time.held.at += HOUR;
    leads.now = true;
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 12n]), time.now(), stretch(10n, 12n));
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);
    delete fake.instead.list;
    const { log: restarted } = digestOn(fake, { time });
    await restarted.read();
    expect(restarted.latest(OTHER, 'agent_key', KEY)).toBe(5n);
    expect(restarted.latest(CHAIN, 'agent', AGENT)).toBe(12n);

    // The positive control: a read while it leads ends whole, and the snapshot is written, holding the leader's fact.
    await log.read();
    log.record(CHAIN, seen(['agent_key', KEY, 11n]), time.now(), stretch(12n, 13n));
    time.held.at += MINUTE;
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(2);
    const { log: fromSnapshot } = digestOn(fake, { time });
    await fromSnapshot.read();
    expect(fromSnapshot.latest(OTHER, 'agent_key', KEY)).toBe(5n);
  });

  it('its own deltas never move its look back: leading again past the lag, a read still takes in what another wrote', async () => {
    const leads = { now: true };
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const log = createDigestLog({
      store: fake.store,
      keys,
      logger: testLogger(),
      now: time.now,
      epoch: 1,
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await log.flush();
    await log.read();

    // It follows; another copy writes a delta, this one's reads failing.
    leads.now = false;
    time.held.at += MINUTE;
    const { log: leader } = digestOn(fake, { time });
    await leader.read();
    leader.record(OTHER, seen(['agent_key', KEY, 5n]), time.now());
    await leader.flush();
    fake.instead.list = () => Promise.reject(new Error('the store is away'));
    await log.read();
    delete fake.instead.list;

    // Leading again ten minutes on, past the lag: its own delta first, then a read.
    time.held.at += 10 * MINUTE;
    leads.now = true;
    log.record(CHAIN, seen(['agent', AGENT, 12n]), time.now(), stretch(10n, 12n));
    await log.flush();
    await log.read();
    expect(log.latest(OTHER, 'agent_key', KEY)).toBe(5n);
  });

  it('a start that finds no delta after its snapshot looks back from the snapshot, never the whole epoch again', async () => {
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const { log: before } = digestOn(fake, { time });
    await before.read();
    before.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await before.flush();
    const old = namesUnder(fake.files, 'deltas');
    time.held.at += 2 * HOUR;
    before.record(CHAIN, seen(['agent', AGENT, 12n]), time.now(), stretch(10n, 12n));
    await before.flush();
    // The delta beside the newer snapshot gone from the listing: quiet hours, nothing written since the snapshot.
    for (const name of namesUnder(fake.files, 'deltas')) if (!old.includes(name)) fake.files.delete(name);
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(2);

    const fetched: string[] = [];
    fake.instead.getAtMost = (name, most) => {
      fetched.push(name);
      return fake.real.getAtMost(name, most);
    };
    time.held.at += MINUTE;
    const { log } = digestOn(fake, { time });
    await log.read();
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(12n);
    log.record(OTHER, seen(['agent', AGENT, 4n]), time.now());
    await log.flush();
    await log.read();
    expect(fetched.filter((name) => old.includes(name))).toEqual([]);
  });

  it('a read begun while it followed and ended once it leads stands for no snapshot; the next one does', async () => {
    const leads = { now: true };
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const log = createDigestLog({
      store: fake.store,
      keys,
      logger: testLogger(),
      now: time.now,
      epoch: 1,
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await log.flush();
    leads.now = false;
    // A follower's read whose list answers only after it has come to lead.
    const { promise: listed, resolve: answer } = Promise.withResolvers<undefined>();
    fake.instead.list = async (...args) => {
      await listed;
      return fake.real.list(...args);
    };
    const reading = log.read();
    leads.now = true;
    answer(undefined);
    await reading;
    delete fake.instead.list;
    time.held.at += HOUR;
    log.record(CHAIN, seen(['agent', AGENT, 12n]), time.now(), stretch(10n, 12n));
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(1);

    await log.read();
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots')).toHaveLength(2);
  });
});

const THIRD_ORG = '0199a0f0-0000-7000-8000-000000000003';
const THIRD: Chain = { kind: 'organisation', orgId: THIRD_ORG };
const PLATFORM: Chain = { kind: 'platform' };

/** `count` agents' facts, from the `from`th: authority, which grows only with what an organisation sets up. */
const agents = (count: number, from = 0) =>
  new Map(
    Array.from({ length: count }, (_, at) => [
      subjectKey('agent', `0199a0f0-0000-7000-8000-${(0x10_000 + from + at).toString(16).padStart(12, '0')}`),
      BigInt(from + at + 1),
    ]),
  );

const said = (capture: LogCapture, event: string) => capture.lines().filter((line) => line.event === event);
const FIRST_REQUEST = '0199a0f0-0000-7000-8000-000000000000';

describe('the digest’s fair share: many small organisations never push out a large one within its share (AT13e)', () => {
  it('a chain past its share with growing objects gives way first, before a larger one of authority alone', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { capture, mostBytes: 40_000 });
    await log.read();
    log.record(THIRD, seen(['agent', AGENT, 1n]), START);
    log.record(OTHER, requests(400), START);
    expect(said(capture, 'audit.state_digest_chain_gave_way')).toEqual([]);
    // The largest chain is of authority alone; the busy one's requests, past its share too, give way instead.
    log.record(CHAIN, agents(900), START);
    expect(said(capture, 'audit.state_digest_chain_gave_way')).toEqual([
      expect.objectContaining({ orgId: OTHER_ORG, what: 'payments' }),
    ]);
    expect(log.latest(CHAIN, 'agent', '0199a0f0-0000-7000-8000-000000010000')).toBe(1n);
    expect(log.latest(THIRD, 'agent', AGENT)).toBe(1n);
    expect(log.latest(OTHER, 'spend_request', FIRST_REQUEST)).toBeUndefined();
    expect(log.memoryHeld().bytes).toBeLessThanOrEqual(40_000);
  });

  it('a chain within its share is never chosen while one past it stands: the one past it gives way whole', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { capture, mostBytes: 40_000 });
    await log.read();
    log.record(THIRD, agents(300), START);
    log.record(OTHER, agents(300, 1000), START);
    log.record(CHAIN, agents(1000, 5000), START);
    expect(said(capture, 'audit.state_digest_chain_gave_way')).toEqual([
      expect.objectContaining({ orgId: ORG, what: 'chain' }),
    ]);
    // Given way whole, it reads as before the digest: no walk is owed it.
    expect(log.owed(CHAIN, 10n)).toBe(false);
    expect(log.owed(THIRD, 10n)).toBe(true);
    expect(log.latest(THIRD, 'agent', '0199a0f0-0000-7000-8000-000000010000')).toBe(1n);
    expect(log.latest(OTHER, 'agent', '0199a0f0-0000-7000-8000-0000000103e8')).toBe(1001n);
  });

  it('the platform chain’s session ends grow with use, and give way before its pause', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { capture, mostBytes: 12_000 });
    await log.read();
    log.record(PLATFORM, seen(['platform.handoff_pause', 'pause', 3n]), START);
    const ends = new Map(
      Array.from({ length: 400 }, (_, at) => [subjectKey('identity.session_ended', `p/${String(at)}`), BigInt(at + 4)]),
    );
    log.record(PLATFORM, ends, START);
    const [line, ...others] = said(capture, 'audit.state_digest_chain_gave_way');
    expect(others).toEqual([]);
    expect(line).toMatchObject({ what: 'session_ends' });
    expect(line?.orgId).toBeUndefined();
    expect(log.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(3n);
    expect(log.latest(PLATFORM, 'identity.session_ended', 'p/0')).toBeUndefined();
  });
});

describe('a chain given way comes back once there is room again (AT13e)', () => {
  /** A chain whose payments gave way under 12 KB, written: coverage to 600, its agent at 3, its requests let go. */
  async function gaveWay() {
    const time = clock();
    const { log, fake } = digestOn(undefined, { time, mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 4n));
    log.record(CHAIN, requests(400), START, stretch(4n, 600n));
    expect(log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBeUndefined();
    await log.flush();
    return { fake, time };
  }

  /** A restart with `mostBytes` (room for it again, unless said). */
  async function restartedWith(
    fake: ReturnType<typeof createFakeWriteOnceStore>,
    time: ReturnType<typeof clock>,
    mostBytes = 1024 * 1024,
  ) {
    const capture = new LogCapture();
    const restarted = digestOn(fake, { time, capture, mostBytes });
    await restarted.log.read();
    return { log: restarted.log, capture };
  }

  it('an hour after it gave way, with room, its catch-up walk reads it again from its first event; no wait meanwhile', async () => {
    const { fake, time } = await gaveWay();
    const { log, capture } = await restartedWith(fake, time);
    // Within the hour it stays given way, though there is room: it never flaps.
    log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    log.record(CHAIN, requests(1, 2000), time.now());
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-0000000007d0')).toBeUndefined();
    expect(log.owed(CHAIN, 600n)).toBe(false);
    expect(said(capture, 'audit.state_digest_chain_coming_back')).toEqual([]);

    time.held.at += HOUR;
    log.record(OTHER, seen(['agent', AGENT, 3n]), time.now());
    expect(said(capture, 'audit.state_digest_chain_coming_back')).toEqual([
      expect.objectContaining({ level: 'info', orgId: ORG, was: 'payments' }),
    ]);
    // Coming back: read as given way (no wait, today's checks), its coverage from nothing, a walk from its first event owed.
    expect(log.covers(CHAIN, 600n)).toBe(true);
    expect(log.coverage(CHAIN)).toBeUndefined();
    expect(log.owed(CHAIN, 600n)).toBe(true);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    log.record(CHAIN, requests(1, 3000), time.now());
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-000000000bb8')).toBe(3001n);

    // The catch-up walk reaches the anchor: back, every fact held, and Tx A held to its coverage as ever.
    log.record(CHAIN, new Map([...requests(400), ...seen(['agent', AGENT, 3n])]), time.now(), stretch(0n, 600n));
    expect(log.owed(CHAIN, 600n)).toBe(false);
    expect(log.covers(CHAIN, 600n)).toBe(true);
    expect(said(capture, 'audit.state_digest_chain_back')).toEqual([expect.objectContaining({ orgId: ORG })]);
    expect(log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBe(1n);
    expect(log.covers(CHAIN, 700n)).toBe(false);
    expect(log.owed(CHAIN, 700n)).toBe(true);

    // A restart agrees: back, covered, the requests held, from the deltas alone as from a snapshot.
    time.held.at += 10 * MINUTE;
    await log.flush();
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);
    const again = await restartedWith(fake, time);
    // Back as written, not coming back: past its coverage it waits, as any chain does.
    expect(again.log.covers(CHAIN, 700n)).toBe(false);
    expect(again.log.covers(CHAIN, 600n)).toBe(true);
    expect(again.log.owed(CHAIN, 600n)).toBe(false);
    expect(again.log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBe(1n);
    expect(said(again.capture, 'audit.state_digest_chain_gave_way')).toEqual([]);
  });

  it('a restart while it comes back holds it so: no wait, no stretch from before it, the walk still owed', async () => {
    const { fake, time } = await gaveWay();
    const first = await restartedWith(fake, time);
    time.held.at += HOUR;
    first.log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    first.log.record(CHAIN, requests(1, 3000), time.now());
    expect(first.log.owed(CHAIN, 600n)).toBe(true);
    time.held.at += 10 * MINUTE;
    await first.log.flush();
    // Every delta read, the oldest (the stretches from before, its give-way) after the newest: still not standing.
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);

    const { log, capture } = await restartedWith(fake, time);
    expect(log.covers(CHAIN, 600n)).toBe(true);
    expect(log.coverage(CHAIN)).toBeUndefined();
    expect(log.owed(CHAIN, 600n)).toBe(true);
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-000000000bb8')).toBe(3001n);
    expect(said(capture, 'audit.state_digest_chain_gave_way')).toEqual([]);
    // A walk from the anchor alone, not from the first event: kept beyond the gap, never standing for the chain.
    log.record(CHAIN, new Map(), time.now(), stretch(600n, 650n));
    expect(log.owed(CHAIN, 650n)).toBe(true);
    log.record(CHAIN, new Map(), time.now(), stretch(0n, 600n));
    expect(log.owed(CHAIN, 650n)).toBe(false);
    expect(log.covers(CHAIN, 650n)).toBe(true);
    expect(log.covers(CHAIN, 651n)).toBe(false);
  });

  it('where what it let go doesn’t fit under half, it never comes back, however long', async () => {
    const capture = new LogCapture();
    const time = clock();
    const { log } = digestOn(undefined, { time, capture, mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, requests(400), START, stretch(0n, 400n));
    time.held.at += 5 * HOUR;
    log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    expect(said(capture, 'audit.state_digest_chain_coming_back')).toEqual([]);
    expect(log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBeUndefined();
  });

  it('given way again while it comes back: read as given way, and coming back anew later its earlier walk stands for nothing', async () => {
    const { fake, time } = await gaveWay();
    const middle = await restartedWith(fake, time, 40_000);
    time.held.at += HOUR;
    middle.log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    expect(said(middle.capture, 'audit.state_digest_chain_coming_back')).toHaveLength(1);
    // Its catch-up walk brings more than there is room for: its payments give way again, still coming back.
    middle.log.record(CHAIN, requests(1600), time.now(), stretch(0n, 600n));
    expect(said(middle.capture, 'audit.state_digest_chain_gave_way')).toHaveLength(2);
    expect(middle.log.covers(CHAIN, 600n)).toBe(true);
    expect(middle.log.covers(CHAIN, 99_999n)).toBe(true);
    expect(middle.log.owed(CHAIN, 600n)).toBe(false);
    expect(said(middle.capture, 'audit.state_digest_chain_back')).toEqual([]);
    time.held.at += 10 * MINUTE;
    await middle.log.flush();

    const { log, capture } = await restartedWith(fake, time);
    expect(log.covers(CHAIN, 99_999n)).toBe(true);
    time.held.at += HOUR;
    log.record(OTHER, seen(['agent', AGENT, 3n]), time.now());
    expect(said(capture, 'audit.state_digest_chain_coming_back')).toHaveLength(1);
    expect(log.coverage(CHAIN)).toBeUndefined();
    expect(log.owed(CHAIN, 600n)).toBe(true);
    expect(log.covers(CHAIN, 600n)).toBe(true);
    time.held.at += 10 * MINUTE;
    await log.flush();
    const last = await restartedWith(fake, time);
    expect(last.log.covers(CHAIN, 600n)).toBe(true);
    expect(last.log.owed(CHAIN, 600n)).toBe(true);
  });
});

describe('the digest’s mark lines, read (AT13e)', () => {
  it('a line naming what was let go but not how far is no line of ours; a generation alone is', async () => {
    const { fake, time, capture } = digestOn();
    const at = (minutes: number) => String(9_999_999_999_999 - (START.getTime() + minutes * MINUTE)).padStart(13, '0');
    const named = (minutes: number, id: string) => `e1/digests/deltas/${at(minutes)}-${id}`;
    const bad = named(1, '0199a0f0-0000-7000-8000-00000000f001');
    const good = named(2, '0199a0f0-0000-7000-8000-00000000f002');
    const chain = `organisation:${ORG}`;
    fake.files.set(bad, closedFile(bad, [JSON.stringify({ c: chain, t: START.toISOString(), n: 3, b: 5 })]));
    fake.files.set(good, closedFile(good, [JSON.stringify({ c: chain, t: START.toISOString(), n: 1 })]));
    time.held.at += 6 * MINUTE;
    const restarted = digestOn(fake, { time, capture });
    await restarted.log.read();
    expect(said(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file' })]);
    // Coming back, as the generation says: read as given way, a walk owed.
    expect(restarted.log.covers(CHAIN, 9n)).toBe(true);
    expect(restarted.log.owed(CHAIN, 9n)).toBe(true);
    expect(restarted.log.owed(CHAIN, 0n)).toBe(false);
  });

  it('a stretch from before a newer generation, read first (a late delta of a copy that lost the lease), stands for nothing', async () => {
    const { fake, time } = digestOn();
    const at = (minutes: number) => String(9_999_999_999_999 - (START.getTime() + minutes * MINUTE)).padStart(13, '0');
    const named = (minutes: number, id: string) => `e1/digests/deltas/${at(minutes)}-${id}`;
    const late = named(2, '0199a0f0-0000-7000-8000-00000000f002');
    const mark = named(1, '0199a0f0-0000-7000-8000-00000000f001');
    const chain = `organisation:${ORG}`;
    const hash = Buffer.alloc(32, 600 % 200).toString('hex');
    // Named later, so read first: a walk's stretch from before the chain began coming back.
    fake.files.set(
      late,
      closedFile(late, [JSON.stringify({ c: chain, t: START.toISOString(), f: '0', u: '600', h: hash, k: 1 })]),
    );
    fake.files.set(mark, closedFile(mark, [JSON.stringify({ c: chain, t: START.toISOString(), n: 1 })]));
    time.held.at += 6 * MINUTE;
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.coverage(CHAIN)).toBeUndefined();
    expect(restarted.log.owed(CHAIN, 600n)).toBe(true);
  });
});

describe('a request’s facts forgotten past the approval horizon (AT13d)', () => {
  const DAY = 24 * HOUR;
  /** The approval horizon, as the API passes it (APPROVAL_HORIZON_MS). */
  const HORIZON = 7 * DAY;
  /** When a fact known by START may go: the horizon and the day's margin past it. */
  const GOES = START.getTime() + HORIZON + DAY;
  const REQUEST = '0199a0f0-0000-7000-8000-0000000000c1';
  const NEWER = '0199a0f0-0000-7000-8000-0000000000c2';
  const INSTRUCTION = '0199a0f0-0000-7000-8000-0000000000d1';
  const TRANSACTION = '0199a0f0-0000-7000-8000-0000000000e1';
  const PROPOSAL = '0199a0f0-0000-7000-8000-0000000000f1';
  const REMITTANCE = '0199a0f0-0000-7000-8000-0000000000f2';

  /** One of each of a payment's objects, an agent, and the chain read whole to 9. */
  const recordEach = (log: ReturnType<typeof digestOn>['log']) => {
    log.record(
      CHAIN,
      seen(
        ['agent', AGENT, 2n],
        ['spend_request', REQUEST, 4n],
        ['instruction', INSTRUCTION, 5n],
        ['transaction', TRANSACTION, 6n],
        ['failure_proposal', PROPOSAL, 7n],
        ['supplier_remittance', REMITTANCE, 8n],
      ),
      START,
      stretch(0n, 9n),
    );
  };

  /** The places it holds for each object recordEach recorded, in its order. */
  const held = (log: ReturnType<typeof digestOn>['log']) => [
    log.latest(CHAIN, 'agent', AGENT),
    log.latest(CHAIN, 'spend_request', REQUEST),
    log.latest(CHAIN, 'instruction', INSTRUCTION),
    log.latest(CHAIN, 'transaction', TRANSACTION),
    log.latest(CHAIN, 'failure_proposal', PROPOSAL),
    log.latest(CHAIN, 'supplier_remittance', REMITTANCE),
  ];

  it('lets a request’s go once its day is a day past the horizon: every other object kept, coverage untouched', async () => {
    const capture = new LogCapture();
    const { log, time } = digestOn(undefined, { forget: HORIZON, capture });
    await log.read();
    recordEach(log);
    const before = log.memoryHeld();
    expect(held(log)).toEqual([2n, 4n, 5n, 6n, 7n, 8n]);

    // A minute short of the horizon and its margin: kept.
    time.held.at = GOES - MINUTE;
    log.record(OTHER, seen(['agent', AGENT, 1n]), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(4n);

    time.held.at = GOES + HOUR;
    log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    expect(held(log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);
    expect(log.covers(CHAIN, 9n)).toBe(true);
    expect(log.coverage(CHAIN)).toEqual(point(9n));
    // One object gone from this chain, one agent come in the other's.
    const after = log.memoryHeld();
    expect(after).toMatchObject({ objects: before.objects, chains: 2 });
    expect(log.bytesHeld()).toBe(after.bytes);
    expect(said(capture, 'audit.state_digest_requests_forgotten')).toEqual([expect.objectContaining({ objects: 1 })]);
    expect(said(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('holds what it may less once they go: the memory a day’s table took is given back', async () => {
    const { log, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 1n]), START);
    const authority = log.memoryHeld().bytes;
    log.record(CHAIN, requests(500), START);
    expect(log.memoryHeld()).toMatchObject({ objects: 501 });
    expect(log.memoryHeld().bytes).toBeGreaterThan(authority + 500 * 16);
    time.held.at = GOES + HOUR;
    log.record(CHAIN, new Map(), time.now());
    expect(log.memoryHeld()).toMatchObject({ objects: 1, bytes: authority });
  });

  it('a request with a newer fact keeps it in its newer day’s table, the highest place standing until that goes too', async () => {
    const { log, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    log.record(CHAIN, seen(['spend_request', REQUEST, 3n], ['spend_request', NEWER, 4n]), START);
    time.held.at = START.getTime() + 5 * DAY;
    log.record(CHAIN, seen(['spend_request', REQUEST, 9n]), time.now());
    // The older day's lower place doesn't hide the newer one.
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(9n);

    time.held.at = GOES + HOUR;
    log.record(CHAIN, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(9n);
    expect(log.latest(CHAIN, 'spend_request', NEWER)).toBeUndefined();

    time.held.at = GOES + 5 * DAY + HOUR;
    log.record(CHAIN, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBeUndefined();
  });

  it('looks them over at most hourly between reads: few loops over the chains', async () => {
    const { log, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    time.held.at = GOES - 10 * MINUTE;
    log.record(CHAIN, seen(['agent', AGENT, 1n]), time.now());
    // Recorded under the clock: known by now, its own day's table.
    log.record(CHAIN, new Map([[subjectKey('spend_request', REQUEST), 3n]]), START);
    time.held.at = GOES - 5 * MINUTE;
    log.record(CHAIN, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(3n);
  });

  it('keeps a day’s table until its latest fact is past the horizon, not its first', async () => {
    const { log, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    log.record(CHAIN, seen(['spend_request', REQUEST, 4n]), START);
    // Later the same day: the same day's table, known by later.
    time.held.at = START.getTime() + 14 * HOUR;
    log.record(CHAIN, seen(['spend_request', NEWER, 5n]), time.now());
    time.held.at = GOES + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(4n);
    expect(log.latest(CHAIN, 'spend_request', NEWER)).toBe(5n);
    time.held.at = GOES + 15 * HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', NEWER)).toBeUndefined();
  });

  it('dates a request’s facts by when the walk recorded them, never by when it began: a long walk errs on keeping', async () => {
    const { log, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    time.held.at = START.getTime() + 3 * DAY;
    // A walk begun three days before it recorded what it read.
    log.record(CHAIN, seen(['spend_request', REQUEST, 4n]), START);
    time.held.at = GOES + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(4n);
    time.held.at = GOES + 3 * DAY + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBeUndefined();
  });

  it('lets go at once what a read took in past the horizon, though it looked them over within the hour', async () => {
    const fake = createFakeWriteOnceStore();
    const writer = digestOn(fake, { forget: HORIZON });
    await writer.log.read();
    recordEach(writer.log);
    await writer.log.flush();
    const time = clock(GOES + HOUR);
    const reader = digestOn(fake, { time, forget: HORIZON });
    reader.log.record(OTHER, seen(['agent', AGENT, 1n]), time.now());
    time.held.at += 10 * MINUTE;
    await reader.log.read();
    expect(held(reader.log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);
  });

  it('a restart agrees with memory: dated as written, never by the start; a snapshot holds only what memory does', async () => {
    const { log, fake, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    recordEach(log);
    await log.flush();
    const early = namesUnder(fake.files, 'snapshots');
    expect(early).toHaveLength(1);

    // A start an hour on reads it back, dated by when it was known, not by the start.
    time.held.at = START.getTime() + HOUR;
    const soon = digestOn(fake, { time, forget: HORIZON });
    await soon.log.read();
    expect(held(soon.log)).toEqual([2n, 4n, 5n, 6n, 7n, 8n]);
    time.held.at = GOES + HOUR;
    soon.log.record(CHAIN, new Map(), time.now());
    expect(held(soon.log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);

    // The first process past the horizon too, its next snapshot without the request.
    log.record(OTHER, seen(['agent', AGENT, 1n]), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBeUndefined();
    await log.flush();
    const late = namesUnder(fake.files, 'snapshots').filter((name) => !early.includes(name));
    expect(late).toHaveLength(1);
    const lateLines = linesOf(fake.files.get(late[0] ?? '') ?? Buffer.alloc(0));
    expect(lateLines.some((line) => line.includes('"y"'))).toBe(false);

    // A start from the late snapshot, and one from the early snapshot alone, read the same.
    const fromLate = digestOn(fake, { time, forget: HORIZON });
    await fromLate.log.read();
    expect(held(fromLate.log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);
    expect(fromLate.log.covers(CHAIN, 9n)).toBe(true);
    for (const name of late) fake.files.delete(name);
    const fromEarly = digestOn(fake, { time, forget: HORIZON });
    await fromEarly.log.read();
    expect(held(fromEarly.log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);
    expect(fromEarly.log.covers(CHAIN, 9n)).toBe(true);
    expect(fromEarly.log.memoryHeld()).toMatchObject({ objects: 6 });
  });

  it('writes a request’s facts as payments’ lines with when they were known by: an image before reads them as kept', async () => {
    const { log, fake, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    recordEach(log);
    await log.flush();
    const [delta] = namesUnder(fake.files, 'deltas');
    const written = linesOf(fake.files.get(delta ?? '') ?? Buffer.alloc(0)).map((line) => JSON.parse(line) as object);
    expect(written).toContainEqual(expect.objectContaining({ p: 1, y: START.toISOString() }));

    // One that forgets nothing (as before AT13d) holds them as payments' facts, for good.
    time.held.at = GOES + DAY;
    const before = digestOn(fake, { time });
    await before.log.read();
    expect(held(before.log)).toEqual([2n, 4n, 5n, 6n, 7n, 8n]);
  });

  it('a payments’ line written before AT13d (no `y`) stays a payment’s fact for good', async () => {
    const { log, fake, time } = digestOn();
    await log.read();
    recordEach(log);
    await log.flush();
    time.held.at = GOES + DAY;
    const restarted = digestOn(fake, { time, forget: HORIZON });
    await restarted.log.read();
    expect(held(restarted.log)).toEqual([2n, 4n, 5n, 6n, 7n, 8n]);
  });

  it.each([
    ['on an authority line', { p: undefined, y: START.toISOString() }],
    ['not a time', { p: 1, y: 'yesterday' }],
    ['a time not written as ours', { p: 1, y: '2026-11-20T09:00:00Z' }],
  ])('a `y` %s is no line of ours: the file is the alarm', async (_what, fields) => {
    const { fake, time, capture } = digestOn();
    const at = String(9_999_999_999_999 - (START.getTime() + MINUTE)).padStart(13, '0');
    const name = `e1/digests/deltas/${at}-0199a0f0-0000-7000-8000-00000000f003`;
    const entry = Buffer.alloc(16);
    entry.writeUInt32BE(1, 0);
    entry.writeUInt32BE(2, 4);
    entry.writeBigUInt64BE(3n, 8);
    const line = { c: `organisation:${ORG}`, t: START.toISOString(), e: entry.toString('base64'), ...fields };
    fake.files.set(name, closedFile(name, [JSON.stringify(line)]));
    time.held.at += 6 * MINUTE;
    const restarted = digestOn(fake, { time, capture, forget: HORIZON });
    await restarted.log.read();
    expect(said(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file' })]);
  });

  it('a chain whose payments give way lets its requests’ days go with them, and keeps none after', async () => {
    const { log } = digestOn(undefined, { forget: HORIZON, mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 4n));
    log.record(CHAIN, requests(400), START, stretch(4n, 500n));
    expect(log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBeUndefined();
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(3n);
    expect(log.memoryHeld().bytes).toBeLessThanOrEqual(12_000);
    expect(log.bytesHeld()).toBe(log.memoryHeld().bytes);
    log.record(CHAIN, requests(1, 2000), START);
    expect(log.latest(CHAIN, 'spend_request', '0199a0f0-0000-7000-8000-0000000007d0')).toBeUndefined();
  });

  it('a write that fails keeps a request’s facts for the next with when they were known by', async () => {
    const { log, fake, time } = digestOn(undefined, { forget: HORIZON });
    await log.read();
    fake.instead.put = () => Promise.reject(new Error('store away'));
    recordEach(log);
    await log.flush();
    delete fake.instead.put;
    time.held.at = START.getTime() + 2 * DAY;
    await log.flush();
    const [delta] = namesUnder(fake.files, 'deltas');
    const written = linesOf(fake.files.get(delta ?? '') ?? Buffer.alloc(0)).map((line) => JSON.parse(line) as object);
    expect(written).toContainEqual(expect.objectContaining({ p: 1, y: START.toISOString() }));
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);
    time.held.at = GOES + HOUR;
    const restarted = digestOn(fake, { time, forget: HORIZON });
    await restarted.log.read();
    expect(held(restarted.log)).toEqual([2n, undefined, 5n, 6n, 7n, 8n]);
  });
});

/** A head as a read finds it: its place and a hash of its own. */
const headAt = (seq: bigint, fill = Number(seq % 200n)) => ({ seq, hash: Buffer.alloc(32, fill) });

describe('the highest head each chain was read at (AT13f)', () => {
  it('holds nothing at first, then each head a read saw where higher, never lower, never a place before the first', async () => {
    const { log } = digestOn();
    await log.read();
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    log.heads(CHAIN)?.saw(headAt(0n));
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    log.heads(CHAIN)?.saw(headAt(7n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(7n));
    log.heads(CHAIN)?.saw(headAt(5n));
    log.heads(CHAIN)?.saw(headAt(7n, 99));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(7n));
    log.heads(CHAIN)?.saw(headAt(9n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    // Each chain its own; nothing said of one never read.
    expect(log.heads(OTHER)?.seen).toBeUndefined();
  });

  it('keeps what it was given as it was: a hash changed after by its giver changes nothing held', async () => {
    const { log } = digestOn();
    await log.read();
    const found = headAt(4n);
    log.heads(CHAIN)?.saw(found);
    found.hash.fill(0);
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(4n));
  });

  it('a watch holds what was seen when it was asked: a head raised since is the next read’s to hold to', async () => {
    const { log } = digestOn();
    await log.read();
    log.heads(CHAIN)?.saw(headAt(3n));
    const asked = log.heads(CHAIN);
    log.heads(CHAIN)?.saw(headAt(8n));
    expect(asked?.seen).toEqual(headAt(3n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(8n));
  });

  it('a rebase after the read that saw a head sets it aside; a head a read asked before a rebase found is never kept', async () => {
    const rebases = new Map<string, Date>();
    const time = clock();
    const { log } = digestOn(undefined, { time, anchors: anchorsWith(rebases) });
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    const before = log.bytesHeld();
    const askedBefore = log.heads(CHAIN);
    time.held.at += MINUTE;
    rebases.set(ORG, new Date(START.getTime() + 30_000));
    // Wound back by the operator, then rebased: what was seen before no longer holds.
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    expect(log.bytesHeld()).toBe(before - 200);
    // A read asked before the rebase may have read the chain as it was: what it found is not kept.
    askedBefore?.saw(headAt(12n));
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    // One asked after it is.
    log.heads(CHAIN)?.saw(headAt(4n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(4n));
    // And a late answer to the read asked before never replaces it: the head seen since the rebase stands.
    askedBefore?.saw(headAt(12n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(4n));
    // Another chain's rebase moves nothing here.
    log.heads(OTHER)?.saw(headAt(6n));
    rebases.set(ORG, new Date(START.getTime() + 2 * MINUTE));
    expect(log.heads(OTHER)?.seen).toEqual(headAt(6n));
  });

  it('says nothing for a chain whose shard is let go; a copy that doesn’t lead keeps the heads and raises them (TR-1 A)', () => {
    const letGo = new Set<string>([OTHER_ORG]);
    const leads = { now: true };
    const log = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      anchors: anchorsWith(new Map(), letGo),
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    expect(log.heads(OTHER)).toBeUndefined();
    const asked = log.heads(CHAIN);
    asked?.saw(headAt(5n));
    expect(log.bytesHeld()).toBe(200);
    leads.now = false;
    // The lease gone, even for a moment: the head seen is still held to, so a cut back below it is still the alarm.
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(5n));
    // A read asked while it led and answered after raises it all the same.
    asked?.saw(headAt(6n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(6n));
    expect(log.heads(OTHER)).toBeUndefined();
    leads.now = true;
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(6n));
    expect(log.bytesHeld()).toBe(200);
  });

  it('holds to where the digest covers the chain too, a walk’s head under an anchor: the higher of the two', async () => {
    const { log } = digestOn();
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 6n));
    expect(log.heads(CHAIN)?.seen).toEqual({ seq: 6n, hash: point(6n).hash });
    log.heads(CHAIN)?.saw(headAt(4n));
    expect(log.heads(CHAIN)?.seen).toEqual({ seq: 6n, hash: point(6n).hash });
    log.heads(CHAIN)?.saw(headAt(10n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(10n));
    log.record(CHAIN, new Map(), START, stretch(6n, 14n));
    expect(log.heads(CHAIN)?.seen).toEqual({ seq: 14n, hash: point(14n).hash });
    // A stretch beyond a gap is no coverage: never held to.
    log.record(OTHER, new Map(), START, stretch(5n, 9n));
    expect(log.heads(OTHER)?.seen).toBeUndefined();
  });

  it('a restart holds the chain to where its walks covered it, read back from the store, and to nothing seen above it', async () => {
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const { log } = digestOn(fake, { time });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 6n));
    log.heads(CHAIN)?.saw(headAt(11n));
    await log.flush();
    time.held.at += MINUTE;
    const restarted = digestOn(fake, { time });
    // Until read, nothing covered: nothing to hold to.
    expect(restarted.log.heads(CHAIN)?.seen).toBeUndefined();
    await restarted.log.read();
    expect(restarted.log.heads(CHAIN)?.seen).toEqual({ seq: 6n, hash: point(6n).hash });
  });

  it('a chain given way whole is held to no coverage: it reads as before the digest', async () => {
    const { log } = digestOn(undefined, { mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, agents(600), START, stretch(0n, 600n));
    // Given way whole (all of it authority): Tx A goes on today's checks, and no coverage is held to.
    expect(log.covers(CHAIN, 600n)).toBe(true);
    expect(log.latest(CHAIN, 'agent', '0199a0f0-0000-7000-8000-000000010000')).toBeUndefined();
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
  });

  it('a chain whose payments gave way keeps its coverage held to; coming back, none until its walk is back', async () => {
    const time = clock();
    const { log, fake } = digestOn(undefined, { time, mostBytes: 12_000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 4n));
    log.record(CHAIN, requests(400), START, stretch(4n, 600n));
    expect(log.latest(CHAIN, 'spend_request', FIRST_REQUEST)).toBeUndefined();
    expect(log.heads(CHAIN)?.seen).toEqual({ seq: 600n, hash: point(600n).hash });
    await log.flush();
    // Restarted with room: still given way its first hour, its coverage held to as before.
    const restarted = digestOn(fake, { time, mostBytes: 1024 * 1024 });
    await restarted.log.read();
    expect(restarted.log.heads(CHAIN)?.seen).toEqual({ seq: 600n, hash: point(600n).hash });
    // An hour on it comes back, its coverage from nothing, so nothing to hold to meanwhile.
    time.held.at += HOUR;
    restarted.log.record(OTHER, seen(['agent', AGENT, 2n]), time.now());
    expect(restarted.log.owed(CHAIN, 600n)).toBe(true);
    restarted.log.record(CHAIN, seen(['agent', AGENT, 3n]), time.now(), stretch(0n, 600n));
    expect(restarted.log.heads(CHAIN)?.seen).toBeUndefined();
    // Back once asked of the anchor its walk reached: held to its coverage again.
    expect(restarted.log.owed(CHAIN, 600n)).toBe(false);
    expect(restarted.log.heads(CHAIN)?.seen).toEqual({ seq: 600n, hash: point(600n).hash });
  });

  it('takes a tenth of what may be held at most, the head raised longest ago going first, counted as it goes', async () => {
    // A tenth of 4,000 bytes: two heads of 200.
    const { log } = digestOn(undefined, { mostBytes: 4000 });
    await log.read();
    log.heads(CHAIN)?.saw(headAt(1n));
    log.heads(OTHER)?.saw(headAt(2n));
    // Raised again: now the latest raised, so the other goes first.
    log.heads(CHAIN)?.saw(headAt(3n));
    log.heads(THIRD)?.saw(headAt(4n));
    expect(log.heads(OTHER)?.seen).toBeUndefined();
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(3n));
    expect(log.heads(THIRD)?.seen).toEqual(headAt(4n));
    expect(log.bytesHeld()).toBe(400);
    expect(log.memoryHeld().bytes).toBe(400);
  });
});

describe('a chain taken as it stands after a signed answer to its cut (AT13h, S208: accept)', () => {
  it('nothing taken at first; once taken, held to where it was taken, the head seen never lowered', async () => {
    const { log } = digestOn();
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    const before = log.bytesHeld();
    log.heads(CHAIN)?.accept(headAt(6n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(6n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    expect(log.bytesHeld()).toBe(before + 200);
    // Taken again (the answer cut off and answered again): lower still, counted once.
    log.heads(CHAIN)?.accept(headAt(5n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(5n));
    expect(log.bytesHeld()).toBe(before + 200);
    // Each chain its own.
    expect(log.heads(OTHER)?.accepted).toBeUndefined();
  });

  it('its own reads raise it alone; a write or a read held to the head seen raises both', async () => {
    const { log } = digestOn();
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    log.heads(CHAIN)?.accept(headAt(6n));
    // A write this copy committed (or a read held to the head seen), below the head seen: raises where it was taken.
    log.heads(CHAIN)?.saw(headAt(7n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(7n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    log.heads(CHAIN)?.accepted?.saw(headAt(8n));
    log.heads(CHAIN)?.accepted?.saw(headAt(7n, 77));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(8n));
    log.heads(CHAIN)?.accepted?.saw(headAt(12n));
    // Past the head seen, its own reads still leave that alone: the other reads stay held where they were.
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(12n));
  });

  it('only over the head seen when the watch was asked, while it still is; none where the watch gave none', async () => {
    const { log } = digestOn();
    await log.read();
    // A watch that gave no head seen takes nothing.
    log.heads(CHAIN)?.accept(headAt(3n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    log.heads(CHAIN)?.saw(headAt(9n));
    const asked = log.heads(CHAIN);
    log.heads(CHAIN)?.saw(headAt(10n));
    // The head seen moved on since the watch was asked: it is not the head the answer was to.
    asked?.accept(headAt(6n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    // A place before the first is no head.
    log.heads(CHAIN)?.accept(headAt(0n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
  });

  it('never taken over a head seen that has moved on, though the head seen falls back to it after (a head let go)', async () => {
    // A tenth of 4,000 bytes: two heads of 200.
    const { log } = digestOn(undefined, { mostBytes: 4000 });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 3n]), START, stretch(0n, 6n));
    const asked = log.heads(CHAIN);
    expect(asked?.seen).toEqual({ seq: 6n, hash: point(6n).hash });
    log.heads(CHAIN)?.saw(headAt(10n));
    asked?.accept(headAt(3n));
    // The head seen here let go for others: held to where the walks cover it again, the head the watch gave.
    log.heads(OTHER)?.saw(headAt(2n));
    log.heads(THIRD)?.saw(headAt(4n));
    expect(log.heads(CHAIN)?.seen).toEqual({ seq: 6n, hash: point(6n).hash });
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
  });

  it('never raised by a watch asked before the read that found the cut: it may have read the chain before the cut', async () => {
    const time = clock();
    const { log } = digestOn(undefined, { time });
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    const stale = log.heads(CHAIN);
    time.held.at += MINUTE;
    log.heads(CHAIN)?.accept(headAt(6n));
    stale?.saw(headAt(9n, 3));
    stale?.accepted?.saw(headAt(9n, 3));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(6n));
    log.heads(CHAIN)?.saw(headAt(7n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(7n));
  });

  it('a write raises only the heads its chain ran through as it wrote (heldThrough, raiseWritten)', async () => {
    expect(heldThrough([], null)).toBe(true);
    expect(heldThrough([headAt(4n)], [Buffer.from(headAt(4n).hash)])).toBe(true);
    expect(heldThrough([headAt(4n)], [headAt(4n, 9).hash])).toBe(false);
    expect(heldThrough([headAt(4n)], [null])).toBe(false);
    expect(heldThrough([headAt(4n)], null)).toBe(false);
    // Every head held to, each at its place (TR-1): one missing is enough.
    expect(heldThrough([headAt(4n), headAt(6n)], [headAt(4n).hash, headAt(6n).hash])).toBe(true);
    expect(heldThrough([headAt(4n), headAt(6n)], [headAt(4n).hash, null])).toBe(false);
    const { log } = digestOn();
    await log.read();
    const watch = () => {
      const asked = log.heads(CHAIN);
      if (asked === undefined) throw new Error('no watch');
      return asked;
    };
    log.heads(CHAIN)?.saw(headAt(9n));
    // Ran through neither, or only the head seen with a head taken it didn't run through: nothing.
    raiseWritten(watch(), headAt(12n), { seen: false, accepted: true });
    raiseWritten(watch(), headAt(12n), { seen: true, accepted: false });
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    log.heads(CHAIN)?.accept(headAt(6n));
    // Through the head taken alone (a write after the answer, on the chain as cut): that alone.
    raiseWritten(watch(), headAt(7n), { seen: false, accepted: true });
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(7n));
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    raiseWritten(watch(), headAt(8n), { seen: false, accepted: false });
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(7n));
    // Through both: both.
    raiseWritten(watch(), headAt(12n), { seen: true, accepted: true });
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(12n));
  });

  it('set aside once the head seen moves past the head it was taken over, its memory given back', async () => {
    const { log } = digestOn();
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    const before = log.bytesHeld();
    log.heads(CHAIN)?.accept(headAt(6n));
    log.heads(CHAIN)?.saw(headAt(11n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(11n));
    expect(log.bytesHeld()).toBe(before);
  });

  it('a rebase after it was taken sets it aside; one asked before a rebase takes nothing and raises nothing', async () => {
    const rebases = new Map<string, Date>();
    const time = clock();
    const { log } = digestOn(undefined, { time, anchors: anchorsWith(rebases) });
    await log.read();
    log.heads(CHAIN)?.saw(headAt(9n));
    log.heads(CHAIN)?.accept(headAt(6n));
    const askedBefore = log.heads(CHAIN);
    time.held.at += MINUTE;
    rebases.set(ORG, new Date(START.getTime() + 30_000));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    expect(log.bytesHeld()).toBe(0);
    askedBefore?.accept(headAt(5n));
    expect(log.heads(CHAIN)?.accepted).toBeUndefined();
    // Raised by a read asked before the rebase: not kept, though taken again after it.
    log.heads(CHAIN)?.saw(headAt(4n));
    log.heads(CHAIN)?.accept(headAt(3n));
    askedBefore?.saw(headAt(8n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(3n));
  });

  it('kept with the heads by a copy that stops leading, and raised while it doesn’t (TR-1 A)', () => {
    const leads = { now: true };
    const log = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      writes: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    log.heads(CHAIN)?.saw(headAt(9n));
    const asked = log.heads(CHAIN);
    asked?.accept(headAt(6n));
    expect(log.bytesHeld()).toBe(400);
    leads.now = false;
    // The head seen stays held to by every other read; the chain taken as it stands stays so for the sessions' reads.
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(9n));
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(6n));
    log.heads(CHAIN)?.accepted?.saw(headAt(7n));
    leads.now = true;
    expect(log.heads(CHAIN)?.accepted?.seen).toEqual(headAt(7n));
    expect(log.bytesHeld()).toBe(400);
  });
});

/** A delta's name for `at`, as the digest names its files. */
const deltaNamed = (at: Date) =>
  `e1/digests/deltas/${String(9_999_999_999_999 - at.getTime()).padStart(13, '0')}-0199a0f0-0000-7000-8000-000000000001`;

/** One entry, packed as a line carries it. */
const oneEntry = (place: bigint): string => {
  const entry = Buffer.alloc(16);
  entry.writeUInt32BE(1, 0);
  entry.writeUInt32BE(2, 4);
  entry.writeBigUInt64BE(place, 8);
  return entry.toString('base64');
};

describe('a head read held to the heads held to (AT13f, AT13h, TR-1: headHeldTo, headCutBelow)', () => {
  const at = (seq: bigint, byte: number) => ({ seq, hash: Buffer.alloc(32, byte) });
  const seen = [at(5n, 5)];

  it('nothing held to holds anything, a head or none', () => {
    expect(headHeldTo([], undefined, null)).toBe(true);
    expect(headHeldTo([], at(1n, 1), null)).toBe(true);
  });

  it('a head at the seen place with its hash, or past it with the same event there, holds', () => {
    expect(headHeldTo(seen, at(5n, 5), [Buffer.alloc(32, 5)])).toBe(true);
    expect(headHeldTo(seen, at(9n, 9), [Buffer.alloc(32, 5)])).toBe(true);
  });

  it('none, below, another hash at the seen place, or another event there: cut back', () => {
    expect(headHeldTo(seen, undefined, [Buffer.alloc(32, 5)])).toBe(false);
    expect(headHeldTo(seen, at(4n, 4), [Buffer.alloc(32, 5)])).toBe(false);
    expect(headHeldTo(seen, at(5n, 6), [Buffer.alloc(32, 5)])).toBe(false);
    expect(headHeldTo(seen, at(9n, 9), [Buffer.alloc(32, 6)])).toBe(false);
    expect(headHeldTo(seen, at(9n, 9), [null])).toBe(false);
    expect(headHeldTo(seen, at(9n, 9), null)).toBe(false);
    expect(headHeldTo(seen, at(9n, 9), 'not a hash')).toBe(false);
  });

  it('two copies’ heads held to apart (TR-1): the honest 105 is not buried by a stale copy’s 106 on a cut branch', () => {
    const honest = at(105n, 1);
    const stale = at(106n, 2);
    const heldTo = [stale, honest];
    // The owner cut to 100; the stale copy wrote 101'–106'; the original row 105 put back at 105: one row each reads
    // true, but 105's place holds the stale branch's event (the hash read there is the cut branch's).
    expect(headCutBelow(heldTo, at(106n, 2), [stale.hash, at(105n, 9).hash])).toEqual(honest);
    expect(headCutBelow(heldTo, at(106n, 2), [stale.hash, honest.hash])).toBeUndefined();
    // Highest-only would have held to 106' alone, and passed the first (the control below shows it does).
    expect(headCutBelow([stale], at(106n, 2), [stale.hash])).toBeUndefined();
    // Below the highest: cut below it, whatever is at the others' places.
    expect(headCutBelow(heldTo, at(105n, 1), [null, honest.hash])).toEqual(stale);
    expect(placesOf(heldTo)).toEqual(['106', '105']);
  });
});

describe('the heads a read is held to (TR-1: heldTo, the witnessed heads)', () => {
  const witnessedHeads = new Map<string, { seq: bigint; hash: Buffer; at: number }[]>();
  const witnessedLog = (anchors = anchorsWith()) =>
    createDigestLog({
      keys,
      logger: testLogger(),
      now: () => START,
      epoch: 1,
      anchors,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
      witnessed: (chain) => witnessedHeads.get(chain.kind === 'platform' ? 'platform' : chain.orgId) ?? [],
    });

  it('holds a read to its own head seen and the highest witnessed heads, each once, at most MOST_WITNESSED of them', () => {
    const log = witnessedLog();
    const many = Array.from({ length: MOST_WITNESSED + 3 }, (_, at) => ({
      seq: BigInt(30 - at),
      hash: Buffer.alloc(32, at + 1),
      at: START.getTime(),
    }));
    witnessedHeads.set(ORG, many);
    log.heads(CHAIN)?.saw(headAt(4n));
    const heldTo = log.heads(CHAIN)?.heldTo ?? [];
    expect(heldTo[0]).toEqual(headAt(4n));
    expect(heldTo.slice(1).map(({ seq }) => seq)).toEqual(many.slice(0, MOST_WITNESSED).map(({ seq }) => seq));
    // The head seen stays this process's own: the witnessed heads are held to, never raised into it.
    expect(log.heads(CHAIN)?.seen).toEqual(headAt(4n));
    // Seen and witnessed alike, it is held to once.
    witnessedHeads.set(ORG, [{ ...headAt(4n), at: START.getTime() }]);
    expect(log.heads(CHAIN)?.heldTo).toEqual([headAt(4n)]);
    witnessedHeads.clear();
  });

  it('a chain taken as it stands holds its reads to witnessed heads noted after it alone, never those before', () => {
    const log = witnessedLog();
    const before = { seq: 9n, hash: Buffer.alloc(32, 9), at: START.getTime() - 1 };
    const after = { seq: 12n, hash: Buffer.alloc(32, 12), at: START.getTime() + 2 * MINUTE };
    // Held to a witnessed head alone (no head seen here): the cut found there may still be answered and taken.
    witnessedHeads.set(ORG, [before]);
    expect(log.heads(CHAIN)?.seen).toBeUndefined();
    log.heads(CHAIN)?.accept(headAt(6n));
    expect(log.heads(CHAIN)?.accepted?.heldTo).toEqual([headAt(6n)]);
    // A head witnessed after the accept (past the margin) holds the accepted reads; the one before never again.
    witnessedHeads.set(ORG, [after, before]);
    expect(log.heads(CHAIN)?.accepted?.heldTo).toEqual([headAt(6n), { seq: after.seq, hash: after.hash }]);
    // Every other read stays held to everything witnessed.
    expect(log.heads(CHAIN)?.heldTo.map(({ seq }) => seq)).toEqual([12n, 9n]);
    witnessedHeads.clear();
    // Held to nothing at all, a chain is never taken as it stands.
    const fresh = witnessedLog();
    fresh.heads(OTHER)?.accept(headAt(6n));
    expect(fresh.heads(OTHER)?.accepted).toBeUndefined();
  });
});

describe('the platform chain’s session ends forgotten past the longest session (AT13g)', () => {
  const DAY = 24 * HOUR;
  /** The longest absolute timeout there can be, as the API passes it (LONGEST_ABSOLUTE_SECONDS). */
  const LONGEST = DAY;
  /** When a fact known by START may go: the longest session and the day's margin past it. */
  const GOES = START.getTime() + LONGEST + DAY;
  const PERSON = '0199a0f0-0000-7000-8000-00000000aa01';
  const RECORD = '0199a0f0-0000-7000-8000-00000000bb01';
  const ENDED = `${PERSON}:${RECORD}`;
  const ROTATED = `${PERSON}:${RECORD}:${'ab'.repeat(32)}`;
  const REQUEST = '0199a0f0-0000-7000-8000-0000000000c1';

  /** A sign-out, a rotation, a person's sessions all ended and the hand-off pause, the platform chain read whole to 9. */
  const recordEach = (log: ReturnType<typeof digestOn>['log']) => {
    log.record(
      PLATFORM,
      seen(
        ['platform.handoff_pause', 'pause', 2n],
        ['identity.session_ended', ENDED, 4n],
        ['identity.session_rotated', ROTATED, 5n],
        ['identity.sessions_ended', PERSON, 6n],
      ),
      START,
      stretch(0n, 9n),
    );
  };

  /** The places it holds for each object recordEach recorded, in its order. */
  const held = (log: ReturnType<typeof digestOn>['log']) => [
    log.latest(PLATFORM, 'platform.handoff_pause', 'pause'),
    log.latest(PLATFORM, 'identity.session_ended', ENDED),
    log.latest(PLATFORM, 'identity.session_rotated', ROTATED),
    log.latest(PLATFORM, 'identity.sessions_ended', PERSON),
  ];

  it('lets them go a day past the longest session: the pause kept, coverage untouched, memory given back, said', async () => {
    const capture = new LogCapture();
    const { log, time } = digestOn(undefined, { forgetSessions: LONGEST, capture });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 1n]), START);
    log.record(PLATFORM, seen(['platform.handoff_pause', 'pause', 1n]), START);
    const authority = log.memoryHeld().bytes;
    recordEach(log);
    expect(held(log)).toEqual([2n, 4n, 5n, 6n]);
    expect(log.memoryHeld().bytes).toBeGreaterThan(authority);

    // A minute short of the longest session and its margin: kept.
    time.held.at = GOES - MINUTE;
    log.record(CHAIN, seen(['agent', AGENT, 2n]), time.now());
    expect(held(log)).toEqual([2n, 4n, 5n, 6n]);

    time.held.at = GOES + HOUR;
    log.record(CHAIN, seen(['agent', AGENT, 3n]), time.now());
    expect(held(log)).toEqual([2n, undefined, undefined, undefined]);
    expect(log.covers(PLATFORM, 9n)).toBe(true);
    expect(log.coverage(PLATFORM)).toEqual(point(9n));
    expect(log.memoryHeld()).toMatchObject({ objects: 2, chains: 2, bytes: authority });
    expect(log.bytesHeld()).toBe(log.memoryHeld().bytes);
    expect(said(capture, 'audit.state_digest_session_ends_forgotten')).toEqual([
      expect.objectContaining({ level: 'info', objects: 3 }),
    ]);
    expect(said(capture, 'audit.state_digest_requests_forgotten')).toEqual([]);
    expect(said(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('each chain by its own horizon: an organisation’s requests by the approval’s, the platform’s ends by the session’s', async () => {
    const { log, time } = digestOn(undefined, { forget: 7 * DAY, forgetSessions: LONGEST });
    await log.read();
    recordEach(log);
    log.record(CHAIN, seen(['spend_request', REQUEST, 3n], ['identity.session_ended', ENDED, 4n]), START);
    time.held.at = GOES + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(PLATFORM, 'identity.session_ended', ENDED)).toBeUndefined();
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBe(3n);
    // A session end's type on an organisation's chain is no session end: kept, as any other fact there.
    expect(log.latest(CHAIN, 'identity.session_ended', ENDED)).toBe(4n);
    time.held.at = START.getTime() + 8 * DAY + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(log.latest(CHAIN, 'spend_request', REQUEST)).toBeUndefined();
    expect(log.latest(CHAIN, 'identity.session_ended', ENDED)).toBe(4n);
  });

  it('with only the requests’ horizon given, the platform’s ends are kept for good; with only the session’s, requests are', async () => {
    const requestsOnly = digestOn(undefined, { forget: 7 * DAY });
    await requestsOnly.log.read();
    recordEach(requestsOnly.log);
    requestsOnly.time.held.at = START.getTime() + 30 * DAY;
    requestsOnly.log.record(OTHER, new Map(), requestsOnly.time.now());
    expect(held(requestsOnly.log)).toEqual([2n, 4n, 5n, 6n]);

    const sessionsOnly = digestOn(undefined, { forgetSessions: LONGEST });
    await sessionsOnly.log.read();
    sessionsOnly.log.record(CHAIN, seen(['spend_request', REQUEST, 3n]), START);
    sessionsOnly.time.held.at = START.getTime() + 30 * DAY;
    sessionsOnly.log.record(OTHER, new Map(), sessionsOnly.time.now());
    expect(sessionsOnly.log.latest(CHAIN, 'spend_request', REQUEST)).toBe(3n);
  });

  it('a newer end of a person’s, in a newer day, stands until that goes too', async () => {
    const { log, time } = digestOn(undefined, { forgetSessions: LONGEST });
    await log.read();
    log.record(PLATFORM, seen(['identity.sessions_ended', PERSON, 3n]), START);
    time.held.at = START.getTime() + DAY + HOUR;
    log.record(PLATFORM, seen(['identity.sessions_ended', PERSON, 8n]), time.now());
    expect(log.latest(PLATFORM, 'identity.sessions_ended', PERSON)).toBe(8n);
    time.held.at = GOES + HOUR;
    log.record(CHAIN, new Map(), time.now());
    expect(log.latest(PLATFORM, 'identity.sessions_ended', PERSON)).toBe(8n);
    time.held.at = GOES + DAY + 2 * HOUR;
    log.record(CHAIN, new Map(), time.now());
    expect(log.latest(PLATFORM, 'identity.sessions_ended', PERSON)).toBeUndefined();
  });

  it('writes them with `s` on the platform’s lines, `y` on an organisation’s; a restart agrees, before and after the horizon', async () => {
    const { log, fake, time } = digestOn(undefined, { forget: 7 * DAY, forgetSessions: LONGEST });
    await log.read();
    recordEach(log);
    log.record(CHAIN, seen(['spend_request', REQUEST, 3n]), START, stretch(0n, 3n));
    await log.flush();
    const [delta] = namesUnder(fake.files, 'deltas');
    const written = linesOf(fake.files.get(delta ?? '') ?? Buffer.alloc(0)).map(
      (line) => JSON.parse(line) as Record<string, unknown>,
    );
    expect(written).toContainEqual(expect.objectContaining({ c: 'platform', p: 1, s: START.toISOString() }));
    expect(written).toContainEqual(expect.objectContaining({ c: `organisation:${ORG}`, p: 1, y: START.toISOString() }));
    expect(written.filter((line) => line.c === 'platform' && 'y' in line)).toEqual([]);
    expect(written.filter((line) => line.c !== 'platform' && 's' in line)).toEqual([]);

    // Before the horizon, a restart from the deltas holds them as memory does.
    time.held.at = START.getTime() + HOUR;
    const early = digestOn(fake, { time, forget: 7 * DAY, forgetSessions: LONGEST });
    await early.log.read();
    expect(held(early.log)).toEqual([2n, 4n, 5n, 6n]);

    // Past it: a snapshot written then holds none of them, and a start from it or from the deltas agrees with memory.
    time.held.at = GOES + HOUR;
    log.record(OTHER, new Map(), time.now());
    expect(held(log)).toEqual([2n, undefined, undefined, undefined]);
    await log.flush();
    expect(namesUnder(fake.files, 'snapshots').length).toBeGreaterThan(0);
    const late = digestOn(fake, { time, forget: 7 * DAY, forgetSessions: LONGEST });
    await late.log.read();
    expect(held(late.log)).toEqual(held(log));
    for (const name of namesUnder(fake.files, 'snapshots')) fake.files.delete(name);
    const fromDeltas = digestOn(fake, { time, forget: 7 * DAY, forgetSessions: LONGEST });
    await fromDeltas.log.read();
    expect(held(fromDeltas.log)).toEqual(held(log));
    expect(fromDeltas.log.latest(CHAIN, 'spend_request', REQUEST)).toBe(3n);
  });

  it('an image that doesn’t forget them reads `s` lines as payments’ facts, kept; lines from before stay kept for good', async () => {
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const { log } = digestOn(fake, { time, forgetSessions: LONGEST });
    await log.read();
    recordEach(log);
    await log.flush();
    time.held.at = GOES + DAY;
    const keeping = digestOn(fake, { time });
    await keeping.log.read();
    keeping.log.record(OTHER, new Map(), time.now());
    expect(held(keeping.log)).toEqual([2n, 4n, 5n, 6n]);

    // A payments' line of the platform's with no `s`, as written before AT13g: kept by one that forgets, for good.
    const before = createFakeWriteOnceStore();
    const name = deltaNamed(START);
    const line = { c: 'platform', t: START.toISOString(), e: oneEntry(4n), p: 1 };
    before.files.set(name, closedFile(name, [JSON.stringify(line)]));
    const restarted = digestOn(before, { time, forgetSessions: LONGEST });
    await restarted.log.read();
    restarted.log.record(OTHER, new Map(), time.now());
    expect(restarted.log.memoryHeld()).toMatchObject({ objects: 1 });
  });

  it.each([
    ['`s` on an organisation’s line', { c: `organisation:${ORG}`, p: 1, s: START.toISOString() }],
    ['`y` on the platform’s', { c: 'platform', p: 1, y: START.toISOString() }],
    ['`s` that isn’t one of our times', { c: 'platform', p: 1, s: 'yesterday' }],
    ['`s` on a line that isn’t a payments’ one', { c: 'platform', s: START.toISOString() }],
  ])('%s: the file is unsound, nothing in it taken', async (_what, fields) => {
    const fake = createFakeWriteOnceStore();
    const time = clock();
    const capture = new LogCapture();
    const name = deltaNamed(START);
    fake.files.set(name, closedFile(name, [JSON.stringify({ t: START.toISOString(), e: oneEntry(4n), ...fields })]));
    time.held.at += 6 * MINUTE;
    const restarted = digestOn(fake, { time, capture, forget: 7 * DAY, forgetSessions: LONGEST });
    await restarted.log.read();
    expect(said(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file' })]);
    expect(restarted.log.memoryHeld().objects).toBe(0);
  });

  it('the platform chain’s session ends’ days give way with its growing objects, and none are kept after', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { forgetSessions: LONGEST, mostBytes: 12_000, capture });
    await log.read();
    log.record(PLATFORM, seen(['platform.handoff_pause', 'pause', 2n]), START, stretch(0n, 4n));
    const ends = new Map(
      Array.from({ length: 400 }, (_, at) => [
        subjectKey('identity.session_ended', `${PERSON}:${String(at)}`),
        BigInt(at + 5),
      ]),
    );
    log.record(PLATFORM, ends, START, stretch(4n, 500n));
    expect(log.latest(PLATFORM, 'identity.session_ended', `${PERSON}:0`)).toBeUndefined();
    expect(log.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(2n);
    expect(said(capture, 'audit.state_digest_chain_gave_way')).toEqual([
      expect.objectContaining({ what: 'session_ends' }),
    ]);
    log.record(PLATFORM, seen(['identity.session_ended', ENDED, 600n]), START);
    expect(log.latest(PLATFORM, 'identity.session_ended', ENDED)).toBeUndefined();
    expect(log.bytesHeld()).toBe(log.memoryHeld().bytes);
  });
});
