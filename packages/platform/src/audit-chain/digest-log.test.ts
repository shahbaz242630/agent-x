import { gunzipSync, gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import { createDigestLog, type DigestAnchors } from './digest-log.ts';
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

    // A restart reads the chain that gave way as uncovered, to be walked again from its first event.
    time.held.at += 2 * HOUR;
    log.record(OTHER, seen(['agent', KEY, 3n]), time.now(), stretch(2n, 3n));
    await log.flush();
    const restarted = digestOn(fake, { time, mostBytes: 1024 * 1024 });
    await restarted.log.read();
    expect(restarted.log.covers(CHAIN, 4n)).toBe(false);
    expect(restarted.log.covers(OTHER, 3n)).toBe(true);
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

describe('the digest in a process that loses the lease (AT13)', () => {
  it('says nothing and forgets all it holds while it doesn’t lead, and reads the store again whole when it does', async () => {
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
      leading: () => leads.now,
      alertAfterMs: MINUTE,
      mostBytes: 1024 * 1024,
    });
    await log.read();
    log.record(CHAIN, seen(['agent', AGENT, 9n]), START, stretch(0n, 10n));
    await log.flush();
    leads.now = false;
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(log.covers(CHAIN, 10n)).toBe(false);
    expect(log.coverage(CHAIN)).toBeUndefined();
    expect(log.state()).toBe('unread');
    // A walk while it doesn't lead records nothing, and it doesn't read the store.
    log.record(CHAIN, seen(['agent', KEY, 3n]), START, stretch(0n, 3n));
    await log.read();
    expect(log.memoryHeld().chains).toBe(0);
    // Meanwhile another copy leads, and the chain is rebased: nothing of the old facts comes back here.
    time.held.at += 2 * MINUTE;
    rebases.set(ORG, new Date(START.getTime() + MINUTE));
    leads.now = true;
    expect(log.covers(CHAIN, 10n)).toBe(false);
    await log.read();
    expect(log.state()).toBe('read');
    expect(log.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(log.covers(CHAIN, 10n)).toBe(false);
  });
});
