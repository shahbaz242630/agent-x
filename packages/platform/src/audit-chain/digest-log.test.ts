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
    expect(log.known(CHAIN)).toBe(true);
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
    expect(log.known(CHAIN)).toBe(false);
    await log.read();
    expect(log.state()).toBe('read');
    expect(log.known(CHAIN)).toBe(true);
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
    expect(log.known(CHAIN)).toBe(false);
    expect(log.known(OTHER)).toBe(true);
    letGo.delete(ORG);
    expect(log.latest(CHAIN, 'agent', AGENT)).toBe(9n);
  });

  it('past half its memory says so, and past all of it keeps nothing more and stands for no chain', async () => {
    const capture = new LogCapture();
    const { log } = digestOn(undefined, { capture, mostBytes: 4000 });
    await log.read();
    const many = (count: number, from: number) =>
      new Map(
        Array.from({ length: count }, (_, at) => [
          subjectKey('spend_request', `0199a0f0-0000-7000-8000-${(from + at).toString(16).padStart(12, '0')}`),
          BigInt(from + at + 1),
        ]),
      );
    log.record(CHAIN, many(40, 0), START);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'audit.state_digest_near_memory' }));
    expect(log.known(CHAIN)).toBe(true);
    log.record(CHAIN, many(400, 100), START);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.state_digest_beyond_memory' }),
    );
    expect(log.known(CHAIN)).toBe(false);
    const held = log.memoryHeld().objects;
    log.record(OTHER, many(10, 1000), START);
    expect(log.memoryHeld().objects).toBe(held);
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
    const restarted = digestOn(fake, { time });
    await restarted.log.read();
    expect(restarted.log.latest(CHAIN, 'agent', AGENT)).toBe(4n);
  });

  it('a read that fails leaves it unknown, a warning, and tries again whole next time', async () => {
    const { log, fake, capture } = digestOn();
    fake.instead.list = () => Promise.reject(new Error('store away'));
    await log.read();
    expect(log.state()).toBe('unread');
    expect(log.known(CHAIN)).toBe(false);
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
