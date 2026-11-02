import { gunzipSync, gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, signAnchor } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import type { Chain } from './chain.ts';

const keyMaterial = (fill: number): KeyMaterial =>
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
  })) satisfies KeyMaterial;
const keys = createKeyProvider(keyMaterial(1));
/** Someone else's signing key: their lines read as anchors, signed wrongly. */
const otherKeys = createKeyProvider(keyMaterial(50));
/** Holding only a later version of the `audit-anchor` key, as `keys` signs with 1. */
const LATER_KEYS = createKeyProvider(
  byPurpose((purpose) => {
    const version = purpose === 'audit-anchor' ? 2 : 1;
    return { current: version, versions: new Map([[version, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 70)]]) };
  }) satisfies KeyMaterial,
);

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const CHAIN: Chain = { kind: 'organisation', orgId: ORG };
const OTHER_CHAIN: Chain = { kind: 'organisation', orgId: OTHER_ORG };
const PLATFORM: Chain = { kind: 'platform' };
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const ALERT_AFTER_MS = 15 * MINUTE;

const anchorAt = (chain: Chain, seq: bigint, at = START, fill = Number(seq), signing = keys): Anchor =>
  signAnchor(signing, chain, { seq, hash: Buffer.alloc(32, fill), macKeyVersion: 2 }, at);

/** A file as the log writes one. */
const fileOf = (...lines: readonly (Anchor | string)[]): Buffer =>
  gzipSync(`${lines.map((line) => (typeof line === 'string' ? line : lineOf(line))).join('\n')}\n`);

const lineOf = (anchor: Anchor): string =>
  JSON.stringify({
    k: 'a',
    chain: anchor.chain,
    seq: anchor.seq.toString(),
    hash: anchor.hash.toString('hex'),
    mk: anchor.macKeyVersion,
    at: anchor.at.toISOString(),
    kv: anchor.keyVersion,
    sig: anchor.signature.toString('base64'),
  });

/** A file's name, `minutes` after START. */
const nameOf = (kind: 'deltas' | 'snapshots', minutes: number, id = 1, epoch = 1): string =>
  `e${String(epoch)}/${kind}/${String(9_999_999_999_999 - (START.getTime() + minutes * MINUTE))}-00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;

const linesIn = (bytes: Buffer | undefined): Record<string, unknown>[] =>
  gunzipSync(bytes ?? Buffer.alloc(0))
    .toString('utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as Record<string, unknown>);

const logOver = (fake: FakeWriteOnceStore = createFakeWriteOnceStore(), epoch = 1, holding = keys) => {
  const capture = new LogCapture();
  const clock = { at: START };
  const log = createAnchorLog({
    store: fake.store,
    keys: holding,
    logger: testLogger(capture),
    now: () => clock.at,
    epoch,
    alertAfterMs: ALERT_AFTER_MS,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  const advance = (minutes: number): void => {
    clock.at = new Date(clock.at.getTime() + minutes * MINUTE);
  };
  return { log, fake, capture, lines, advance };
};

/** A log that read the store and has written its first file, a snapshot. */
async function started(fake?: FakeWriteOnceStore) {
  const made = logOver(fake);
  await made.log.read();
  made.log.keep(anchorAt(PLATFORM, 1n));
  await made.log.flush();
  return made;
}

const failing = (): Promise<never> => Promise.reject(new Error('the store is away'));

const files = (fake: FakeWriteOnceStore, kind: 'deltas' | 'snapshots') =>
  [...fake.files.keys()].filter((name) => name.includes(`/${kind}/`));

describe('the durable anchors (4D2e E, PL-58)', () => {
  describe('what is written', () => {
    it('writes each anchor as one signed line, gzipped, whole on the first write', async () => {
      const { log, fake, lines } = logOver();
      await log.read();
      const anchor = anchorAt(CHAIN, 812n);
      log.keep(anchor);
      await log.flush();

      const [name, ...others] = [...fake.files.keys()];
      expect(others).toEqual([]);
      expect(name).toMatch(/^e1\/snapshots\/\d{13}-[0-9a-f-]{36}$/);
      expect(name?.slice('e1/snapshots/'.length, 'e1/snapshots/'.length + 13)).toBe(
        String(9_999_999_999_999 - START.getTime()),
      );
      expect(linesIn(fake.files.get(String(name)))).toEqual([
        {
          k: 'a',
          chain: `organisation:${ORG}`,
          seq: '812',
          hash: Buffer.alloc(32, 812 % 256).toString('hex'),
          mk: 2,
          at: START.toISOString(),
          kv: 1,
          sig: anchor.signature.toString('base64'),
        },
      ]);
      expect(lines('audit.anchors_written')).toEqual([
        expect.objectContaining({ level: 'info', kind: 'snapshots', lines: 1 }),
      ]);
    });

    it('writes nothing where nothing moved', async () => {
      const { log, fake } = await started();
      const before = fake.calls.puts;
      await log.flush();
      expect(fake.calls.puts).toBe(before);
    });

    it('writes what moved as a delta, then every chain as a snapshot once the hour is up', async () => {
      const { log, fake, advance } = await started();
      advance(59);
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      expect(files(fake, 'deltas')).toHaveLength(1);
      expect(linesIn(fake.files.get(String(files(fake, 'deltas')[0]))).map((line) => line.chain)).toEqual([
        `organisation:${ORG}`,
      ]);
      advance(1);
      log.keep(anchorAt(OTHER_CHAIN, 3n));
      await log.flush();

      expect(files(fake, 'deltas')).toHaveLength(1);
      const snapshots = files(fake, 'snapshots').toSorted();
      expect(snapshots).toHaveLength(2);
      expect(
        linesIn(fake.files.get(String(snapshots[0])))
          .map((line) => line.chain)
          .toSorted(),
      ).toEqual(['platform', `organisation:${ORG}`, `organisation:${OTHER_ORG}`].toSorted());
    });

    it('keeps the new anchors in the epoch the setting names, and reads no other', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0, 1, 1), fileOf(anchorAt(CHAIN, 9n)));
      const { log } = logOver(fake, 2);
      await log.read();
      expect(log.latest(CHAIN)).toBeUndefined();
      log.keep(anchorAt(CHAIN, 1n));
      await log.flush();
      expect(files(fake, 'snapshots').filter((name) => name.startsWith('e2/'))).toHaveLength(1);
    });

    it('a later anchor of a chain, kept while its file is compressed, goes in the next file', async () => {
      const { log, fake } = await started();
      log.keep(anchorAt(CHAIN, 2n));
      const writing = log.flush();
      log.keep(anchorAt(CHAIN, 3n));
      await writing;
      await log.flush();

      const seqs = files(fake, 'deltas').flatMap((name) => linesIn(fake.files.get(name)).map((line) => line.seq));
      expect(seqs.toSorted()).toEqual(['2', '3']);
    });

    it('holds an anchor kept while a file is being made for the next file', async () => {
      const { log, fake } = await started();
      const { promise: holding, resolve: letGo } = Promise.withResolvers<undefined>();
      fake.instead.put = async (name, bytes) => {
        await holding;
        return fake.real.put(name, bytes);
      };
      log.keep(anchorAt(CHAIN, 2n));
      const writing = log.flush();
      await new Promise((resolve) => setTimeout(resolve, 20));
      log.keep(anchorAt(OTHER_CHAIN, 3n));
      letGo(undefined);
      await writing;
      delete fake.instead.put;
      await log.flush();

      const chains = files(fake, 'deltas').flatMap((name) => linesIn(fake.files.get(name)).map((line) => line.chain));
      expect(chains.toSorted()).toEqual([`organisation:${ORG}`, `organisation:${OTHER_ORG}`].toSorted());
    });
  });

  describe('a restart', () => {
    it('reads the newest snapshot and the deltas since: 2 lists and at most 13 gets at the default interval', async () => {
      const fake = createFakeWriteOnceStore();
      const first = await started(fake);
      for (let run = 1; run <= 12; run += 1) {
        first.advance(5);
        if (run === 12) first.advance(-1);
        first.log.keep(anchorAt(CHAIN, BigInt(run)));
        await first.log.flush();
      }
      expect(files(fake, 'deltas')).toHaveLength(12);
      fake.calls.lists = 0;
      fake.calls.gets = 0;

      const { log, lines } = logOver(fake);
      expect(log.state()).toBe('unread');
      expect(log.latest(CHAIN)).toBeUndefined();
      await log.read();

      expect(fake.calls).toMatchObject({ lists: 2, gets: 13 });
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)).toMatchObject({ seq: 12n, macKeyVersion: 2, keyVersion: 1 });
      expect(log.latest(CHAIN)?.hash).toEqual(Buffer.alloc(32, 12));
      expect(log.latest(CHAIN)?.at).toEqual(START);
      expect(log.latest(PLATFORM)).toMatchObject({ seq: 1n });
      expect(lines('audit.anchors_read')).toEqual([
        expect.objectContaining({ level: 'info', epoch: 1, chains: 2, snapshot: true, deltas: 12 }),
      ]);
      // Its first write comes from the snapshot's time, not as if there had been none.
      log.keep(anchorAt(CHAIN, 13n));
      await log.flush();
      expect(files(fake, 'snapshots')).toHaveLength(1);
    });

    it('reads no delta older than the snapshot it read, and only the newest snapshot', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(OTHER_CHAIN, 40n)));
      fake.files.set(nameOf('deltas', 5), fileOf(anchorAt(OTHER_CHAIN, 41n)));
      fake.files.set(nameOf('snapshots', 60), fileOf(anchorAt(CHAIN, 50n)));
      fake.files.set(nameOf('deltas', 65), fileOf(anchorAt(CHAIN, 51n)));
      const { log } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(51n);
      expect(log.latest(OTHER_CHAIN)).toBeUndefined();
      expect(fake.calls.gets).toBe(2);
    });

    it('takes the highest place of a chain, whichever file it is in', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 5), fileOf(anchorAt(CHAIN, 9n)));
      fake.files.set(nameOf('deltas', 10), fileOf(anchorAt(CHAIN, 4n)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(9n);
      expect(lines('audit.integrity_failed')).toEqual([]);
    });

    it('reads on over a page of deltas, as a store a snapshot could not reach would have', async () => {
      const fake = createFakeWriteOnceStore();
      for (let delta = 1; delta <= 101; delta += 1) {
        fake.files.set(nameOf('deltas', delta), fileOf(anchorAt(CHAIN, BigInt(delta))));
      }
      const { log } = logOver(fake);
      await log.read();

      expect(fake.calls).toMatchObject({ lists: 3, gets: 101 });
      expect(log.latest(CHAIN)?.seq).toBe(101n);
    });

    it('says every organisation with a chain in the store has been seen, and the platform is none', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(
        nameOf('snapshots', 0),
        fileOf(anchorAt(CHAIN, 1n), anchorAt(PLATFORM, 2n), anchorAt(OTHER_CHAIN, 1n)),
      );
      const { log } = logOver(fake);
      await log.read();

      expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());
    });

    it('a call that fails leaves nothing read: no part of the store is taken for the whole', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 1n)));
      fake.files.set(nameOf('deltas', 5), fileOf(anchorAt(OTHER_CHAIN, 2n)));
      const { log, lines } = logOver(fake);
      fake.instead.get = (name) => (name.includes('/deltas/') ? failing() : fake.real.get(name));
      await log.read();

      expect(log.state()).toBe('unreadable');
      expect(log.latest(CHAIN)).toBeUndefined();
      expect(log.organisations()).toEqual([]);
      expect(lines('audit.anchor_store_unreadable')).toEqual([
        expect.objectContaining({
          level: 'error',
          err: expect.objectContaining({ message: 'the store is away' }) as unknown,
        }),
      ]);
      expect(lines('audit.anchors_read')).toEqual([]);

      delete fake.instead.get;
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)?.seq).toBe(1n);
      expect(log.latest(OTHER_CHAIN)?.seq).toBe(2n);
    });

    it('a list that fails is the same', async () => {
      const fake = createFakeWriteOnceStore();
      fake.instead.list = failing;
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.state()).toBe('unreadable');
      expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
    });

    it('reads once at a time: a second call joins the first, and a later one reads again', async () => {
      const fake = createFakeWriteOnceStore();
      const { log } = logOver(fake);
      await Promise.all([log.read(), log.read()]);
      expect(fake.calls.lists).toBe(2);
      await log.read();
      expect(fake.calls.lists).toBe(4);
    });
  });

  describe('a line or file that fails (`integrity_failed`, `check: anchor_store`, never a hold)', () => {
    it('SEC-DB-11 skips a line with a bad signature and is the alarm, keeping the good ones', async () => {
      const fake = createFakeWriteOnceStore();
      const forged = anchorAt(CHAIN, 99n, START, 99, otherKeys);
      fake.files.set(nameOf('snapshots', -60), fileOf(anchorAt(CHAIN, 2n), anchorAt(OTHER_CHAIN, 1n)));
      fake.files.set(nameOf('snapshots', 0), fileOf(forged, anchorAt(OTHER_CHAIN, 3n)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(2n);
      expect(log.latest(OTHER_CHAIN)?.seq).toBe(3n);
      expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());
      expect(lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({
          level: 'error',
          chain: 'store',
          check: 'anchor_store',
          reason: 'signature',
          kind: 'snapshots',
          lines: 1,
          fileAt: START.toISOString(),
        }),
      ]);
      expect(log.state()).toBe('read');
    });

    const good = anchorAt(CHAIN, 7n);
    const goodLine = JSON.parse(lineOf(good)) as Record<string, unknown>;
    const withField = (change: Record<string, unknown>): string => JSON.stringify({ ...goodLine, ...change });

    it.each([
      ['another place', withField({ seq: '8' })],
      ['another hash', withField({ hash: Buffer.alloc(32, 8).toString('hex') })],
      ['another MAC key version', withField({ mk: 3 })],
      ['another time', withField({ at: '2026-11-02T09:00:00.001Z' })],
      ['another chain', withField({ chain: `organisation:${OTHER_ORG}` })],
      ['a signing key this process has not', withField({ kv: 9 })],
      ['a signature cut short', withField({ sig: good.signature.subarray(1).toString('base64') })],
    ])('refuses a line signed for something else: %s', async (_what, line) => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(line));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.organisations()).toEqual([]);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 1 })]);
    });

    it.each([
      ['not JSON', 'not json at all'],
      ['not an object', '7'],
      ['null', 'null'],
      ['no kind', JSON.stringify({ chain: 'platform' })],
      ['a kind no piece writes', withField({ k: 'z' })],
      ['a chain of no form', withField({ chain: 'organisation:someone' })],
      ['a chain in capitals', withField({ chain: `organisation:${ORG.toUpperCase()}` })],
      ['a chain with more after it', withField({ chain: `platform\n` })],
      ['no chain', withField({ chain: 7 })],
      ['a place of no form', withField({ seq: '-1' })],
      ['a place with a leading nought', withField({ seq: '07' })],
      ['a place too long for the database', withField({ seq: '1'.repeat(20) })],
      ['a place not text', withField({ seq: 7 })],
      ['a hash too short', withField({ hash: 'ab' })],
      ['a hash not text', withField({ hash: 7 })],
      ['a MAC key version not a count', withField({ mk: '2' })],
      ['a negative MAC key version', withField({ mk: -1 })],
      ['a signing key version not a whole number', withField({ kv: 1.5 })],
      ['a time of no form', withField({ at: 'soon' })],
      ['a time in another form', withField({ at: '2026-11-02T09:00:00Z' })],
      ['a time not text', withField({ at: 7 })],
      ['a signature not text', withField({ sig: 7 })],
    ])('refuses a line of no form: %s', async (_what, line) => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(line, good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 1 })]);
      expect(log.latest(CHAIN)?.seq).toBe(7n);
    });

    it("passes over the lines a later piece writes, with no alarm: going back a release isn't tampering", async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(JSON.stringify({ k: 'p' }), JSON.stringify({ k: 'r' }), good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([]);
      expect(log.latest(CHAIN)?.seq).toBe(7n);
    });

    it('SEC-DB-11 same place, two hashes: the alarm, and the older kept whichever is read first', async () => {
      const older = anchorAt(CHAIN, 5n, START, 5);
      const newer = anchorAt(CHAIN, 5n, new Date(START.getTime() + MINUTE), 6);
      for (const [first, second] of [
        [older, newer],
        [newer, older],
      ] as const) {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('deltas', 0), fileOf(first));
        fake.files.set(nameOf('deltas', 5), fileOf(second));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.latest(CHAIN)?.hash).toEqual(older.hash);
        expect(lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({
            level: 'error',
            check: 'anchor_store',
            reason: 'fork',
            seq: '5',
            orgId: ORG,
          }),
        ]);
      }
    });

    it('the platform chain forked is the alarm too, naming no organisation', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(anchorAt(PLATFORM, 5n, START, 5), anchorAt(PLATFORM, 5n, START, 6)));
      const { log, lines } = logOver(fake);
      await log.read();

      const [line] = lines('audit.integrity_failed');
      expect(line).toMatchObject({ reason: 'fork' });
      expect(line).not.toHaveProperty('orgId');
      // At one time, the one held stays.
      expect(log.latest(PLATFORM)?.hash).toEqual(Buffer.alloc(32, 5));
    });

    it('the same line twice is nothing', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(good));
      fake.files.set(nameOf('deltas', 5), fileOf(good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([]);
    });

    it('a newest snapshot that will not open is the alarm, and must not hide the one before it', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n)));
      fake.files.set(nameOf('snapshots', 60), Buffer.from('not gzip'));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({
          reason: 'file',
          kind: 'snapshots',
          fileAt: new Date(START.getTime() + 60 * MINUTE).toISOString(),
        }),
      ]);
    });

    describe('a snapshot with a line that fails can not stand for the whole', () => {
      const spoiled = (): Buffer => fileOf('not a line');

      it('the one before it is read too, and every delta since that one', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)));
        fake.files.set(nameOf('deltas', 30), fileOf(anchorAt(CHAIN, 5n)));
        fake.files.set(nameOf('snapshots', 60), spoiled());
        fake.files.set(nameOf('deltas', 65), fileOf(anchorAt(OTHER_CHAIN, 6n)));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(5n);
        expect(log.latest(OTHER_CHAIN)?.seq).toBe(6n);
        expect(lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({ reason: 'signature', kind: 'snapshots', lines: 1 }),
        ]);
        expect(lines('audit.anchors_read')).toEqual([
          expect.objectContaining({ chains: 2, snapshot: true, deltas: 2 }),
        ]);
      });

      it('reads none of them twice: the next read starts from the newest, spoiled or not', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), spoiled());
        const { log, lines } = logOver(fake);
        await log.read();
        fake.calls.gets = 0;

        await log.read();

        expect(fake.calls.gets).toBe(0);
        expect(lines('audit.integrity_failed')).toHaveLength(1);
      });

      it('goes no further back than the first one with nothing wrong', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -60), fileOf(anchorAt(OTHER_CHAIN, 1n)));
        fake.files.set(nameOf('deltas', -30), fileOf(anchorAt(OTHER_CHAIN, 2n)));
        fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), spoiled());
        const { log } = logOver(fake);
        await log.read();

        expect(fake.calls.gets).toBe(2);
        expect(log.latest(OTHER_CHAIN)).toBeUndefined();
      });

      it('a key version gone: the newest signed with it, the one before still read, every chain still seen', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)));
        fake.files.set(
          nameOf('snapshots', 60),
          fileOf(anchorAt(CHAIN, 5n, START, 5, LATER_KEYS), anchorAt(OTHER_CHAIN, 6n, START, 6, LATER_KEYS)),
        );
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(3n);
        expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());
        expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 2 })]);
      });

      it('SEC-DB-11 none with nothing wrong: the store reads as unreadable, nothing is taken from it, until the key is back', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), fileOf(anchorAt(CHAIN, 4n)));
        const { log, lines } = logOver(fake, 1, LATER_KEYS);
        await log.read();

        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
        expect(log.organisations()).toEqual([]);
        expect(lines('audit.anchor_store_unreadable')).toEqual([
          expect.objectContaining({
            level: 'error',
            err: expect.objectContaining({ message: expect.stringContaining('no snapshot') as unknown }) as unknown,
          }),
        ]);
        expect(lines('audit.anchors_read')).toEqual([]);

        const back = logOver(fake);
        await back.log.read();
        expect(back.log.state()).toBe('read');
        expect(back.log.latest(CHAIN)?.seq).toBe(4n);
      });

      it('no snapshot that opens is the same', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), Buffer.from('not gzip'));
        fake.files.set(nameOf('deltas', 5), fileOf(anchorAt(CHAIN, 3n)));
        const { log } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
      });

      it('goes back a day of snapshots, and no further: past that the store reads as unreadable', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -25 * 60), fileOf(anchorAt(CHAIN, 3n)));
        for (let hour = 0; hour < 24; hour += 1) fake.files.set(nameOf('snapshots', -hour * 60), spoiled());
        const reached = logOver(fake);
        await reached.log.read();
        expect(reached.log.state()).toBe('read');
        expect(reached.log.latest(CHAIN)?.seq).toBe(3n);
        expect(fake.calls.gets).toBe(25);

        fake.files.set(nameOf('snapshots', 60), spoiled());
        fake.calls.gets = 0;
        const past = logOver(fake);
        await past.log.read();
        expect(past.log.state()).toBe('unreadable');
        expect(fake.calls.gets).toBe(25);
      });

      it('what it found goes in the next snapshot, so a later restart needs neither older file', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -60), fileOf(anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)));
        fake.files.set(nameOf('snapshots', 0), spoiled());
        const { log, advance } = logOver(fake);
        await log.read();
        advance(60);
        log.keep(anchorAt(CHAIN, 5n));
        await log.flush();
        fake.calls.gets = 0;

        const later = logOver(fake);
        await later.log.read();
        expect(fake.calls.gets).toBe(1);
        expect(later.log.latest(CHAIN)?.seq).toBe(5n);
        expect(later.log.latest(OTHER_CHAIN)?.seq).toBe(4n);
      });

      it('once read, another copy spoiling a snapshot costs nothing: what it read before is in memory', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, lines } = await started(fake);
        fake.files.set(nameOf('snapshots', 60, 7), spoiled());
        fake.calls.gets = 0;
        await log.read();

        expect(log.state()).toBe('read');
        expect(fake.calls.gets).toBe(1);
        expect(log.latest(PLATFORM)?.seq).toBe(1n);
        expect(lines('audit.anchor_store_read_failed')).toEqual([]);

        await log.read();
        expect(fake.calls.gets).toBe(1);
      });
    });

    it('a delta that will not open is the alarm, and the others are read', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(anchorAt(CHAIN, 3n)));
      fake.files.set(nameOf('deltas', 5), Buffer.from('not gzip'));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file', kind: 'deltas' })]);
    });

    it('a file that opens to more than a store could hold is one that will not open', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), gzipSync(Buffer.alloc(65 * 1024 * 1024)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file' })]);
      // It makes 65 MB to shrink, which took over 5 seconds once on a busy machine.
    }, 30_000);

    it('warns of a file it would never have named, and never reads it', async () => {
      const fake = createFakeWriteOnceStore();
      const planted = 'e1/deltas/0000000000000-not-an-id';
      fake.files.set(planted, fileOf(anchorAt(CHAIN, 999n)));
      fake.files.set(nameOf('deltas', 0), fileOf(anchorAt(CHAIN, 2n)));
      fake.instead.list = async (start, most, after) => {
        const page = await fake.real.list(start, most, after);
        return start.includes('/deltas/') ? { ...page, foreign: 1 } : page;
      };
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(2n);
      expect(fake.calls.gets).toBe(1);
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ level: 'warn', files: 2 })]);
    });

    it('counts a foreign name only as far as a read goes: the stated limit', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 60), fileOf(anchorAt(CHAIN, 2n)));
      fake.files.set(nameOf('deltas', 65), fileOf(anchorAt(CHAIN, 3n)));
      fake.files.set('e1/snapshots/0-sorts-first', fileOf(anchorAt(CHAIN, 998n)));
      fake.files.set('e1/snapshots/z-sorts-after', fileOf(anchorAt(CHAIN, 999n)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
    });

    it('says nothing of foreign files where there are none', async () => {
      const { lines, log } = logOver();
      await log.read();
      expect(lines('audit.anchor_store_foreign')).toEqual([]);
    });
  });

  describe('each run after the first', () => {
    it("reads what another copy wrote, the highest place winning, and doesn't read its own again", async () => {
      const fake = createFakeWriteOnceStore();
      const { log, advance } = await started(fake);
      advance(5);
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      fake.calls.gets = 0;

      await log.read();
      expect(fake.calls.gets).toBe(0);

      fake.files.set(nameOf('deltas', 10, 7), fileOf(anchorAt(CHAIN, 8n), anchorAt(OTHER_CHAIN, 1n)));
      await log.read();
      expect(fake.calls.gets).toBe(1);
      expect(log.latest(CHAIN)?.seq).toBe(8n);
      expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());

      // And never again.
      await log.read();
      expect(fake.calls.gets).toBe(1);
    });

    it('reads no delta older than the snapshot it wrote itself', async () => {
      const fake = createFakeWriteOnceStore();
      const { log } = await started(fake);
      fake.files.set(nameOf('deltas', -60, 7), fileOf(anchorAt(CHAIN, 8n)));
      fake.calls.gets = 0;
      await log.read();

      expect(fake.calls.gets).toBe(0);
      expect(log.latest(CHAIN)).toBeUndefined();
    });

    it("reads another copy's newer snapshot, and no older one", async () => {
      const fake = createFakeWriteOnceStore();
      const { log } = await started(fake);
      fake.calls.gets = 0;
      fake.files.set(nameOf('snapshots', 60, 7), fileOf(anchorAt(CHAIN, 8n)));
      fake.files.set(nameOf('snapshots', -60, 8), fileOf(anchorAt(OTHER_CHAIN, 8n)));
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(8n);
      expect(log.latest(OTHER_CHAIN)).toBeUndefined();
      expect(fake.calls.gets).toBe(1);
    });

    it('a read that fails once the store has been read leaves things as they are, with a warning', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines } = await started(fake);
      fake.instead.list = failing;
      await log.read();

      expect(log.state()).toBe('read');
      expect(log.latest(PLATFORM)?.seq).toBe(1n);
      expect(lines('audit.anchor_store_read_failed')).toEqual([expect.objectContaining({ level: 'warn' })]);
      expect(lines('audit.anchor_store_unreadable')).toEqual([]);
    });

    it('reads that keep failing are the alert once they have lasted, and it clears on a read', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines, advance } = await started(fake);
      fake.instead.list = failing;
      await log.read();
      advance(14);
      await log.read();
      expect(lines('audit.anchor_store_read_failed')).toHaveLength(2);
      expect(lines('audit.anchor_store_read_failing')).toEqual([]);

      advance(1);
      await log.read();
      expect(lines('audit.anchor_store_read_failing')).toEqual([
        expect.objectContaining({ level: 'error', forMs: ALERT_AFTER_MS }),
      ]);

      // Its time counts afresh, and neither a read's failing nor a write's starts the other's.
      delete fake.instead.list;
      await log.read();
      fake.instead.list = failing;
      await log.read();
      advance(14);
      await log.read();
      expect(lines('audit.anchor_store_read_failing')).toHaveLength(1);
      expect(log.state()).toBe('read');
      expect(lines('audit.anchor_store_unwritable')).toEqual([]);
    });

    it('a read run past its deadline counts toward the alert too', async () => {
      const { log, lines, advance } = await started();
      log.readFailed(new Error('past its deadline'));
      advance(15);
      log.readFailed(new Error('past its deadline'));
      expect(lines('audit.anchor_store_read_failing')).toHaveLength(1);
    });
  });

  describe('a store that can not be written', () => {
    it('keeps every anchor in memory and warns, then is the alert once it has lasted, and clears on a write', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines, advance } = await started(fake);
      fake.instead.put = failing;
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();

      expect(log.latest(CHAIN)?.seq).toBe(2n);
      expect(lines('audit.anchor_store_write_failed')).toEqual([expect.objectContaining({ level: 'warn' })]);
      expect(lines('audit.anchor_store_unwritable')).toEqual([]);

      advance(14);
      await log.flush();
      expect(lines('audit.anchor_store_unwritable')).toEqual([]);

      advance(1);
      await log.flush();
      expect(lines('audit.anchor_store_unwritable')).toEqual([
        expect.objectContaining({ level: 'error', forMs: ALERT_AFTER_MS }),
      ]);

      delete fake.instead.put;
      await log.flush();
      fake.instead.put = failing;
      log.keep(anchorAt(CHAIN, 3n));
      await log.flush();
      // Its time counts afresh.
      expect(lines('audit.anchor_store_unwritable')).toHaveLength(1);
    });

    it('tries a file again under the same name, with the same bytes, then writes what moved since', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, advance } = await started(fake);
      const tried: [string, Buffer][] = [];
      fake.instead.put = (name, bytes) => {
        tried.push([name, bytes]);
        return failing();
      };
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      advance(5);
      log.keep(anchorAt(CHAIN, 3n));
      await log.flush();

      expect(tried).toHaveLength(2);
      expect(tried[1]).toEqual(tried[0]);

      delete fake.instead.put;
      advance(5);
      await log.flush();
      const deltas = files(fake, 'deltas');
      expect(deltas).toHaveLength(2);
      expect(deltas).toContain(tried[0]?.[0]);
    });

    it('a write whose answer was lost: the name holds the same bytes, so it is written, with no alarm', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines } = await started(fake);
      fake.instead.put = async (name, bytes) => {
        await fake.real.put(name, bytes);
        throw new Error('the answer was lost');
      };
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      delete fake.instead.put;
      await log.flush();

      expect(files(fake, 'deltas')).toHaveLength(1);
      expect(lines('audit.integrity_failed')).toEqual([]);
      // The file is settled: nothing is tried again.
      const before = fake.calls.puts;
      await log.flush();
      expect(fake.calls.puts).toBe(before);
    });

    it('SEC-DB-11 a name that holds other bytes is the alarm, and its lines go again under a new name', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines, advance } = await started(fake);
      fake.instead.put = async (name, _bytes) => {
        await fake.real.put(name, Buffer.from('someone else'));
        throw new Error('the answer was lost');
      };
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      delete fake.instead.put;
      await log.flush();
      expect(lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({ level: 'error', check: 'anchor_store', reason: 'overwrite', kind: 'deltas' }),
      ]);

      advance(5);
      await log.flush();
      const written = files(fake, 'deltas').flatMap((name) => {
        const bytes = fake.files.get(name);
        return bytes?.toString() === 'someone else' ? [] : linesIn(bytes).map((line) => line.seq);
      });
      expect(written).toEqual(['2']);
    });

    it('a later anchor waiting wins over a line going again', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, advance } = await started(fake);
      fake.instead.put = async (name) => {
        await fake.real.put(name, Buffer.from('someone else'));
        throw new Error('the answer was lost');
      };
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      delete fake.instead.put;
      log.keep(anchorAt(CHAIN, 3n));
      await log.flush();
      advance(5);
      await log.flush();

      const written = files(fake, 'deltas').flatMap((name) => {
        const bytes = fake.files.get(name);
        return bytes?.toString() === 'someone else' ? [] : linesIn(bytes).map((line) => line.seq);
      });
      expect(written).toEqual(['3']);
    });

    it('stays unsent if the name can not be compared', async () => {
      const fake = createFakeWriteOnceStore();
      const { log, lines } = await started(fake);
      fake.instead.put = async (name, bytes) => {
        await fake.real.put(name, bytes);
        throw new Error('the answer was lost');
      };
      log.keep(anchorAt(CHAIN, 2n));
      await log.flush();
      delete fake.instead.put;
      fake.instead.get = failing;
      await log.flush();

      expect(lines('audit.anchor_store_write_failed')).toHaveLength(2);
      expect(lines('audit.integrity_failed')).toEqual([]);
      const puts = fake.calls.puts;
      delete fake.instead.get;
      await log.flush();
      expect(fake.calls.puts).toBe(puts + 1);
      expect(lines('audit.anchor_store_write_failed')).toHaveLength(2);
    });

    it('writes once at a time: a second call joins the first', async () => {
      const fake = createFakeWriteOnceStore();
      const { log } = await started(fake);
      log.keep(anchorAt(CHAIN, 2n));
      const before = fake.calls.puts;
      await Promise.all([log.flush(), log.flush()]);
      expect(fake.calls.puts).toBe(before + 1);
    });
  });

  it('can be told a read or a write ran out of time, as its caller bounds them', () => {
    const { log, lines } = logOver();
    log.readFailed(new Error('past its deadline'));
    expect(log.state()).toBe('unreadable');
    expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
    log.writeFailed(new Error('past its deadline'));
    expect(lines('audit.anchor_store_write_failed')).toHaveLength(1);
  });

  describe('an anchor behind the one held', () => {
    it.each([
      ['a lower place', anchorAt(CHAIN, 4n)],
      ['the same place with another hash', anchorAt(CHAIN, 5n, START, 6)],
    ])(
      'SEC-DB-11 %s is refused and is the alarm: the one held stays, and it is never written',
      async (_what, behind) => {
        const { log, lines, fake } = await started();
        const held = anchorAt(CHAIN, 5n);
        log.keep(held);
        await log.flush();
        const puts = fake.calls.puts;

        log.keep(behind);
        await log.flush();

        expect(log.latest(CHAIN)).toBe(held);
        expect(fake.calls.puts).toBe(puts);
        expect(lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({
            level: 'error',
            check: 'anchor_store',
            reason: 'behind',
            seq: behind.seq.toString(),
            anchorSeq: '5',
            orgId: ORG,
          }),
        ]);
      },
    );

    it('the platform chain the same, naming no organisation', async () => {
      const { log, lines } = await started();
      log.keep(anchorAt(PLATFORM, 2n));
      log.keep(anchorAt(PLATFORM, 1n));

      expect(log.latest(PLATFORM)?.seq).toBe(2n);
      const [line] = lines('audit.integrity_failed');
      expect(line).toMatchObject({ reason: 'behind' });
      expect(line).not.toHaveProperty('orgId');
    });

    it('the same anchor again, or one past it, is kept', async () => {
      const { log, lines } = await started();
      const held = anchorAt(CHAIN, 5n);
      log.keep(held);
      log.keep(held);
      log.keep(anchorAt(CHAIN, 6n));

      expect(log.latest(CHAIN)?.seq).toBe(6n);
      expect(lines('audit.integrity_failed')).toEqual([]);
    });
  });

  it('keeps the current anchor in memory for Tx A, with no trip', async () => {
    const fake = createFakeWriteOnceStore();
    const log: AnchorLog = (await started(fake)).log;
    log.keep(anchorAt(CHAIN, 2n));
    const calls = { ...fake.calls };

    expect(log.latest(CHAIN)?.seq).toBe(2n);
    expect(log.latest(OTHER_CHAIN)).toBeUndefined();
    expect(fake.calls).toEqual(calls);
  });
});
