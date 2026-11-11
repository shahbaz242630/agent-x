import { gunzipSync, gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, type Progress, signAnchor, signPass, signProgress } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import { type Chain, chainName } from './chain.ts';
import { cutoverFile } from './cutover.ts';
import { type Rebase, rebaseFile, rebaseFileName, signRebase } from './rebase.ts';

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
const OTHER: Chain = { kind: 'platform' };
const OTHER_CHAIN: Chain = { kind: 'organisation', orgId: OTHER_ORG };
const PLATFORM: Chain = { kind: 'platform' };
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const ALERT_AFTER_MS = 15 * MINUTE;

const anchorAt = (chain: Chain, seq: bigint, at = START, fill = Number(seq), signing = keys, epoch = 1): Anchor =>
  signAnchor(signing, chain, { seq, hash: Buffer.alloc(32, fill), macKeyVersion: 2 }, at, epoch);

/** A closing line, as the log writes one. */
const closingOf = (
  name: string,
  lines: number,
  signing = keys,
  epoch = Number(/^e(\d+)\//.exec(name)?.[1]),
): string => {
  const { signature, keyVersion } = signing.sign('audit-anchor', [
    'audit-anchor-file',
    name,
    String(epoch),
    String(lines),
  ]);
  return JSON.stringify({ k: 'c', name, epoch, lines, kv: keyVersion, sig: signature.toString('base64') });
};

const gzippedLines = (lines: readonly string[]): Buffer => gzipSync(`${lines.join('\n')}\n`);

/** A file as the log writes one, closed for the name it goes under by `signing`. */
const signedFile = (signing: typeof keys, name: string, ...lines: readonly (Anchor | string)[]): Buffer =>
  gzippedLines([
    ...lines.map((line) => (typeof line === 'string' ? line : lineOf(line))),
    closingOf(name, lines.length, signing),
  ]);
const fileOf = (name: string, ...lines: readonly (Anchor | string)[]): Buffer => signedFile(keys, name, ...lines);

const lineOf = (anchor: Anchor | Progress, k = 'a'): string =>
  JSON.stringify({
    k,
    chain: anchor.chain,
    seq: anchor.seq.toString(),
    hash: anchor.hash.toString('hex'),
    mk: anchor.macKeyVersion,
    at: anchor.at.toISOString(),
    ...('began' in anchor ? { b: anchor.began.toISOString() } : {}),
    kv: anchor.keyVersion,
    sig: anchor.signature.toString('base64'),
  });

/** A file's name, `minutes` after START. */
const nameOf = (kind: 'deltas' | 'snapshots', minutes: number, id = 1, epoch = 1): string =>
  `e${String(epoch)}/${kind}/${String(9_999_999_999_999 - (START.getTime() + minutes * MINUTE))}-00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;

/** A file's lines, its closing one too. */
const allLinesIn = (bytes: Buffer | undefined): Record<string, unknown>[] =>
  gunzipSync(bytes ?? Buffer.alloc(0))
    .toString('utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as Record<string, unknown>);
const linesIn = (bytes: Buffer | undefined): Record<string, unknown>[] =>
  allLinesIn(bytes).filter((line) => line.k !== 'c');

/** A day on: a read past the files a test names, each minutes from START, so none is dated ahead of the clock. */
const LATER = new Date(START.getTime() + 24 * 60 * MINUTE);

const logOver = (fake: FakeWriteOnceStore = createFakeWriteOnceStore(), epoch = 1, holding = keys, at = LATER) => {
  const capture = new LogCapture();
  const clock = { at };
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
  const made = logOver(fake, 1, keys, START);
  await made.log.read();
  made.log.keep(anchorAt(PLATFORM, 1n));
  await made.log.flush();
  return made;
}

/** A log over the store with this much of a file it can hold, and what it says. */
const limited = (fake: FakeWriteOnceStore, mostFileBytes: number) => {
  const capture = new LogCapture();
  const log = createAnchorLog({
    store: fake.store,
    keys,
    logger: testLogger(capture),
    now: () => LATER,
    epoch: 1,
    alertAfterMs: 1000,
    mostFileBytes,
  });
  return { log, capture };
};

const failing = (): Promise<never> => Promise.reject(new Error('the store is away'));

const files = (fake: FakeWriteOnceStore, kind: 'deltas' | 'snapshots') =>
  [...fake.files.keys()].filter((name) => name.includes(`/${kind}/`));

describe('the durable anchors (4D2e E, PL-58)', () => {
  describe('what is written', () => {
    it('writes each anchor as one signed line, gzipped, whole on the first write', async () => {
      const { log, fake, lines } = logOver(undefined, 1, keys, START);
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
      fake.files.set(nameOf('snapshots', 0, 1, 1), fileOf(nameOf('snapshots', 0, 1, 1), anchorAt(CHAIN, 9n)));
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
    it('reads the newest snapshot and the deltas since: 3 lists and at most 13 gets at the default interval', async () => {
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

      // As the hour's up only a minute on, its first write stays a delta.
      const { log, lines } = logOver(fake, 1, keys, new Date(START.getTime() + 59 * MINUTE));
      expect(log.state()).toBe('unread');
      expect(log.latest(CHAIN)).toBeUndefined();
      await log.read();

      // One name each of the later layout's two folders (PL-65), the rebases' list (E11), the snapshots' and the deltas'.
      expect(fake.calls).toMatchObject({ lists: 5, gets: 13 });
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
      fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(OTHER_CHAIN, 40n)));
      fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), anchorAt(OTHER_CHAIN, 41n)));
      fake.files.set(nameOf('snapshots', 60), fileOf(nameOf('snapshots', 60), anchorAt(CHAIN, 50n)));
      fake.files.set(nameOf('deltas', 65), fileOf(nameOf('deltas', 65), anchorAt(CHAIN, 51n)));
      const { log } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(51n);
      expect(log.latest(OTHER_CHAIN)).toBeUndefined();
      expect(fake.calls.gets).toBe(2);
    });

    it('takes the highest place of a chain, whichever file it is in', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), anchorAt(CHAIN, 9n)));
      fake.files.set(nameOf('deltas', 10), fileOf(nameOf('deltas', 10), anchorAt(CHAIN, 4n)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(9n);
      expect(lines('audit.integrity_failed')).toEqual([]);
    });

    it('reads on over a page of deltas, as a store a snapshot could not reach would have', async () => {
      const fake = createFakeWriteOnceStore();
      for (let delta = 1; delta <= 101; delta += 1) {
        fake.files.set(nameOf('deltas', delta), fileOf(nameOf('deltas', delta), anchorAt(CHAIN, BigInt(delta))));
      }
      const { log } = logOver(fake);
      await log.read();

      // The later layout's two folders (PL-65), the rebases' list (E11), then the snapshots' and two pages of deltas.
      expect(fake.calls).toMatchObject({ lists: 6, gets: 101 });
      expect(log.latest(CHAIN)?.seq).toBe(101n);
    });

    it('says every organisation with a chain in the store has been seen, and the platform is none', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(
        nameOf('snapshots', 0),
        fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 1n), anchorAt(PLATFORM, 2n), anchorAt(OTHER_CHAIN, 1n)),
      );
      const { log } = logOver(fake);
      await log.read();

      expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());
    });

    it('a call that fails leaves nothing read: no part of the store is taken for the whole', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 1n)));
      fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), anchorAt(OTHER_CHAIN, 2n)));
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

    describe('a store moved on to a later layout (PL-65): only a signed cutover marker stops this version reading', () => {
      /** A store this version could read whole, a chain anchored at 5. */
      const readable = (): FakeWriteOnceStore => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 5n)));
        return fake;
      };
      const MARKER = 'e1/cutover/shards-v1';
      const marker = (signing = keys, more: { epoch?: number; layout?: string } = {}) =>
        cutoverFile(signing, {
          epoch: more.epoch ?? 1,
          at: START,
          ...(more.layout === undefined ? {} : { layout: more.layout }),
        });
      const put = (fake: FakeWriteOnceStore, file: { name: string; bytes: Buffer }): void => {
        fake.files.set(file.name, file.bytes);
      };
      const movedOn = (lines: (event: string) => Record<string, unknown>[]) => lines('audit.anchor_store_moved_on');
      const alarms = (lines: (event: string) => Record<string, unknown>[]) => lines('audit.integrity_failed');

      it('a signed marker for this epoch fails the read closed, with its own alarm, and nothing of the old files is taken', async () => {
        const fake = readable();
        put(fake, marker());
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
        expect(log.organisations()).toEqual([]);
        expect(movedOn(lines)).toEqual([expect.objectContaining({ level: 'error', epoch: 1, file: MARKER })]);
        expect(lines('audit.anchor_store_unreadable')).toEqual([]);
        expect(lines('audit.anchors_read')).toEqual([]);
        // The marker alone fetched, and no more than a marker's size of it.
        expect(fake.calls).toMatchObject({ gets: 0, smallGets: 1 });
      });

      it('asks the one name, a marker’s size at most, and one or two names of each folder', async () => {
        const fake = readable();
        const asked: string[] = [];
        fake.instead.getAtMost = (name, most) => {
          asked.push(`get ${name} ${String(most)}`);
          return fake.real.getAtMost(name, most);
        };
        fake.instead.list = (start, most, after) => {
          if (/^e1\/(?:cutover|shards)\//.test(start)) asked.push(`list ${start} ${String(most)}`);
          return fake.real.list(start, most, after);
        };
        const { log } = logOver(fake);
        await log.read();
        expect(asked).toEqual(['get e1/cutover/shards-v1 4096', 'list e1/cutover/ 2', 'list e1/shards/ 1']);
      });

      it.each([
        ['unsigned', 'file', () => ({ name: MARKER, bytes: gzipSync('anything') })],
        ['signed by another key', 'signature', () => marker(otherKeys)],
        ['signed by a key version this process lacks', 'signature', () => marker(LATER_KEYS)],
        [
          'of another layout, at this name',
          'file',
          () => ({ name: MARKER, bytes: marker(keys, { layout: 'v0' }).bytes }),
        ],
        ['of another epoch, copied here', 'file', () => ({ name: MARKER, bytes: marker(keys, { epoch: 2 }).bytes })],
        ['larger than any marker', 'file', () => ({ name: MARKER, bytes: Buffer.alloc(4097) })],
      ])('a marker %s is the alarm, once, and moves nothing: the read goes on', async (_, problem, made) => {
        const fake = readable();
        put(fake, made());
        const { log, lines } = logOver(fake);
        await log.read();
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(5n);
        expect(movedOn(lines)).toEqual([]);
        expect(alarms(lines)).toEqual([
          expect.objectContaining({ level: 'error', check: 'anchor_store', reason: 'cutover', problem, file: MARKER }),
        ]);
      });

      it('a marker there but unreadable by a plain read is the alarm, once, and the read goes on', async () => {
        const fake = readable();
        put(fake, marker());
        fake.instead.getAtMost = (name, most) =>
          name === MARKER ? Promise.resolve('unreadable') : fake.real.getAtMost(name, most);
        const { log, lines } = logOver(fake);
        await log.read();
        await log.read();

        expect(log.state()).toBe('read');
        expect(movedOn(lines)).toEqual([]);
        expect(alarms(lines)).toEqual([expect.objectContaining({ reason: 'cutover', problem: 'file', file: MARKER })]);
      });

      it('a signed marker of another layout, at its own name, is another name under the folder: the alarm', async () => {
        const fake = readable();
        put(fake, marker(keys, { layout: 'shards-v0' }));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(alarms(lines)).toEqual([expect.objectContaining({ reason: 'cutover', problem: 'name' })]);
      });

      it('a marker of another epoch in its own folder is not this one: nothing said', async () => {
        const fake = readable();
        put(fake, marker(keys, { epoch: 2 }));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(alarms(lines)).toEqual([]);
      });

      it('names that only start alike, or another epoch’s, are none of these folders: nothing said', async () => {
        const fake = readable();
        for (const name of ['e1/cutovers/x', 'e1/shards-elsewhere', 'e2/shards/a7/x', 'e2/cutover/x']) {
          fake.files.set(name, gzipSync('anything'));
        }
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(5n);
        expect(alarms(lines)).toEqual([]);
        expect(movedOn(lines)).toEqual([]);
      });

      it.each([
        ['under `cutover/`', 'e1/cutover/x', 'cutover'],
        ['under `shards/`', 'e1/shards/a7/snapshots/x', 'shards'],
      ])('another name %s is the alarm, once a process, and the read goes on', async (_, name, reason) => {
        const fake = readable();
        fake.files.set(name, gzipSync('anything'));
        const { log, lines } = logOver(fake);
        await log.read();
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(5n);
        expect(movedOn(lines)).toEqual([]);
        expect(alarms(lines)).toEqual([expect.objectContaining({ reason })]);
      });

      it('beside a marker that is none, another name under `cutover/` is said too', async () => {
        const fake = readable();
        put(fake, { name: MARKER, bytes: gzipSync('anything') });
        fake.files.set('e1/cutover/x', gzipSync('anything'));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(alarms(lines).map((line) => line.problem)).toEqual(['file', 'name']);
      });

      it('a signed marker beside other names still counts', async () => {
        const fake = readable();
        for (const name of ['e1/cutover/a', 'e1/cutover/b', 'e1/cutover/z']) fake.files.set(name, gzipSync(''));
        put(fake, marker());
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('unreadable');
        expect(movedOn(lines)).toHaveLength(1);
      });

      it.each(['e1/cutover/', 'e1/shards/'])(
        'a page of %s with only names it would never write, or only more to come, is the alarm, those names counted too',
        async (folder) => {
          for (const answer of [
            { names: [], foreign: 1, next: undefined },
            { names: [], foreign: 0, next: 'more' },
          ]) {
            const fake = readable();
            fake.instead.list = (start, most, after) =>
              start === folder ? Promise.resolve(answer) : fake.real.list(start, most, after);
            const { log, lines } = logOver(fake);
            await log.read();

            expect(log.state()).toBe('read');
            expect(alarms(lines)).toHaveLength(1);
            expect(lines('audit.anchor_store_foreign')).toEqual(
              answer.foreign > 0 ? [expect.objectContaining({ files: 1 })] : [],
            );
          }
        },
      );

      it('the marker’s own name alone in the folder is no other name', async () => {
        const fake = readable();
        put(fake, { name: MARKER, bytes: gzipSync('anything') });
        const { log, lines } = logOver(fake);
        await log.read();

        expect(alarms(lines).map((line) => line.problem)).toEqual(['file']);
      });

      it.each([
        ['a fetch of the marker', 'getAtMost'],
        ['a list of the folder', 'list'],
      ] as const)('%s that fails is a failed read', async (_, call) => {
        const fake = readable();
        if (call === 'getAtMost') fake.instead.getAtMost = failing;
        else
          fake.instead.list = (start, most, after) =>
            start === 'e1/cutover/' ? failing() : fake.real.list(start, most, after);
        const { log, lines } = logOver(fake);
        await log.read();
        expect(log.state()).toBe('unreadable');
        expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
      });

      it('a process already reading stops anchoring when a marker appears, and stays so at every read after', async () => {
        const fake = readable();
        const { log, lines } = logOver(fake);
        await log.read();
        expect(log.state()).toBe('read');

        put(fake, marker());
        await log.read();
        expect(log.state()).toBe('unreadable');
        await log.read();
        expect(log.state()).toBe('unreadable');
        expect(movedOn(lines)).toHaveLength(2);
        expect(lines('audit.anchor_store_read_failed')).toEqual([]);
      });
    });

    it('reads once at a time: a second call joins the first, and a later one reads again', async () => {
      const fake = createFakeWriteOnceStore();
      const { log } = logOver(fake);
      await Promise.all([log.read(), log.read()]);
      // The later layout's two folders (PL-65), rebases (E11), snapshots and deltas: once for both calls.
      expect(fake.calls.lists).toBe(5);
      await log.read();
      expect(fake.calls.lists).toBe(10);
    });
  });

  describe('a line or file that fails (`integrity_failed`, `check: anchor_store`, never a hold)', () => {
    it('SEC-DB-11 skips a line with a bad signature and is the alarm, keeping the good ones', async () => {
      const fake = createFakeWriteOnceStore();
      const forged = anchorAt(CHAIN, 99n, START, 99, otherKeys);
      fake.files.set(
        nameOf('snapshots', -60),
        fileOf(nameOf('snapshots', -60), anchorAt(CHAIN, 2n), anchorAt(OTHER_CHAIN, 1n)),
      );
      fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), forged, anchorAt(OTHER_CHAIN, 3n)));
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
      ['another epoch', lineOf(anchorAt(CHAIN, 7n, START, 7, keys, 2))],
      ['a signing key this process has not', withField({ kv: 9 })],
      ['a signature cut short', withField({ sig: good.signature.subarray(1).toString('base64') })],
    ])('refuses a line signed for something else: %s', async (_what, line) => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), line));
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
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), line, good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 1 })]);
      expect(log.latest(CHAIN)?.seq).toBe(7n);
    });

    it("passes over the lines a later piece writes, with no alarm: going back a release isn't tampering", async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), JSON.stringify({ k: 'r' }), good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([]);
      expect(log.latest(CHAIN)?.seq).toBe(7n);
    });

    it('a finished pass is a kind of its own now (E7): one with no signature is a line that fails', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), JSON.stringify({ k: 'p' }), good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 1 })]);
      expect(log.latest(CHAIN)?.seq).toBe(7n);
      expect(log.lastPass(CHAIN)).toBeUndefined();
    });

    it('SEC-DB-11 same place, two hashes: the alarm, and the older kept whichever is read first', async () => {
      const older = anchorAt(CHAIN, 5n, START, 5);
      const newer = anchorAt(CHAIN, 5n, new Date(START.getTime() + MINUTE), 6);
      for (const [first, second] of [
        [older, newer],
        [newer, older],
      ] as const) {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), first));
        fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), second));
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
      fake.files.set(
        nameOf('deltas', 0),
        fileOf(nameOf('deltas', 0), anchorAt(PLATFORM, 5n, START, 5), anchorAt(PLATFORM, 5n, START, 6)),
      );
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
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), good));
      fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), good));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(lines('audit.integrity_failed')).toEqual([]);
    });

    it('a newest snapshot that will not open is the alarm, and must not hide the one before it', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
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
      const spoiled = (name: string): Buffer => fileOf(name, 'not a line');

      it('the one before it is read too, and every delta since that one', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(
          nameOf('snapshots', 0),
          fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)),
        );
        fake.files.set(nameOf('deltas', 30), fileOf(nameOf('deltas', 30), anchorAt(CHAIN, 5n)));
        fake.files.set(nameOf('snapshots', 60), spoiled(nameOf('snapshots', 60)));
        fake.files.set(nameOf('deltas', 65), fileOf(nameOf('deltas', 65), anchorAt(OTHER_CHAIN, 6n)));
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

      it('reads the spoiled one again, its alarm with it, and the sound one behind it not', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), spoiled(nameOf('snapshots', 60)));
        const { log, lines } = logOver(fake);
        await log.read();
        fake.calls.gets = 0;

        await log.read();

        expect(fake.calls.gets).toBe(1);
        expect(lines('audit.integrity_failed')).toHaveLength(2);
      });

      it('goes no further back than the first one with nothing wrong', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -60), fileOf(nameOf('snapshots', -60), anchorAt(OTHER_CHAIN, 1n)));
        fake.files.set(nameOf('deltas', -30), fileOf(nameOf('deltas', -30), anchorAt(OTHER_CHAIN, 2n)));
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), spoiled(nameOf('snapshots', 60)));
        const { log } = logOver(fake);
        await log.read();

        expect(fake.calls.gets).toBe(2);
        expect(log.latest(OTHER_CHAIN)).toBeUndefined();
      });

      it('a key version gone: the newest signed with it, the one before still read, every chain still seen', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(
          nameOf('snapshots', 0),
          fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)),
        );
        fake.files.set(
          nameOf('snapshots', 60),
          signedFile(
            LATER_KEYS,
            nameOf('snapshots', 60),
            anchorAt(CHAIN, 5n, START, 5, LATER_KEYS),
            anchorAt(OTHER_CHAIN, 6n, START, 6, LATER_KEYS),
          ),
        );
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(3n);
        expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG].toSorted());
        expect(lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({ reason: 'signature', lines: 2 }),
          expect.objectContaining({ reason: 'unclosed' }),
        ]);
      });

      it('SEC-DB-11 none with nothing wrong: the store reads as unreadable, nothing is taken from it, until the key is back', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', 60), fileOf(nameOf('snapshots', 60), anchorAt(CHAIN, 4n)));
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
        fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), anchorAt(CHAIN, 3n)));
        const { log } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
      });

      it('goes back a day of snapshots, and no further: past that the store reads as unreadable', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -25 * 60), fileOf(nameOf('snapshots', -25 * 60), anchorAt(CHAIN, 3n)));
        for (let hour = 0; hour < 24; hour += 1)
          fake.files.set(nameOf('snapshots', -hour * 60), spoiled(nameOf('snapshots', -hour * 60)));
        const reached = logOver(fake);
        await reached.log.read();
        expect(reached.log.state()).toBe('read');
        expect(reached.log.latest(CHAIN)?.seq).toBe(3n);
        expect(fake.calls.gets).toBe(25);

        fake.files.set(nameOf('snapshots', 60), spoiled(nameOf('snapshots', 60)));
        fake.calls.gets = 0;
        const past = logOver(fake);
        await past.log.read();
        expect(past.log.state()).toBe('unreadable');
        expect(fake.calls.gets).toBe(25);
      });

      it('what it found goes in the next snapshot, so a later restart needs neither older file', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(
          nameOf('snapshots', -60),
          fileOf(nameOf('snapshots', -60), anchorAt(CHAIN, 3n), anchorAt(OTHER_CHAIN, 4n)),
        );
        fake.files.set(nameOf('snapshots', 0), spoiled(nameOf('snapshots', 0)));
        const { log } = logOver(fake);
        await log.read();
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
        const { log, lines, advance } = await started(fake);
        advance(60);
        fake.files.set(nameOf('snapshots', 60, 7), spoiled(nameOf('snapshots', 60, 7)));
        fake.calls.gets = 0;
        await log.read();

        expect(log.state()).toBe('read');
        expect(fake.calls.gets).toBe(1);
        expect(log.latest(PLATFORM)?.seq).toBe(1n);
        expect(lines('audit.anchor_store_read_failed')).toEqual([]);

        await log.read();
        expect(fake.calls.gets).toBe(2);
      });
    });

    describe('a file closes for its own name', () => {
      const line = anchorAt(CHAIN, 7n);
      const NAME = nameOf('snapshots', 60);
      const older = (fake: FakeWriteOnceStore): void => {
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('deltas', 30), fileOf(nameOf('deltas', 30), anchorAt(CHAIN, 5n)));
      };

      it('every file the log writes ends in a closing line, signed for its name, its epoch and its count', async () => {
        const { log, fake } = logOver(createFakeWriteOnceStore(), 3);
        await log.read();
        log.keep(anchorAt(CHAIN, 2n));
        log.keep(anchorAt(OTHER_CHAIN, 3n));
        await log.flush();

        const [name] = [...fake.files.keys()];
        const all = allLinesIn(fake.files.get(String(name)));
        expect(all).toHaveLength(3);
        const closing = all.at(-1);
        expect(closing).toMatchObject({ k: 'c', name, epoch: 3, lines: 2, kv: 1 });
        expect(
          keys.verifySignature(
            'audit-anchor',
            1,
            ['audit-anchor-file', String(name), '3', '2'],
            Buffer.from(String(closing?.sig), 'base64'),
          ),
        ).toBe(true);
      });

      it('what the log wrote reads back sound, with no alarm', async () => {
        const fake = createFakeWriteOnceStore();
        const first = await started(fake);
        first.advance(5);
        first.log.keep(anchorAt(CHAIN, 2n));
        await first.log.flush();

        const { log, lines } = logOver(fake);
        await log.read();
        expect(log.latest(CHAIN)?.seq).toBe(2n);
        expect(lines('audit.integrity_failed')).toEqual([]);
      });

      it.each([
        ['an empty file', (): Buffer => gzipSync('')],
        ['a file of no lines', (): Buffer => gzipSync('\n\n')],
        ['no closing line', (): Buffer => gzippedLines([lineOf(line)])],
        ['one for another name', (): Buffer => gzippedLines([lineOf(line), closingOf(nameOf('snapshots', 61), 1)])],
        ['one for another epoch', (): Buffer => gzippedLines([lineOf(line), closingOf(NAME, 1, keys, 2)])],
        ['one counting other lines', (): Buffer => gzippedLines([lineOf(line), closingOf(NAME, 2)])],
        ['one counting none', (): Buffer => gzippedLines([lineOf(line), closingOf(NAME, 0)])],
        ['one signed by someone else', (): Buffer => gzippedLines([lineOf(line), closingOf(NAME, 1, otherKeys)])],
        [
          'one by a key this process has not',
          (): Buffer => gzippedLines([lineOf(line), closingOf(NAME, 1, LATER_KEYS)]),
        ],
        [
          'one whose name was edited after signing',
          (): Buffer =>
            gzippedLines([
              lineOf(line),
              JSON.stringify({ ...(JSON.parse(closingOf(nameOf('snapshots', 61), 1)) as object), name: NAME }),
            ]),
        ],
        [
          'one whose version is no count',
          (): Buffer =>
            gzippedLines([lineOf(line), JSON.stringify({ ...(JSON.parse(closingOf(NAME, 1)) as object), kv: 'one' })]),
        ],
        [
          'one whose signature is not text',
          (): Buffer =>
            gzippedLines([lineOf(line), JSON.stringify({ ...(JSON.parse(closingOf(NAME, 1)) as object), sig: 7 })]),
        ],
      ])(
        '%s is spoiled and is the alarm: the older snapshot and every delta since it are read',
        async (_what, file) => {
          const fake = createFakeWriteOnceStore();
          older(fake);
          fake.files.set(NAME, file());
          const { log, lines } = logOver(fake);
          await log.read();

          expect(log.state()).toBe('read');
          // Sound lines count wherever they are; 7 is here in the files that hold it.
          expect(log.latest(CHAIN)?.seq).toBeGreaterThanOrEqual(5n);
          expect(lines('audit.integrity_failed')).toEqual([
            expect.objectContaining({ level: 'error', check: 'anchor_store', reason: 'unclosed', kind: 'snapshots' }),
          ]);
        },
      );

      it('a closing line anywhere but the end is a line that fails, and the file is spoiled', async () => {
        const fake = createFakeWriteOnceStore();
        older(fake);
        fake.files.set(NAME, gzippedLines([closingOf(NAME, 1), lineOf(line)]));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.latest(CHAIN)?.seq).toBe(7n);
        expect(lines('audit.integrity_failed').map((each) => each.reason)).toEqual(['signature', 'unclosed']);
      });

      it('the same in a delta: the alarm, its sound lines still count, and the others are read', async () => {
        const fake = createFakeWriteOnceStore();
        older(fake);
        fake.files.set(nameOf('deltas', 40), gzippedLines([lineOf(line)]));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(log.latest(CHAIN)?.seq).toBe(7n);
        expect(lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({ reason: 'unclosed', kind: 'deltas' }),
        ]);
      });

      it('a snapshot of no chains stands only when its closing line says so', async () => {
        const fake = createFakeWriteOnceStore();
        older(fake);
        fake.files.set(NAME, fileOf(NAME));
        const { log, lines } = logOver(fake);
        await log.read();

        expect(lines('audit.integrity_failed')).toEqual([]);
        expect(log.latest(CHAIN)).toBeUndefined();
      });

      it('a sole file with none is no base: the store reads as unreadable', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(NAME, gzipSync(''));
        const { log } = logOver(fake);
        await log.read();

        expect(log.state()).toBe('unreadable');
      });

      it('a spoiled snapshot added hourly does not stop snapshots: their time counts from the last sound one', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', -60), fileOf(nameOf('snapshots', -60), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('snapshots', -1), gzipSync(''));
        const { log } = logOver(fake, 1, keys, START);
        await log.read();
        log.keep(anchorAt(CHAIN, 4n));
        await log.flush();

        expect(files(fake, 'snapshots')).toHaveLength(3);
        expect(files(fake, 'deltas')).toEqual([]);
      });

      it('another copy spoiling one once read does not bring the next snapshot forward', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        advance(30);
        fake.files.set(nameOf('snapshots', 20, 7), gzipSync(''));
        await log.read();
        log.keep(anchorAt(CHAIN, 2n));
        await log.flush();
        advance(30);
        log.keep(anchorAt(CHAIN, 3n));
        await log.flush();

        // The hour from the snapshot it wrote, and no later for the one added at 20 minutes.
        expect(files(fake, 'deltas')).toHaveLength(1);
        expect(files(fake, 'snapshots')).toHaveLength(3);
      });
    });

    describe('the read markers move only for sound files', () => {
      it('an unsigned delta named ahead hides no honest delta named before it', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        fake.files.set(nameOf('deltas', 4, 9), gzipSync(''));
        await log.read();
        fake.files.set(nameOf('deltas', 1, 8), fileOf(nameOf('deltas', 1, 8), anchorAt(CHAIN, 8n)));
        advance(1);
        await log.read();

        expect(log.latest(CHAIN)?.seq).toBe(8n);
      });

      it('an unsigned snapshot named ahead hides no honest snapshot named before it, nor its deltas', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        fake.files.set(nameOf('snapshots', 4, 9), gzipSync(''));
        await log.read();
        fake.files.set(nameOf('snapshots', 1, 8), fileOf(nameOf('snapshots', 1, 8), anchorAt(CHAIN, 8n)));
        fake.files.set(nameOf('deltas', 2, 8), fileOf(nameOf('deltas', 2, 8), anchorAt(OTHER_CHAIN, 3n)));
        advance(2);
        await log.read();

        expect(log.latest(CHAIN)?.seq).toBe(8n);
        expect(log.latest(OTHER_CHAIN)?.seq).toBe(3n);
      });

      it('so the next snapshot this copy writes holds what those honest files held', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        fake.files.set(nameOf('deltas', 4, 9), gzipSync(''));
        await log.read();
        fake.files.set(nameOf('deltas', 1, 8), fileOf(nameOf('deltas', 1, 8), anchorAt(CHAIN, 8n)));
        advance(60);
        await log.read();
        log.keep(anchorAt(OTHER_CHAIN, 3n));
        await log.flush();

        const newest = files(fake, 'snapshots').toSorted()[0];
        expect(linesIn(fake.files.get(String(newest))).map((line) => line.chain)).toContain(`organisation:${ORG}`);
      });

      it('a sound delta after it moves the marker on: older ones are not read again', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        fake.files.set(nameOf('deltas', 1, 8), fileOf(nameOf('deltas', 1, 8), anchorAt(CHAIN, 8n)));
        advance(1);
        await log.read();
        fake.calls.gets = 0;
        await log.read();

        expect(fake.calls.gets).toBe(0);
      });
    });

    describe('a name dated past the clock', () => {
      const FAR = 365 * 24 * 60;

      it.each(['snapshots', 'deltas'] as const)(
        'in %s is passed over, reported, never read, and hides nothing later written',
        async (kind) => {
          const fake = createFakeWriteOnceStore();
          fake.files.set(nameOf(kind, FAR, 9), fileOf(nameOf(kind, FAR, 9), anchorAt(CHAIN, 999n)));
          fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
          fake.files.set(nameOf('deltas', 1), fileOf(nameOf('deltas', 1), anchorAt(CHAIN, 4n)));
          const { log, lines } = logOver(fake);
          await log.read();

          expect(log.latest(CHAIN)?.seq).toBe(4n);
          expect(fake.calls.gets).toBe(2);
          expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
          expect(lines('audit.integrity_failed')).toEqual([
            expect.objectContaining({
              level: 'error',
              check: 'anchor_store',
              reason: 'future',
              kind,
              fileAt: new Date(START.getTime() + FAR * MINUTE).toISOString(),
            }),
          ]);

          fake.files.set(nameOf('deltas', 2, 8), fileOf(nameOf('deltas', 2, 8), anchorAt(CHAIN, 5n)));
          await log.read();
          expect(log.latest(CHAIN)?.seq).toBe(5n);
        },
      );

      it('does not stop this process writing snapshots', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('snapshots', FAR, 9), fileOf(nameOf('snapshots', FAR, 9), anchorAt(CHAIN, 999n)));
        const { log, advance } = logOver(fake);
        await log.read();
        log.keep(anchorAt(CHAIN, 1n));
        await log.flush();
        advance(60);
        log.keep(anchorAt(CHAIN, 2n));
        await log.flush();

        expect(files(fake, 'snapshots')).toHaveLength(3);
      });

      it('allows 5 minutes of clocks disagreeing, and no more', async () => {
        const fake = createFakeWriteOnceStore();
        fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), anchorAt(CHAIN, 3n)));
        fake.files.set(nameOf('deltas', 5.001, 2), fileOf(nameOf('deltas', 5.001, 2), anchorAt(CHAIN, 4n)));
        const { log, lines } = logOver(fake, 1, keys, START);
        await log.read();

        expect(log.latest(CHAIN)?.seq).toBe(3n);
        expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'future' })]);
      });

      it('never counts toward the snapshots a read goes back past', async () => {
        const fake = createFakeWriteOnceStore();
        for (let hour = 1; hour <= 25; hour += 1) {
          fake.files.set(nameOf('snapshots', hour * 60), gzipSync(''));
        }
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 3n)));
        const { log } = logOver(fake, 1, keys, START);
        await log.read();

        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(3n);
        expect(fake.calls.gets).toBe(1);
      });
    });

    it('a delta that will not open is the alarm, and the others are read', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), anchorAt(CHAIN, 3n)));
      fake.files.set(nameOf('deltas', 5), Buffer.from('not gzip'));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'file', kind: 'deltas' })]);
    });

    describe('a file past what this process can hold', () => {
      it('signed and sound is capacity, with the true reason: never `file`, and payments wait', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('snapshots', 0);
        fake.files.set(name, fileOf(name, anchorAt(CHAIN, 3n), anchorAt(OTHER, 4n)));
        const { log, capture } = limited(fake, 200);
        await log.read();
        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
        expect(capture.lines().filter((line) => line.event === 'audit.integrity_failed')).toEqual([]);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([
          expect.objectContaining({ level: 'error', kind: 'snapshots', mostBytes: 200 }),
        ]);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_unreadable')).toEqual([]);
      });

      it('does not walk back to an older snapshot, which would read older anchors', async () => {
        const fake = createFakeWriteOnceStore();
        const [older, newer] = [nameOf('snapshots', 0), nameOf('snapshots', 60)];
        fake.files.set(older, fileOf(older, anchorAt(CHAIN, 3n)));
        fake.files.set(newer, fileOf(newer, anchorAt(CHAIN, 9n), anchorAt(OTHER, 4n), anchorAt(CHAIN, 10n)));
        const { log } = limited(fake, fileOf(older, anchorAt(CHAIN, 3n)).length * 2);
        await log.read();
        expect(log.state()).toBe('unreadable');
        expect(log.latest(CHAIN)).toBeUndefined();
      });

      it('a forged line past it is `file`, and the read stops there', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        fake.files.set(
          name,
          gzippedLines([lineOf(anchorAt(CHAIN, 3n)), lineOf(anchorAt(OTHER, 4n)).replace('"a"', '"z"')]),
        );
        const { log, capture } = limited(fake, 200);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file')).toHaveLength(1);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([]);
        expect(log.latest(CHAIN)).toBeUndefined();
      });

      it('a forged last line, with a sound closing, past it is `file`, not capacity', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        const forged = lineOf(anchorAt(OTHER, 4n)).replace('"seq":"4"', '"seq":"5"');
        fake.files.set(name, fileOf(name, anchorAt(CHAIN, 3n), forged));
        const { log, capture } = limited(fake, 200);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file')).toHaveLength(1);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([]);
        expect(log.state()).not.toBe('unread');
      });

      it('a forged line past it ends the read: nothing after it is checked', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        const forged = lineOf(anchorAt(OTHER, 4n)).replace('"seq":"4"', '"seq":"5"');
        const after = Array.from({ length: 10 }, () => lineOf(anchorAt(OTHER, 6n)));
        fake.files.set(name, gzippedLines([forged, ...after]));
        let checked = 0;
        const counting: typeof keys = {
          ...keys,
          verifySignature: (...asked) => {
            checked += 1;
            return keys.verifySignature(...asked);
          },
        };
        const log = createAnchorLog({
          store: fake.store,
          keys: counting,
          logger: testLogger(new LogCapture()),
          now: () => LATER,
          epoch: 1,
          alertAfterMs: 1000,
          // Past it, and short of the eight times that would stop the read anyway: the forged line is what must.
          mostFileBytes: 1000,
        });
        await log.read();
        // The forged one, and at most the next, before the read stops.
        expect(checked).toBeLessThanOrEqual(2);
      });

      it('an empty line in an otherwise sound file past it is `file`: no honest file has one', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        const sound = gunzipSync(fileOf(name, anchorAt(CHAIN, 3n), anchorAt(OTHER, 4n))).toString('utf8');
        const [first, ...rest] = sound.split('\n');
        fake.files.set(name, gzipSync(`${first ?? ''}\n\n${rest.join('\n')}`));
        const { capture, log } = limited(fake, 200);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file')).toHaveLength(1);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([]);
      });

      it('with no closing line past it is `file`', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        fake.files.set(name, gzippedLines([lineOf(anchorAt(CHAIN, 3n)), lineOf(anchorAt(OTHER, 4n))]));
        const { capture, log } = limited(fake, 200);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file').length).toBeGreaterThan(0);
      });

      it('far past it is `file` however it is signed: a file anyone can add must not be read for ever', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('snapshots', 0);
        fake.files.set(name, fileOf(name, anchorAt(CHAIN, 3n), anchorAt(OTHER, 4n)));
        const { log, capture } = limited(fake, 50);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file')).toHaveLength(1);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([]);
        expect(log.state()).toBe('unreadable');
      });

      it('a run of empty lines past it is `file` at once: no honest file has them, and they would cost no key to make', async () => {
        const fake = createFakeWriteOnceStore();
        const name = nameOf('deltas', 0);
        fake.files.set(name, gzipSync(Buffer.alloc(1024 * 1024, 10)));
        const { capture, log } = limited(fake, 50);
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'file')).toHaveLength(1);
      });

      it('a process already reading goes on from what it holds, with the true reason', async () => {
        const fake = createFakeWriteOnceStore();
        const small = nameOf('snapshots', 0);
        fake.files.set(small, fileOf(small, anchorAt(CHAIN, 3n)));
        const size = fileOf(small, anchorAt(CHAIN, 3n)).length * 4;
        const { log, capture } = limited(fake, size);
        await log.read();
        expect(log.state()).toBe('read');
        const big = nameOf('snapshots', 60);
        const many = Array.from({ length: 20 }, (_, index) => anchorAt(CHAIN, BigInt(index + 10)));
        fake.files.set(big, fileOf(big, ...many));
        await log.read();
        expect(log.state()).toBe('read');
        expect(log.latest(CHAIN)?.seq).toBe(3n);
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toHaveLength(1);
      });
    });

    describe('a read holds one line a chain, and all of it counts against what this process can hold', () => {
      const chain = (index: number): Chain => ({
        kind: 'organisation',
        orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
      });
      /** What a line held costs in the budget's count (anchor-log.ts `KEPT_LINE_BYTES`). */
      const KEPT_LINE = 340;
      /** A delta with no closing line: spoiled, its lines still counted as signed. */
      const spoiled = (fake: FakeWriteOnceStore, minutes: number, from: number, count: number): void => {
        const lines = Array.from({ length: count }, (_, index) => lineOf(anchorAt(chain(from + index), 1n)));
        fake.files.set(nameOf('deltas', minutes), gzippedLines(lines));
      };

      it('two spoiled files each under the limit, together past it: no more kept, and the true reason', async () => {
        const fake = createFakeWriteOnceStore();
        spoiled(fake, 1, 0, 40);
        spoiled(fake, 2, 100, 40);
        // Room for 50 lines: 40 alone fit, 80 together don't.
        const size = 50 * KEPT_LINE;
        const { log, capture } = limited(fake, size);
        await log.read();
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toHaveLength(1);
        expect(log.state()).toBe('unreadable');
        expect(log.organisations()).toEqual([]);
      });

      it('the same chains replayed in many files cost one line each: nothing past the limit', async () => {
        const fake = createFakeWriteOnceStore();
        for (let minutes = 1; minutes <= 5; minutes += 1) spoiled(fake, minutes, 0, 40);
        const size = 50 * KEPT_LINE;
        const { log, capture } = limited(fake, size);
        await log.read();
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toEqual([]);
        expect(log.organisations()).toHaveLength(40);
      });

      /** A log already holding `count` chains at place 1, from a sound snapshot. */
      const holding = async (fake: FakeWriteOnceStore, mostFileBytes: number, count: number) => {
        const first = Array.from({ length: count }, (_, index) => anchorAt(chain(index), 1n));
        fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), ...first));
        const held = limited(fake, mostFileBytes);
        await held.log.read();
        expect(held.log.state()).toBe('read');
        return held;
      };
      const beyond = (capture: LogCapture) =>
        capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory');

      it('the budget counts what is held and what this read staged together, and past it refuses', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = await holding(fake, 25 * KEPT_LINE, 20);
        // Six new chains in another copy's file: 26 in all, past 25. Neither alone is.
        const moved = Array.from({ length: 6 }, (_, index) => anchorAt(chain(100 + index), 1n));
        fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), ...moved));
        await log.read();
        expect(beyond(capture)).toHaveLength(1);
        // It stays reading from what it holds, and none of those part-read is believed.
        expect(log.state()).toBe('read');
        expect(log.latest(chain(100))).toBeUndefined();
      });

      it('an honest return of the lease, mostly unchanged lines, stages almost nothing: no refusal, near the limit', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = await holding(fake, 25 * KEPT_LINE, 20);
        // Another copy's whole snapshot: the same 20, one moved on and each signed later. 2 x 20 would be past the limit.
        const later = new Date(START.getTime() + MINUTE);
        const lines = Array.from({ length: 20 }, (_, index) => anchorAt(chain(index), index === 0 ? 2n : 1n, later));
        fake.files.set(nameOf('snapshots', 60), fileOf(nameOf('snapshots', 60), ...lines));
        await log.read();
        expect(beyond(capture)).toEqual([]);
        expect(log.latest(chain(0))?.seq).toBe(2n);
        // The newer time is taken, in place, for the order a restart goes in.
        expect(log.latest(chain(7))?.at).toEqual(later);
      });

      it('a replayed file of old lines stages none of them, whatever its size', async () => {
        const fake = createFakeWriteOnceStore();
        // Room for the 20 held and 20 moved on, as they stage first, and no more: a replay staged would pass it.
        const { log, capture } = await holding(fake, 45 * KEPT_LINE, 20);
        const later = Array.from({ length: 20 }, (_, index) => anchorAt(chain(index), 9n));
        fake.files.set(nameOf('deltas', 2), fileOf(nameOf('deltas', 2), ...later));
        await log.read();
        const old = Array.from({ length: 20 }, (_, index) => anchorAt(chain(index), 1n));
        const name = nameOf('deltas', 3);
        fake.files.set(name, gzippedLines([...old, ...old].map((line) => lineOf(line))));
        await log.read();
        expect(beyond(capture)).toEqual([]);
        expect(log.latest(chain(3))?.seq).toBe(9n);
      });

      it('stops at the budget within a file, not after reading all of it', async () => {
        const fake = createFakeWriteOnceStore();
        const length = lineOf(anchorAt(chain(0), 1n)).length;
        expect(length).toBeLessThan(KEPT_LINE);
        // Within the file's own limit in bytes, past the budget in lines; a spoiled file, whose closing is never reached.
        spoiled(fake, 1, 0, 40);
        const { log, capture } = limited(fake, 41 * length);
        await log.read();
        expect(beyond(capture)).toHaveLength(1);
        expect(capture.lines().filter((line) => line.reason === 'unclosed')).toEqual([]);
        expect(log.state()).toBe('unreadable');
      });

      it('near_memory speaks long before the budget refuses: past half of it, in the same chains', async () => {
        const fake = createFakeWriteOnceStore();
        const mostFileBytes = 25 * KEPT_LINE;
        const { log, capture } = limited(fake, mostFileBytes);
        await log.read();
        // 13 of 25: past half, and under the budget, by the same count a read would make.
        for (let index = 0; index < 13; index += 1) log.keep(anchorAt(chain(index), 1n, LATER));
        await log.flush();
        expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_near_memory')).toHaveLength(1);
        expect(beyond(capture)).toEqual([]);
      });

      it('a lease return with every chain moved, what is held at the very limit, reads in full: nothing staged', async () => {
        const fake = createFakeWriteOnceStore();
        // A single line staged would pass this limit.
        const { log, capture } = await holding(fake, 20 * KEPT_LINE, 20);
        const moved = Array.from({ length: 20 }, (_, index) => anchorAt(chain(index), 2n));
        fake.files.set(nameOf('snapshots', 60), fileOf(nameOf('snapshots', 60), ...moved));
        await log.read();
        expect(beyond(capture)).toEqual([]);
        for (let index = 0; index < 20; index += 1) expect(log.latest(chain(index))?.seq).toBe(2n);
      });

      it('a line behind what is held changes nothing, and a chain new to this process comes in with the whole read', async () => {
        const fake = createFakeWriteOnceStore();
        const { log } = await holding(fake, 40 * KEPT_LINE, 20);
        fake.files.set(nameOf('deltas', 2), fileOf(nameOf('deltas', 2), anchorAt(chain(1), 5n)));
        await log.read();
        fake.files.set(
          nameOf('deltas', 3),
          fileOf(nameOf('deltas', 3), anchorAt(chain(1), 3n), anchorAt(chain(50), 1n)),
        );
        await log.read();
        expect(log.latest(chain(1))?.seq).toBe(5n);
        expect(log.latest(chain(50))?.seq).toBe(1n);
      });

      it('a failed read keeps what it applied, signed and higher, a new chain out, and its marks where they were', async () => {
        const fake = createFakeWriteOnceStore();
        const { log } = await holding(fake, 40 * KEPT_LINE, 20);
        const snapshot = nameOf('snapshots', 60);
        fake.files.set(snapshot, fileOf(snapshot, anchorAt(chain(0), 7n), anchorAt(chain(50), 1n)));
        const delta = nameOf('deltas', 61);
        fake.files.set(delta, fileOf(delta, anchorAt(chain(1), 7n)));
        const real = (name: string) => fake.real.get(name);
        fake.instead.get = (name) => (name === delta ? Promise.reject(new Error('the store is away')) : real(name));
        await log.read();
        expect(log.state()).toBe('read');
        expect(log.latest(chain(0))?.seq).toBe(7n);
        expect(log.latest(chain(50))).toBeUndefined();

        // Nothing moved the marks: the next read opens that snapshot again, and takes all of it.
        const opened: string[] = [];
        fake.instead.get = (name) => {
          opened.push(name);
          return real(name);
        };
        await log.read();
        expect(opened).toContain(snapshot);
        expect(log.latest(chain(50))?.seq).toBe(1n);
        expect(log.latest(chain(1))?.seq).toBe(7n);
      });

      it('a read refused past the budget keeps what it applied, a new chain out, and its marks where they were', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = await holding(fake, 20 * KEPT_LINE, 20);
        const snapshot = nameOf('snapshots', 60);
        fake.files.set(snapshot, fileOf(snapshot, anchorAt(chain(0), 7n), anchorAt(chain(50), 1n)));
        await log.read();
        expect(beyond(capture)).toHaveLength(1);
        expect(log.state()).toBe('read');
        expect(log.latest(chain(0))?.seq).toBe(7n);
        expect(log.latest(chain(50))).toBeUndefined();
        await log.read();
        expect(beyond(capture)).toHaveLength(2);
      });

      it('another hash at the place held still goes by the whole read, and is the alarm, however it arrives', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = await holding(fake, 40 * KEPT_LINE, 20);
        const other = anchorAt(chain(0), 1n, new Date(START.getTime() + MINUTE), 9);
        fake.files.set(nameOf('deltas', 5), fileOf(nameOf('deltas', 5), other));
        await log.read();
        expect(capture.lines().filter((line) => line.reason === 'fork')).toHaveLength(1);
        expect(log.latest(chain(0))?.at).toEqual(START);
      });

      it('another hash at the place held changes nothing, and says nothing, until the read is whole', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = await holding(fake, 40 * KEPT_LINE, 20);
        const held = log.latest(chain(0));
        const delta = nameOf('deltas', 5);
        // Older than what is held, so a fork would take it, were this read to settle one.
        const other = anchorAt(chain(0), 1n, new Date(START.getTime() - MINUTE), 9);
        fake.files.set(delta, fileOf(delta, other));
        const failed = nameOf('deltas', 4);
        fake.files.set(failed, fileOf(failed, anchorAt(chain(1), 1n)));
        const real = (name: string) => fake.real.get(name);
        fake.instead.get = (name) => (name === failed ? Promise.reject(new Error('the store is away')) : real(name));
        await log.read();
        expect(log.latest(chain(0))).toEqual(held);
        expect(capture.lines().filter((line) => line.reason === 'fork')).toEqual([]);
      });

      it('a fork between two files is still the alarm while reading, the older kept', async () => {
        const fake = createFakeWriteOnceStore();
        const older = anchorAt(CHAIN, 3n, START, 3);
        const newer = anchorAt(CHAIN, 3n, new Date(START.getTime() + MINUTE), 9);
        fake.files.set(nameOf('deltas', 1), fileOf(nameOf('deltas', 1), older));
        fake.files.set(nameOf('deltas', 2), fileOf(nameOf('deltas', 2), newer));
        const { log, lines: said } = logOver(fake);
        await log.read();
        expect(said('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'fork' })]);
        expect(log.latest(CHAIN)?.at).toEqual(START);
      });
    });

    describe('what is held, near what a process can hold (PL-65)', () => {
      /** The budget for 20 lines at 340 bytes, what a line held costs in its count: half of it is 10. */
      const SIZE = 20 * 340;
      const near = async (count: number) => {
        const capture = new LogCapture();
        const fake = createFakeWriteOnceStore();
        const clock = { at: LATER };
        const log = createAnchorLog({
          store: fake.store,
          keys,
          logger: testLogger(capture),
          now: () => clock.at,
          epoch: 1,
          alertAfterMs: 1000,
          mostFileBytes: SIZE,
        });
        await log.read();
        for (let index = 0; index < count; index += 1) {
          const orgId = `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`;
          log.keep(anchorAt({ kind: 'organisation', orgId }, 1n, LATER));
        }
        await log.flush();
        const said = () => capture.lines().filter((line) => line.event === 'audit.anchor_store_near_memory');
        return { log, clock, said };
      };

      it('past half of it, says so with the organisations held and where a read would stop', async () => {
        const { said } = await near(11);
        expect(said()).toEqual([
          expect.objectContaining({
            level: 'error',
            kind: 'snapshots',
            bytes: 11 * 340,
            mostBytes: SIZE,
            organisations: 11,
            edgeOrganisations: 10,
          }),
        ]);
      });

      it('at half of it, or under, says nothing', async () => {
        expect((await near(10)).said()).toEqual([]);
      });

      it('says it with each snapshot, hourly, not with every delta; the platform is no organisation', async () => {
        const { log, clock, said } = await near(11);
        log.keep(anchorAt(PLATFORM, 1n, LATER));
        clock.at = new Date(LATER.getTime() + MINUTE);
        await log.flush();
        expect(said()).toHaveLength(1);

        log.keep(anchorAt(PLATFORM, 2n, LATER));
        clock.at = new Date(LATER.getTime() + 60 * MINUTE);
        await log.flush();
        expect(said()).toEqual([
          expect.anything(),
          expect.objectContaining({ kind: 'snapshots', bytes: 12 * 340, organisations: 11 }),
        ]);
      });
    });

    it('reads a file far larger than one chunk of its opening, lines across the chunks, every one checked', async () => {
      const fake = createFakeWriteOnceStore();
      const name = nameOf('snapshots', 0);
      const many = Array.from({ length: 1000 }, (_, index) =>
        anchorAt({ kind: 'organisation', orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}` }, 1n),
      );
      fake.files.set(name, fileOf(name, ...many));
      const { log, lines } = logOver(fake);
      await log.read();
      expect(lines('audit.integrity_failed')).toEqual([]);
      expect(log.state()).toBe('read');
      expect(log.organisations()).toHaveLength(1000);
    });

    it('the same place signed later replaces the older in memory, an older one not, and neither is a fork', async () => {
      const fake = createFakeWriteOnceStore();
      const newer = new Date(START.getTime() + 60_000);
      fake.files.set(nameOf('deltas', 2), fileOf(nameOf('deltas', 2), anchorAt(CHAIN, 3n, newer)));
      fake.files.set(nameOf('deltas', 1), fileOf(nameOf('deltas', 1), anchorAt(CHAIN, 3n, START)));
      const { log, lines } = logOver(fake);
      await log.read();
      expect(log.latest(CHAIN)?.at).toEqual(newer);
      expect(lines('audit.integrity_failed')).toEqual([]);
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
      fake.files.set(planted, fileOf(planted, anchorAt(CHAIN, 999n)));
      fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), anchorAt(CHAIN, 2n)));
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
      fake.files.set(nameOf('snapshots', 60), fileOf(nameOf('snapshots', 60), anchorAt(CHAIN, 2n)));
      fake.files.set(nameOf('deltas', 65), fileOf(nameOf('deltas', 65), anchorAt(CHAIN, 3n)));
      fake.files.set('e1/snapshots/0-sorts-first', fileOf('e1/snapshots/0-sorts-first', anchorAt(CHAIN, 998n)));
      fake.files.set('e1/snapshots/z-sorts-after', fileOf('e1/snapshots/z-sorts-after', anchorAt(CHAIN, 999n)));
      const { log, lines } = logOver(fake);
      await log.read();

      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
    });

    it('says no snapshot was read where none is there', async () => {
      const { log, lines } = logOver();
      await log.read();
      expect(lines('audit.anchors_read')).toEqual([expect.objectContaining({ chains: 0, snapshot: false, deltas: 0 })]);
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

      fake.files.set(
        nameOf('deltas', 10, 7),
        fileOf(nameOf('deltas', 10, 7), anchorAt(CHAIN, 8n), anchorAt(OTHER_CHAIN, 1n)),
      );
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
      fake.files.set(nameOf('deltas', -60, 7), fileOf(nameOf('deltas', -60, 7), anchorAt(CHAIN, 8n)));
      fake.calls.gets = 0;
      await log.read();

      expect(fake.calls.gets).toBe(0);
      expect(log.latest(CHAIN)).toBeUndefined();
    });

    it("reads another copy's newer snapshot, and no older one", async () => {
      const fake = createFakeWriteOnceStore();
      const { log, advance } = await started(fake);
      advance(60);
      fake.calls.gets = 0;
      fake.files.set(nameOf('snapshots', 60, 7), fileOf(nameOf('snapshots', 60, 7), anchorAt(CHAIN, 8n)));
      fake.files.set(nameOf('snapshots', -60, 8), fileOf(nameOf('snapshots', -60, 8), anchorAt(OTHER_CHAIN, 8n)));
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

    describe('a file sent again after an overwrite is read back from its own bytes (PR1 review round 2)', () => {
      const overwriting = (fake: FakeWriteOnceStore): void => {
        fake.instead.put = async (name) => {
          await fake.real.put(name, Buffer.from('someone else'));
          throw new Error('the answer was lost');
        };
      };
      const ours = (fake: FakeWriteOnceStore, kind: 'deltas' | 'snapshots') =>
        files(fake, kind).flatMap((name) => {
          const bytes = fake.files.get(name);
          return bytes?.toString() === 'someone else' ? [] : linesIn(bytes);
        });
      const orgChain = (index: number): Chain => ({
        kind: 'organisation',
        orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
      });
      const KEPT_LINE = 340;
      const beyond = (capture: LogCapture) =>
        capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory');

      it('a line sent again keeps the stamp it had, so the snapshot that holds it settles it (K1)', async () => {
        const fake = createFakeWriteOnceStore();
        const { log } = logOver(fake, 1, keys, START);
        await log.read();
        log.keep(anchorAt(CHAIN, 2n));
        overwriting(fake);
        await log.flush();
        delete fake.instead.put;
        await log.flush();
        const puts = fake.calls.puts;
        await log.flush();
        expect(fake.calls.puts).toBe(puts);
      });

      it('a place a pass reached goes again too (K2)', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, advance } = await started(fake);
        advance(5);
        const at = new Date(START.getTime() + 5 * MINUTE);
        log.keepProgress(
          signProgress(keys, CHAIN, { seq: 40n, hash: Buffer.alloc(32, 40), macKeyVersion: 2 }, { at, began: at }, 1),
        );
        overwriting(fake);
        await log.flush();
        delete fake.instead.put;
        advance(1);
        await log.flush();
        expect(ours(fake, 'deltas').map((line) => line.k)).toEqual(['u']);
      });

      it.each([
        [
          'a hash of 31 bytes',
          (line: Anchor): Anchor => ({ ...line, hash: Buffer.alloc(31, 2) }),
          'hash',
          '02'.repeat(31),
        ],
        [
          'a chain not of its kind',
          (line: Anchor): Anchor => ({ ...line, chain: 'organisation:not-a-uuid' }),
          'chain',
          'organisation:not-a-uuid',
        ],
        [
          'a place past a count',
          (line: Anchor): Anchor => ({ ...line, seq: 10n ** 19n }),
          'seq',
          (10n ** 19n).toString(),
        ],
        ['a fractional MAC key version', (line: Anchor): Anchor => ({ ...line, macKeyVersion: 1.5 }), 'mk', 1.5],
        ['a fractional key version', (line: Anchor): Anchor => ({ ...line, keyVersion: 1.5 }), 'kv', 1.5],
      ] as const)(
        "a line whose text can't give it back is kept whole and sent again as it was: %s (K5)",
        async (_name, odd, field, value) => {
          const fake = createFakeWriteOnceStore();
          const { log, advance } = await started(fake);
          advance(5);
          log.keep(odd(anchorAt(CHAIN, 2n, new Date(START.getTime() + 5 * MINUTE))));
          overwriting(fake);
          await log.flush();
          delete fake.instead.put;
          advance(1);
          await log.flush();
          const again = ours(fake, 'deltas');
          expect(again).toHaveLength(1);
          expect(again[0]?.[field]).toEqual(value);
        },
      );

      it('an unsent file counts its stamps against what this process can hold (K3)', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = limited(fake, 11 * KEPT_LINE + 40);
        await log.read();
        for (let index = 0; index < 10; index += 1) log.keep(anchorAt(orgChain(index), 1n));
        fake.instead.put = failing;
        await log.flush();
        fake.files.set(nameOf('deltas', 60), fileOf(nameOf('deltas', 60), anchorAt(orgChain(10), 1n)));
        await log.read();
        expect(beyond(capture)).toHaveLength(1);
      });

      it('a file made and sent lets go of what it took (K4)', async () => {
        const fake = createFakeWriteOnceStore();
        const { log, capture } = limited(fake, 11 * KEPT_LINE + 50);
        await log.read();
        for (let index = 0; index < 10; index += 1) log.keep(anchorAt(orgChain(index), 1n));
        await log.flush();
        for (let index = 0; index < 5; index += 1) {
          log.keep(anchorAt(orgChain(index), 2n));
          await log.flush();
        }
        fake.files.set(nameOf('deltas', 24 * 60), fileOf(nameOf('deltas', 24 * 60), anchorAt(orgChain(10), 1n)));
        await log.read();
        expect(beyond(capture)).toEqual([]);
        expect(log.organisations()).toHaveLength(11);
      });

      it('a file being made counts what it took against a read made meanwhile (M5)', async () => {
        const fake = createFakeWriteOnceStore();
        const held = 10;
        const { log, capture } = limited(fake, (held + 1) * KEPT_LINE + 16 * held - 1);
        await log.read();
        for (let index = 0; index < held; index += 1) log.keep(anchorAt(orgChain(index), 1n));
        fake.files.set(nameOf('deltas', 60), fileOf(nameOf('deltas', 60), anchorAt(orgChain(held), 1n)));
        // The read runs while the snapshot's bytes are being gzipped: its 10 taken lines still held beside the tables.
        await Promise.all([log.flush(), log.read()]);
        expect(beyond(capture)).toHaveLength(1);
      });
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

        expect(log.latest(CHAIN)).toEqual(held);
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

describe('finished full passes, kept beside the anchors (4D2e E7)', () => {
  const passAt = (chain: Chain, seq: bigint, at = START, signing = keys, epoch = 1): Anchor =>
    signPass(signing, chain, { seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 2 }, at, epoch);

  it('writes a pass as a signed `p` line with what moved, and a restart reads it back', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    advance(5);
    const pass = passAt(CHAIN, 4n, new Date(START.getTime() + 5 * MINUTE));
    log.keepPass(pass);
    expect(log.lastPass(CHAIN)).toEqual(pass);
    await log.flush();

    const [delta] = files(fake, 'deltas');
    expect(linesIn(fake.files.get(String(delta)))).toEqual([
      {
        k: 'p',
        chain: `organisation:${ORG}`,
        seq: '4',
        hash: Buffer.alloc(32, 4).toString('hex'),
        mk: 2,
        at: pass.at.toISOString(),
        kv: 1,
        sig: pass.signature.toString('base64'),
      },
    ]);
    const again = logOver(fake);
    await again.log.read();
    expect(again.log.lastPass(CHAIN)?.at).toEqual(pass.at);
    expect(again.log.lastPass(OTHER_CHAIN)).toBeUndefined();
    // A pass is no anchor: the chain is not anchored by it.
    expect(again.log.latest(CHAIN)).toBeUndefined();
    expect(again.lines('audit.integrity_failed')).toEqual([]);
  });

  it('every snapshot holds every pass too, so a restart past the hour still knows them', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    log.keepPass(passAt(CHAIN, 4n));
    await log.flush();
    advance(60);
    log.keep(anchorAt(OTHER_CHAIN, 3n));
    await log.flush();

    const [newest] = files(fake, 'snapshots').toSorted();
    expect(linesIn(fake.files.get(String(newest))).map((line) => line.k)).toEqual(['a', 'a', 'p']);
    // Only the newest snapshot is read: what the delta held must be in it.
    for (const name of files(fake, 'deltas')) fake.files.delete(name);
    const again = logOver(fake);
    await again.log.read();
    expect(again.log.lastPass(CHAIN)?.seq).toBe(4n);
  });

  it('writes a file for a pass alone, and nothing again once it is written', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    advance(1);
    log.keepPass(passAt(CHAIN, 4n));
    await log.flush();
    expect(files(fake, 'deltas')).toHaveLength(1);
    const puts = fake.calls.puts;
    await log.flush();
    expect(fake.calls.puts).toBe(puts);
  });

  it('keeps the newest pass of a chain, whichever file is read first', async () => {
    const older = passAt(CHAIN, 4n, START);
    const newer = passAt(CHAIN, 3n, new Date(START.getTime() + MINUTE));
    for (const [first, second] of [
      [older, newer],
      [newer, older],
    ] as const) {
      const fake = createFakeWriteOnceStore();
      fake.files.set(nameOf('deltas', 0), signedFileOf(nameOf('deltas', 0), [first]));
      fake.files.set(nameOf('deltas', 5), signedFileOf(nameOf('deltas', 5), [second]));
      const { log } = logOver(fake);
      await log.read();
      expect(log.lastPass(CHAIN)?.at).toEqual(newer.at);
    }
  });

  it("SEC-DB-11 a pass line signed as an anchor, or an anchor's as a pass, is a line that fails", async () => {
    const asAnchor = anchorAt(CHAIN, 4n);
    const asPass = passAt(CHAIN, 4n);
    const fake = createFakeWriteOnceStore();
    fake.files.set(
      nameOf('deltas', 0),
      fileOf(nameOf('deltas', 0), lineOf(asAnchor, 'p'), lineOf(asPass, 'a'), anchorAt(OTHER_CHAIN, 2n)),
    );
    const { log, lines } = logOver(fake);
    await log.read();

    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 2 })]);
    expect(log.lastPass(CHAIN)).toBeUndefined();
    expect(log.latest(CHAIN)).toBeUndefined();
    expect(log.latest(OTHER_CHAIN)?.seq).toBe(2n);
  });

  it('a pass line signed for another epoch fails as an anchor line would', async () => {
    const fake = createFakeWriteOnceStore();
    fake.files.set(nameOf('deltas', 0), signedFileOf(nameOf('deltas', 0), [passAt(CHAIN, 4n, START, keys, 2)]));
    const { log, lines } = logOver(fake);
    await log.read();
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 1 })]);
    expect(log.lastPass(CHAIN)).toBeUndefined();
  });

  it('passes count against what this process can hold, with the anchors', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = Array.from({ length: 3 }, (_, index): Chain => ({
      kind: 'organisation',
      orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
    }));
    fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), ...chains.map((one) => anchorAt(one, 1n))));
    fake.files.set(
      nameOf('deltas', 5),
      signedFileOf(
        nameOf('deltas', 5),
        chains.map((one) => passAt(one, 1n)),
      ),
    );
    // Either file alone is under it; three anchors and three passes held, six lines, are past it.
    const { log, capture } = limited(fake, 1800);
    await log.read();
    expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toHaveLength(1);
  });

  it('SEC-DB-11 a name that holds other bytes: its passes go again under a new name, unless a later one waits', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    fake.instead.put = async (name) => {
      await fake.real.put(name, Buffer.from('someone else'));
      throw new Error('the answer was lost');
    };
    log.keepPass(passAt(CHAIN, 4n));
    log.keepPass(passAt(OTHER_CHAIN, 2n));
    await log.flush();
    delete fake.instead.put;
    log.keepPass(passAt(OTHER_CHAIN, 3n, new Date(START.getTime() + MINUTE)));
    await log.flush();
    advance(5);
    await log.flush();

    const written = files(fake, 'deltas').flatMap((name) => {
      const bytes = fake.files.get(name);
      return bytes?.toString() === 'someone else'
        ? []
        : linesIn(bytes).map((line) => `${String(line.k)}${String(line.seq)}`);
    });
    expect(written.toSorted()).toEqual(['p3', 'p4']);
  });
});

describe('the place a pass under way has reached, kept beside the passes (4D2e E7 review)', () => {
  const placeAt = (chain: Chain, seq: bigint, at = START, began = at): Progress =>
    signProgress(keys, chain, { seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 2 }, { at, began }, 1);

  it("keeps the latest pass's place, and of that pass the furthest, however the files are read", async () => {
    const older = placeAt(CHAIN, 90n, START, START);
    const furtherSame = placeAt(CHAIN, 50n, START, new Date(START.getTime() + MINUTE));
    const nearerSame = placeAt(CHAIN, 30n, START, new Date(START.getTime() + MINUTE));
    for (const order of [
      [older, furtherSame, nearerSame],
      [nearerSame, furtherSame, older],
    ]) {
      const fake = createFakeWriteOnceStore();
      order.forEach((line, index) => {
        fake.files.set(nameOf('deltas', index), fileOf(nameOf('deltas', index), lineOf(line, 'u')));
      });
      const { log } = logOver(fake);
      await log.read();
      expect(log.lastProgress(CHAIN)?.seq).toBe(50n);
    }
  });

  it('a place of the very pass that finished, begun at the same moment, is overtaken by it', async () => {
    const fake = createFakeWriteOnceStore();
    fake.files.set(
      nameOf('deltas', 0),
      fileOf(
        nameOf('deltas', 0),
        lineOf(placeAt(CHAIN, 40n, START, START), 'u'),
        lineOf(signPass(keys, CHAIN, { seq: 90n, hash: Buffer.alloc(32, 90), macKeyVersion: 2 }, START, 1), 'p'),
      ),
    );
    const { log } = logOver(fake);
    await log.read();
    expect(log.lastProgress(CHAIN)).toBeUndefined();
  });

  it("SEC-DB-11 a place whose pass's start was changed fails its signature", async () => {
    const place = placeAt(CHAIN, 40n);
    const changed = JSON.stringify({
      ...(JSON.parse(lineOf(place, 'u')) as object),
      b: new Date(START.getTime() + MINUTE).toISOString(),
    });
    const missing = JSON.stringify({ ...(JSON.parse(lineOf(place, 'u')) as object), b: undefined });
    const fake = createFakeWriteOnceStore();
    fake.files.set(nameOf('deltas', 0), fileOf(nameOf('deltas', 0), changed, missing));
    const { log, lines } = logOver(fake);
    await log.read();
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 2 })]);
    expect(log.lastProgress(CHAIN)).toBeUndefined();
  });

  it('writes a place as a signed `u` line, a restart reads it back, and a later finished pass overtakes it', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    advance(5);
    log.keepProgress(placeAt(CHAIN, 40n, new Date(START.getTime() + 5 * MINUTE)));
    await log.flush();
    expect(
      linesIn(fake.files.get(String(files(fake, 'deltas')[0]))).map((line) => `${String(line.k)}${String(line.seq)}`),
    ).toEqual(['u40']);

    const again = logOver(fake);
    await again.log.read();
    expect(again.log.lastProgress(CHAIN)?.seq).toBe(40n);
    expect(again.log.latest(CHAIN)).toBeUndefined();
    expect(again.lines('audit.integrity_failed')).toEqual([]);

    // A pass finished after it, in another copy's file: the place goes on to nothing.
    fake.files.set(
      nameOf('deltas', 10),
      signedFileOf(nameOf('deltas', 10), [
        signPass(
          keys,
          CHAIN,
          { seq: 90n, hash: Buffer.alloc(32, 90), macKeyVersion: 2 },
          new Date(START.getTime() + 10 * MINUTE),
          1,
        ),
      ]),
    );
    const third = logOver(fake);
    await third.log.read();
    expect(third.log.lastProgress(CHAIN)).toBeUndefined();
    // And its next snapshot leaves the overtaken place out.
    third.log.keep(anchorAt(OTHER_CHAIN, 3n));
    await third.log.flush();
    const [newest] = files(fake, 'snapshots').toSorted();
    expect(linesIn(fake.files.get(String(newest))).map((line) => line.k)).toEqual(['a', 'a', 'p']);
  });

  it("keepPass drops the chain's place: no file after holds it", async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = await started(fake);
    log.keepProgress(placeAt(CHAIN, 40n));
    log.keepProgress(placeAt(OTHER_CHAIN, 7n));
    log.keepPass(signPass(keys, CHAIN, { seq: 90n, hash: Buffer.alloc(32, 90), macKeyVersion: 2 }, START, 1));
    expect(log.lastProgress(CHAIN)).toBeUndefined();
    expect(log.lastProgress(OTHER_CHAIN)?.seq).toBe(7n);
    // Nor the delta written now: the dropped place is not even sent.
    advance(1);
    await log.flush();
    expect(
      linesIn(fake.files.get(String(files(fake, 'deltas')[0]))).map(
        (line) => `${String(line.k)} ${String(line.chain)}`,
      ),
    ).toEqual([`p organisation:${ORG}`, `u organisation:${OTHER_ORG}`]);
    advance(60);
    log.keepProgress(placeAt(OTHER_CHAIN, 8n));
    await log.flush();
    const [newest] = files(fake, 'snapshots').toSorted();
    expect(
      linesIn(fake.files.get(String(newest)))
        .map((line) => `${String(line.k)} ${String(line.chain)}`)
        .toSorted(),
    ).toEqual(['a platform', `p organisation:${ORG}`, `u organisation:${OTHER_ORG}`].toSorted());
  });

  it('a place dropped by its pass no longer counts against memory', async () => {
    const fake = createFakeWriteOnceStore();
    // An anchor and a pass are under half of it, a dropped place kept as well is not.
    const { log, capture } = limited(fake, 3000);
    await log.read();
    log.keep(anchorAt(CHAIN, 1n));
    log.keepProgress(placeAt(CHAIN, 1n));
    log.keepPass(signPass(keys, CHAIN, { seq: 1n, hash: Buffer.alloc(32, 1), macKeyVersion: 2 }, START, 1));
    await log.flush();
    expect(capture.lines().filter((line) => line.event === 'audit.anchor_store_near_memory')).toEqual([]);
  });

  it('SEC-DB-11 a place signed as a pass, or as an anchor, is a line that fails', async () => {
    const fake = createFakeWriteOnceStore();
    const asPass = signPass(keys, CHAIN, { seq: 4n, hash: Buffer.alloc(32, 4), macKeyVersion: 2 }, START, 1);
    fake.files.set(
      nameOf('deltas', 0),
      fileOf(nameOf('deltas', 0), lineOf(asPass, 'u'), lineOf(anchorAt(CHAIN, 4n), 'u')),
    );
    const { log, lines } = logOver(fake);
    await log.read();
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'signature', lines: 2 })]);
    expect(log.lastProgress(CHAIN)).toBeUndefined();
  });

  it('says when the newest file read or written was named: where the last process left off', async () => {
    expect(logOver().log.lastFileAt()).toBeUndefined();
    const fake = createFakeWriteOnceStore();
    fake.files.set(nameOf('snapshots', 0), fileOf(nameOf('snapshots', 0), anchorAt(CHAIN, 1n)));
    fake.files.set(nameOf('deltas', 30), fileOf(nameOf('deltas', 30), anchorAt(CHAIN, 2n)));
    const { log } = logOver(fake);
    await log.read();
    expect(log.lastFileAt()).toEqual(new Date(START.getTime() + 30 * MINUTE));

    const snapshotOnly = createFakeWriteOnceStore();
    snapshotOnly.files.set(nameOf('snapshots', 20), fileOf(nameOf('snapshots', 20), anchorAt(CHAIN, 1n)));
    const second = logOver(snapshotOnly);
    await second.log.read();
    expect(second.log.lastFileAt()).toEqual(new Date(START.getTime() + 20 * MINUTE));
  });
});

/** A file of pass lines as the log writes them, closed for its name. */
function signedFileOf(name: string, passes: readonly Anchor[]): Buffer {
  return fileOf(name, ...passes.map((pass) => lineOf(pass, 'p')));
}

describe('a rebase moves a chain on (4D2e E11)', () => {
  const at = (minutes: number): Date => new Date(START.getTime() + minutes * MINUTE);
  const rebaseOf = (chain: Chain, seq: bigint, minutes: number, id = 1, signing = keys): Rebase =>
    signRebase(signing, 1, {
      id: `0199a0f0-0000-7000-8000-${String(id).padStart(12, '0')}`,
      chain: chainName(chain),
      seq,
      hash: Buffer.alloc(32, Number(seq) + 100),
      macKeyVersion: 2,
      at: at(minutes),
      reason: 'repaired',
      evidence: 'INC-2026-11-05',
      from: null,
    });
  const stored = (fake: FakeWriteOnceStore, rebase: Rebase): void => {
    fake.files.set(rebaseFileName(1, rebase.id), rebaseFile(rebase));
  };
  const placeOf = (chain: Chain, seq: bigint, began: number): Progress =>
    signProgress(
      keys,
      chain,
      { seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 2 },
      { at: START, began: at(began) },
      1,
    );
  /** A store holding CHAIN anchored at 10 and OTHER_CHAIN at 7, in a snapshot at START. */
  const anchoredAtTen = (): FakeWriteOnceStore => {
    const fake = createFakeWriteOnceStore();
    const name = nameOf('snapshots', 0);
    fake.files.set(name, fileOf(name, anchorAt(CHAIN, 10n), anchorAt(OTHER_CHAIN, 7n)));
    return fake;
  };
  const chainsIn = (fake: FakeWriteOnceStore, names: readonly string[]): string[] =>
    names.flatMap((name) => linesIn(fake.files.get(name))).map((line) => `${String(line.chain)}@${String(line.seq)}`);

  it('SEC-DB-11 a signed rebase stands in for an older anchor, says so, and moves no other chain', async () => {
    const fake = anchoredAtTen();
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(10n);
    // Written while the process runs: its next read takes it in.
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    await log.read();

    expect(log.latest(CHAIN)).toMatchObject({ seq: 4n, hash: Buffer.alloc(32, 104), at: at(30) });
    expect(log.latest(OTHER_CHAIN)?.seq).toBe(7n);
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(lines('audit.rebased')).toEqual([
      expect.objectContaining({
        level: 'warn',
        orgId: ORG,
        chain: 'organisation',
        seq: '4',
        anchorSeq: '10',
        moved: true,
        reason: 'repaired',
      }),
    ]);
    expect(log.organisations().toSorted()).toEqual([ORG, OTHER_ORG]);

    // A restart takes it in again, and reads no file twice in a process.
    const after = logOver(fake);
    await after.log.read();
    expect(after.log.latest(CHAIN)?.seq).toBe(4n);
    fake.calls.gets = 0;
    await after.log.read();
    expect(fake.calls.gets).toBe(0);
  });

  it("the platform chain's rebase is said without an organisation", async () => {
    const fake = createFakeWriteOnceStore();
    stored(fake, rebaseOf(PLATFORM, 1n, 30));
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.latest(PLATFORM)?.seq).toBe(1n);
    expect(lines('audit.rebased')).toEqual([
      expect.objectContaining({ chain: 'platform', seq: '1', anchorSeq: null, moved: true }),
    ]);
    expect(lines('audit.rebased')[0]).not.toHaveProperty('orgId');
  });

  it('every line of the chain dated before it is passed over, across restarts; those after it count', async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    // Signed before the rebase, higher: the chain as it was.
    fake.files.set(nameOf('deltas', 20), fileOf(nameOf('deltas', 20), anchorAt(CHAIN, 12n, at(20))));
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(4n);

    fake.files.set(nameOf('deltas', 40), fileOf(nameOf('deltas', 40), anchorAt(CHAIN, 6n, at(40))));
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(6n);
    // A check that began on the chain as it was: its anchor is passed over, and no alarm.
    log.keep(anchorAt(CHAIN, 20n, at(29)));
    expect(log.latest(CHAIN)?.seq).toBe(6n);
    log.keep(anchorAt(CHAIN, 7n, at(50)));
    expect(log.latest(CHAIN)?.seq).toBe(7n);
    expect(lines('audit.integrity_failed')).toEqual([]);

    const after = logOver(fake);
    await after.log.read();
    expect(after.log.latest(CHAIN)?.seq).toBe(6n);
  });

  it('a snapshot leaves a chain still at its rebase out, as the rebase file holds it; a later anchor goes in', async () => {
    const fake = createFakeWriteOnceStore();
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    const { log } = logOver(fake);
    await log.read();
    // Before the rebase, waiting to be written: it goes too.
    log.keep(anchorAt(OTHER_CHAIN, 1n, LATER));
    await log.flush();
    expect(chainsIn(fake, files(fake, 'snapshots'))).toEqual([`${chainName(OTHER_CHAIN)}@1`]);

    const after = logOver(fake);
    await after.log.read();
    expect(after.log.latest(CHAIN)).toMatchObject({ seq: 4n, at: at(30) });

    // Signed again as this process's own, it is written as any anchor.
    after.log.keep(anchorAt(CHAIN, 4n, LATER, 104));
    after.advance(61);
    after.log.keep(anchorAt(OTHER_CHAIN, 2n, LATER));
    await after.log.flush();
    const newest = files(fake, 'snapshots').toSorted()[0] ?? '';
    expect(chainsIn(fake, [newest]).toSorted()).toEqual([`${chainName(CHAIN)}@4`, `${chainName(OTHER_CHAIN)}@2`]);
  });

  it('an anchor of the chain waiting to be written, from before the rebase, is never written', async () => {
    const fake = createFakeWriteOnceStore();
    const { log, advance } = logOver(fake, 1, keys, at(0));
    await log.read();
    log.keep(anchorAt(OTHER_CHAIN, 1n, at(0)));
    await log.flush();
    log.keep(anchorAt(CHAIN, 9n, at(1)));
    stored(fake, rebaseOf(CHAIN, 4n, 2));
    advance(3);
    await log.read();
    log.keep(anchorAt(OTHER_CHAIN, 2n, at(3)));
    await log.flush();
    expect(chainsIn(fake, files(fake, 'deltas'))).toEqual([`${chainName(OTHER_CHAIN)}@2`]);
  });

  it("clears the chain's place a pass reached before it, so the next resume starts again; places after it stand", async () => {
    const fake = createFakeWriteOnceStore();
    fake.files.set(nameOf('deltas', 10), fileOf(nameOf('deltas', 10), lineOf(placeOf(CHAIN, 50n, 10), 'u')));
    const { log, lines, advance } = logOver(fake);
    await log.read();
    expect(log.lastProgress(CHAIN)?.seq).toBe(50n);
    // Kept here, not written yet: the chain's goes too, the other's stays.
    log.keepProgress(placeOf(OTHER_CHAIN, 3n, 12));
    log.keepProgress(placeOf(CHAIN, 60n, 15));

    stored(fake, rebaseOf(CHAIN, 4n, 30));
    await log.read();
    expect(log.lastProgress(CHAIN)).toBeUndefined();
    expect(log.lastProgress(OTHER_CHAIN)?.seq).toBe(3n);
    expect(log.rebasedAfter(CHAIN, at(10))).toBe(true);
    expect(log.rebasedAfter(CHAIN, at(30))).toBe(false);
    expect(log.rebasedAfter(OTHER_CHAIN, at(10))).toBe(false);
    // A pass that began before it, under way still: its place goes nowhere.
    log.keepProgress(placeOf(CHAIN, 70n, 20));
    expect(log.lastProgress(CHAIN)).toBeUndefined();
    await log.flush();
    expect(chainsIn(fake, files(fake, 'snapshots'))).toEqual([`${chainName(OTHER_CHAIN)}@3`]);

    log.keepProgress(placeOf(CHAIN, 2n, 40));
    expect(log.lastProgress(CHAIN)?.seq).toBe(2n);
    advance(1);
    await log.flush();
    const after = logOver(fake);
    await after.log.read();
    expect(after.log.lastProgress(CHAIN)?.seq).toBe(2n);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('SEC-DB-11 a forged or unsigned rebase, or no rebase file at all, is refused: the alarm, once a process', async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30, 1, otherKeys));
    stored(fake, { ...rebaseOf(CHAIN, 3n, 31, 2), signature: Buffer.alloc(0) });
    fake.files.set(rebaseFileName(1, '0199a0f0-0000-7000-8000-000000000003'), gzipSync('not a rebase\n'));
    fake.files.set('e1/rebases/not-ours', Buffer.from('x'));
    const { log, lines } = logOver(fake);
    await log.read();

    expect(log.latest(CHAIN)?.seq).toBe(10n);
    expect(lines('audit.rebased')).toEqual([]);
    expect(lines('audit.integrity_failed').map((line) => [line.check, line.reason, line.problem])).toEqual([
      ['anchor_store', 'rebase', 'signature'],
      ['anchor_store', 'rebase', 'signature'],
      ['anchor_store', 'rebase', 'file'],
    ]);
    expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
    await log.read();
    expect(lines('audit.integrity_failed')).toHaveLength(3);
  });

  const SECOND = 1000;
  const seconds = (count: number): number => (count * SECOND) / MINUTE;

  it('E11 review: dated by a database clock up to 20 s ahead of this one, it stands at once; its own anchors from before pass over', async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    const { log, lines } = logOver(fake, 1, keys, new Date(at(30).getTime() - 15 * SECOND));
    await log.read();
    expect(log.latest(CHAIN)).toMatchObject({ seq: 4n, at: at(30) });
    // A check running on this clock signs the chain again where the rebase put it: dated before it, so passed over.
    log.keep(anchorAt(CHAIN, 4n, new Date(at(30).getTime() - 10 * SECOND), 104));
    expect(log.latest(CHAIN)).toMatchObject({ seq: 4n, at: at(30) });
    // Once this clock is past it, the check's anchor stands.
    log.keep(anchorAt(CHAIN, 5n, new Date(at(30).getTime() + 5 * SECOND)));
    expect(log.latest(CHAIN)?.seq).toBe(5n);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('E11 review: more than 20 s ahead of this clock it waits, the alarm each read, then stands once its time comes', async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    const { log, lines, advance } = logOver(fake, 1, keys, new Date(at(30).getTime() - 25 * SECOND));
    await log.read();
    advance(seconds(4));
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(10n);
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'rebase', problem: 'future', orgId: ORG }),
      expect.objectContaining({ reason: 'rebase', problem: 'future', orgId: ORG }),
    ]);
    advance(seconds(2));
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(4n);
  });

  it('E11 review: dated by a database clock behind this one, it stands, and only what is older than it is set aside', async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30));
    // This clock ten minutes ahead: an anchor of the old chain it signed meanwhile, on its own clock, after the rebase's time.
    fake.files.set(nameOf('deltas', 38), fileOf(nameOf('deltas', 38), anchorAt(CHAIN, 3n, at(38))));
    const { log, lines } = logOver(fake, 1, keys, at(40));
    await log.read();
    // The highest place since the rebase's time wins: the rebase's own.
    expect(log.latest(CHAIN)).toMatchObject({ seq: 4n, at: at(30) });
    log.keep(anchorAt(CHAIN, 6n, at(41)));
    expect(log.latest(CHAIN)?.seq).toBe(6n);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it("the chain's newest rebase stands, in any order read; one older than an anchor held sets aside only what is older", async () => {
    const fake = anchoredAtTen();
    stored(fake, rebaseOf(CHAIN, 4n, 30, 1));
    stored(fake, rebaseOf(CHAIN, 2n, 20, 2));
    stored(fake, rebaseOf(CHAIN, 5n, 30, 3));
    const { log } = logOver(fake);
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(4n);

    const held = createFakeWriteOnceStore();
    held.files.set(nameOf('deltas', 50), fileOf(nameOf('deltas', 50), anchorAt(CHAIN, 11n, at(50))));
    const later = logOver(held);
    await later.log.read();
    stored(held, rebaseOf(CHAIN, 4n, 30));
    await later.log.read();
    expect(later.log.latest(CHAIN)?.seq).toBe(11n);
    expect(later.lines('audit.rebased')).toEqual([expect.objectContaining({ moved: false, anchorSeq: '11' })]);
  });

  it('a rebase line in a delta is no rebase: passed over, moving nothing and raising nothing', async () => {
    const fake = anchoredAtTen();
    const line = gunzipSync(rebaseFile(rebaseOf(CHAIN, 4n, 30)))
      .toString('utf8')
      .trim();
    fake.files.set(nameOf('deltas', 40), fileOf(nameOf('deltas', 40), line));
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(10n);
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(lines('audit.rebased')).toEqual([]);
  });

  it('a failed list of the rebases is a failed read: nothing of it taken in', async () => {
    const fake = anchoredAtTen();
    fake.instead.list = (start, most, after) =>
      start.includes('/rebases/') ? failing() : fake.real.list(start, most, after);
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.state()).toBe('unreadable');
    expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
  });

  it('a rebase file past any rebase is no rebase: never fetched whole, the alarm, and the read goes on', async () => {
    const fake = anchoredAtTen();
    const name = rebaseFileName(1, '00000000-0000-4000-8000-0000000000aa');
    fake.files.set(name, Buffer.alloc(4097));
    const asked: number[] = [];
    fake.instead.getAtMost = (got, most) => {
      if (got === name) asked.push(most);
      return fake.real.getAtMost(got, most);
    };
    const { log, lines } = logOver(fake);
    await log.read();
    expect(asked).toEqual([4096]);
    expect(log.state()).toBe('read');
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ check: 'anchor_store', reason: 'rebase', problem: 'file', file: name }),
    ]);
    expect(fake.calls.gets).toBe(1);
  });

  it('a rebase file there but unreadable by a plain read is no rebase: the alarm, and the read goes on', async () => {
    const fake = anchoredAtTen();
    const name = rebaseFileName(1, '00000000-0000-4000-8000-0000000000aa');
    fake.files.set(name, Buffer.alloc(10));
    fake.instead.getAtMost = (asked, most) =>
      asked === name ? Promise.resolve('unreadable') : fake.real.getAtMost(asked, most);
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.state()).toBe('read');
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'rebase', problem: 'file', file: name }),
    ]);
  });

  it('a rebase file listed and then not there is a failed read', async () => {
    const fake = anchoredAtTen();
    const name = rebaseFileName(1, '00000000-0000-4000-8000-0000000000aa');
    fake.files.set(name, Buffer.alloc(10));
    fake.instead.getAtMost = (asked, most) =>
      asked === name ? Promise.resolve('missing') : fake.real.getAtMost(asked, most);
    const { log, lines } = logOver(fake);
    await log.read();
    expect(log.state()).toBe('unreadable');
    expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
  });

  it('lists the rebases a page at a time', async () => {
    const fake = createFakeWriteOnceStore();
    for (let id = 1; id <= 101; id += 1) stored(fake, rebaseOf(id % 2 === 0 ? CHAIN : OTHER_CHAIN, BigInt(id), id, id));
    const { log } = logOver(fake, 1, keys, at(200));
    await log.read();
    expect(log.latest(CHAIN)?.seq).toBe(100n);
    expect(log.latest(OTHER_CHAIN)?.seq).toBe(101n);
  });
});
