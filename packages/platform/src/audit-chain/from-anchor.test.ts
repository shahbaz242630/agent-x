// 4D2e E1: checking a chain from its last anchor, a step of a full pass, and a
// count, on a store in memory. One test for each row of the design's table of
// what verifyChain proves: wound back, tail removed, events past the head, an
// event edited after the anchor, the anchored event edited, and the MAC key's
// version going backwards, which is the trap in starting part way along.
import { createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyProvider, type PurposeKeys } from '../keys/key-provider.ts';
import { encodeMessage, type Message } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import {
  type Chain,
  CHAIN_START,
  type ChainHead,
  chainName,
  type CheckedPoint,
  GENESIS_HASH,
  genesisHead,
  linkHash,
  sealNext,
  type StoredEntry,
} from './chain.ts';
import {
  type ChainEdgeReader,
  type ChainEdges,
  ChainStoreError,
  countStep,
  passStep,
  verifyFromAnchor,
} from './store.ts';

const AUDIT_MAC = PURPOSES.indexOf('audit-mac') + 1;
const fill = (byte: number): Buffer => Buffer.alloc(32, byte);

function provider(auditMac?: PurposeKeys): KeyProvider {
  return createKeyProvider(
    byPurpose((purpose) =>
      purpose === 'audit-mac' && auditMac !== undefined
        ? auditMac
        : { current: 1, versions: new Map([[1, fill(PURPOSES.indexOf(purpose) + 1)]]) },
    ),
  );
}

/** Version 1 and 2 of the MAC key, `current` the one events are sealed with. */
const macKeys = (current: number): PurposeKeys => ({
  current,
  versions: new Map([
    [1, fill(AUDIT_MAC)],
    [2, fill(99)],
  ]),
});

const keys = provider();
const CHAIN: Chain = { kind: 'platform' };
const RECORDED_AT = new Date('2026-09-19T08:00:00.123Z');

const entryAt = (seq: bigint, content: Message = ['action', `step.${seq.toString()}`]) => ({
  seq,
  id: `0199a0f0-0000-7000-8000-${seq.toString().padStart(12, '0')}`,
  recordedAt: RECORDED_AT,
  content,
});

/** A chain's tables in memory, with what a test does to them past the app. */
class Tables implements ChainEdgeReader {
  head: ChainHead | 'none' | 'unreadable';
  rows: StoredEntry[] = [];
  unreadable = new Set<bigint>();
  /** The numbers the edges were asked about, and the events asked for, per trip. */
  edgeTrips: bigint[] = [];
  pages: { after: bigint; upTo: bigint; limit: number }[] = [];
  /** A store that gives fewer events than it holds, ending early. */
  stopsAt: bigint | undefined;
  /** Changes what edges() says, for a store that breaks its contract. */
  edgesAs: ((edges: ChainEdges) => ChainEdges) | undefined;
  /** Replaces what events() gives. */
  pageAs: ((rows: (StoredEntry | undefined)[]) => (StoredEntry | undefined)[]) | undefined;

  private readonly sealing: KeyProvider;

  constructor(sealing: KeyProvider = keys, count = 0) {
    this.sealing = sealing;
    this.head = genesisHead(sealing, CHAIN);
    this.grow(count);
  }

  grow(count: number, sealing: KeyProvider = this.sealing): this {
    for (let n = 0; n < count; n += 1) {
      const head = this.head as ChainHead;
      const entry = entryAt(head.seq + 1n);
      const sealed = sealNext(sealing, CHAIN, head, entry);
      this.rows.push({ ...entry, ...sealed.link });
      this.head = sealed.head;
    }
    return this;
  }

  row(seq: bigint): StoredEntry {
    const found = this.rows.find((row) => row.seq === seq);
    if (found === undefined) throw new Error('The test expected that event');
    return found;
  }

  /** Where the check would have anchored: the event numbered `seq`, as signed. */
  point(seq: bigint): CheckedPoint {
    const { hash, macKeyVersion } = this.row(seq);
    return { seq, hash, macKeyVersion };
  }

  remove(seq: bigint): void {
    this.rows = this.rows.filter((row) => row.seq !== seq);
  }

  replace(seq: bigint, row: StoredEntry): void {
    this.rows = this.rows.map((each) => (each.seq === seq ? row : each));
  }

  /** The genuine head the chain had at `seq`: every earlier head was once sealed, which is what winding back relies on. */
  headAt(seq: bigint, sealing: KeyProvider = this.sealing): ChainHead {
    let head = genesisHead(sealing, CHAIN);
    for (let at = 1n; at <= seq; at += 1n) head = sealNext(sealing, CHAIN, head, entryAt(at)).head;
    return head;
  }

  edges(anchored: bigint): Promise<ChainEdges> {
    this.edgeTrips.push(anchored);
    const numbers = this.rows.map(({ seq }) => seq);
    const sorted = numbers.toSorted((a, b) => Number(a - b));
    const { head } = this;
    const edges: ChainEdges = {
      head,
      lowest: sorted[0] ?? null,
      highest: sorted.at(-1) ?? null,
      headEventHash: typeof head === 'string' ? undefined : this.rows.find(({ seq }) => seq === head.seq)?.hash,
      anchored: this.unreadable.has(anchored) ? undefined : this.rows.find(({ seq }) => seq === anchored),
    };
    return Promise.resolve(this.edgesAs?.(edges) ?? edges);
  }

  events(after: bigint, upTo: bigint, limit: number): Promise<(StoredEntry | undefined)[]> {
    this.pages.push({ after, upTo, limit });
    const rows = this.rows
      .filter(({ seq }) => seq > after && seq <= upTo && (this.stopsAt === undefined || seq <= this.stopsAt))
      .toSorted((a, b) => Number(a.seq - b.seq))
      .slice(0, limit)
      .map((row) => (this.unreadable.has(row.seq) ? undefined : row));
    return Promise.resolve(this.pageAs?.(rows) ?? rows);
  }

  countBetween(after: bigint, upTo: bigint): Promise<bigint> {
    return Promise.resolve(BigInt(this.rows.filter(({ seq }) => seq > after && seq <= upTo).length));
  }
}

const refusal = (reason: string, seq: bigint) => ({ ok: false, problem: { reason, seq } });

describe('checking from an anchor (4D2e E1)', () => {
  it('walks only the events past the anchor, one read of the edges and one page, and says where it stands', async () => {
    const tables = new Tables(keys, 8);

    const report = await verifyFromAnchor(keys, CHAIN, tables, tables.point(5n));

    expect(report).toEqual({ ok: true, seq: 8n, hash: tables.row(8n).hash, macKeyVersion: 1, to: 8n });
    expect(tables.edgeTrips).toEqual([5n]);
    expect(tables.pages).toEqual([{ after: 5n, upTo: 8n, limit: 500 }]);
  });

  it('takes a chain that has not moved in the one read', async () => {
    const tables = new Tables(keys, 3);

    expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(3n))).toMatchObject({ ok: true, seq: 3n, to: 3n });
    expect(tables.pages).toEqual([]);
  });

  it('from the start of a chain, reads it all; on a chain with no events, reports it empty', async () => {
    const tables = new Tables(keys, 2);
    const empty = new Tables(keys, 0);

    expect(await verifyFromAnchor(keys, CHAIN, tables, CHAIN_START)).toMatchObject({ ok: true, seq: 2n });
    expect(await verifyFromAnchor(keys, CHAIN, empty, CHAIN_START)).toEqual({
      ok: true,
      seq: 0n,
      hash: GENESIS_HASH,
      macKeyVersion: 0,
      to: 0n,
    });
    expect(empty.pages).toEqual([]);
  });

  it('stops at its limit, good as far as it went, and the next step goes on from there', async () => {
    const tables = new Tables(keys, 7);

    const first = await verifyFromAnchor(keys, CHAIN, tables, tables.point(1n), 4);
    expect(first).toMatchObject({ ok: true, seq: 5n, to: 7n, hash: tables.row(5n).hash });
    if (!first.ok) throw new Error('The step should pass');

    expect(await verifyFromAnchor(keys, CHAIN, tables, first, 4)).toMatchObject({ ok: true, seq: 7n, to: 7n });
  });

  it('a step short of the head is not compared with it; a step ending exactly at it is', async () => {
    const tables = new Tables(keys, 5);
    const entry = entryAt(5n, ['action', 'other']);
    const sealed = sealNext(keys, CHAIN, tables.headAt(4n), entry);
    tables.pageAs = (rows) => rows.map((row) => (row?.seq === 5n ? { ...entry, ...sealed.link } : row));

    expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(1n), 3)).toMatchObject({
      ok: true,
      seq: 4n,
      to: 5n,
    });
    expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(1n), 4)).toEqual(refusal('head', 5n));
  });

  it.each([0, -1, 1.5])('refuses a step of %s events, before any read', async (most) => {
    const tables = new Tables(keys, 2);

    await expect(verifyFromAnchor(keys, CHAIN, tables, CHAIN_START, most)).rejects.toThrow(RangeError);
    expect(tables.edgeTrips).toEqual([]);
  });

  describe('the head (design: head MAC, every run)', () => {
    it('refuses a head whose MAC is wrong', async () => {
      const tables = new Tables(keys, 3);
      tables.head = { ...(tables.head as ChainHead), mac: fill(1) };

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(3n))).toEqual(refusal('head', 3n));
    });

    it('refuses a head that cannot be read', async () => {
      const tables = new Tables(keys, 3);
      const from = tables.point(3n);
      tables.head = 'unreadable';

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 0n));
    });
  });

  describe('wound back (design: head.seq, anchored event against anchor)', () => {
    it('refuses a head and tail wound back together, every event left whole', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(5n);
      tables.remove(5n);
      tables.remove(4n);
      tables.head = tables.headAt(3n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('anchor', 5n));
    });

    it('refuses a head behind the anchor by the head alone, whatever a failing store says of the anchored event', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(5n);
      const anchored = tables.row(5n);
      tables.remove(5n);
      tables.remove(4n);
      tables.head = tables.headAt(3n);
      // Redundant with the anchored event being gone, in a store that keeps its contract: a security check, kept.
      tables.edgesAs = (edges) => ({ ...edges, anchored });

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('anchor', 5n));
    });

    it('refuses a chain wound back and grown again past the anchor: another event stands where the anchored one was', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(5n);
      // Grown again from event 3 with events of other content: every one sealed, as only a key holder could.
      tables.remove(5n);
      tables.remove(4n);
      tables.head = tables.headAt(3n);
      for (const seq of [4n, 5n, 6n]) {
        const head = tables.head;
        const entry = entryAt(seq, ['action', `regrown.${seq.toString()}`]);
        const sealed = sealNext(keys, CHAIN, head, entry);
        tables.rows.push({ ...entry, ...sealed.link });
        tables.head = sealed.head;
      }

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('anchor', 5n));
    });

    it('refuses a head removed where the chain had been anchored, with or without events', async () => {
      const tables = new Tables(keys, 2);
      const from = tables.point(2n);
      tables.head = 'none';
      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 0n));

      tables.rows = [];
      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('anchor', 2n));
    });

    it('reads a chain never started, from the start, as empty; events with no head are the alarm', async () => {
      const tables = new Tables(keys, 0);
      tables.head = 'none';
      expect(await verifyFromAnchor(keys, CHAIN, tables, CHAIN_START)).toMatchObject({ ok: true, seq: 0n, to: 0n });

      tables.rows = new Tables(keys, 1).rows;
      expect(await verifyFromAnchor(keys, CHAIN, tables, CHAIN_START)).toEqual(refusal('head', 0n));
    });
  });

  describe('the tail (design: hash at head = head hash; max(seq) = head)', () => {
    it('refuses a tail removed, the head left', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(3n);
      tables.remove(5n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 5n));
    });

    it('refuses every event removed, the head left', async () => {
      const tables = new Tables(keys, 2);
      tables.rows = [];

      expect(await verifyFromAnchor(keys, CHAIN, tables, CHAIN_START)).toEqual(refusal('head', 2n));
    });

    it('refuses events past the head, even a head that has not moved, reading no event', async () => {
      const tables = new Tables(keys, 3);
      const from = tables.point(3n);
      const genuine = tables.head;
      tables.grow(1);
      tables.head = genuine;

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 3n));
      expect(tables.pages).toEqual([]);
    });

    it('refuses events past a wound-back head as events past the head, as the whole check does', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(5n);
      tables.head = tables.headAt(3n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 3n));
    });

    it('refuses an event on a chain whose head is at its start', async () => {
      const tables = new Tables(keys, 1);
      tables.head = genesisHead(keys, CHAIN);

      expect(await verifyFromAnchor(keys, CHAIN, tables, CHAIN_START)).toEqual(refusal('head', 0n));
    });

    it('refuses another hash stored at the head, the event at the head being one the head does not name', async () => {
      const tables = new Tables(keys, 3);
      tables.replace(3n, { ...tables.row(3n), hash: fill(5) });

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(2n))).toEqual(refusal('head', 3n));
    });

    it('refuses a walk ending on a hash other than the head holds, though the edges agreed', async () => {
      const tables = new Tables(keys, 3);
      const entry = entryAt(3n, ['action', 'other']);
      const sealed = sealNext(keys, CHAIN, tables.headAt(2n), entry);
      tables.pageAs = (rows) => rows.map((row) => (row?.seq === 3n ? { ...entry, ...sealed.link } : row));

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(2n))).toEqual(refusal('head', 3n));
    });
  });

  describe('the start (design: min(seq) = 1)', () => {
    it('refuses the first events removed, wherever the anchor stands', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(4n);
      tables.remove(1n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('gap', 1n));
    });

    it('refuses an event at a number the check would never read', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(4n);
      tables.rows.push({ ...tables.row(1n), seq: 0n });

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('head', 5n));
    });

    it('allows exactly 1 as the lowest', async () => {
      const tables = new Tables(keys, 1);

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(1n))).toMatchObject({ ok: true });
    });
  });

  describe('the anchored event (design: the anchored event against the anchor)', () => {
    it('refuses it edited, its hash recomputed: its MAC no longer stands', async () => {
      const tables = new Tables(keys, 3);
      const from = tables.point(2n);
      const edited = { ...tables.row(2n), content: ['action', 'edited'] as Message };
      tables.replace(2n, edited);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('anchor', 2n));
    });

    it('refuses it gone, or its row unreadable', async () => {
      const gone = new Tables(keys, 3);
      const from = gone.point(2n);
      gone.remove(2n);
      expect(await verifyFromAnchor(keys, CHAIN, gone, from)).toEqual(refusal('anchor', 2n));

      const unreadable = new Tables(keys, 3);
      unreadable.unreadable.add(2n);
      expect(await verifyFromAnchor(keys, CHAIN, unreadable, from)).toEqual(refusal('anchor', 2n));
    });

    it('refuses a whole, sealed event that is not the one anchored', async () => {
      const tables = new Tables(keys, 3);

      expect(await verifyFromAnchor(keys, CHAIN, tables, { ...tables.point(2n), hash: fill(7) })).toEqual(
        refusal('anchor', 2n),
      );
    });

    it('refuses an anchor naming another MAC key version than the event was sealed with', async () => {
      const tables = new Tables(keys, 3);

      expect(await verifyFromAnchor(keys, CHAIN, tables, { ...tables.point(2n), macKeyVersion: 2 })).toEqual(
        refusal('anchor', 2n),
      );
    });

    it('refuses a start of the chain that is not the start', async () => {
      const tables = new Tables(keys, 1);

      expect(await verifyFromAnchor(keys, CHAIN, tables, { ...CHAIN_START, hash: fill(7) })).toEqual(
        refusal('anchor', 0n),
      );
      expect(await verifyFromAnchor(keys, CHAIN, tables, { ...CHAIN_START, macKeyVersion: 1 })).toEqual(
        refusal('anchor', 0n),
      );
    });
  });

  describe('the events past the anchor (design: link, hash, MAC walk)', () => {
    it('refuses one edited', async () => {
      const tables = new Tables(keys, 4);
      const from = tables.point(2n);
      tables.replace(3n, { ...tables.row(3n), content: ['action', 'edited'] });

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('hash', 3n));
    });

    it('refuses one missing in the middle, at its place', async () => {
      const tables = new Tables(keys, 5);
      const from = tables.point(2n);
      tables.remove(4n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('gap', 4n));
    });

    it('refuses one unreadable, at its place', async () => {
      const tables = new Tables(keys, 4);
      const from = tables.point(2n);
      tables.unreadable.add(3n);

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('unreadable', 3n));
    });

    it('refuses the first event past the anchor not linked to the anchored one', async () => {
      const tables = new Tables(keys, 3);
      const from = { ...tables.point(2n) };
      tables.replace(3n, { ...tables.row(3n), prevHash: fill(5) });

      expect(await verifyFromAnchor(keys, CHAIN, tables, from)).toEqual(refusal('link', 3n));
    });

    it('refuses a store that runs out of events short of where it was asked, at the place it stopped', async () => {
      const tables = new Tables(keys, 5);
      tables.stopsAt = 3n;

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(2n))).toEqual(refusal('gap', 4n));
    });

    it('reads on until the head, whatever page size the store gives', async () => {
      const tables = new Tables(keys, 8);
      tables.pageAs = (rows) => rows.slice(0, 2);

      expect(await verifyFromAnchor(keys, CHAIN, tables, tables.point(1n))).toMatchObject({ ok: true, seq: 8n });
      expect(tables.pages.map(({ after }) => after)).toEqual([1n, 3n, 5n, 7n]);
    });

    it('throws for a store giving more than asked, or an event past where it was asked', async () => {
      const many = new Tables(keys, 3);
      const row = many.row(3n);
      many.pageAs = () => Array.from({ length: 501 }, () => row);
      await expect(verifyFromAnchor(keys, CHAIN, many, many.point(2n))).rejects.toThrow(ChainStoreError);

      const past = new Tables(keys, 4);
      const beyond = past.row(4n);
      past.pageAs = () => [beyond];
      await expect(verifyFromAnchor(keys, CHAIN, past, past.point(2n), 1)).rejects.toThrow(ChainStoreError);
    });
  });

  describe('the MAC key going backwards: the trap in starting part way (ADR-012 §2)', () => {
    /** An event sealed under key version 1, as whoever copied that key before it was rotated out could make. */
    function withOldKey(previous: Buffer, seq: bigint): StoredEntry {
      const entry = entryAt(seq, ['action', 'added.with.an.old.key']);
      const hash = linkHash(CHAIN, previous, entry);
      const mac = createHmac('sha256', fill(AUDIT_MAC))
        .update(encodeMessage(['audit-event', chainName(CHAIN), seq.toString(), entry.id, hash]))
        .digest();
      return { ...entry, prevHash: previous, hash, mac, macKeyVersion: 1 };
    }

    /** A chain rotated to version 2 at its third event, this process holding both. */
    const rotated = provider(macKeys(2));
    const afterRotation = (): Tables => new Tables(provider(macKeys(1)), 2).grow(2, rotated);

    it('passes events sealed with a newer version than the anchor saw: a rotation is no alarm', async () => {
      const tables = afterRotation();
      const report = await verifyFromAnchor(rotated, CHAIN, tables, tables.point(2n));

      expect(tables.point(2n).macKeyVersion).toBe(1);
      expect(report).toMatchObject({ ok: true, seq: 4n, macKeyVersion: 2 });
    });

    it('refuses an event after the anchor sealed with an older version than the anchor signed', async () => {
      const tables = afterRotation();
      const from = tables.point(4n);
      // The head can be forged too, with the same copied key: the walk is what finds it.
      const event = withOldKey(from.hash, 5n);
      const head: ChainHead = {
        seq: 5n,
        hash: event.hash,
        macKeyVersion: 1,
        mac: createHmac('sha256', fill(AUDIT_MAC))
          .update(encodeMessage(['audit-head', chainName(CHAIN), '5', event.hash]))
          .digest(),
      };
      tables.rows.push(event);
      tables.head = head;

      expect(await verifyFromAnchor(rotated, CHAIN, tables, from)).toEqual(refusal('mac', 5n));
    });

    it('takes that event only from a place naming the older version: the reason the version is signed', async () => {
      const tables = afterRotation();
      const from = tables.point(4n);
      const event = withOldKey(from.hash, 5n);
      tables.rows.push(event);
      const target = { ...event, macKeyVersion: 1 };

      expect(from.macKeyVersion).toBe(2);
      expect(await passStep(rotated, CHAIN, tables, from, target, 10)).toEqual(refusal('mac', 5n));
      expect(await passStep(rotated, CHAIN, tables, { ...from, macKeyVersion: 1 }, target, 10)).toMatchObject({
        ok: true,
        seq: 5n,
      });
    });

    it('refuses the anchored event sealed again under the older version, whose hash is unchanged', async () => {
      const tables = afterRotation();
      const from = tables.point(4n);
      const row = tables.row(4n);
      const mac = createHmac('sha256', fill(AUDIT_MAC))
        .update(encodeMessage(['audit-event', chainName(CHAIN), '4', row.id, row.hash]))
        .digest();
      tables.replace(4n, { ...row, mac, macKeyVersion: 1 });

      expect(await verifyFromAnchor(rotated, CHAIN, tables, from)).toEqual(refusal('anchor', 4n));
    });
  });
});

describe('a step of a full pass (4D2e E1)', () => {
  const walked = async (tables: Tables, target: CheckedPoint, most: number) => {
    const steps = [];
    let cursor = CHAIN_START;
    for (;;) {
      const step = await passStep(keys, CHAIN, tables, cursor, target, most);
      steps.push(step);
      if (!step.ok || step.seq === step.to) return steps;
      cursor = step;
    }
  };

  it('reads one page a step, from the start to where it set out for, and no further', async () => {
    const tables = new Tables(keys, 7);
    const steps = await walked(tables, tables.point(5n), 2);

    expect(steps.map((step) => (step.ok ? step.seq : -1n))).toEqual([2n, 4n, 5n]);
    expect(steps.at(-1)).toMatchObject({ to: 5n, hash: tables.row(5n).hash, macKeyVersion: 1 });
    expect(tables.pages).toEqual([
      { after: 0n, upTo: 2n, limit: 2 },
      { after: 2n, upTo: 4n, limit: 2 },
      { after: 4n, upTo: 5n, limit: 2 },
    ]);
  });

  it('finds an old event edited, and one deleted, at its place', async () => {
    const edited = new Tables(keys, 5);
    const target = edited.point(5n);
    edited.replace(2n, { ...edited.row(2n), content: ['action', 'edited'] });
    expect((await walked(edited, target, 10)).at(-1)).toEqual(refusal('hash', 2n));

    const deleted = new Tables(keys, 5);
    deleted.remove(2n);
    expect((await walked(deleted, target, 10)).at(-1)).toEqual(refusal('gap', 2n));
  });

  it('finds an old event sealed under a version below one before it, from where the cursor stands', async () => {
    const rotated = provider(macKeys(2));
    const tables = new Tables(provider(macKeys(1)), 1).grow(2, rotated);
    const row = tables.row(3n);
    const mac = createHmac('sha256', fill(AUDIT_MAC))
      .update(encodeMessage(['audit-event', chainName(CHAIN), '3', row.id, row.hash]))
      .digest();
    tables.replace(3n, { ...row, mac, macKeyVersion: 1 });

    expect(await passStep(rotated, CHAIN, tables, tables.point(2n), tables.point(2n), 1)).toMatchObject({ ok: true });
    expect(await passStep(rotated, CHAIN, tables, tables.point(2n), { ...row, macKeyVersion: 1 }, 5)).toEqual(
      refusal('mac', 3n),
    );
  });

  it('refuses reaching where it set out for on another hash, or another key version', async () => {
    const tables = new Tables(keys, 2);

    expect(await passStep(keys, CHAIN, tables, CHAIN_START, { ...tables.point(2n), hash: fill(5) }, 5)).toEqual(
      refusal('anchor', 2n),
    );
    expect(await passStep(keys, CHAIN, tables, CHAIN_START, { ...tables.point(2n), macKeyVersion: 2 }, 5)).toEqual(
      refusal('anchor', 2n),
    );
  });

  it('does not compare a hash short of where it set out for', async () => {
    const tables = new Tables(keys, 3);

    expect(await passStep(keys, CHAIN, tables, CHAIN_START, tables.point(3n), 1)).toMatchObject({
      ok: true,
      seq: 1n,
      to: 3n,
    });
  });

  it('goes on from a page shorter than asked, and calls a store with nothing left a gap', async () => {
    const short = new Tables(keys, 4);
    short.pageAs = (rows) => rows.slice(0, 1);
    expect(await passStep(keys, CHAIN, short, CHAIN_START, short.point(4n), 3)).toMatchObject({ ok: true, seq: 3n });

    const gone = new Tables(keys, 4);
    const target = gone.point(4n);
    gone.rows = [];
    expect(await passStep(keys, CHAIN, gone, CHAIN_START, target, 3)).toEqual(refusal('gap', 1n));
  });

  it('has nothing to read at its end, and refuses a cursor past it or a step of nothing', async () => {
    const tables = new Tables(keys, 2);

    expect(await passStep(keys, CHAIN, tables, tables.point(2n), tables.point(2n), 5)).toMatchObject({
      ok: true,
      seq: 2n,
      to: 2n,
    });
    expect(tables.pages).toEqual([]);
    await expect(passStep(keys, CHAIN, tables, tables.point(2n), tables.point(1n), 5)).rejects.toThrow(RangeError);
    await expect(passStep(keys, CHAIN, tables, CHAIN_START, tables.point(1n), 0)).rejects.toThrow(RangeError);
  });

  it('throws for a store giving more than the step asked', async () => {
    const tables = new Tables(keys, 3);
    const row = tables.row(1n);
    tables.pageAs = () => [row, row];

    await expect(passStep(keys, CHAIN, tables, CHAIN_START, tables.point(3n), 1)).rejects.toThrow(ChainStoreError);
  });
});

describe('counting a stretch of a chain (4D2e E1)', () => {
  it('passes a stretch with every event there, whichever events lie outside it', async () => {
    const tables = new Tables(keys, 5);
    tables.remove(1n);

    expect(await countStep(tables, 2n, 5n)).toBeUndefined();
  });

  it('finds a stretch short of an event, and says where the stretch starts', async () => {
    const tables = new Tables(keys, 5);
    tables.remove(4n);

    expect(await countStep(tables, 2n, 5n)).toEqual({ reason: 'gap', seq: 3n });
  });

  it('finds a stretch holding more than it can, a key dropped and a number doubled', async () => {
    const tables = new Tables(keys, 3);
    tables.rows.push(tables.row(2n));

    expect(await countStep(tables, 0n, 3n)).toEqual({ reason: 'gap', seq: 1n });
  });

  it('counts just the last event of a stretch of one, and refuses a stretch of none', async () => {
    const tables = new Tables(keys, 2);

    expect(await countStep(tables, 1n, 2n)).toBeUndefined();
    await expect(countStep(tables, 2n, 2n)).rejects.toThrow(RangeError);
  });
});
