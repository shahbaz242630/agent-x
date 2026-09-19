import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Chain, type ChainHead, GENESIS_HASH, genesisHead, type StoredEntry } from './chain.ts';
import {
  appendEvent,
  ChainBroken,
  type ChainReader,
  ChainStoreError,
  type ChainWriter,
  headFields,
  sealedFields,
  verifyChain,
} from './store.ts';

const keys: KeyProvider = createKeyProvider(
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]),
  })) satisfies KeyMaterial,
);

const CHAIN: Chain = { kind: 'platform' };
const NOW = new Date('2026-09-19T08:00:00.123Z');
const CONTENT: Message = ['action', 'probe.stepped'];
const id = (n: number): string => `0199a0f0-0000-7000-8000-${n.toString().padStart(12, '0')}`;

/**
 * A chain's tables in memory, as a module's store would keep them in Postgres:
 * the head (or none, or a row that can't be read) and the events, some of
 * which a test can make unreadable.
 */
class MemoryChain implements ChainWriter, ChainReader {
  head: ChainHead | 'none' | 'unreadable' = 'none';
  rows: StoredEntry[] = [];
  unreadable = new Set<bigint>();
  /** Every call made, in order. */
  calls: string[] = [];
  /** A store that never shows the head it was given, to test a start that doesn't take. */
  loses = false;
  /** Someone else moves the head between the lock and the write, as with a store that didn't lock. */
  racedBy: ChainHead | undefined;
  /** The most events one page gives, whatever was asked: a store that pages differently. */
  pageSize = Number.POSITIVE_INFINITY;
  /** How many pages of events the check has asked for. */
  pages = 0;

  lockHead(): Promise<{ head: ChainHead | undefined } | undefined> {
    this.calls.push('lockHead');
    if (this.head === 'none') return Promise.resolve(undefined);
    return Promise.resolve({ head: this.head === 'unreadable' ? undefined : this.head });
  }

  start(head: ChainHead): Promise<void> {
    this.calls.push('start');
    if (this.head === 'none' && !this.loses) this.head = head;
    return Promise.resolve();
  }

  hasEventsPast(seq: bigint): Promise<boolean> {
    this.calls.push('hasEventsPast');
    return Promise.resolve(this.rows.some((event) => event.seq > seq));
  }

  now(): Promise<Date> {
    this.calls.push('now');
    return Promise.resolve(NOW);
  }

  append(event: Omit<StoredEntry, 'content'>, head: ChainHead, previous: ChainHead): Promise<boolean> {
    this.calls.push('append');
    if (this.racedBy !== undefined) this.head = this.racedBy;
    const current = this.head;
    if (typeof current === 'string' || current.seq !== previous.seq || !current.hash.equals(previous.hash)) {
      return Promise.resolve(false);
    }
    this.head = head;
    this.rows.push({ ...event, content: CONTENT });
    return Promise.resolve(true);
  }

  state(): Promise<{ head: ChainHead | 'none' | 'unreadable'; stored: bigint }> {
    return Promise.resolve({ head: this.head, stored: BigInt(this.rows.length) });
  }

  events(after: bigint, upTo: bigint, limit: number): Promise<(StoredEntry | undefined)[]> {
    this.pages += 1;
    const rows = this.rows
      .filter((event) => event.seq > after && event.seq <= upTo)
      .sort((a, b) => Number(a.seq - b.seq))
      .slice(0, Math.min(limit, this.pageSize));
    return Promise.resolve(rows.map((event) => (this.unreadable.has(event.seq) ? undefined : event)));
  }
}

/** A chain of `count` events appended through the steps under test. */
async function chainOf(count: number): Promise<MemoryChain> {
  const memory = new MemoryChain();
  for (let n = 1; n <= count; n += 1) await appendEvent(keys, CHAIN, memory, { nextId: () => id(n), content: CONTENT });
  return memory;
}

describe('appending an event', () => {
  it('starts the chain, takes the next place, and checks out', async () => {
    const memory = new MemoryChain();
    const first = await appendEvent(keys, CHAIN, memory, { nextId: () => id(1), content: CONTENT });
    const second = await appendEvent(keys, CHAIN, memory, { nextId: () => id(2), content: CONTENT });

    expect([first.seq, second.seq]).toEqual([1n, 2n]);
    expect(second.prevHash).toEqual(first.hash);
    expect(first.recordedAt).toBe(NOW);
    expect(await verifyChain(keys, CHAIN, memory)).toEqual({ ok: true, seq: 2n, hash: second.hash });
  });

  it('reads the time only once the head is locked and found clean, then writes', async () => {
    const memory = await chainOf(1);
    memory.calls = [];
    await appendEvent(keys, CHAIN, memory, { nextId: () => id(2), content: CONTENT });

    expect(memory.calls).toEqual(['lockHead', 'hasEventsPast', 'now', 'append']);
  });

  it('writes the ID in lower case, as Postgres returns a uuid', async () => {
    const sealed = await appendEvent(keys, CHAIN, new MemoryChain(), {
      nextId: () => id(1).toUpperCase(),
      content: CONTENT,
    });

    expect(sealed.id).toBe(id(1));
  });

  it('draws the ID once the head is locked and found clean, so IDs rise with the numbers', async () => {
    const memory = await chainOf(1);
    memory.calls = [];
    await appendEvent(keys, CHAIN, memory, {
      nextId: () => {
        memory.calls.push('nextId');
        return id(2);
      },
      content: CONTENT,
    });

    expect(memory.calls).toEqual(['lockHead', 'hasEventsPast', 'nextId', 'now', 'append']);
  });

  it('refuses an ID that is not a UUID, and writes nothing', async () => {
    const memory = new MemoryChain();

    await expect(appendEvent(keys, CHAIN, memory, { nextId: () => 'not-a-uuid', content: CONTENT })).rejects.toThrow(
      new RangeError('The ID generator gave an ID that is not a UUID'),
    );
    expect(memory.calls).not.toContain('append');
  });

  it('refuses when the head moved after it was read, as with a store that did not lock it', async () => {
    const memory = await chainOf(1);
    const other = await chainOf(2);
    memory.racedBy = other.head as ChainHead;

    await expect(appendEvent(keys, CHAIN, memory, { nextId: () => id(2), content: CONTENT })).rejects.toThrow(
      new ChainBroken(CHAIN),
    );
    expect(memory.rows).toHaveLength(1);
  });

  it.each([
    [
      'whose head fails its check',
      (memory: MemoryChain) => {
        memory.head = { ...(memory.head as ChainHead), seq: 9n };
      },
    ],
    [
      "whose head can't be read",
      (memory: MemoryChain) => {
        memory.head = 'unreadable';
      },
    ],
    [
      'holding an event past its head',
      (memory: MemoryChain) => {
        memory.head = genesisHead(keys, CHAIN);
      },
    ],
    [
      'whose head was removed, its events left',
      (memory: MemoryChain) => {
        memory.head = 'none';
      },
    ],
  ])('refuses a chain %s, and writes nothing', async (_case, tamper) => {
    const memory = await chainOf(2);
    tamper(memory);
    memory.calls = [];

    await expect(appendEvent(keys, CHAIN, memory, { nextId: () => id(3), content: CONTENT })).rejects.toThrow(
      new ChainBroken(CHAIN),
    );
    expect(memory.calls).not.toContain('append');
  });

  it('refuses when a new chain is started and its head still cannot be found', async () => {
    const memory = new MemoryChain();
    memory.loses = true;

    await expect(appendEvent(keys, CHAIN, memory, { nextId: () => id(1), content: CONTENT })).rejects.toThrow(
      ChainBroken,
    );
  });

  it("names the chain in its refusal: an organisation's, or the platform's", () => {
    expect(new ChainBroken(CHAIN).message).toMatch(/^The platform's audit chain fails its check/);
    expect(new ChainBroken({ kind: 'organisation', orgId: id(9) }).message).toMatch(/^The organisation's audit chain/);
  });
});

describe('checking a chain', () => {
  it('passes a chain that was never started as empty', async () => {
    expect(await verifyChain(keys, CHAIN, new MemoryChain())).toEqual({ ok: true, seq: 0n, hash: GENESIS_HASH });
  });

  it('reports a chain emptied after it was anchored, where the chain alone would look new', async () => {
    const anchored = { seq: 3n, hash: Buffer.alloc(32, 3) };

    expect(await verifyChain(keys, CHAIN, new MemoryChain(), anchored)).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 3n },
    });
    expect(await verifyChain(keys, CHAIN, new MemoryChain(), { seq: 0n, hash: GENESIS_HASH })).toMatchObject({
      ok: true,
      seq: 0n,
    });
  });

  it('checks the chain against its anchor as it reads it', async () => {
    const memory = await chainOf(3);
    const at2 = memory.rows[1];
    if (at2 === undefined) throw new Error('The chain is shorter than the test expects');

    expect(await verifyChain(keys, CHAIN, memory, { seq: 2n, hash: at2.hash })).toMatchObject({ ok: true, seq: 3n });
    expect(await verifyChain(keys, CHAIN, memory, { seq: 2n, hash: Buffer.alloc(32, 7) })).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 2n },
    });
  });

  it('reports events left with no head, and a head that cannot be read, at 0', async () => {
    const headless = await chainOf(2);
    headless.head = 'none';
    const unreadable = await chainOf(2);
    unreadable.head = 'unreadable';

    for (const memory of [headless, unreadable]) {
      expect(await verifyChain(keys, CHAIN, memory)).toEqual({ ok: false, problem: { reason: 'head', seq: 0n } });
    }
  });

  it('reads a long chain in batches of 500, and finds a problem deep in it', async () => {
    const memory = await chainOf(1001);

    expect(await verifyChain(keys, CHAIN, memory)).toMatchObject({ ok: true, seq: 1001n });
    const at = memory.rows[776];
    if (at === undefined) throw new Error('The chain is shorter than the test expects');
    memory.rows[776] = { ...at, content: ['action', 'probe.edited'] };
    expect(await verifyChain(keys, CHAIN, memory)).toEqual({ ok: false, problem: { reason: 'hash', seq: 777n } });
  });

  it('asks for no page once it has reached the head', async () => {
    const small = await chainOf(3);
    const full = await chainOf(500);
    await verifyChain(keys, CHAIN, small);
    await verifyChain(keys, CHAIN, full);

    expect([small.pages, full.pages]).toEqual([1, 1]);
  });

  it('reads on until the head, whatever page size the store gives', async () => {
    const memory = await chainOf(250);
    memory.pageSize = 100;

    expect(await verifyChain(keys, CHAIN, memory)).toMatchObject({ ok: true, seq: 250n });
  });

  it('stops reading when the store runs out of events before the head, and reports the head', async () => {
    const memory = await chainOf(3);
    memory.head = (await chainOf(5)).head;

    expect(await verifyChain(keys, CHAIN, memory)).toEqual({ ok: false, problem: { reason: 'head', seq: 5n } });
  });

  it('refuses a store that gives events past the head it was asked to read up to', async () => {
    // The head counts two events; the store hands over its third as well.
    const memory = await chainOf(3);
    const shorter = (await chainOf(2)).head as ChainHead;
    const broken: ChainReader = {
      state: () => Promise.resolve({ head: shorter, stored: 3n }),
      events: (after, _upTo, limit) => memory.events(after, 99n, limit),
    };

    await expect(verifyChain(keys, CHAIN, broken)).rejects.toThrow(
      new ChainStoreError('it gave an event past the head it was asked to read up to'),
    );
  });

  it('refuses a store that gives more events than it was asked for', async () => {
    const memory = await chainOf(501);
    const broken: ChainReader = {
      state: () => memory.state(),
      events: (after, upTo) => memory.events(after, upTo, 501),
    };

    await expect(verifyChain(keys, CHAIN, broken)).rejects.toThrow(
      new ChainStoreError('it gave 501 events where at most 500 were asked for'),
    );
  });

  it('reports a row that cannot be read at its place, and reads no further', async () => {
    const memory = await chainOf(3);
    memory.unreadable.add(2n);

    expect(await verifyChain(keys, CHAIN, memory)).toEqual({ ok: false, problem: { reason: 'unreadable', seq: 2n } });
  });
});

describe('reading stored rows as untrusted', () => {
  const head = genesisHead(keys, CHAIN);
  const HEAD_ROW = { seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion };
  const EVENT_ROW = {
    seq: 1n,
    id: id(1),
    recorded_at: NOW,
    whole_ms: true,
    prev_hash: GENESIS_HASH,
    hash: Buffer.alloc(32, 1),
    mac: Buffer.alloc(32, 2),
    mac_key_version: 1,
  };

  it('reads well-formed rows', () => {
    expect(headFields(HEAD_ROW)).toEqual(head);
    expect(sealedFields(EVENT_ROW)).toEqual({
      seq: 1n,
      id: id(1),
      recordedAt: NOW,
      prevHash: GENESIS_HASH,
      hash: Buffer.alloc(32, 1),
      mac: Buffer.alloc(32, 2),
      macKeyVersion: 1,
    });
  });

  it.each([
    ['seq', '1'],
    ['hash', null],
    ['mac', 'text'],
    ['mac_key_version', null],
  ])('refuses a head row whose %s is %j', (column, value) => {
    expect(headFields({ ...HEAD_ROW, [column]: value })).toBeUndefined();
  });

  it.each([
    ['seq', 1],
    ['id', null],
    ['recorded_at', '2026-09-19'],
    ['recorded_at', Number.POSITIVE_INFINITY],
    ['recorded_at', new Date(Number.NaN)],
    ['whole_ms', false],
    ['whole_ms', null],
    ['prev_hash', null],
    ['hash', 'text'],
    ['mac', null],
    ['mac_key_version', '1'],
  ])('refuses an event row whose %s is %j', (column, value) => {
    expect(sealedFields({ ...EVENT_ROW, [column]: value })).toBeUndefined();
  });
});
