// S206 V6: the job that seals the security rows from before 0105, without a
// database: run only with an anchor store; its outcome said, a failure said;
// the chain anchored at once after each of the sealing's records, a write
// that fails or a chain that won't anchor its own error line.
import { FixedClock, LogCapture, SequentialIds, testLogger } from '@agentx/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createLegacySealJob, LEGACY_SEAL_STALL_MS } from './legacy-seal-job.ts';

/** What the job hands the sealing, and what the sealing answers. */
const sealing = vi.hoisted(() => ({
  given: [] as Record<string, unknown>[],
  answer: (): Promise<string> => Promise.resolve('sealed'),
}));

vi.mock('@agentx/core/modules/security-events', () => ({
  sealLegacyRows: (_db: unknown, given: Record<string, unknown>) => {
    sealing.given.push(given);
    return sealing.answer();
  },
}));

/** What the platform chain's check from the anchor answers. */
const chain = vi.hoisted((): { step: Readonly<Record<string, unknown>> } => ({
  step: { ok: true, seq: 9n, to: 9n, hash: Buffer.alloc(32, 9), macKeyVersion: 1 },
}));

vi.mock('@agentx/core/modules/platform-controls', () => ({
  createPlatformChain: () => ({ checkFromAnchor: () => Promise.resolve(chain.step) }),
}));

vi.mock('@agentx/core/modules/directory', () => ({
  listedOrganizations: () => Promise.resolve(['0199a0f0-0000-7000-8000-00000000abcd']),
}));

vi.mock('@agentx/platform/audit-chain', () => ({
  signAnchor: (_keys: unknown, _chain: unknown, point: unknown) => ({ signed: point }),
}));

const ANCHOR = { seq: 7n, hash: Buffer.alloc(32, 7), macKeyVersion: 1 };

/** A stand-in for the jobs' anchor store: what it keeps, and how many times it is written. */
function anchorStore({ state = 'read', latest = ANCHOR }: { readonly state?: string; readonly latest?: unknown } = {}) {
  const kept: unknown[] = [];
  const flushes = { count: 0 };
  return {
    kept,
    flushes,
    log: {
      epoch: 1,
      read: () => Promise.resolve(),
      state: () => state,
      pin: () => Promise.resolve(() => undefined),
      latest: () => latest ?? undefined,
      keep: (anchor: unknown) => kept.push(anchor),
      flush: () => {
        flushes.count += 1;
        return Promise.resolve();
      },
    },
  };
}

let capture: LogCapture;
const jobWith = (anchors: unknown, clock = new FixedClock(new Date('2026-11-25T00:00:00.000Z'))) =>
  createLegacySealJob({
    database: {} as never,
    anchors: anchors as never,
    keys: {} as never,
    ids: new SequentialIds(1),
    clock,
    logger: testLogger(capture),
    retentionDays: 30,
  });

const lines = () => capture.lines().map(({ event, outcome }) => [event, outcome]);

/** The lines anchoring said. */
const unanchored = () => capture.lines().filter(({ event }) => event === 'security.legacy_seal_unanchored');

/** The sealing's own `anchorNow`, as the job gave it. */
const anchorNow = () => (sealing.given.at(-1)?.anchorNow as () => Promise<void>)();

beforeEach(() => {
  capture = new LogCapture();
  sealing.given.length = 0;
  sealing.answer = () => Promise.resolve('sealed');
  chain.step = { ok: true, seq: 9n, to: 9n, hash: Buffer.alloc(32, 9), macKeyVersion: 1 };
});

describe('the security rows’ sealing job (S206 V6)', () => {
  it('seals nothing where no anchor store is: said', async () => {
    await jobWith(undefined).run();

    expect(sealing.given).toEqual([]);
    expect(lines()).toEqual([['security.legacy_seal_done', 'no_anchor_store']]);
  });

  it('says what the sealing found, holding the chain to the store’s last anchor', async () => {
    sealing.answer = () => Promise.resolve('busy');
    await jobWith(anchorStore().log).run();

    expect(lines()).toEqual([['security.legacy_seal_done', 'busy']]);
    expect(await (sealing.given[0]?.anchor as () => Promise<unknown>)()).toEqual(ANCHOR);
    // Every organisation, from the directory's list.
    expect(await (sealing.given[0]?.orgs as () => Promise<unknown>)()).toEqual([
      '0199a0f0-0000-7000-8000-00000000abcd',
    ]);
  });

  it('a store it cannot read gives no anchor', async () => {
    await jobWith(anchorStore({ state: 'unreadable' }).log).run();

    expect(await (sealing.given[0]?.anchor as () => Promise<unknown>)()).toBeUndefined();
  });

  it('says a sealing that failed, and never throws', async () => {
    sealing.answer = () => Promise.reject(new Error('the database went away'));
    await jobWith(anchorStore().log).run();

    expect(lines()).toEqual([['security.legacy_seal_failed', undefined]]);
  });

  it('anchors the chain at its head at once, as the anchor check would', async () => {
    const store = anchorStore();
    await jobWith(store.log).run();
    await anchorNow();

    expect(store.kept).toEqual([{ signed: chain.step }]);
    expect(store.flushes.count).toBe(1);
    expect(unanchored()).toEqual([]);
  });

  it.each([
    ['the store holds no anchor', { latest: null }, undefined],
    ['the chain fails its check from it', {}, { ok: false, problem: { reason: 'gap', seq: 8n } }],
    ['the check stops short of the head', {}, { ok: true, seq: 8n, to: 9n, hash: Buffer.alloc(32), macKeyVersion: 1 }],
  ] as const)('an anchor not written (%s): its own error line, nothing thrown', async (_why, store, step) => {
    if (step !== undefined) chain.step = step;
    const { log, kept } = anchorStore(store);
    await jobWith(log).run();
    await anchorNow();

    expect(unanchored()).toHaveLength(1);
    if (step !== undefined) expect(kept).toEqual([]);
  });

  it('an anchor store that throws: its own error line, nothing thrown', async () => {
    const { log } = anchorStore();
    await jobWith({ ...log, read: () => Promise.reject(new Error('the store went away')) }).run();
    await anchorNow();

    expect(unanchored()).toHaveLength(1);
  });

  it('the sealer’s lock found taken on two runs an hour apart: the stall is the alarm, each run it stays so, until a run gets it', async () => {
    const clock = new FixedClock(new Date('2026-11-25T00:00:00.000Z'));
    const job = jobWith(anchorStore().log, clock);
    const stalls = () => capture.lines().filter(({ event }) => event === 'security.legacy_seal_stalled');
    sealing.answer = () => Promise.resolve('busy');

    await job.run();
    // Another copy sealing a moment later still holds it: no alarm yet.
    clock.advanceBy(LEGACY_SEAL_STALL_MS - 1);
    await job.run();
    expect(stalls()).toEqual([]);
    // Each run after the first that found it taken hands the sealing that time: no row it seals is newer.
    expect(sealing.given.map(({ notAfter }) => notAfter)).toEqual([undefined, new Date('2026-11-25T00:00:00.000Z')]);

    clock.advanceBy(1);
    await job.run();
    clock.advanceBy(60 * 60_000);
    await job.run();
    expect(stalls().map(({ level, busySince }) => [level, busySince])).toEqual([
      ['error', '2026-11-25T00:00:00.000Z'],
      ['error', '2026-11-25T00:00:00.000Z'],
    ]);

    // A run that gets it ends the stall; the lock taken again starts it over.
    sealing.answer = () => Promise.resolve('sealed');
    await job.run();
    sealing.answer = () => Promise.resolve('busy');
    clock.advanceBy(60 * 60_000);
    await job.run();
    expect(stalls()).toHaveLength(2);
  });
});
