// The anchor check with its anchors in the write-once store (4D2e E, PL-58): the
// forced cases, a restart being a new log and a new check over the same store.
// The real chains, with the real Tx A, are in handoff.db.test.ts.
import { gzipSync } from 'node:zlib';

import { type ChainReport, createAnchorLog, signAnchor } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, type FakeWriteOnceStore, FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type CheckedChain, createAnchorCheck, type OrganisationChains, scheduleAnchorCheck } from './anchor-check.ts';

const keysFilled = (fill: number) =>
  createKeyProvider(
    Object.fromEntries(
      PURPOSES.map((purpose, index) => [
        purpose,
        { current: 1, versions: new Map([[1, Buffer.alloc(32, index + fill)]]) },
      ]),
    ),
  );
const keys = keysFilled(1);
/** As a process whose `audit-anchor` version 1 has gone missing: that key at version 2 alone. */
const KEYS_LACKING_THE_OLD = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => {
      const version = purpose === 'audit-anchor' ? 2 : 1;
      return [purpose, { current: version, versions: new Map([[version, Buffer.alloc(32, index + 1)]]) }];
    }),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-11-02T09:00:00.000Z');
const STALE_MS = 900_000;
const DEADLINE_MS = 120_000;

const ok = (seq: bigint, fill = Number(seq)): ChainReport => ({
  ok: true,
  seq,
  hash: Buffer.alloc(32, fill),
  macKeyVersion: 1,
});

/** The chains as a database holds them: each organisation's report, and what the check asked of them. */
function chainsHolding(reports: Record<string, ChainReport>) {
  const held = { ...reports };
  const given: Record<string, unknown[]> = {};
  const holds: [string, string | undefined][] = [];
  let listed = Object.keys(reports);
  const organizations: OrganisationChains = {
    list: () => Promise.resolve(listed),
    recorded: () => Promise.resolve(listed),
    verify: (orgId, anchor) => {
      given[orgId] = [...(given[orgId] ?? []), anchor?.seq];
      const report = held[orgId];
      if (report === undefined) throw new Error('The test holds no chain for it');
      return Promise.resolve(report);
    },
    // Given no failure it only tries again a hold waiting: not a hold.
    hold: (orgId, failure) => {
      if (failure !== undefined) holds.push([orgId, failure]);
      return Promise.resolve();
    },
  };
  return {
    held,
    given,
    holds,
    organizations,
    /** The organisation taken off both the list and the record. */
    remove: (orgId: string) => {
      listed = listed.filter((id) => id !== orgId);
    },
  };
}

const PLATFORM_OK: CheckedChain = { chain: { kind: 'platform' }, verify: () => Promise.resolve(ok(1n)) };

/** One process's start: a log and a check over the store. */
function process(
  fake: FakeWriteOnceStore,
  organizations: OrganisationChains,
  chains: readonly CheckedChain[] = [],
  holding = keys,
) {
  const capture = new LogCapture();
  const logger = testLogger(capture);
  const clock = new FixedClock(AT);
  const log = createAnchorLog({
    store: fake.store,
    keys: holding,
    logger,
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: STALE_MS,
  });
  const check = createAnchorCheck({
    chains,
    organizations,
    keys: holding,
    clock,
    logger,
    staleAfterMs: STALE_MS,
    deadlineMs: DEADLINE_MS,
    durable: log,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  return { log, check, lines, clock };
}

const failing = (): Promise<never> => Promise.reject(new Error('the store is away'));
const never = (): Promise<never> => new Promise(() => undefined);
const CHAIN = { kind: 'organisation', orgId: ORG } as const;

afterEach(() => {
  vi.useRealTimers();
});

describe('the anchor check over the write-once store (4D2e E, PL-58)', () => {
  it('a restart compares each chain with the anchor it last wrote, from its first run', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = chainsHolding({ [ORG]: ok(3n) });
    const before = process(fake, chains.organizations);
    await before.check.run();
    expect(before.lines('audit.anchored')).toHaveLength(1);
    expect(fake.files.size).toBe(1);

    const after = process(fake, chains.organizations);
    await after.check.run();

    expect(chains.given[ORG]).toEqual([undefined, 3n]);
    expect(after.lines('audit.anchored')).toEqual([]);
    expect(after.lines('audit.anchor_check_done')).toEqual([
      expect.objectContaining({ chains: 1, anchored: 0, unchanged: 1, unanchored: 0, failed: 0, unchecked: 0 }),
    ]);
    // Nothing moved: nothing written.
    expect(fake.files.size).toBe(1);
  });

  it('SEC-DB-11 finds a chain wound back while no process ran: the alarm and the hold, first run after a restart', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = chainsHolding({ [ORG]: ok(9n), [OTHER_ORG]: ok(2n) });
    await process(fake, chains.organizations).check.run();

    // Wound back to an earlier state that seals up, as the real check reports it given the anchor.
    chains.held[ORG] = { ok: false, problem: { reason: 'anchor', seq: 9n } };
    const after = process(fake, chains.organizations);
    await after.check.run();

    expect(chains.given[ORG]).toEqual([undefined, 9n]);
    expect(after.lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', check: 'anchor', reason: 'anchor', anchorSeq: '9', orgId: ORG }),
    ]);
    expect(chains.holds).toContainEqual([ORG, 'anchor']);
    expect(chains.holds).not.toContainEqual([OTHER_ORG, expect.anything()]);
  });

  it('SEC-DB-11 catches a report that hides it: the head behind the anchor, with no anchor passed on', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = chainsHolding({ [ORG]: ok(9n) });
    await process(fake, chains.organizations).check.run();

    chains.held[ORG] = ok(4n);
    const after = process(fake, chains.organizations);
    await after.check.run();

    expect(after.lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'anchor', orgId: ORG })]);
    expect(after.log.latest(CHAIN)?.seq).toBe(9n);
  });

  it('SEC-DB-11 an organisation taken off the list and the record while no process ran is seen: the store is the seen-set', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = chainsHolding({ [ORG]: ok(3n), [OTHER_ORG]: ok(2n) });
    await process(fake, chains.organizations).check.run();

    chains.remove(ORG);
    const after = process(fake, chains.organizations);
    await after.check.run();

    expect(after.lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', check: 'anchor', reason: 'unlisted', anchorSeq: '3', orgId: ORG }),
    ]);
    expect(chains.holds).toContainEqual([ORG, 'unlisted']);
  });

  it('a new organisation, the store read: anchored on its first check, alone', async () => {
    const fake = createFakeWriteOnceStore();
    const chains = chainsHolding({ [ORG]: ok(3n) });
    const first = process(fake, chains.organizations);
    await first.check.run();

    const newly = chainsHolding({ [ORG]: ok(3n), [OTHER_ORG]: ok(1n) });
    const after = process(fake, newly.organizations);
    await after.check.anchorOrganisation(OTHER_ORG);

    expect(newly.given).toEqual({ [OTHER_ORG]: [undefined] });
    expect(after.log.latest({ kind: 'organisation', orgId: OTHER_ORG })?.seq).toBe(1n);
    expect(after.lines('audit.integrity_failed')).toEqual([]);
  });

  describe('a store unreadable after a restart', () => {
    it('anchors no chain for the first time, so payments wait for every organisation, and says so, until it can be read', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n), [OTHER_ORG]: ok(2n) });
      await process(fake, chains.organizations, [PLATFORM_OK]).check.run();
      const writes = fake.calls.puts;
      chains.given[ORG] = [];

      fake.instead.list = failing;
      const after = process(fake, chains.organizations, [PLATFORM_OK]);

      // What Tx A reads: nothing, for every organisation; its hand-off's anchorFirst makes none, and asks no database.
      await after.check.anchorOrganisation(ORG);
      expect(after.log.latest(CHAIN)).toBeUndefined();
      expect(after.log.latest({ kind: 'organisation', orgId: OTHER_ORG })).toBeUndefined();
      expect(chains.given[ORG]).toEqual([]);
      expect(after.lines('audit.anchor_store_unreadable')).toHaveLength(1);

      // Once it has failed, the run alone tries again: a hand-off pass can't stall on it, organisation after organisation.
      const lists = fake.calls.lists;
      await after.check.anchorOrganisation(OTHER_ORG);
      expect(fake.calls.lists).toBe(lists);

      // The run still checks every seal, and anchors nothing.
      await after.check.run();
      expect(chains.given[ORG]).toEqual([undefined]);
      expect(after.log.latest(CHAIN)).toBeUndefined();
      expect(after.log.latest({ kind: 'platform' })).toBeUndefined();
      expect(fake.calls.puts).toBe(writes);
      expect(after.lines('audit.anchored')).toEqual([]);
      expect(after.lines('audit.anchor_check_done')).toEqual([
        expect.objectContaining({ chains: 3, anchored: 0, unchanged: 0, unanchored: 3, failed: 0 }),
      ]);
      expect(after.lines('audit.anchor_store_unreadable')).toHaveLength(2);
      expect(after.lines('audit.anchor_store_unreadable')[0]).toMatchObject({ level: 'error' });
      expect(chains.holds).toEqual([]);

      // The store back: the next run loads it and compares, and payments resume.
      delete fake.instead.list;
      await after.check.run();
      expect(chains.given[ORG]).toEqual([undefined, 3n]);
      expect(after.log.latest(CHAIN)?.seq).toBe(3n);
      expect(after.log.latest({ kind: 'platform' })?.seq).toBe(1n);
      expect(after.lines('audit.anchored')).toEqual([]);
    });

    it('a seal that fails during the outage is still the alarm and the hold', async () => {
      const fake = createFakeWriteOnceStore();
      fake.instead.list = failing;
      const chains = chainsHolding({ [ORG]: { ok: false, problem: { reason: 'mac', seq: 2n } } });
      const after = process(fake, chains.organizations);
      await after.check.run();

      expect(after.lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'mac', orgId: ORG })]);
      expect(chains.holds).toEqual([[ORG, 'mac']]);
    });

    it('SEC-DB-11 a key version gone reads as unreadable: a chain wound back is not anchored afresh, and shows once it is back', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(100n) });
      await process(fake, chains.organizations).check.run();

      chains.held[ORG] = ok(50n);
      const lacking = process(fake, chains.organizations, [], KEYS_LACKING_THE_OLD);
      await lacking.check.run();
      expect(lacking.log.latest(CHAIN)).toBeUndefined();
      expect(lacking.lines('audit.anchored')).toEqual([]);
      expect(lacking.lines('audit.anchor_store_unreadable')).toHaveLength(1);
      expect(lacking.lines('audit.anchor_check_done')).toEqual([
        expect.objectContaining({ unanchored: 1, anchored: 0 }),
      ]);
      expect(chains.holds).toEqual([]);

      const back = process(fake, chains.organizations);
      await back.check.run();
      expect(back.lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({ reason: 'anchor', anchorSeq: '100', orgId: ORG }),
      ]);
      expect(chains.holds).toEqual([[ORG, 'anchor']]);
    });

    it('a read that outlasts its deadline counts as failed, and the run goes on; it may still land later', async () => {
      vi.useFakeTimers();
      const fake = createFakeWriteOnceStore();
      const { promise: answer, resolve: answers } = Promise.withResolvers<undefined>();
      fake.instead.list = async (start, most, after) => {
        await answer;
        return fake.real.list(start, most, after);
      };
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const after = process(fake, chains.organizations);

      const run = after.check.run();
      await vi.advanceTimersByTimeAsync(DEADLINE_MS);
      await run;
      expect(after.lines('audit.anchor_store_unreadable')).toHaveLength(1);
      expect(after.log.latest(CHAIN)).toBeUndefined();
      expect(after.lines('audit.anchor_check_done')).toEqual([expect.objectContaining({ chains: 1, unanchored: 1 })]);

      answers(undefined);
      await vi.advanceTimersByTimeAsync(0);
      expect(after.log.state()).toBe('read');
    });

    describe('a read past its deadline that lands while a chain is being checked', () => {
      /** A restart whose store answers, and whose one chain's check answers, only when told. */
      async function landingMidCheck(head: ChainReport) {
        vi.useFakeTimers();
        const fake = createFakeWriteOnceStore();
        const chains = chainsHolding({ [ORG]: ok(100n) });
        await process(fake, chains.organizations).check.run();
        const writes = fake.calls.puts;

        chains.held[ORG] = head;
        const { promise: storeAnswer, resolve: storeAnswers } = Promise.withResolvers<undefined>();
        fake.instead.list = async (start, most, after) => {
          await storeAnswer;
          return fake.real.list(start, most, after);
        };
        const { promise: chainAnswer, resolve: chainAnswers } = Promise.withResolvers<undefined>();
        const organizations: OrganisationChains = {
          ...chains.organizations,
          verify: async (orgId, anchor) => {
            await chainAnswer;
            return chains.organizations.verify(orgId, anchor);
          },
        };
        const after = process(fake, organizations);

        const run = after.check.run();
        await vi.advanceTimersByTimeAsync(DEADLINE_MS);
        // The check began with no anchor, the store then unread.
        expect(after.log.state()).toBe('unreadable');
        storeAnswers(undefined);
        // Its files open off the event loop, where fake timers don't reach.
        await vi.waitFor(() => {
          expect(after.log.state()).toBe('read');
        });
        expect(after.log.latest(CHAIN)?.seq).toBe(100n);
        chainAnswers(undefined);
        await run;
        return { after, chains, fake, writes };
      }

      it('SEC-DB-11 a head wound back is the alarm and the hold, and the anchor stays', async () => {
        const { after, chains, fake, writes } = await landingMidCheck(ok(50n));

        expect(chains.given[ORG]).toEqual([undefined, undefined]);
        expect(after.lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({
            level: 'error',
            check: 'anchor',
            reason: 'anchor',
            seq: '100',
            anchorSeq: '100',
            orgId: ORG,
          }),
        ]);
        expect(chains.holds).toEqual([[ORG, 'anchor']]);
        expect(after.log.latest(CHAIN)?.seq).toBe(100n);
        expect(after.lines('audit.anchored')).toEqual([]);
        expect(fake.calls.puts).toBe(writes);
      });

      it('SEC-DB-11 the same place with another hash is the alarm and the hold', async () => {
        const { after, chains } = await landingMidCheck(ok(100n, 7));

        expect(after.lines('audit.integrity_failed')).toEqual([
          expect.objectContaining({ reason: 'anchor', anchorSeq: '100', orgId: ORG }),
        ]);
        expect(chains.holds).toEqual([[ORG, 'anchor']]);
        expect(after.log.latest(CHAIN)?.hash).toEqual(Buffer.alloc(32, 100));
      });

      it('the head just where the store has it is unchanged', async () => {
        const { after, chains } = await landingMidCheck(ok(100n));

        expect(after.lines('audit.integrity_failed')).toEqual([]);
        expect(after.lines('audit.anchor_check_done')).toEqual([
          expect.objectContaining({ unchanged: 1, anchored: 0 }),
        ]);
        expect(chains.holds).toEqual([]);
      });

      it('a head past it is not anchored, as nothing compared it with that anchor: the next run does', async () => {
        const { after, chains } = await landingMidCheck(ok(120n));

        expect(after.log.latest(CHAIN)?.seq).toBe(100n);
        expect(after.lines('audit.anchored')).toEqual([]);
        expect(after.lines('audit.anchor_check_done')).toEqual([
          expect.objectContaining({ unanchored: 1, anchored: 0, failed: 0 }),
        ]);

        await after.check.run();
        expect(chains.given[ORG]?.at(-1)).toBe(100n);
        expect(after.log.latest(CHAIN)?.seq).toBe(120n);
      });
    });

    it("a hand-off's first anchor joins the run's first read, rather than go first", async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      await process(fake, chains.organizations).check.run();
      const after = process(fake, chains.organizations);
      fake.calls.lists = 0;

      await Promise.all([after.check.run(), after.check.anchorOrganisation(ORG)]);

      expect(fake.calls.lists).toBe(2);
      expect(chains.given[ORG]).toEqual([undefined, 3n, 3n]);
    });

    it('a stop during the read ends the run at once, and anchors nothing', async () => {
      const fake = createFakeWriteOnceStore();
      fake.instead.list = never;
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const after = process(fake, chains.organizations);
      const stopping = new AbortController();

      const run = after.check.run(stopping.signal);
      stopping.abort();
      await run;

      expect(chains.given).toEqual({});
      expect(after.lines('audit.anchor_store_unreadable')).toEqual([]);
      expect(after.lines('audit.anchor_check_done')).toEqual([expect.objectContaining({ chains: 0 })]);

      // The same for a hand-off asking first.
      const asked = process(fake, chains.organizations);
      await asked.check.anchorOrganisation(ORG, AbortSignal.abort());
      expect(chains.given).toEqual({});
    });
  });

  describe('a store that can not be written', () => {
    it('goes on from memory and warns, then the alert, with no hold; a restart then has the last it wrote', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const first = process(fake, chains.organizations);
      await first.check.run();

      fake.instead.put = failing;
      chains.held[ORG] = ok(4n);
      await first.check.run();

      // Tx A has the newest; payments go on.
      expect(first.log.latest(CHAIN)?.seq).toBe(4n);
      expect(first.lines('audit.anchor_store_write_failed')).toEqual([expect.objectContaining({ level: 'warn' })]);
      expect(first.lines('audit.anchor_store_unwritable')).toEqual([]);

      first.clock.advanceBy(STALE_MS);
      await first.check.run();
      expect(first.lines('audit.anchor_store_unwritable')).toEqual([
        expect.objectContaining({ level: 'error', forMs: STALE_MS }),
      ]);
      expect(chains.holds).toEqual([]);
      expect(first.lines('audit.integrity_failed')).toEqual([]);

      // The stated gap: a restart compares with the last one written.
      const after = process(fake, chains.organizations);
      await after.log.read();
      expect(after.log.latest(CHAIN)?.seq).toBe(3n);
    });

    it('a write that outlasts its deadline is a warning, and the run ends', async () => {
      vi.useFakeTimers();
      const fake = createFakeWriteOnceStore();
      fake.instead.put = never;
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const after = process(fake, chains.organizations);

      const run = after.check.run();
      await vi.advanceTimersByTimeAsync(DEADLINE_MS);
      await run;

      expect(after.lines('audit.anchor_store_write_failed')).toHaveLength(1);
      expect(after.lines('audit.anchor_check_done')).toHaveLength(1);
    });

    it('a stop during the write ends the run at once, with no warning: the stop writes it', async () => {
      const fake = createFakeWriteOnceStore();
      fake.instead.put = never;
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const after = process(fake, chains.organizations);
      const stopping = new AbortController();

      const run = after.check.run(stopping.signal);
      await vi.waitFor(() => {
        expect(fake.calls.puts).toBe(1);
      });
      stopping.abort();
      await run;

      expect(after.lines('audit.anchor_store_write_failed')).toEqual([]);
    });
  });

  describe('as the API stops', () => {
    it('writes what moved, so a restart holds it', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const first = process(fake, chains.organizations);
      await first.log.read();
      await first.check.anchorOrganisation(ORG);
      expect(fake.files.size).toBe(0);

      await first.check.finish();

      expect(fake.files.size).toBe(1);
      const after = process(fake, chains.organizations);
      await after.log.read();
      expect(after.log.latest(CHAIN)?.seq).toBe(3n);
    });

    it('finish: a store that never answers holds it 5 seconds and no more, and says so', async () => {
      vi.useFakeTimers();
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const first = process(fake, chains.organizations);
      await first.log.read();
      await first.check.anchorOrganisation(ORG);
      fake.instead.put = never;

      let done = false;
      const finishing = first.check.finish().then(() => {
        done = true;
      });
      await vi.advanceTimersByTimeAsync(4_999);
      expect(done).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await finishing;

      expect(done).toBe(true);
      expect(first.lines('audit.anchor_store_write_failed')).toEqual([
        expect.objectContaining({
          level: 'warn',
          err: expect.objectContaining({ message: 'the check did not finish within 5000 ms' }) as unknown,
        }),
      ]);
    });

    it('waits for a write under way, then writes what moved since it began', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const first = process(fake, chains.organizations);
      await first.log.read();
      await first.check.anchorOrganisation(ORG);
      const { promise: answer, resolve: answers } = Promise.withResolvers<undefined>();
      fake.instead.put = async (name, bytes) => {
        await answer;
        return fake.real.put(name, bytes);
      };
      const under = first.log.flush();
      await vi.waitFor(() => {
        expect(fake.calls.puts).toBe(1);
      });
      chains.held[OTHER_ORG] = ok(1n);
      await first.check.anchorOrganisation(OTHER_ORG);

      const finishing = first.check.finish();
      answers(undefined);
      await Promise.all([under, finishing]);

      expect(fake.calls.puts).toBe(2);
      const after = process(fake, chains.organizations);
      await after.log.read();
      expect(after.log.latest({ kind: 'organisation', orgId: OTHER_ORG })?.seq).toBe(1n);
    });

    it('with nothing moved, or no store, asks nothing of it', async () => {
      const fake = createFakeWriteOnceStore();
      const chains = chainsHolding({ [ORG]: ok(3n) });
      await process(fake, chains.organizations).check.finish();
      expect(fake.calls).toEqual({ puts: 0, lists: 0, gets: 0 });

      const memoryOnly = createAnchorCheck({
        chains: [],
        keys,
        clock: new FixedClock(AT),
        logger: testLogger(new LogCapture()),
        staleAfterMs: STALE_MS,
        deadlineMs: DEADLINE_MS,
      });
      await expect(memoryOnly.finish()).resolves.toBeUndefined();
    });

    it('the schedule stops its runs first, then writes', async () => {
      const steps: string[] = [];
      const schedule = scheduleAnchorCheck(
        {
          run: (signal) =>
            new Promise<void>((resolve) => {
              signal?.addEventListener('abort', () => {
                steps.push('run stopped');
                resolve();
              });
            }),
        },
        1_000,
        () => {
          steps.push('written');
          return Promise.resolve();
        },
      );
      await schedule.stop();

      expect(steps).toEqual(['run stopped', 'written']);
    });
  });

  describe('what the store holds that fails', () => {
    const fileOf = (...lines: readonly unknown[]): Buffer =>
      gzipSync(`${lines.map((line) => JSON.stringify(line)).join('\n')}\n`);
    const lineFrom = (signing: typeof keys, seq: bigint, fill: number, at = AT) => {
      const anchor = signAnchor(signing, CHAIN, ok(seq, fill) as Extract<ChainReport, { ok: true }>, at);
      return {
        k: 'a',
        chain: anchor.chain,
        seq: anchor.seq.toString(),
        hash: anchor.hash.toString('hex'),
        mk: anchor.macKeyVersion,
        at: anchor.at.toISOString(),
        kv: anchor.keyVersion,
        sig: anchor.signature.toString('base64'),
      };
    };
    const FILE_ID = '00000000-0000-4000-8000-000000000001';
    const deltaName = (order: number): string =>
      `e1/deltas/${String(9_999_999_999_999 - AT.getTime() + order)}-${FILE_ID}`;

    it('SEC-DB-11 a line with a bad signature is skipped and is the alarm: no hold, payments as if it were not there', async () => {
      const fake = createFakeWriteOnceStore();
      fake.files.set(deltaName(0), fileOf(lineFrom(keysFilled(50), 99n, 9)));
      const chains = chainsHolding({ [ORG]: ok(3n) });
      const after = process(fake, chains.organizations);
      await after.check.run();

      expect(after.lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({ level: 'error', check: 'anchor_store', reason: 'signature', lines: 1 }),
      ]);
      expect(chains.holds).toEqual([]);
      // Its place never counted: the chain anchored where it stands, and no false `anchor` alarm.
      expect(chains.given[ORG]).toEqual([undefined]);
      expect(after.log.latest(CHAIN)?.seq).toBe(3n);
    });

    it('SEC-DB-11 same place, two hashes: the alarm; the older kept; the organisation held if its chain holds the other', async () => {
      const older = lineFrom(keys, 5n, 5, AT);
      const newer = lineFrom(keys, 5n, 6, new Date(AT.getTime() + 60_000));

      for (const [fill, held] of [
        [6, true],
        [5, false],
      ] as const) {
        const fake = createFakeWriteOnceStore();
        fake.files.set(deltaName(0), fileOf(older));
        fake.files.set(deltaName(1), fileOf(newer));
        const given: bigint[] = [];
        const holds: unknown[] = [];
        const organizations: OrganisationChains = {
          list: () => Promise.resolve([ORG]),
          recorded: () => Promise.resolve([ORG]),
          // As the real check does, which compares the anchored event.
          verify: (_orgId, anchor) => {
            if (anchor !== undefined) given.push(anchor.seq);
            return Promise.resolve(
              anchor?.hash.equals(Buffer.alloc(32, fill)) === true
                ? ok(5n, fill)
                : { ok: false, problem: { reason: 'anchor', seq: 5n } },
            );
          },
          hold: (orgId, failure) => {
            if (failure !== undefined) holds.push([orgId, failure]);
            return Promise.resolve();
          },
        };
        const after = process(fake, organizations);
        await after.check.run();

        expect(given).toEqual([5n]);
        expect(after.log.latest(CHAIN)?.hash).toEqual(Buffer.alloc(32, 5));
        expect(after.lines('audit.integrity_failed')[0]).toMatchObject({ check: 'anchor_store', reason: 'fork' });
        expect(holds).toEqual(held ? [[ORG, 'anchor']] : []);
      }
    });
  });

  it('without a store the check keeps its anchors in memory as it did, and a run reads and writes nothing', async () => {
    const chains = chainsHolding({ [ORG]: ok(3n) });
    const capture = new LogCapture();
    const check = createAnchorCheck({
      chains: [],
      organizations: chains.organizations,
      keys,
      clock: new FixedClock(AT),
      logger: testLogger(capture),
      staleAfterMs: STALE_MS,
      deadlineMs: DEADLINE_MS,
    });
    await check.anchorOrganisation(ORG);
    await check.run();

    expect(chains.given[ORG]).toEqual([undefined, 3n]);
    expect(capture.lines().filter((line) => String(line.event).startsWith('audit.anchor_store'))).toEqual([]);
  });
});
