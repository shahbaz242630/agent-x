// The anchor check keeping the signed states' digest (AT13): each walk under a new anchor records what it read, written
// beside the anchors and read back after them by a process started since. The decisions held to it, on the real
// tables, are in owner-tamper.db.test.ts (core) and handoff.db.test.ts.
import { gunzipSync } from 'node:zlib';

import {
  type ChainReport,
  createAnchorLog,
  createDigestLog,
  type DigestLog,
  subjectKey,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, type FakeWriteOnceStore, FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { type CheckedChain, createAnchorCheck, type OrganisationChains, type WalkedReport } from './anchor-check.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const CHAIN = { kind: 'organisation', orgId: ORG } as const;
const AT = new Date('2026-11-20T09:00:00.000Z');
const STALE_MS = 900_000;

const walk = (seq: bigint, signed?: ReadonlyMap<string, bigint>): WalkedReport => ({
  ok: true,
  seq,
  hash: Buffer.alloc(32, Number(seq)),
  macKeyVersion: 1,
  ...(signed === undefined ? {} : { signed }),
});

/** One organisation's chain answering whatever `report` holds now, each place it was walked from kept in `from`. */
function chainOf(
  report: { current: WalkedReport | ChainReport },
  from: (bigint | undefined)[] = [],
  holds: string[] = [],
): OrganisationChains {
  return {
    list: () => Promise.resolve([ORG]),
    recorded: () => Promise.resolve([ORG]),
    verify: (_orgId, anchor) => {
      from.push(anchor?.seq);
      return Promise.resolve(report.current);
    },
    hold: (_orgId, failure) => {
      if (failure !== undefined) holds.push(failure);
      return Promise.resolve();
    },
  };
}

/** One process's start: the anchors' log and the digest over the same store, and the check keeping both. */
function process(
  fake: FakeWriteOnceStore,
  organizations: OrganisationChains,
  { deadlineMs = 120_000, chains = [] as readonly CheckedChain[] } = {},
) {
  const capture = new LogCapture();
  const logger = testLogger(capture);
  const clock = new FixedClock(AT);
  const now = () => clock.now();
  const log = createAnchorLog({ store: fake.store, keys, logger, now, epoch: 1, alertAfterMs: STALE_MS });
  const digest: DigestLog = createDigestLog({
    store: fake.store,
    keys,
    logger,
    now,
    epoch: 1,
    anchors: log,
    alertAfterMs: STALE_MS,
    mostBytes: 1024 * 1024,
  });
  const check = createAnchorCheck({
    chains,
    organizations,
    keys,
    clock,
    logger,
    staleAfterMs: STALE_MS,
    deadlineMs,
    durable: log,
    digest,
  });
  return { log, digest, check, capture, clock };
}

const digestFiles = (fake: FakeWriteOnceStore) => [...fake.files.keys()].filter((name) => name.includes('/digests/'));

describe('SEC-DB-16 the anchor check keeping the platform chain’s signed states in the digest (AT13c)', () => {
  const PLATFORM = { kind: 'platform' } as const;
  const PAUSE = subjectKey('platform.handoff_pause', 'pause');
  const ENDED = subjectKey('identity.session_ended', 'p/r');

  it('records its walk from the anchor, a whole walk from its first event even where the anchor stays, and reads back', async () => {
    const fake = createFakeWriteOnceStore();
    const platform: { current: WalkedReport } = { current: { ...walk(4n, new Map([[PAUSE, 3n]])), walkedFrom: 0n } };
    const chains = [{ chain: PLATFORM, verify: () => Promise.resolve(platform.current) }];
    const first = process(fake, chainOf({ current: walk(1n) }), { chains });
    await first.check.run();
    expect(first.digest.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(3n);
    expect(first.digest.covers(PLATFORM, 4n)).toBe(true);
    // The anchor stays at 4: a whole walk read it all again, so what it read is kept.
    platform.current = { ...walk(4n, new Map([[ENDED, 2n]])), walkedFrom: 0n };
    await first.check.run();
    expect(first.digest.latest(PLATFORM, 'identity.session_ended', 'p/r')).toBe(2n);
    // A walk from the anchor that moved nothing reads nothing new: nothing kept from it.
    platform.current = walk(4n, new Map([[subjectKey('identity.sessions_ended', 'p'), 1n]]));
    await first.check.run();
    expect(first.digest.latest(PLATFORM, 'identity.sessions_ended', 'p')).toBeUndefined();
    // One that moved it on, from the anchor: its stretch joins on.
    platform.current = walk(6n, new Map([[PAUSE, 5n]]));
    await first.check.run();
    expect(first.digest.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(5n);
    expect(first.digest.covers(PLATFORM, 6n)).toBe(true);

    const restarted = process(fake, chainOf({ current: walk(1n) }), { chains });
    expect(restarted.digest.covers(PLATFORM, 6n)).toBe(false);
    await restarted.check.run();
    expect(restarted.digest.covers(PLATFORM, 6n)).toBe(true);
    expect(restarted.digest.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(5n);
    expect(restarted.digest.latest(PLATFORM, 'identity.session_ended', 'p/r')).toBe(2n);
  });

  it('its digest files lost: the first whole walk after a start covers it from its first event, the anchor where it was', async () => {
    const fake = createFakeWriteOnceStore();
    const platform: { current: WalkedReport } = { current: { ...walk(4n, new Map([[PAUSE, 3n]])), walkedFrom: 0n } };
    const chains = [{ chain: PLATFORM, verify: () => Promise.resolve(platform.current) }];
    const first = process(fake, chainOf({ current: walk(1n) }), { chains });
    await first.check.run();
    for (const name of digestFiles(fake)) fake.files.delete(name);

    const restarted = process(fake, chainOf({ current: walk(1n) }), { chains });
    await restarted.check.run();
    expect(restarted.digest.covers(PLATFORM, 4n)).toBe(true);
    expect(restarted.digest.latest(PLATFORM, 'platform.handoff_pause', 'pause')).toBe(3n);
  });
});

describe('SEC-DB-11 the anchor check keeping the signed states’ digest (AT13)', () => {
  it('records what a walk read with its new anchor, writes it beside the anchors, and a restart reads it back', async () => {
    const fake = createFakeWriteOnceStore();
    const report = { current: walk(5n, new Map([[subjectKey('agent', AGENT), 4n]])) };
    const first = process(fake, chainOf(report));
    await first.check.run();
    expect(first.digest.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    expect(digestFiles(fake).length).toBeGreaterThan(0);

    const restarted = process(fake, chainOf(report));
    expect(restarted.digest.covers(CHAIN, 5n)).toBe(false);
    await restarted.check.run();
    expect(restarted.digest.covers(CHAIN, 5n)).toBe(true);
    expect(restarted.digest.latest(CHAIN, 'agent', AGENT)).toBe(4n);
  });

  it('records nothing from a walk that failed, nor from one that moved nothing', async () => {
    const fake = createFakeWriteOnceStore();
    const report: { current: WalkedReport | ChainReport } = { current: walk(5n) };
    const { check, digest } = process(fake, chainOf(report));
    await check.run();
    // The anchor stays at 5: the same place again says nothing new, whatever it carries.
    report.current = walk(5n, new Map([[subjectKey('agent', AGENT), 4n]]));
    await check.run();
    expect(digest.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    report.current = { ok: false, problem: { reason: 'hash', seq: 6n } };
    await check.run();
    expect(digest.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
  });

  it('its first anchor for a hand-off records too, and the stop writes what waits', async () => {
    const fake = createFakeWriteOnceStore();
    const report = { current: walk(3n, new Map([[subjectKey('agent', AGENT), 2n]])) };
    const { check, digest } = process(fake, chainOf(report));
    await check.anchorOrganisation(ORG);
    expect(digest.latest(CHAIN, 'agent', AGENT)).toBe(2n);
    expect(digestFiles(fake)).toEqual([]);
    await check.finish();
    expect(digestFiles(fake).length).toBeGreaterThan(0);
  });

  it('a digest read that outlasts the deadline is a warning, and leaves it unknown; the next run reads it', async () => {
    const fake = createFakeWriteOnceStore();
    const report = { current: walk(3n) };
    const { check, digest, capture } = process(fake, chainOf(report), { deadlineMs: 50 });
    const list = fake.store.list.bind(fake.store);
    fake.instead.list = (start, most, after) =>
      start.includes('/digests/') ? new Promise(() => undefined) : list(start, most, after);
    await check.run();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.state_digest_store_failed', what: 'read' }),
    );
    expect(digest.covers(CHAIN, 3n)).toBe(false);
  });

  it('an anchor written and its digest delta lost: a restart leaves it uncovered until the catch-up walk reads on', async () => {
    const fake = createFakeWriteOnceStore();
    const report: { current: WalkedReport } = { current: walk(5n, new Map([[subjectKey('agent', AGENT), 4n]])) };
    const first = process(fake, chainOf(report));
    await first.check.run();
    // The next walk anchors at 9, and the anchor is written; the digest's write never lands.
    report.current = walk(9n, new Map([[subjectKey('agent', AGENT), 8n]]));
    const put = fake.real.put.bind(fake.real);
    fake.instead.put = (name, bytes) =>
      name.includes('/digests/') ? Promise.reject(new Error('stopped')) : put(name, bytes);
    await first.check.run();
    delete fake.instead.put;

    const walkedFrom: (bigint | undefined)[] = [];
    const after = process(fake, chainOf(report, walkedFrom));
    await after.log.read();
    await after.digest.read();
    expect(after.log.latest(CHAIN)?.seq).toBe(9n);
    // Tx A asks to 9: not covered, so it waits (digest_pending), this organisation alone.
    expect(after.digest.covers(CHAIN, 9n)).toBe(false);
    expect(after.digest.coverage(CHAIN)?.seq).toBe(5n);
    // The chain has grown meanwhile: its turn walks 9 to 12 and anchors there, which joins nothing below 9.
    report.current = walk(12n, new Map([[subjectKey('agent', AGENT), 11n]]));
    await after.check.run();
    // Then, still not covered, it walks on from where the digest is covered: 5.
    expect(walkedFrom).toEqual([9n, 5n]);
    expect(after.digest.covers(CHAIN, 12n)).toBe(true);
    expect(after.digest.latest(CHAIN, 'agent', AGENT)).toBe(11n);
  });

  it('a catch-up walk that fails is the alarm, and leaves the chain uncovered', async () => {
    const fake = createFakeWriteOnceStore();
    const report: { current: WalkedReport | ChainReport } = { current: walk(5n) };
    const first = process(fake, chainOf(report));
    await first.check.run();
    // A process whose digest is empty, as after a rebase: its catch-up walks from the first event, and finds it broken.
    const fresh = createFakeWriteOnceStore();
    for (const [name, bytes] of fake.files) if (!name.includes('/digests/')) fresh.files.set(name, bytes);
    const walkedFrom: (bigint | undefined)[] = [];
    const after = process(fresh, chainOf(report, walkedFrom));
    await after.log.read();
    let calls = 0;
    const answers: (WalkedReport | ChainReport)[] = [walk(5n), { ok: false, problem: { reason: 'hash', seq: 2n } }];
    const organizations = chainOf(report, walkedFrom);
    const failing: OrganisationChains = {
      ...organizations,
      verify: (orgId, anchor) => {
        report.current = answers[Math.min(calls, 1)] ?? walk(5n);
        calls += 1;
        return organizations.verify(orgId, anchor);
      },
    };
    const check = createAnchorCheck({
      chains: [],
      organizations: failing,
      keys,
      clock: after.clock,
      logger: testLogger(after.capture),
      staleAfterMs: STALE_MS,
      deadlineMs: 120_000,
      durable: after.log,
      digest: after.digest,
    });
    await check.run();
    expect(walkedFrom).toEqual([5n, 0n]);
    expect(after.digest.covers(CHAIN, 5n)).toBe(false);
    expect(after.capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.integrity_failed', reason: 'hash', seq: '2' }),
    );
  });

  it('dates what a walk read when the walk began, so a rebase landing during it sets it aside', async () => {
    const fake = createFakeWriteOnceStore();
    const clocked: { advance?: () => void } = {};
    const { check, digest, clock } = process(fake, {
      ...chainOf({ current: walk(3n) }),
      verify: () => {
        // The walk takes ten seconds: the anchor is signed at its end.
        clocked.advance?.();
        return Promise.resolve(walk(3n, new Map([[subjectKey('agent', AGENT), 2n]])));
      },
    });
    clocked.advance = () => {
      clock.advanceBy(10_000);
    };
    await check.run();
    expect(digest.latest(CHAIN, 'agent', AGENT)).toBe(2n);
    const [delta] = digestFiles(fake).filter((name) => name.includes('/deltas/'));
    const [line] = gunzipSync(fake.files.get(delta ?? '') ?? Buffer.alloc(0))
      .toString('utf8')
      .split('\n');
    expect(JSON.parse(line ?? '{}')).toMatchObject({ t: AT.toISOString() });
  });

  it('no catch-up while the chain’s own check is still under way past its deadline, and nothing said of it', async () => {
    const fake = createFakeWriteOnceStore();
    await process(fake, chainOf({ current: walk(5n) })).check.run();
    // A process with the anchor and no digest yet: uncovered, but its check hangs past the deadline.
    const fresh = createFakeWriteOnceStore();
    for (const [name, bytes] of fake.files) if (!name.includes('/digests/')) fresh.files.set(name, bytes);
    const walkedFrom: (bigint | undefined)[] = [];
    const hanging: OrganisationChains = {
      ...chainOf({ current: walk(5n) }, walkedFrom),
      verify: (_orgId, anchor) => {
        walkedFrom.push(anchor?.seq);
        return new Promise(() => undefined);
      },
    };
    const { check, digest, capture } = process(fresh, hanging, { deadlineMs: 50 });
    await check.run();
    expect(walkedFrom).toEqual([5n]);
    expect(digest.covers(CHAIN, 5n)).toBe(false);
    expect(capture.lines().filter((line) => line.event === 'audit.state_digest_catch_up_failed')).toEqual([]);
  });

  it('a slow digest write is its own warning, never the anchors’ write failing', async () => {
    const fake = createFakeWriteOnceStore();
    const report = { current: walk(3n, new Map([[subjectKey('agent', AGENT), 2n]])) };
    const { check, capture } = process(fake, chainOf(report), { deadlineMs: 50 });
    const put = fake.real.put.bind(fake.real);
    fake.instead.put = (name, bytes) => (name.includes('/digests/') ? new Promise(() => undefined) : put(name, bytes));
    await check.run();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.state_digest_store_failed', what: 'write' }),
    );
    expect(capture.lines().filter((line) => String(line.event).startsWith('audit.anchor_store_write'))).toEqual([]);
    expect([...fake.files.keys()].some((name) => !name.includes('/digests/'))).toBe(true);
  });
});
