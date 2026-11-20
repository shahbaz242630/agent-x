// The anchor check keeping the signed states' digest (AT13): each walk under a new anchor records what it read, written
// beside the anchors and read back after them by a process started since. The decisions held to it, on the real
// tables, are in owner-tamper.db.test.ts (core) and handoff.db.test.ts.
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

import { createAnchorCheck, type OrganisationChains, type WalkedReport } from './anchor-check.ts';

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

/** One organisation's chain answering whatever `report` holds now. */
function chainOf(report: { current: WalkedReport | ChainReport }): OrganisationChains {
  return {
    list: () => Promise.resolve([ORG]),
    recorded: () => Promise.resolve([ORG]),
    verify: () => Promise.resolve(report.current),
    hold: () => Promise.resolve(),
  };
}

/** One process's start: the anchors' log and the digest over the same store, and the check keeping both. */
function process(fake: FakeWriteOnceStore, organizations: OrganisationChains, { deadlineMs = 120_000 } = {}) {
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
    chains: [],
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

describe('the anchor check keeping the signed states’ digest (AT13)', () => {
  it('records what a walk read with its new anchor, writes it beside the anchors, and a restart reads it back', async () => {
    const fake = createFakeWriteOnceStore();
    const report = { current: walk(5n, new Map([[subjectKey('agent', AGENT), 4n]])) };
    const first = process(fake, chainOf(report));
    await first.check.run();
    expect(first.digest.latest(CHAIN, 'agent', AGENT)).toBe(4n);
    expect(digestFiles(fake).length).toBeGreaterThan(0);

    const restarted = process(fake, chainOf(report));
    expect(restarted.digest.known(CHAIN)).toBe(false);
    await restarted.check.run();
    expect(restarted.digest.known(CHAIN)).toBe(true);
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
    expect(digest.known(CHAIN)).toBe(false);
  });
});
