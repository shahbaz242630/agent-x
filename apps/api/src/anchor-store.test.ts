import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { LONGEST_ABSOLUTE_SECONDS } from '@agentx/core/modules/identity';
import { APPROVAL_HORIZON_MS } from '@agentx/core/modules/spend-requests';
import { createWitnessLog, signAnchor, subjectKey } from '@agentx/platform/audit-chain';
import type { Config } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { anchorLogOf, anchorsKeptOf } from './anchor-store.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const AT = new Date('2026-11-02T09:00:00.000Z');
const services = { keys, logger: testLogger(new LogCapture()), clock: { now: () => AT }, alertAfterMs: 900_000 };
/** The log it makes for the config, and the lines saying no store is named. */
const madeFor = (config: Config) => {
  const capture = new LogCapture();
  const log = anchorLogOf(config, { ...services, logger: testLogger(capture) });
  return { log, notSet: capture.lines().filter((line) => line.event === 'audit.anchor_store_not_set') };
};
const CONTAINER = {
  url: 'http://127.0.0.1:1/audit-anchors',
  clientId: 'c',
  identityEndpoint: 'http://127.0.0.1:1/token',
  identityHeader: 'h',
};
const configWith = (anchorStore: Config['anchorStore'], anchorEpoch = 1, environment = 'test'): Config =>
  ({ environment, anchorStore, audit: { anchorSeconds: 300, anchorEpoch } }) as Config;

const folders: string[] = [];
afterEach(() => {
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});

describe("where the chains' anchors are kept (PL-58)", () => {
  it.each(['development', 'test'])('memory alone with no store named, in %s, which is no fault', (environment) => {
    const { log, notSet } = madeFor(configWith({ directory: null, container: null }, 1, environment));
    expect(log).toBeUndefined();
    expect(notSet).toEqual([]);
  });

  it('staging with no store named runs from memory, and says so where the alert reads it', () => {
    const { log, notSet } = madeFor(configWith({ directory: null, container: null }, 1, 'staging'));
    expect(log).toBeUndefined();
    expect(notSet).toEqual([expect.objectContaining({ level: 'error', environment: 'staging' })]);
  });

  it('the container where one is named', () => {
    const { log, notSet } = madeFor(configWith({ directory: null, container: CONTAINER }, 1, 'staging'));
    expect(log?.state()).toBe('unread');
    expect(notSet).toEqual([]);
  });

  it('the folder where one is named, under the epoch the setting names, across a restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchors-'));
    folders.push(directory);
    const log = anchorLogOf(configWith({ directory, container: null }, 2), services);
    await log?.read();
    log?.keep(signAnchor(keys, { kind: 'platform' }, { seq: 4n, hash: Buffer.alloc(32, 4), macKeyVersion: 1 }, AT, 2));
    await log?.flush();

    const after = anchorLogOf(configWith({ directory, container: null }, 2), services);
    await after?.read();
    expect(after?.latest({ kind: 'platform' })?.seq).toBe(4n);

    const newEpoch = anchorLogOf(configWith({ directory, container: null }, 3), services);
    await newEpoch?.read();
    expect(newEpoch?.state()).toBe('read');
    expect(newEpoch?.latest({ kind: 'platform' })).toBeUndefined();
  });

  it('the signed states’ digest in the same folder, half the anchors’ budget, counted in theirs (AT13)', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchors-'));
    folders.push(directory);
    const config = configWith({ directory, container: null }, 2);
    const kept = anchorsKeptOf(config, services);
    if (kept === undefined) throw new Error('A folder is named');
    const { log, digest } = kept;
    expect(digest.memoryHeld().mostBytes).toBe(Math.floor(log.memoryHeld().mostBytes / 2));
    const before = log.memoryHeld().bytes;
    await log.read();
    await digest.read();
    const chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000001' } as const;
    digest.record(chain, new Map([[subjectKey('agent', '0199a0f0-0000-7000-8000-0000000000a1'), 3n]]), AT);
    expect(log.memoryHeld().bytes).toBe(before + digest.memoryHeld().bytes);
    await digest.flush();

    const after = anchorsKeptOf(config, services);
    await after?.log.read();
    await after?.digest.read();
    expect(after?.digest.latest(chain, 'agent', '0199a0f0-0000-7000-8000-0000000000a1')).toBe(3n);
    expect(anchorsKeptOf(configWith({ directory: null, container: null }), services)).toBeUndefined();
  });

  it('its digest forgets a request’s facts past the approval horizon, and session ends past the longest session (AT13d/g)', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchors-'));
    folders.push(directory);
    const time = { at: AT.getTime() };
    const kept = anchorsKeptOf(configWith({ directory, container: null }, 2), {
      ...services,
      clock: { now: () => new Date(time.at) },
    });
    if (kept === undefined) throw new Error('A folder is named');
    await kept.log.read();
    await kept.digest.read();
    const chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000001' } as const;
    const platform = { kind: 'platform' } as const;
    const REQUEST = '0199a0f0-0000-7000-8000-0000000000c1';
    const ENDED = '0199a0f0-0000-7000-8000-0000000000aa:0199a0f0-0000-7000-8000-0000000000bb';
    kept.digest.record(chain, new Map([[subjectKey('spend_request', REQUEST), 3n]]), AT);
    kept.digest.record(platform, new Map([[subjectKey('identity.session_ended', ENDED), 4n]]), AT);
    const DAY = 86_400_000;
    // The longest session (LONGEST_ABSOLUTE_SECONDS) and the day's margin past it, and a minute: the end goes.
    time.at = AT.getTime() + LONGEST_ABSOLUTE_SECONDS * 1000 + DAY + 60_000;
    kept.digest.record(chain, new Map(), new Date(time.at));
    expect(kept.digest.latest(platform, 'identity.session_ended', ENDED)).toBeUndefined();
    expect(kept.digest.latest(chain, 'spend_request', REQUEST)).toBe(3n);
    // The approval horizon (APPROVAL_HORIZON_MS) and the day's margin past it, and an hour: the request's go.
    time.at = AT.getTime() + APPROVAL_HORIZON_MS + DAY + 3_600_000;
    kept.digest.record(chain, new Map(), new Date(time.at));
    expect(kept.digest.latest(chain, 'spend_request', REQUEST)).toBeUndefined();
  });

  it('SEC-DB-20 TR-9: its digest holds each read to the witness log’s whole held set, a head released on a probe’s finding too', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchors-'));
    folders.push(directory);
    const witness = createWitnessLog({
      store: createFakeWriteOnceStore().store,
      keys,
      logger: testLogger(),
      now: () => AT,
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 1024 * 1024,
    });
    const kept = anchorsKeptOf(configWith({ directory, container: null }, 2), { ...services, witness });
    if (kept === undefined) throw new Error('A folder is named');
    await kept.log.read();
    await kept.digest.read();
    const chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000001' } as const;
    const stop = { seq: 4n, hash: Buffer.alloc(32, 4) };
    const higher = { seq: 6n, hash: Buffer.alloc(32, 6) };
    witness.soon(chain, stop);
    witness.soon(chain, higher);
    // An anchor below both, kept whole, as the probe releases above it (this folder's log holds none).
    witness.useAnchors({ rebasedAfter: () => false, latest: () => ({ seq: 2n, hash: Buffer.alloc(32, 2) }) });
    witness.release(chain, [stop]);
    expect(witness.pending(chain)).toEqual([expect.objectContaining(higher)]);
    expect(kept.digest.heads(chain)?.heldTo).toEqual([higher, { seq: 4n, hash: stop.hash.subarray(0, 16) }]);
  });
});
