// TR-1 F.6 (S209): the hand-off's witness gate, every doubt that needs no walk of the database, each with the payment
// let go beside it. The walks above Tx A's heads (a later write linked, a fork, a pause after P) are
// witness-gate.db.test.ts's.
import type { FrontierStart, WalkedWithin } from '@agentx/core/modules/audit';
import type { Chain, HeadSeen, WitnessedHead } from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { LogCapture, SequentialIds, testLogger } from '@agentx/testing';
import { describe, expect, it, vi } from 'vitest';

import { HANDOFF_PAUSED, HANDOFF_RESUMED } from '@agentx/core/modules/platform-controls';

import {
  createHandoffWitnessGate,
  type GateWalks,
  pauseStartedIn,
  walkedOf,
  type WitnessedTxA,
} from './handoff-witness-gate.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-00000000a001';
const hash = (fill: number): Buffer => Buffer.alloc(32, fill);
const point = (seq: bigint) => ({ seq, hash: hash(Number(seq)), macKeyVersion: 1 });
const seen = (seq: bigint, fill = Number(seq)): WitnessedHead => ({ seq, hash: hash(fill), at: 0 });

/** A chain walked from an anchor at 2 to the head 6, every event's hash its place. */
const walkedTo = (head: bigint): { readonly start: FrontierStart; readonly walk: WalkedWithin } => ({
  start: { base: point(2n), hashes: Buffer.alloc(0), from: point(2n), at: 0 },
  walk: {
    kind: 'walked',
    head: point(head),
    path: new Map(Array.from({ length: Number(head - 2n) }, (_, n) => [3n + BigInt(n), hash(3 + n)])),
  },
});

/** Tx A as it committed: its head 8 (two events past the head it locked, 6), both chains walked. */
const txA = (head: WitnessedTxA['head'] = { seq: 8n, hash: hash(8) }): WitnessedTxA => ({
  orgId: ORG,
  requestId: '0199a0f0-0000-7000-8000-00000000a002',
  head,
  org: walkedTo(6n),
  platform: walkedTo(6n),
});

/** A witness log as the gate asks it, every answer a test's to set. */
function witnessWith({
  org = [],
  platform = [],
  put = () => Promise.resolve(),
  whole = () => Promise.resolve(true),
  beyond = false,
}: {
  readonly org?: readonly HeadSeen[];
  readonly platform?: readonly HeadSeen[];
  readonly put?: () => Promise<void>;
  readonly whole?: () => Promise<boolean>;
  readonly beyond?: boolean;
} = {}) {
  const pending = (chain: Chain): readonly WitnessedHead[] =>
    (chain.kind === 'platform' ? platform : org).map((head) => ({ ...head, at: 0 }));
  return {
    now: vi.fn(put),
    settled: vi.fn(put),
    refreshWhole: vi.fn(whole),
    pending: vi.fn(pending),
    beyondMemory: vi.fn(() => beyond),
  };
}

/** Walks a test never expects: one asked for fails the test. */
const NO_WALKS: GateWalks = {
  org: () => Promise.reject(new Error('no walk expected')),
  platform: () => Promise.reject(new Error('no walk expected')),
};

/** A walk's answer: reached the head it was asked to (`to`), short of it, or refused. */
const reached = (seq: bigint, to = seq) => ({ ok: true as const, ...point(seq), to });
const refused = (reason: 'cut_back' | 'hash', seq: bigint) => ({ ok: false as const, problem: { reason, seq } });

/** The gate over the witness given, its database never reached (a hold's write fails, said, and never throws). */
async function cleared(
  witness: ReturnType<typeof witnessWith>,
  asked = txA(),
  { deadlineMs, walks = NO_WALKS }: { readonly deadlineMs?: number; readonly walks?: GateWalks | 'database' } = {},
) {
  const capture = new LogCapture();
  const gate = createHandoffWitnessGate({
    witness,
    database: {} as Database<never>,
    keys,
    ids: new SequentialIds(0x9a00_0000),
    ...(walks === 'database' ? {} : { walks }),
    ...(deadlineMs === undefined ? {} : { deadlineMs }),
  });
  const go = await gate.clear(asked, testLogger(capture));
  const held = capture
    .lines()
    .filter(({ event }) => event === 'handoff.held_before_sending')
    .map(({ reason }) => reason);
  const forks = capture.lines().filter(({ event, check }) => event === 'audit.integrity_failed' && check === 'witness');
  return { go, held, forks };
}

describe('TR-1 F.6 the witness gate before the partner call', () => {
  it('lets the payment go where every head witnessed is on Tx A’s paths, or its own head; H_A noted, its Put waited for', async () => {
    const witness = witnessWith({ org: [seen(4n), seen(8n)], platform: [seen(5n)] });
    expect(await cleared(witness)).toEqual({ go: true, held: [], forks: [] });
    expect(witness.settled).toHaveBeenCalledTimes(1);
    expect(witness.now).not.toHaveBeenCalled();
    // H_A not noted here (its commit's hook missed it): noted and written now.
    const unnoted = witnessWith();
    expect((await cleared(unnoted)).go).toBe(true);
    expect(unnoted.now).toHaveBeenCalledWith({ kind: 'organisation', orgId: ORG }, { seq: 8n, hash: hash(8) });
  });

  it.each([
    ['no head to witness', witnessWith(), { ...txA(), head: undefined }, 'no_head'],
    [
      'its head not confirmed',
      witnessWith({ put: () => Promise.reject(new Error('down')) }),
      txA(),
      'witness_unconfirmed',
    ],
    [
      'a read after the commit not whole',
      witnessWith({ whole: () => Promise.resolve(false) }),
      txA(),
      'witness_unread',
    ],
    ['a read that throws', witnessWith({ whole: () => Promise.reject(new Error('x')) }), txA(), 'witness_unread'],
    ['the log past its memory', witnessWith({ beyond: true }), txA(), 'witness_pending'],
    ['a Tx A that walked no organisation chain', witnessWith(), { ...txA(), org: undefined }, 'not_walked'],
    ['a Tx A that walked no platform chain', witnessWith(), { ...txA(), platform: undefined }, 'not_walked'],
    ['a head below Tx A’s stretch', witnessWith({ org: [seen(1n)] }), txA(), 'unjudged'],
    ['a platform head below Tx A’s stretch', witnessWith({ platform: [seen(1n)] }), txA(), 'unjudged'],
  ])('holds the payment, unsent, on %s', async (_what, witness, asked, reason) => {
    expect(await cleared(witness, asked)).toEqual({ go: false, held: [reason], forks: [] });
  });

  it('a head off the organisation’s path, or another at H_A’s place, is a fork: held, the alarm, the organisation held', async () => {
    for (const org of [[seen(4n, 99)], [seen(8n, 99)], [seen(6n, 99)]]) {
      const { go, held, forks } = await cleared(witnessWith({ org }));
      expect(go).toBe(false);
      expect(held).toEqual(['cut_back']);
      expect(forks).toEqual([expect.objectContaining({ chain: 'organisation', check: 'witness', reason: 'cut_back' })]);
    }
  });

  it('a platform head off Tx A’s platform path is the platform cut: held and the alarm, no organisation held', async () => {
    const { go, held, forks } = await cleared(witnessWith({ platform: [seen(5n, 99)] }));
    expect({ go, held }).toEqual({ go: false, held: ['platform_cut_back'] });
    expect(forks).toEqual([expect.objectContaining({ chain: 'platform', check: 'witness', seq: '5' })]);
  });

  it('heads above Tx A’s: a walk from the head it locked, linked, lets it go; a fork, too far or a pause after P holds it', async () => {
    const above = witnessWith({ org: [seen(9n)], platform: [seen(7n)] });
    const asked: { org?: readonly HeadSeen[]; platform?: readonly HeadSeen[] } = {};
    const linked: GateWalks = {
      org: (_orgId, from, heldTo) => {
        expect(from.seq).toBe(6n);
        asked.org = heldTo;
        return Promise.resolve(reached(9n));
      },
      platform: (from, heldTo) => {
        expect(from.seq).toBe(6n);
        asked.platform = heldTo;
        return Promise.resolve(reached(7n));
      },
    };
    expect(await cleared(above, txA(), { walks: linked })).toEqual({ go: true, held: [], forks: [] });
    // Held to the heads above, and to H_A itself.
    expect(asked.org?.map(({ seq }) => seq)).toEqual([9n, 8n]);
    expect(asked.platform?.map(({ seq }) => seq)).toEqual([7n]);

    const fork = await cleared(above, txA(), {
      walks: { ...linked, org: () => Promise.resolve(refused('cut_back', 9n)) },
    });
    expect(fork.held).toEqual(['cut_back']);
    expect(fork.forks).toEqual([expect.objectContaining({ chain: 'organisation', seq: '9' })]);
    const short = await cleared(above, txA(), { walks: { ...linked, org: () => Promise.resolve(reached(8n, 9n)) } });
    expect(short.held).toEqual(['too_far']);
    const platformFork = await cleared(above, txA(), {
      walks: { ...linked, platform: () => Promise.resolve(refused('hash', 7n)) },
    });
    expect(platformFork.held).toEqual(['platform_hash']);
    expect(platformFork.forks).toEqual([expect.objectContaining({ chain: 'platform', seq: '7' })]);
    const platformShort = await cleared(above, txA(), {
      walks: { ...linked, platform: () => Promise.resolve(reached(6n, 7n)) },
    });
    expect(platformShort.held).toEqual(['too_far']);
    const paused = await cleared(above, txA(), {
      walks: { ...linked, platform: () => Promise.resolve({ ...reached(7n), signed: new Map([['pause', 7n]]) }) },
    });
    expect(paused).toEqual({ go: false, held: ['paused'], forks: [] });
    // A walk that found nothing to note: none paused.
    const noted = await cleared(above, txA(), {
      walks: { ...linked, platform: () => Promise.resolve({ ...reached(7n), signed: new Map() }) },
    });
    expect(noted.go).toBe(true);
  });

  it('the database’s own walks, failing (no database here), hold it as a gate that failed', async () => {
    const org = await cleared(witnessWith({ org: [seen(9n)] }), txA(), { walks: 'database' });
    expect(org.held).toEqual(['gate_failed']);
    const platform = await cleared(witnessWith({ platform: [seen(9n)] }), txA(), { walks: 'database' });
    expect(platform.held).toEqual(['gate_failed']);
  });

  it('a walk is whole only with its start and its reading; only a pause started is one the platform walk notes', () => {
    const { start, walk } = walkedTo(6n);
    expect(walkedOf(start, walk)).toEqual({ start, walk });
    expect(walkedOf(undefined, walk)).toBeUndefined();
    expect(walkedOf(start, undefined)).toBeUndefined();
    expect(pauseStartedIn(HANDOFF_PAUSED)).toBeDefined();
    expect(pauseStartedIn(HANDOFF_RESUMED)).toBeUndefined();
  });

  it('a store that never answers holds the payment at the deadline; a gate that fails holds it too', async () => {
    const hung = witnessWith({ whole: () => new Promise<boolean>(() => undefined) });
    expect(await cleared(hung, txA(), { deadlineMs: 10 })).toEqual({ go: false, held: ['deadline'], forks: [] });
    const broken = witnessWith();
    broken.beyondMemory.mockImplementation(() => {
      throw new Error('broken');
    });
    expect(await cleared(broken)).toEqual({ go: false, held: ['gate_failed'], forks: [] });
  });
});
