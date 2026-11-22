// Where the witness log (TR-1, @agentx/platform/audit-chain's witness-log.ts) keeps every copy's chain heads, as the
// config sets it up: the heads' write-once container on Azure as the process's own managed identity and the leader's
// snapshots' apart, or local folders in development and test. Every copy of the API, a web copy too, adds its heads and
// reads the others'; only the copy leading the jobs writes snapshots (and only it is given a role that may).
//
// With no heads' store named, there is no witness log: every write and read goes on as before it. Production never
// gets here (its config refuses to start); staging says so as the error line `audit.witness_store_not_set` (code can
// reach it before its `apps` hand deploy sets the store, and a refusal would take it down until then); development and
// test say nothing, as they run without one on purpose.
//
// Its job (`createWitnessJob`), on every copy: what waits written every few seconds (the `soon` heads; a `now` head
// goes at once, without it), the store read again on the copy's cadence (the jobs copy every 10 s, as its hand-offs and
// probes need it fresh; a web copy every minute, as its anchors), and the leader's probe of the chains that gained a
// head, and of those holding most (anchor-check.ts's probeWitnessed: TR-3, the heads it confirms let go between anchor
// runs, so a burst never fills what may be held). As the API stops, what waits is written.
//
// What may be held (TR-3): enough for an anchor interval's heads at the target rate, with headroom, or the heap share
// where that is more, and never past a tenth of the heap: a spike may slow a chain's anchoring, never stop it.
import { getHeapStatistics } from 'node:v8';

import type { Clock } from '@agentx/core/shared-kernel';
import { type Chain, createWitnessLog, WITNESS_HEAD_BYTES, type WitnessLog } from '@agentx/platform/audit-chain';
import { type Config, LOCAL_ONLY, type StorePlace } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import {
  azureBlobOrigins,
  azureWriteOnceStore,
  folderWriteOnceStore,
  type WriteOnceStore,
} from '@agentx/platform/storage';

import { scheduleRuns } from './background.ts';
import { webCopyLogger } from './anchor-store.ts';

/** How often what waits is written: the `soon` heads' longest wait. */
export const WITNESS_FLUSH_EVERY_MS = 5_000;

/** How often the jobs copy reads the store again: its hand-offs and probes go by it. */
export const JOBS_WITNESS_EVERY_MS = 10_000;

/** How often a web copy reads it again: as its anchors (web-anchors.ts). */
export const WEB_WITNESS_EVERY_MS = 60_000;

/** The share of the heap the witnessed heads may take at least: 80,000 heads in a 1 GiB heap. */
const HEAP_SHARE = 0.005;

/** The most of the heap they may take, however busy: a tenth, as the digest's. */
const MOST_HEAP_SHARE = 0.1;

/** The chain writes a second what may be held is sized for (4D2e's target: 170 a second), and the headroom on it. */
const TARGET_WRITES_A_SECOND = 170;
const HEADROOM = 4;

/** How many of the chains holding most the leader probes after each read, beside those that gained a head. */
const CROWDED_PROBED = 50;

/**
 * What the witnessed heads may take (the header): an anchor interval's heads at the target rate, with headroom, or the
 * heap share where that is more; never past MOST_HEAP_SHARE.
 */
export function witnessMostBytes(anchorSeconds: number, heapLimit: number): number {
  // With the fingerprints' tenth on top (witness-log.ts).
  const forTheRate = (anchorSeconds * TARGET_WRITES_A_SECOND * HEADROOM * WITNESS_HEAD_BYTES * 11) / 10;
  return Math.floor(Math.min(heapLimit * MOST_HEAP_SHARE, Math.max(heapLimit * HEAP_SHARE, forTheRate)));
}

/** A chain's name, to tell two apart. */
const chainNamed = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId.toLowerCase());

/** The store a place names, or none. */
export function storeAt({ directory, container }: StorePlace): WriteOnceStore | undefined {
  if (container !== null) {
    return azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  }
  return directory === null ? undefined : folderWriteOnceStore(directory);
}

/**
 * The witness log the config names, or none (the header). A web copy's lines go by a web copy's logger
 * (anchor-store.ts's webCopyLogger: its read failures as `audit.web_witness_read_failed`); a write failing stays this
 * copy's own, as its stops wait on it.
 */
export function witnessOf(
  config: Config,
  {
    keys,
    logger,
    clock,
    leading,
  }: {
    readonly keys: KeyProvider;
    readonly logger: Logger;
    readonly clock: Clock;
    /** Whether this copy leads the jobs, and so writes the snapshots: none, never (a web copy). */
    readonly leading?: (() => boolean) | undefined;
  },
): WitnessLog | undefined {
  const store = storeAt(config.witnessStore.heads);
  if (store === undefined) {
    if (!LOCAL_ONLY.includes(config.environment)) {
      logger.error('audit.witness_store_not_set', { environment: config.environment });
    }
    return undefined;
  }
  return createWitnessLog({
    store,
    snapshots: storeAt(config.witnessStore.snapshots),
    keys,
    logger: config.role === 'web' ? webCopyLogger(logger) : logger,
    now: () => clock.now(),
    epoch: config.audit.anchorEpoch,
    writes: leading,
    // A web copy checks no chain: it lets a head go once the jobs copy, which confirms every head, anchored past it.
    dropsAtAnchor: config.role === 'web',
    // As the anchor check's own stale limit: what the store may fail before that is the alert.
    alertAfterMs: config.audit.anchorSeconds * 3 * 1000,
    mostBytes: witnessMostBytes(config.audit.anchorSeconds, getHeapStatistics().heap_size_limit),
  });
}

/**
 * The witness log's job (the header): its writes every WITNESS_FLUSH_EVERY_MS, its reads every `refreshEveryMs`, each
 * read's gained chains and the chains holding most handed to `afterRefresh` (the leader's probe). Writes what waits as
 * it stops. Never throws.
 */
export function createWitnessJob({
  witness,
  refreshEveryMs,
  now,
  afterRefresh,
}: {
  readonly witness: Pick<WitnessLog, 'flush' | 'refresh'> & Partial<Pick<WitnessLog, 'crowded'>>;
  readonly refreshEveryMs: number;
  readonly now: () => number;
  readonly afterRefresh?: (gained: readonly Chain[], signal?: AbortSignal) => Promise<void>;
}) {
  let refreshedAt: number | undefined;
  const work = {
    async run(signal?: AbortSignal): Promise<void> {
      await witness.flush();
      const at = now();
      if (refreshedAt !== undefined && at - refreshedAt < refreshEveryMs) return;
      refreshedAt = at;
      const gained = await witness.refresh();
      // Those holding most too, so heads confirmed between anchor runs are let go (TR-3), each chain once.
      const probed = [...gained];
      for (const chain of witness.crowded?.(CROWDED_PROBED) ?? []) {
        if (!probed.some((one) => chainNamed(one) === chainNamed(chain))) probed.push(chain);
      }
      if (probed.length > 0) await afterRefresh?.(probed, signal);
    },
  };
  return {
    work,
    /** Its runs scheduled, and what waits written once they stop. */
    schedule: (
      watched: { run(signal?: AbortSignal): Promise<unknown> },
      everyMs: number,
    ): { stop(): Promise<void> } => {
      const runs = scheduleRuns(watched, everyMs);
      return {
        stop: async () => {
          await runs.stop();
          await witness.flush();
        },
      };
    },
  };
}
