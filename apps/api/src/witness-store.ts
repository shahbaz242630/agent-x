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
// head (anchor-check.ts's probeWitnessed). As the API stops, what waits is written.
import { getHeapStatistics } from 'node:v8';

import type { Clock } from '@agentx/core/shared-kernel';
import { type Chain, createWitnessLog, type WitnessLog } from '@agentx/platform/audit-chain';
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

/** The share of the heap the witnessed heads may take: 80,000 heads in a 1 GiB heap. */
const HEAP_SHARE = 0.005;

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
    // As the anchor check's own stale limit: what the store may fail before that is the alert.
    alertAfterMs: config.audit.anchorSeconds * 3 * 1000,
    mostBytes: Math.floor(getHeapStatistics().heap_size_limit * HEAP_SHARE),
  });
}

/**
 * The witness log's job (the header): its writes every WITNESS_FLUSH_EVERY_MS, its reads every `refreshEveryMs`, each
 * read's gained chains handed to `afterRefresh` (the leader's probe). Writes what waits as it stops. Never throws.
 */
export function createWitnessJob({
  witness,
  refreshEveryMs,
  now,
  afterRefresh,
}: {
  readonly witness: Pick<WitnessLog, 'flush' | 'refresh'>;
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
      if (gained.length > 0) await afterRefresh?.(gained, signal);
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
