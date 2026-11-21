// Where the chains' anchors are kept, as the config sets it up (PL-58): a
// write-once container on Azure as the API's own managed identity, or the local
// folder in development and test. With neither set, memory alone, as job-list.ts
// has it, and a restart forgets them: deployed that is an error line and the
// store's alert. Production's jobs never get here, their config refuses to start
// (config.ts); staging runs on, as code can reach it before its `apps` hand deploy
// sets the store, and a refusal would take it down until then.
//
// A `web` copy (AT13b) reads the same store and never writes it (`anchorsReadOf`): its identity is given only the
// anchors' reader role in production (modules/evidence.bicep), and the store it is handed refuses every write besides,
// so no path in the anchors' log or the digest can add a file from a copy that doesn't lead.
import type { Clock } from '@agentx/core/shared-kernel';
import { type AnchorLog, createAnchorLog, createDigestLog, type DigestLog } from '@agentx/platform/audit-chain';
import { type Config, LOCAL_ONLY } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import {
  azureBlobOrigins,
  azureWriteOnceStore,
  folderWriteOnceStore,
  type WriteOnceStore,
} from '@agentx/platform/storage';

interface StoreServices {
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly clock: Clock;
  readonly alertAfterMs: number;
}

/** The anchors' log and the signed states' digest, kept in the same store. */
export interface AnchorsKept {
  readonly log: AnchorLog;
  readonly digest: DigestLog;
}

/** A write a read-only copy tried: never meant to happen, so it is the error line and the write fails. */
export class ReadOnlyStore extends Error {}

/** The store as a copy that only reads it sees it: every write refused, said. */
export function readOnlyStore(store: WriteOnceStore, logger: Logger): WriteOnceStore {
  return Object.freeze({
    put: (name: string): Promise<void> => {
      logger.error('audit.anchor_store_write_refused', { file: name });
      return Promise.reject(new ReadOnlyStore(`a read-only copy may not write ${name}`));
    },
    list: (start: string, most: number, after?: string) => store.list(start, most, after),
    get: (name: string) => store.get(name),
    getAtMost: (name: string, mostBytes: number) => store.getAtMost(name, mostBytes),
  });
}

export function anchorLogOf(config: Config, services: StoreServices): AnchorLog | undefined {
  return anchorsKeptOf(config, services)?.log;
}

/** The store the config names, or none, said where that is a fault. */
function storeOf(
  { environment, anchorStore: { directory, container } }: Config,
  logger: Logger,
): WriteOnceStore | undefined {
  if (container !== null) {
    return azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  }
  if (directory !== null) return folderWriteOnceStore(directory);
  if (!LOCAL_ONLY.includes(environment)) logger.error('audit.anchor_store_not_set', { environment });
  return undefined;
}

/** The log and the digest over a store: the digest after the log, whose rebases and shards it goes by. */
function keptIn(
  store: WriteOnceStore,
  epoch: number,
  { clock, ...services }: StoreServices,
  { cutOver, leading }: { readonly cutOver: boolean; readonly leading: (() => boolean) | undefined },
): AnchorsKept {
  const now = (): Date => clock.now();
  // Made after the log, which counts it: asked only once both are made.
  const kept: { digest?: DigestLog } = {};
  // Shards let go past what the process can hold (PR3), asking for one's anchors only with it pinned or held: so a
  // chain whose shard went says nothing from the digest either, on a copy that keeps the anchors or one that reads them.
  const log = createAnchorLog({
    ...services,
    store,
    epoch,
    now,
    cutOver,
    evicts: true,
    alsoHeld: () => kept.digest?.bytesHeld() ?? 0,
  });
  const digest = createDigestLog({
    ...services,
    store,
    epoch,
    now,
    anchors: log,
    leading,
    mostBytes: Math.floor(log.memoryHeld().mostBytes / 2),
  });
  kept.digest = digest;
  return { log, digest };
}

/**
 * The anchors' log and, in the same store, the signed states' digest (AT13, digest-log.ts): the digest after the log,
 * whose rebases and shards it goes by, and counted in the log's budget, keeping itself to half of it.
 */
export function anchorsKeptOf(
  config: Config,
  services: StoreServices,
  /** Whether this process leads the jobs: one that doesn't says nothing from its digest (digest-log.ts). */
  leading?: () => boolean,
): AnchorsKept | undefined {
  const store = storeOf(config, services.logger);
  // The API's jobs anchor, so they move the store on to the shards (PL-65 PR2); the operator's job only reads it.
  return store && keptIn(store, config.audit.anchorEpoch, services, { cutOver: true, leading });
}

/**
 * A `web` copy's (AT13b): the same log and digest, read only. It never moves the store on (no cutover: that is a write),
 * never leads, so its digest speaks from what it read whatever the lease says, and its store refuses every write. The
 * same budget as a copy that keeps them, a share of its own heap, so it gives way the same way.
 */
export function anchorsReadOf(config: Config, services: StoreServices): AnchorsKept | undefined {
  const store = storeOf(config, services.logger);
  return (
    store &&
    keptIn(readOnlyStore(store, services.logger), config.audit.anchorEpoch, services, {
      cutOver: false,
      leading: undefined,
    })
  );
}
