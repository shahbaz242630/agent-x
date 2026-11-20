// Where the chains' anchors are kept, as the config sets it up (PL-58): a
// write-once container on Azure as the API's own managed identity, or the local
// folder in development and test. With neither set, memory alone, as job-list.ts
// has it, and a restart forgets them: deployed that is an error line and the
// store's alert. Production never gets here, its config refuses to start
// (config.ts); staging runs on, as code can reach it before its `apps` hand deploy
// sets the store, and a refusal would take it down until then.
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

export function anchorLogOf(config: Config, services: StoreServices): AnchorLog | undefined {
  return anchorsKeptOf(config, services)?.log;
}

/**
 * The anchors' log and, in the same store, the signed states' digest (AT13, digest-log.ts): the digest after the log,
 * whose rebases and shards it goes by, and counted in the log's budget, keeping itself to half of it.
 */
export function anchorsKeptOf(
  { environment, anchorStore: { directory, container }, audit: { anchorEpoch: epoch } }: Config,
  { clock, ...services }: StoreServices,
): { readonly log: AnchorLog; readonly digest: DigestLog } | undefined {
  let store: WriteOnceStore;
  if (container !== null) {
    store = azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  } else if (directory !== null) {
    store = folderWriteOnceStore(directory);
  } else {
    if (!LOCAL_ONLY.includes(environment)) services.logger.error('audit.anchor_store_not_set', { environment });
    return undefined;
  }
  const now = (): Date => clock.now();
  // Made after the log, which counts it: asked only once both are made.
  const kept: { digest?: DigestLog } = {};
  // The API's jobs anchor, so they move the store on to the shards (PL-65 PR2); the operator's job only reads it. They
  // let shards go past what they can hold (PR3), asking for one's anchors only with it pinned or held.
  const log = createAnchorLog({
    ...services,
    store,
    epoch,
    now,
    cutOver: true,
    evicts: true,
    alsoHeld: () => kept.digest?.memoryHeld().bytes ?? 0,
  });
  const digest = createDigestLog({
    ...services,
    store,
    epoch,
    now,
    anchors: log,
    mostBytes: Math.floor(log.memoryHeld().mostBytes / 2),
  });
  kept.digest = digest;
  return { log, digest };
}
