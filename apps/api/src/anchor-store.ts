// Where the chains' anchors are kept, as the config sets it up (PL-58): a
// write-once container on Azure as the API's own managed identity, or the local
// folder in development and test. With neither set, memory alone, as job-list.ts
// has it, and a restart forgets them: deployed that is an error line and the
// store's alert. Production never gets here, its config refuses to start
// (config.ts); staging runs on, as code can reach it before its `apps` hand deploy
// sets the store, and a refusal would take it down until then.
import type { Clock } from '@agentx/core/shared-kernel';
import { type AnchorLog, createAnchorLog } from '@agentx/platform/audit-chain';
import { type Config, LOCAL_ONLY } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureWriteOnceStore, folderWriteOnceStore } from '@agentx/platform/storage';

export function anchorLogOf(
  { environment, anchorStore: { directory, container }, audit: { anchorEpoch: epoch } }: Config,
  {
    clock,
    ...services
  }: {
    readonly keys: KeyProvider;
    readonly logger: Logger;
    readonly clock: Clock;
    readonly alertAfterMs: number;
  },
): AnchorLog | undefined {
  // The API's jobs anchor, so they move the store on to the shards (PL-65 PR2); the operator's job only reads it. They
  // let shards go past what they can hold (PR3), asking for one's anchors only with it pinned or held.
  const shared = { ...services, epoch, now: () => clock.now(), cutOver: true, evicts: true };
  if (container !== null) {
    const fetch = createOutboundFetch(azureBlobOrigins(container));
    return createAnchorLog({ ...shared, store: azureWriteOnceStore({ settings: container, fetch }) });
  }
  if (directory !== null) return createAnchorLog({ ...shared, store: folderWriteOnceStore(directory) });
  if (!LOCAL_ONLY.includes(environment)) services.logger.error('audit.anchor_store_not_set', { environment });
  return undefined;
}
