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
import { APPROVAL_HORIZON_MS } from '@agentx/core/modules/spend-requests';
import type { Clock } from '@agentx/core/shared-kernel';
import { type AnchorLog, createAnchorLog, createDigestLog, type DigestLog } from '@agentx/platform/audit-chain';
import { type Config, LOCAL_ONLY } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger, ProblemEvent } from '@agentx/platform/observability';
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

/** The store the config names, or none, said where `faulty` says that is a fault. */
function storeOf(
  { environment, anchorStore: { directory, container } }: Config,
  logger: Logger,
  faulty: (environment: Config['environment']) => boolean,
): WriteOnceStore | undefined {
  if (container !== null) {
    return azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  }
  if (directory !== null) return folderWriteOnceStore(directory);
  if (faulty(environment)) logger.error('audit.anchor_store_not_set', { environment });
  return undefined;
}

/**
 * What a store's failures are called on a web copy (AT13b): the jobs copy's lines say payments wait, which is never so
 * on a web copy (Tx A runs in the jobs copy), so each is said under a web copy's own name and words, as a warning: its
 * decisions go on with today's checks. Only the lasting ones page (the anchor store's alert, environment.bicep): a
 * read failing past `alertAfterMs`, anchors' or digest's, or a heap too small for the store. A first read that fails is
 * a blip until then: the digest's own count runs from its first failure, the start's included, so access that never
 * works still pages once the digest's has lasted; a store whose files alone are wrong pages through the jobs copy.
 */
export const WEB_COPY_NAMES = {
  'audit.anchor_store_read_failed': 'audit.web_anchors_read_failed',
  'audit.anchor_shard_unreadable': 'audit.web_anchors_read_failed',
  'audit.state_digest_store_failed': 'audit.web_anchors_read_failed',
  'audit.anchor_store_unreadable': 'audit.web_anchors_read_failed',
  'audit.anchor_store_read_failing': 'audit.web_anchors_read_failing',
  'audit.state_digest_store_failing': 'audit.web_anchors_read_failing',
  'audit.anchor_store_beyond_memory': 'audit.web_anchors_beyond_memory',
} as const satisfies Partial<Record<ProblemEvent, ProblemEvent>>;

/** A web copy's logger: every line says `copy: web`, and a store's failures go by the web copy's names (above). */
export function webCopyLogger(logger: Logger): Logger {
  const renamed =
    (said: Logger['error']): Logger['error'] =>
    (event, fields) => {
      const web = (WEB_COPY_NAMES as Partial<Record<ProblemEvent, ProblemEvent>>)[event];
      if (web === undefined) said(event, { ...fields, copy: 'web' });
      else logger.warn(web, { ...fields, copy: 'web', was: event });
    };
  const marked =
    (said: Logger['info']): Logger['info'] =>
    (event, fields) => {
      said(event, { ...fields, copy: 'web' });
    };
  return Object.freeze({
    error: renamed(logger.error.bind(logger)),
    warn: renamed(logger.warn.bind(logger)),
    info: marked(logger.info.bind(logger)),
    debug: marked(logger.debug.bind(logger)),
    child: (bindings: Parameters<Logger['child']>[0]) => webCopyLogger(logger.child(bindings)),
    flush: logger.flush.bind(logger),
  });
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
    // An approval older than this is never handed off (AT13d): so a request's facts needn't be kept past it.
    forgetRequestsAfterMs: APPROVAL_HORIZON_MS,
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
  const store = storeOf(config, services.logger, (environment) => !LOCAL_ONLY.includes(environment));
  // The API's jobs anchor, so they move the store on to the shards (PL-65 PR2); the operator's job only reads it.
  return store && keptIn(store, config.audit.anchorEpoch, services, { cutOver: true, leading });
}

/**
 * A `web` copy's (AT13b): the same log and digest, read only. It never moves the store on (no cutover: that is a write),
 * never leads, so its digest speaks from what it read whatever the lease says, and its store refuses every write. The
 * same budget as a copy that keeps them, a share of its own heap, so it gives way the same way. Its lines by a web
 * copy's logger (`webCopyLogger`).
 *
 * No store named is a fault only in production, whose policy holds every web copy to the store: elsewhere a web copy
 * without one is on purpose (Stage G's throwaway copy, whose jobs keep their own container the API isn't given), so it
 * goes on as before the digest, said once as information, never as the anchors' alert.
 */
export function anchorsReadOf(config: Config, services: StoreServices): AnchorsKept | undefined {
  const logger = webCopyLogger(services.logger);
  const store = storeOf(config, logger, (environment) => environment === 'production');
  if (store === undefined) {
    if (config.environment !== 'production') logger.info('audit.web_anchors_off', { environment: config.environment });
    return undefined;
  }
  return keptIn(
    readOnlyStore(store, logger),
    config.audit.anchorEpoch,
    { ...services, logger },
    {
      cutOver: false,
      leading: undefined,
    },
  );
}
