// The security rows from before 0105 sealed (S206 V6; core's legacy-seal.ts
// says how), as one of the jobs: run by the copy that holds the jobs' lease,
// where the anchor store is (the jobs side when split, the one process
// otherwise), never by a web copy, which has none. Hourly, so a sealing a stop
// cut short is taken up again within the hour; a no-op once sealed.
//
// After each record of the sealing (its start, its end) the platform chain is
// anchored at once, as the anchor check anchors it, so deleting either record
// is a chain wound back past an anchor, which the next sealing (and the anchor
// check) refuses. It uses the jobs' one anchor store, the anchor check's own,
// whose writes go one at a time. An anchor it can't take is its own error; a
// write that fails is the store's own line and alert. Either way the record
// stays unanchored until the anchor check's next run anchors it.
//
// A sealing held up is loud. Until it ends, the day seal excuses a marked row
// with no MAC written before it began (or before now, if it hasn't): the
// database's owner holding the sealer's lock in a session of his own would
// keep that excuse up until the cutoff. The lock is held only while a sealing
// runs, a few minutes even for every row, so finding it taken on two runs in
// a row, an hour apart, is never a sealing at work: `security.legacy_seal_stalled`,
// an error, each run it stays so. Kept in memory: no one but this copy
// runs the jobs, and a restart only delays it by an hour.
//
// TODO(S206 AT10-style): delete this with sealLegacyRows once every environment holds its `all_sealed` record.
import { type SecurityEventsTables, sealLegacyRows } from '@agentx/core/modules/security-events';
import { type PlatformControlsTables, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { listedOrganizations, type DirectoryTables } from '@agentx/core/modules/directory';
import { type Clock, type IdGenerator } from '@agentx/core/shared-kernel';
import { type AnchorLog, signAnchor } from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often the sealing is tried: a no-op once done. */
export const LEGACY_SEAL_EVERY_MS = 60 * 60_000;

/** How long the sealer's lock may be found taken before it is the alarm: under two runs, so the second one says it. */
export const LEGACY_SEAL_STALL_MS = 50 * 60_000;

const PLATFORM = { kind: 'platform' } as const;

type Tables = SecurityEventsTables & PlatformControlsTables & DirectoryTables;

/** The platform chain's last anchor in the store, read whole first; undefined if it can't be read, or holds none. */
async function platformAnchorIn(anchors: AnchorLog) {
  await anchors.read();
  if (anchors.state() !== 'read') return undefined;
  const release = await anchors.pin(PLATFORM);
  try {
    return anchors.latest(PLATFORM);
  } finally {
    release?.();
  }
}

export function createLegacySealJob({
  database,
  anchors,
  keys,
  ids,
  clock,
  logger,
  retentionDays,
}: {
  readonly database: Database<Tables>;
  /** The jobs' anchor store; undefined where none is configured (a machine of our own): nothing is sealed there. */
  readonly anchors: AnchorLog | undefined;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  readonly retentionDays: number;
}): { run(): Promise<void> } {
  const platform = createPlatformChain({ keys, ids });
  /** When the sealer's lock was first found taken, in this run of finding it so; undefined once a run got it. */
  let busySince: Date | undefined;

  /** The chain anchored at its head now, its check run from the last anchor first. Never throws: a failure is said. */
  const anchorNow = async (store: AnchorLog): Promise<void> => {
    try {
      const from = await platformAnchorIn(store);
      const step = from === undefined ? undefined : await platform.checkFromAnchor(database, from);
      if (step?.ok !== true || step.seq !== step.to) {
        logger.error('security.legacy_seal_unanchored', {});
        return;
      }
      // Kept in the jobs' one store, beside the anchor check's own, and written through its single flight (one write
      // at a time; a second joins the first). A write that fails is the store's own line and alert, as the check's is.
      store.keep(signAnchor(keys, PLATFORM, step, clock.now(), store.epoch));
      await store.flush();
    } catch (error) {
      logger.error('security.legacy_seal_unanchored', { err: error });
    }
  };

  return {
    async run() {
      if (anchors === undefined) {
        logger.info('security.legacy_seal_done', { outcome: 'no_anchor_store' });
        return;
      }
      try {
        const outcome = await sealLegacyRows(database, {
          keys,
          ids,
          clock,
          logger,
          orgs: () => listedOrganizations(database),
          retentionDays,
          anchor: () => platformAnchorIn(anchors),
          anchorNow: () => anchorNow(anchors),
          notAfter: busySince,
        });
        logger.info('security.legacy_seal_done', { outcome });
        busySince = outcome === 'busy' ? (busySince ?? clock.now()) : undefined;
        if (busySince !== undefined && clock.now().getTime() - busySince.getTime() >= LEGACY_SEAL_STALL_MS) {
          logger.error('security.legacy_seal_stalled', { busySince: busySince.toISOString() });
        }
      } catch (error) {
        logger.error('security.legacy_seal_failed', { err: error });
      }
    },
  };
}
