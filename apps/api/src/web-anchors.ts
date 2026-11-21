// A `web` copy's anchors and signed states' digest, read only (AT13b, R-15). Where the API runs split (production), the
// `jobs` copy keeps the anchors and the digest and the `web` copies serve every request: so this is what holds a web
// copy's decisions (approvals, agent asks, member and policy changes, sessions' signed ends) to the digest, as the jobs
// copy's own reads are held. It reads the store as a start does, then each run what landed since (the log's and the
// digest's own `read`: the newest snapshot and the deltas after it, then only the files named since), the anchors
// first, as their rebases decide which of the digest's lines are passed over (digest-log.ts). It never writes either,
// never takes the lease, and never checks a chain: the jobs copy alone walks, anchors and records.
//
// Lag: a copy's digest is at most a run (plus a read) behind the jobs copy's. A fact is a place a walk read, sealed, so
// a lagging copy holds fewer true facts, never a false one: it can only miss a rollback the jobs copy would catch, never
// raise an alarm the jobs copy wouldn't. The one exception is a chain rebased (playbook H, after a chain-restore that
// gave events up) inside the lag: until the copy reads the rebase, it may still alarm on that chain's objects, as the
// jobs copy does from the restore until the rebase, the organisation already held from the restore's incident.
// A chain the copy's digest doesn't cover reads exactly as before the digest: today's checks, plus whatever facts it
// holds. Tx A, the one read that waits for coverage (`digest_pending`), runs in the jobs copy alone.
import type { AnchorLog, DigestLog } from '@agentx/platform/audit-chain';
import type { Logger } from '@agentx/platform/observability';

import { Stopped, withinDeadline } from './background.ts';

/**
 * How often a web copy reads what landed in the store since its last read: about once each write the jobs copy makes
 * (a delta at most every minute of a run, anchor-check.ts), so it lags by one write at most; when nothing landed, a
 * read is a few lists, cheap at any number of copies.
 */
export const WEB_ANCHORS_EVERY_MS = 60_000;

/** How long the anchors' read may take: as the anchor check gives it (a start's whole read included). */
const ANCHORS_WITHIN_MS = 120_000;

/** How long the digest's read may take: as the anchor check gives it (a start's snapshot of a few tens of MB). */
const DIGEST_WITHIN_MS = 60_000;

/** The run that reads the store again: the anchors, then the digest. Never throws; each failure said as the jobs say it. */
export function createWebAnchorRead({
  log,
  digest,
  logger,
}: {
  readonly log: Pick<AnchorLog, 'read' | 'readFailed'>;
  readonly digest: Pick<DigestLog, 'read'>;
  readonly logger: Logger;
}): { run(signal?: AbortSignal): Promise<void> } {
  return {
    async run(signal?: AbortSignal): Promise<void> {
      try {
        await withinDeadline(log.read(), ANCHORS_WITHIN_MS, signal);
      } catch (error) {
        if (error instanceof Stopped) return;
        log.readFailed(error);
      }
      // After the anchors, which read the rebases it passes lines over by. Its own failures it says itself.
      try {
        await withinDeadline(digest.read(), DIGEST_WITHIN_MS, signal);
      } catch (error) {
        if (!(error instanceof Stopped)) {
          logger.warn('audit.web_anchors_read_failed', {
            copy: 'web',
            what: 'read',
            was: 'audit.state_digest_store_failed',
            err: error,
          });
        }
      }
    },
  };
}
