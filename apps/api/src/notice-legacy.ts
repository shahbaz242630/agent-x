// The notices queued before seals, sealed once (S206 V4, Threat-Model R-15;
// 0104), as S205 sealed the people made before 0100: in the background, once
// the API answers (main.ts), every notice still to be sent that has no seal
// and no `notice.queued` record gets one over what it says now, and the
// platform chain records it (`notice.legacy_sealed`, with how many). Until
// then they wait, never claimed (the sender takes sealed notices alone); a
// notice with no seal still unsent a day on raises the notice check's alarm.
//
// It runs only while all of these hold, the S205 backfill's way of bounding
// what a forced restart can bless:
// - before NOTICE_SEAL_BACKFILL_UNTIL;
// - on a database an API started on before the release that brought 0105
//   (databaseBirth, S207: its platform chain's first start, MAC-checked,
//   records no ROW_MACS_FROM). One
//   born sealed (production's) holds no notice from before seals: one marked
//   so is the owner's, planted, never sealed, and the notice check's alarm a
//   day on. A first start that can't be believed, or none, seals nothing,
//   with the integrity alarm (check `start_record`);
// - no notice written by this release yet (before_seals false): once the app
//   has queued one, every notice from before had its chance;
// - the platform chain holds no `notice.legacy_sealed` (read first: a pass
//   done ends there), and checks out whole, from its start to its head, still
//   holding its last anchor, read from the anchor store outside the database:
//   a record of a pass deleted shows as a gap, or, as the chain's newest,
//   under a head wound back past the anchor taken right after it was written;
//   a chain wiped fails its anchor. Each seals nothing, with the integrity
//   alarm (check `start_record`); no anchor to be read seals nothing either,
//   with a warning (`notification.legacy_seal_no_anchor`).
// One with a `notice.queued` record was queued sealed: unsealed now, it had
// its seal taken out, and stays so.
//
// Off the start's path, only where the anchor store is set (`jobs` when the
// roles are split, `all` otherwise; never `web`), one replica at a time (an
// advisory lock, only tried: the others leave it quietly): a long chain's
// check never holds a start up past its probe, and nothing here can stop the
// API. A pass that fails, or couldn't
// read an organisation's records, says so (`notification.legacy_seal_failed`,
// `notification.legacy_seal_incomplete`) and records nothing, so the next
// start tries again. A complete pass records itself even with none sealed.
//
// What it can't tell: a notice from before seals the owner changed before
// that pass is sealed as it stands, as S205's people were.
//
// TODO(S206 V4): a later commit deletes this once NOTICE_SEAL_BACKFILL_UNTIL has passed, its call in main.ts with it,
// and sealNoticesFromBefore (Outstanding-Work AT10).
import type { AuditTables } from '@agentx/core/modules/audit';
import {
  type NotificationsTables,
  sealNoticesFromBefore,
  tookLegacySealPass,
} from '@agentx/core/modules/notifications';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { databaseBirth } from '@agentx/core/modules/security-events';
import { type Clock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { type AnchorLog, type AnchorPoint, type CheckedPoint, signAnchor } from '@agentx/platform/audit-chain';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** The platform chain's record that the notices from before seals were sealed, and how many. */
export const LEGACY_SEALED = 'notice.legacy_sealed';

/** After this, no pass seals a notice from before seals, whatever it finds (the way S205's people backfill had its cutoff). */
export const NOTICE_SEAL_BACKFILL_UNTIL = new Date('2026-12-07T00:00:00Z');

type LegacyTables = NotificationsTables & PlatformControlsTables & AuditTables;

/** The platform chain's anchors, as the pass reads and moves them: the anchor log's (`platformAnchorsOf`), a fake in tests. */
export interface PlatformAnchors {
  /** The chain's last anchor, from the store read whole; undefined if it can't be read whole, or holds none. */
  latest(): Promise<AnchorPoint | undefined>;
  /** Anchors the chain at `point`, signed now, and writes it to the store. Throws if it can't. */
  anchor(point: CheckedPoint): Promise<void>;
}

const PLATFORM = { kind: 'platform' } as const;

/**
 * The anchor log's platform anchors (ADR-012 §2, ANC-1): a write-once store outside the database (Azure blob storage,
 * version-level immutability; a folder locally), which the API only adds to and the database's owner can't reach.
 */
export function platformAnchorsOf(log: AnchorLog, keys: KeyProvider, clock: Clock): PlatformAnchors {
  const pinned = async <T>(work: () => T | Promise<T>): Promise<T | undefined> => {
    await log.read();
    if (log.state() !== 'read') return undefined;
    const release = await log.pin(PLATFORM);
    if (release === undefined) return undefined;
    try {
      return await work();
    } finally {
      release();
    }
  };
  return {
    latest: () => pinned(() => log.latest(PLATFORM)),
    async anchor(point) {
      const kept = await pinned(() => {
        log.keep(signAnchor(keys, PLATFORM, point, clock.now(), log.epoch));
        return true;
      });
      if (kept !== true) throw new Error("the anchor store can't be read whole, so nothing is anchored");
      await log.flush();
    },
  };
}

/** Whether this pass may seal, before any chain is read: `no` past the cutoff, once the app has queued a notice, or once one did. */
async function mayStillSeal(tx: DatabaseTransaction<LegacyTables>, now: Date): Promise<boolean> {
  if (now.getTime() >= NOTICE_SEAL_BACKFILL_UNTIL.getTime()) return false;
  const written = await tx
    .selectFrom('notifications.outbox')
    .select('id')
    .where('before_seals', '=', false)
    .limit(1)
    .executeTakeFirst();
  if (written !== undefined) return false;
  // Its record first, the cheap read: a pass done ends it here, before any chain is checked.
  const before = await tx
    .selectFrom('platform_controls.audit_events')
    .select('seq')
    .where('action', '=', LEGACY_SEALED)
    .limit(1)
    .executeTakeFirst();
  return before === undefined;
}

/**
 * Anchors the platform chain where it now stands, past the pass's record. A failure leaves the record unanchored until
 * the anchor check's next run anchors it, and is said as an error: the record stands (no pass runs again), and the
 * anchor store wants looking at.
 */
async function anchoredPast(
  platform: ReturnType<typeof createPlatformChain>,
  database: Database<LegacyTables>,
  anchors: PlatformAnchors,
  anchor: AnchorPoint,
  logger: Logger,
): Promise<void> {
  try {
    const reached = await platform.verifyAlone(database, anchor);
    if (!reached.ok) {
      logger.error('notification.legacy_seal_unanchored', { reason: reached.problem.reason });
      return;
    }
    await anchors.anchor(reached);
  } catch (error) {
    logger.error('notification.legacy_seal_unanchored', { err: error });
  }
}

/** Seals the notices from before seals, once ever, as above. Never throws: what went wrong is logged. */
export async function sealLegacyNotices(
  {
    database,
    keys,
    logger,
  }: { readonly database: Database<LegacyTables>; readonly keys: KeyProvider; readonly logger: Logger },
  { now, anchors }: { readonly now: Date; readonly anchors: PlatformAnchors | undefined },
): Promise<void> {
  const platform = createPlatformChain({ keys, ids: uuidV7Ids });
  try {
    if (!(await limitedTransaction(database, (tx) => mayStillSeal(tx, now)))) return;
    const birth = await limitedTransaction(database, (tx) => databaseBirth(tx, keys));
    if (birth === 'unsealed') {
      logger.error('audit.integrity_failed', { chain: 'platform', check: 'start_record' });
      return;
    }
    if (birth === 'sealed') return;
    const anchor = await anchors?.latest();
    if (anchors === undefined || anchor === undefined) {
      logger.warn('notification.legacy_seal_no_anchor');
      return;
    }
    const sealed = await limitedTransaction(database, async (tx) => {
      // Another replica of the web side has it under way: it is that one's, quietly.
      if (!(await tookLegacySealPass(tx))) return undefined;
      if (!(await mayStillSeal(tx, now))) return undefined;
      // Whole, in this transaction, and still holding its anchor: a record of the pass deleted, mid-chain or under a
      // head wound back past the anchor, or the chain wiped, is refused.
      const report = await platform.verify(tx, anchor);
      if (!report.ok) {
        logger.error('audit.integrity_failed', { chain: 'platform', check: 'start_record' });
        return undefined;
      }
      const pass = await sealNoticesFromBefore(tx, database, keys);
      if (!pass.complete) {
        logger.warn('notification.legacy_seal_incomplete', { notices: pass.sealed });
        return undefined;
      }
      // Recorded even with none sealed: from then on no start seals anything, whatever is planted later.
      // The platform head's lock last.
      await platform.record(tx, {
        actor: { type: 'system', id: 'api' },
        action: LEGACY_SEALED,
        details: { notices: pass.sealed },
      });
      return pass.sealed;
    });
    if (sealed === undefined) return;
    logger.info('notification.legacy_sealed', { notices: sealed });
    // Anchored at once past its record, as the anchor check would within minutes: deleting it, even as the chain's
    // newest, is then a chain wound back behind its anchor, which the next pass's check refuses.
    await anchoredPast(platform, database, anchors, anchor, logger);
  } catch (error) {
    logger.warn('notification.legacy_seal_failed', { err: error });
  }
}
