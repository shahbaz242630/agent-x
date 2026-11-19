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
// - no notice written by this release yet (before_seals false): once the app
//   has queued one, every notice from before had its chance;
// - the platform chain checks out whole, from its start to its head, and holds
//   no `notice.legacy_sealed`: one deleted shows as a gap, and nothing is
//   sealed, with the integrity alarm (check `start_record`).
// One with a `notice.queued` record was queued sealed: unsealed now, it had
// its seal taken out, and stays so.
//
// Off the start's path, on the web side alone (not `jobs`), one replica at a
// time (an advisory lock, only tried: the others leave it quietly): a long
// chain's check never holds a start up past its probe, and nothing here can
// stop the API. A pass that fails, or couldn't
// read an organisation's records, says so (`notification.legacy_seal_failed`,
// `notification.legacy_seal_incomplete`) and records nothing, so the next
// start tries again. A pass that sealed none records nothing either.
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
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** The platform chain's record that the notices from before seals were sealed, and how many. */
export const LEGACY_SEALED = 'notice.legacy_sealed';

/** After this, no pass seals a notice from before seals, whatever it finds (S205's USER_MAC_BACKFILL_UNTIL's way). */
export const NOTICE_SEAL_BACKFILL_UNTIL = new Date('2026-12-07T00:00:00Z');

type LegacyTables = NotificationsTables & PlatformControlsTables & AuditTables;

/** Whether this pass may seal: `yes`, `no`, or `unbelieved` for a platform chain that fails its whole check. */
async function maySeal(
  tx: DatabaseTransaction<LegacyTables>,
  keys: KeyProvider,
  now: Date,
): Promise<'yes' | 'no' | 'unbelieved'> {
  if (now.getTime() >= NOTICE_SEAL_BACKFILL_UNTIL.getTime()) return 'no';
  const written = await tx
    .selectFrom('notifications.outbox')
    .select('id')
    .where('before_seals', '=', false)
    .limit(1)
    .executeTakeFirst();
  if (written !== undefined) return 'no';
  // Whole, in this transaction: a record of it deleted, even the newest under a head wound back to it, is a gap.
  const report = await createPlatformChain({ keys, ids: uuidV7Ids }).verify(tx, undefined);
  if (!report.ok) return 'unbelieved';
  const before = await tx
    .selectFrom('platform_controls.audit_events')
    .select('seq')
    .where('action', '=', LEGACY_SEALED)
    .limit(1)
    .executeTakeFirst();
  return before === undefined ? 'yes' : 'no';
}

/** Seals the notices from before seals, once ever, as above. Never throws: what went wrong is logged. */
export async function sealLegacyNotices(
  {
    database,
    keys,
    logger,
  }: { readonly database: Database<LegacyTables>; readonly keys: KeyProvider; readonly logger: Logger },
  { now }: { readonly now: Date },
): Promise<void> {
  try {
    await limitedTransaction(database, async (tx) => {
      // Another replica of the web side has it under way: it is that one's, quietly.
      if (!(await tookLegacySealPass(tx))) return;
      const may = await maySeal(tx, keys, now);
      if (may === 'unbelieved') logger.error('audit.integrity_failed', { chain: 'platform', check: 'start_record' });
      if (may !== 'yes') return;
      const { sealed, complete } = await sealNoticesFromBefore(tx, database, keys);
      if (!complete) logger.warn('notification.legacy_seal_incomplete', { notices: sealed });
      if (!complete || sealed === 0) return;
      // The platform head's lock last.
      await createPlatformChain({ keys, ids: uuidV7Ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: LEGACY_SEALED,
        details: { notices: sealed },
      });
      logger.info('notification.legacy_sealed', { notices: sealed });
    });
  } catch (error) {
    logger.warn('notification.legacy_seal_failed', { err: error });
  }
}
