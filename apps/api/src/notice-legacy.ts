// The notices queued before seals, sealed once (S206 V4, Threat-Model R-15;
// 0105), as S205 sealed the people made before 0100: a start of the release
// with seals seals every notice still to be sent that has none, over what it
// says now, in the transaction that records the start on the platform chain,
// and says so in that start's record (`noticesSealed`). From then on a notice
// with no seal is one the database's owner wrote, never claimed by the sender,
// and the notice check alarms for any still unsent a day on.
//
// It runs only while all of these hold, the S205 backfill's way of bounding
// what a forced restart can bless:
// - before NOTICE_SEAL_BACKFILL_UNTIL;
// - no notice written by this release yet (before_seals false): once the app
//   has queued one, every notice from before had its chance;
// - the platform chain checks out whole, from its start to its head, and no
//   start in it says it sealed them: a record of it deleted shows as a gap,
//   and seals nothing, with the integrity alarm (check `start_record`).
// And it seals only a notice with no `notice.queued` record: one with a record
// was queued sealed, so one unsealed now had its seal taken out.
//
// A pass that couldn't read an organisation's records (a statement's limit, a
// busy pool) seals none of its notices and says nothing in the start's record,
// so the next start tries again, with a warning (`notification.legacy_seal_incomplete`).
// A start whose record fails seals nothing either: its transaction rolls back.
//
// What it can't tell: a notice from before seals the owner changed before that
// start is sealed as it stands, as S205's people were.
//
// TODO(S206 V4): a later commit deletes this once NOTICE_SEAL_BACKFILL_UNTIL has passed, boot.ts back to recordStart
// alone, with sealNoticesFromBefore (Outstanding-Work AT10).
import type { AuditTables } from '@agentx/core/modules/audit';
import { type NotificationsTables, sealNoticesFromBefore } from '@agentx/core/modules/notifications';
import {
  createPlatformChain,
  platformEventsSigned,
  type PlatformControlsTables,
} from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { StartFacts } from './start-record.ts';

/** The start record's detail that says the notices from before seals were sealed then, and how many. */
export const NOTICES_SEALED = 'noticesSealed';

/** After this, no start seals a notice from before seals, whatever it finds (S205's USER_MAC_BACKFILL_UNTIL's way). */
export const NOTICE_SEAL_BACKFILL_UNTIL = new Date('2026-12-07T00:00:00Z');

type LegacyTables = NotificationsTables & PlatformControlsTables & AuditTables;

/**
 * Whether this start may seal the notices from before seals: `yes`, `no`, or `unbelieved` for a platform chain that
 * fails its whole check (nothing is sealed; the caller raises the alarm).
 */
async function maySeal(
  tx: DatabaseTransaction<LegacyTables>,
  keys: KeyProvider,
  ids: IdGenerator,
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
  // Whole, in this transaction: a start's record deleted, even the newest under a head wound back to it, is a gap.
  const report = await createPlatformChain({ keys, ids }).verify(tx, undefined);
  if (!report.ok) return 'unbelieved';
  const starts = await platformEventsSigned(tx).where('e.action', '=', 'platform.started').execute();
  const sealedBefore = starts.some(
    ({ details }) => typeof details === 'string' && Object.hasOwn(JSON.parse(details) as object, NOTICES_SEALED),
  );
  return sealedBefore ? 'no' : 'yes';
}

/**
 * recordStart, and with a start that may, the notices from before seals sealed in the same transaction, its record
 * saying how many when every one could be looked at. Gives back the start's place in the chain.
 */
export async function recordStartSealingNotices(
  database: Database<LegacyTables>,
  keys: KeyProvider,
  ids: IdGenerator,
  facts: StartFacts,
  { logger, now }: { readonly logger: Logger; readonly now: Date },
): Promise<bigint> {
  const recorded = await limitedTransaction(database, async (tx) => {
    const may = await maySeal(tx, keys, ids, now);
    if (may === 'unbelieved') logger.error('audit.integrity_failed', { chain: 'platform', check: 'start_record' });
    const pass = may === 'yes' ? await sealNoticesFromBefore(tx, database, keys) : undefined;
    if (pass?.complete === false) logger.warn('notification.legacy_seal_incomplete', { notices: pass.sealed });
    // The platform head's lock last.
    return createPlatformChain({ keys, ids }).record(tx, {
      actor: { type: 'system', id: 'api' },
      action: 'platform.started',
      details: {
        configHash: facts.configHash,
        release: facts.release,
        ...(facts.gateRef === undefined ? {} : { gateRef: facts.gateRef }),
        ...(pass?.complete === true ? { [NOTICES_SEALED]: pass.sealed } : {}),
      },
    });
  });
  return recorded.seq;
}
