// The notices queued before seals, sealed once (S206 V4, Threat-Model R-15;
// 0105), as S205 sealed the people made before 0100: the first start of the
// release with seals seals every notice still to be sent that has none, over
// what it says now, in the transaction that records the start on the platform
// chain, and says so in that start's record (`noticesSealed`). A start that
// finds a start before it said so seals nothing: from then on a notice with no
// seal is one the database's owner wrote, which the sender gives up unsent
// with the integrity alarm, whatever its dates say. A start whose record fails
// seals nothing either, as its transaction rolls back; it doesn't start.
//
// What it can't tell: a notice the owner changed before that start is sealed
// as it stands, as S205's people were. Notices the release before writes while
// this one rolls out (minutes) have no seal and are refused, with the alarm.
//
// TODO(S206 V4): once a release has run it, go back to recordStart alone in boot.ts and delete this (Outstanding-Work AT10).
import { type NotificationsTables, sealNoticesFromBefore } from '@agentx/core/modules/notifications';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import type { StartFacts } from './start-record.ts';

/** The start record's detail that says the notices from before seals were sealed then, and how many. */
export const NOTICES_SEALED = 'noticesSealed';

type LegacyTables = NotificationsTables & PlatformControlsTables;

/** Whether a start before this one sealed them: its record names how many. */
const sealedBefore = async (tx: DatabaseTransaction<LegacyTables>): Promise<boolean> =>
  (await tx
    .selectFrom('platform_controls.audit_events')
    .select('seq')
    .where('action', '=', 'platform.started')
    .where('details', 'like', `%"${NOTICES_SEALED}":%`)
    .limit(1)
    .executeTakeFirst()) !== undefined;

/**
 * recordStart, and with the first start of the release with seals, the notices from before them sealed in the same
 * transaction, its record saying how many. Gives back the start's place in the chain.
 */
export async function recordStartSealingNotices(
  database: Database<LegacyTables>,
  keys: KeyProvider,
  ids: IdGenerator,
  facts: StartFacts,
): Promise<bigint> {
  const recorded = await limitedTransaction(database, async (tx) => {
    const sealed = (await sealedBefore(tx)) ? undefined : await sealNoticesFromBefore(tx, keys);
    // The platform head's lock last.
    return createPlatformChain({ keys, ids }).record(tx, {
      actor: { type: 'system', id: 'api' },
      action: 'platform.started',
      details: {
        configHash: facts.configHash,
        release: facts.release,
        ...(facts.gateRef === undefined ? {} : { gateRef: facts.gateRef }),
        ...(sealed === undefined ? {} : { [NOTICES_SEALED]: sealed }),
      },
    });
  });
  return recorded.seq;
}
