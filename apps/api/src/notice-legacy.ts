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
// The starts before are read through the platform chain's own check of each
// (platformEventSealed): one edited to hide that it sealed them is no start
// that didn't, and seals nothing, with the integrity alarm. And it seals only a
// notice with no `notice.queued` record: one with a record was queued sealed,
// so one unsealed now had its seal taken out, and stays refused.
//
// What it can't tell: a notice from before seals the owner changed before that
// start is sealed as it stands, as S205's people were. While this release
// rolls out, the release before can neither write a notice nor end one: 0105
// refuses either with no seal (its change fails whole, and is tried again).
//
// TODO(S206 V4): once a release has run it, go back to recordStart alone in boot.ts and delete this (Outstanding-Work AT10).
import { type NotificationsTables, sealNoticesFromBefore } from '@agentx/core/modules/notifications';
import {
  createPlatformChain,
  platformEventSealed,
  platformEventsSigned,
  type PlatformControlsTables,
} from '@agentx/core/modules/platform-controls';
import type { AuditTables } from '@agentx/core/modules/audit';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { StartFacts } from './start-record.ts';

/** The start record's detail that says the notices from before seals were sealed then, and how many. */
export const NOTICES_SEALED = 'noticesSealed';

type LegacyTables = NotificationsTables & PlatformControlsTables & AuditTables;

/**
 * Whether a start before this one sealed them, its record naming how many: every start read and believed only as
 * the chain sealed it. `unbelieved` for a start record that isn't: nothing is sealed, and the caller raises the alarm.
 */
async function sealedBefore(tx: DatabaseTransaction<LegacyTables>, keys: KeyProvider): Promise<boolean | 'unbelieved'> {
  const starts = await platformEventsSigned(tx).where('e.action', '=', 'platform.started').execute();
  let sealed = false;
  for (const start of starts) {
    if (!platformEventSealed(keys, start)) return 'unbelieved';
    if (typeof start.details === 'string' && Object.hasOwn(JSON.parse(start.details) as object, NOTICES_SEALED)) {
      sealed = true;
    }
  }
  return sealed;
}

/**
 * recordStart, and with the first start of the release with seals, the notices from before them sealed in the same
 * transaction, its record saying how many. Gives back the start's place in the chain.
 */
export async function recordStartSealingNotices(
  database: Database<LegacyTables>,
  keys: KeyProvider,
  ids: IdGenerator,
  facts: StartFacts,
  logger: Logger,
): Promise<bigint> {
  const recorded = await limitedTransaction(database, async (tx) => {
    const before = await sealedBefore(tx, keys);
    if (before === 'unbelieved') logger.error('audit.integrity_failed', { chain: 'platform', check: 'start_record' });
    const sealed = before === false ? await sealNoticesFromBefore(tx, database, keys) : undefined;
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
