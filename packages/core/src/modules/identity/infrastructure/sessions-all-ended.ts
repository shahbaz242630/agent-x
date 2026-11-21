// Every console session ended at once, signed, as the answer to a platform chain cut back (AT13h, S208's partner
// decision). A session read held to the highest platform head this copy has seen (sessions.ts) that finds the chain cut
// back below it can't tell which of the sessions a cut-off sign-out, rotation or all-ended named. Before this, every
// session read on that copy was refused until an operator recorded a rebase, the cut events were put back, or the copy
// restarted. Now the copy ends every session there is, once, with a signed record (`identity.sessions_all_ended`,
// signed-ends.ts), and takes the chain as it now stands for the sessions' reads alone: people sign in again with their
// passkey and carry on. The attack this answers, the database's owner deleting a session's signed end to bring a
// stolen, ended session back, is answered whole: every session signed in before the record is no session on any copy,
// restarted or not, as each read finds the record by its index; any signed in after it can't be one a deleted end named.
//
// In one transaction of its own, each statement limited:
// - the database's clock read, then a lock only this takes (a transaction advisory lock), so copies answering the same
//   cut at once go one at a time;
// - a record sealed, at or below the head, and recorded after that moment (the database's clock under the head's lock)
//   was recorded on the chain as this copy found it, after every event it held: it answers the cut, and nothing more
//   is recorded. Any older one, or one the owner put back, answers nothing: a copy that finds the cut once another's
//   record has committed records its own (no clock-free proof that one came after its cut), once a minute at most;
// - else every session's row deleted, but those another transaction holds now (a request reading its own session):
//   the record ends them all the same, quietly, and the hourly sweep takes them; then the head's lock (the last lock),
//   and the record, its time taken holding it;
// - the head locked and read, sealed, at or above the record: where the chain is taken from once the transaction
//   commits (afterCommit), so nothing this copy records meanwhile is missed. A head below it is taken from nowhere.
// A failure is logged and nothing is taken: the reads go on refusing, as before.
//
// At most one answer a copy each ANSWER_EVERY_MS, counted from each start: the owner deleting the record again only
// signs everyone out again, once a minute at most, and the chain grows by a record a copy a minute at most. Inside the
// minute the reads go on refusing. The hand-off pause is not answered: it stays held to the head seen (handoff-pause.ts).
import { afterCommit, limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import {
  createPlatformChain,
  lockedPlatformHead,
  platformEventSealed,
  platformEventsSigned,
  type PlatformTransaction,
} from '../../platform-controls/index.ts';
import { type CutAnswered, SESSIONS_ALL_ENDED, sessionsAllEndedEvent } from './signed-ends.ts';
import type { IdentityTables } from './tables.ts';

/** How often a copy may answer a cut at most: one start a minute. */
export const ANSWER_EVERY_MS = 60_000;

/** A platform head as a read holds it. */
interface Head {
  readonly seq: bigint;
  readonly hash: Buffer;
}

/** A cut a session read found: what it was held to and found, and the watch it asked, which takes the chain as it stands. */
interface PlatformCut extends CutAnswered {
  readonly watch: { accept(to: Head): void };
}

export interface AllSessionsEnding {
  /** Ends every session, signed, and takes the chain as it stands for the sessions' reads, unless a copy answered within the minute. */
  answer(cut: PlatformCut): Promise<void>;
}

/** The record's own lock: one answer at a time across copies. */
const ONE_AT_A_TIME = sql<string>`pg_catalog.hashtextextended(${SESSIONS_ALL_ENDED}, 0)`;

/**
 * The place of a record of every session's end that answers the cut already: sealed, at or below the head, and
 * recorded (the database's clock, under the head's lock) after `asked`, a moment after the read that found the cut, so
 * on the chain as it found it. An older one, or one put back by the owner, answers nothing. One statement.
 */
async function answeredSince(tx: PlatformTransaction, keys: KeyProvider, asked: Date): Promise<bigint | undefined> {
  const row = await platformEventsSigned(tx)
    .where('e.action', '=', SESSIONS_ALL_ENDED)
    .where('e.recorded_at', '>', asked)
    .where('e.seq', '<=', sql<bigint>`(select h.seq from platform_controls.audit_head h limit 1)`)
    .orderBy('e.seq', 'desc')
    .limit(1)
    .executeTakeFirst();
  return row !== undefined && platformEventSealed(keys, row) ? row.seq : undefined;
}

export function createAllSessionsEnding({
  db,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly db: Kysely<IdentityTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): AllSessionsEnding {
  const platform = createPlatformChain({ keys, ids });
  let startedAt: number | undefined;

  const end = async (cut: PlatformCut): Promise<void> => {
    const done = await db.transaction().execute(async (tx) => {
      await limitStatements(tx);
      const chain = tx as unknown as PlatformTransaction;
      // The database's clock before waiting for the lock: after the read that found the cut.
      const { rows } = await sql<{ now: Date }>`select pg_catalog.clock_timestamp() as now`.execute(tx);
      const [{ now: asked }] = rows as [{ readonly now: Date }];
      await sql`select pg_catalog.pg_advisory_xact_lock(${ONE_AT_A_TIME})`.execute(tx);
      let seq = await answeredSince(chain, keys, asked);
      let ended: number | undefined;
      if (seq === undefined) {
        const rows = await tx
          .deleteFrom('identity.sessions')
          .where('id', 'in', (eb) => eb.selectFrom('identity.sessions').select('id').forUpdate().skipLocked())
          .returning('id')
          .execute();
        ended = rows.length;
        // Its time taken holding the head's lock (the last lock): every event before it on the chain was recorded before
        // that time, so every session one names signed in before it. A sign-in as the rows went only signs in again.
        await lockedPlatformHead(chain, keys);
        seq = (await platform.record(chain, sessionsAllEndedEvent(cut, clock.now()))).seq;
      }
      const head = await lockedPlatformHead(chain, keys);
      if (head !== undefined && head.seq >= seq) {
        await afterCommit(tx, () => {
          cut.watch.accept(head);
        });
      }
      return { seq, ended };
    });
    if (done.ended === undefined) {
      logger.info('identity.sessions_all_ended_found', { seq: done.seq.toString() });
      return;
    }
    logger.error('identity.sessions_all_ended', {
      check: 'platform_chain',
      reason: 'cut_back',
      seq: done.seq.toString(),
      seen: cut.held.seq.toString(),
      // `null` where no head was found, its row gone.
      found: String(cut.found),
      ended: done.ended,
    });
  };

  return {
    async answer(cut) {
      const now = clock.now().getTime();
      // A clock gone back counts as within the minute: refused, as before.
      if (startedAt !== undefined && now - startedAt < ANSWER_EVERY_MS) return;
      startedAt = now;
      try {
        await end(cut);
      } catch (error) {
        logger.error('identity.sessions_all_end_failed', { error: error instanceof Error ? error.name : 'unknown' });
      }
    },
  };
}
