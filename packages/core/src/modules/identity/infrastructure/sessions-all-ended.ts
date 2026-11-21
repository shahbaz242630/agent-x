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
// - a lock only this takes (a transaction advisory lock), so copies answering the same cut at once go one at a time;
// - the newest such record read: one sealed, at or below the head, and recorded after the read that found the cut (above
//   the head it found) or for the same head held to (its `seen`), answers the cut already, and nothing is recorded;
// - else every session's row deleted, but those another transaction holds now (a request reading its own session):
//   the record ends them all the same, quietly, and the hourly sweep takes them; then the record, the head's lock last;
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
 * The place of the newest record of every session's end, where it answers the cut already: sealed, at or below the
 * head, and recorded after the head the read found, or for the same head held to. One statement.
 */
async function answeredAt(tx: PlatformTransaction, keys: KeyProvider, cut: CutAnswered): Promise<bigint | undefined> {
  const row = await platformEventsSigned(tx)
    .where('e.action', '=', SESSIONS_ALL_ENDED)
    .where('e.seq', '<=', sql<bigint>`(select h.seq from platform_controls.audit_head h limit 1)`)
    .orderBy('e.seq', 'desc')
    .limit(1)
    .executeTakeFirst();
  if (row === undefined || !platformEventSealed(keys, row)) return undefined;
  if (cut.found !== null && row.seq > cut.found) return row.seq;
  const { seen, seenHash } = JSON.parse(row.details) as { seen?: unknown; seenHash?: unknown };
  return seen === cut.held.seq.toString() && seenHash === cut.held.hash.toString('hex') ? row.seq : undefined;
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
    const endedAt = clock.now();
    const done = await db.transaction().execute(async (tx) => {
      await limitStatements(tx);
      const chain = tx as unknown as PlatformTransaction;
      await sql`select pg_catalog.pg_advisory_xact_lock(${ONE_AT_A_TIME})`.execute(tx);
      let seq = await answeredAt(chain, keys, cut);
      let ended: number | undefined;
      if (seq === undefined) {
        const rows = await tx
          .deleteFrom('identity.sessions')
          .where('id', 'in', (eb) => eb.selectFrom('identity.sessions').select('id').forUpdate().skipLocked())
          .returning('id')
          .execute();
        ended = rows.length;
        seq = (await platform.record(chain, sessionsAllEndedEvent(cut, endedAt))).seq;
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
      found: cut.found === null ? 'none' : cut.found.toString(),
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
