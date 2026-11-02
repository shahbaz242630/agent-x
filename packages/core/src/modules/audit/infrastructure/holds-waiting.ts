// directory.holds_waiting (0069): an integrity hold that couldn't be recorded,
// kept outside the process. Its rows only add caution: with-signed-states.ts says
// what it does with them, and signed-states.ts how Tx A reads them.
import { limitedTransaction, readAloneOnOneTrip } from '@agentx/platform/db';
import type { Kysely, Transaction } from 'kysely';

import { subjectKeyProblems } from '../domain/event.ts';
import type { AuditTables } from './tables.ts';

/** One hold waiting: IDs and the sign, naming the record as a hold found directly names it. */
export interface HoldWaiting {
  readonly org_id: string;
  readonly subject_type: string;
  readonly object_id: string;
  readonly reason: string;
}

/** What names a row: the record, in its organisation. */
export interface NamedRecord {
  readonly orgId: string;
  readonly subjectType: string;
  readonly objectId: string;
}

/** Whether the app could have written this naming: what every finding names, and what 0069's checks hold a row to. */
export const namedAsTheAppWrites = ({ subject_type: type, object_id: id }: HoldWaiting): boolean =>
  subjectKeyProblems({ type, id }).length === 0 && id === id.toLowerCase();

const named = (tx: Transaction<AuditTables>, { orgId, subjectType, objectId }: NamedRecord) =>
  tx
    .selectFrom('directory.holds_waiting')
    .select('reason')
    .where('org_id', '=', orgId)
    .where('subject_type', '=', subjectType)
    .where('object_id', '=', objectId);

/** One there for this record stands. */
const inserted = (tx: Transaction<AuditTables>, { orgId, subjectType, objectId }: NamedRecord, reason: string) =>
  tx
    .insertInto('directory.holds_waiting')
    .values({ org_id: orgId, subject_type: subjectType, object_id: objectId, reason })
    .onConflict((conflict) => conflict.doNothing())
    .execute();

/** Keeps a hold that couldn't be recorded. Its own transaction, so a hung statement ends. */
export async function keepHoldWaiting(db: Kysely<AuditTables>, record: NamedRecord, reason: string): Promise<void> {
  await limitedTransaction(db, (tx) => inserted(tx, record, reason));
}

/**
 * Keeps a hold on one record, in the transaction that found the hold names another, so the two can't part. Holding the
 * head's lock: the key's share lock on the directory's row waits on nothing, as the app never changes or deletes one.
 */
export async function keepHoldWaitingHere(
  tx: Transaction<AuditTables>,
  record: NamedRecord,
  reason: string,
): Promise<void> {
  await inserted(tx, record, reason);
}

/** Whether the record's row is there now. */
export async function holdStillWaiting(tx: Transaction<AuditTables>, record: NamedRecord): Promise<boolean> {
  return (await named(tx, record).execute()).length > 0;
}

/** Takes the record's row away, in the transaction that recorded the hold (or found it held), so the two can't part. */
export async function holdNoLongerWaiting(
  tx: Transaction<AuditTables>,
  { orgId, subjectType, objectId }: NamedRecord,
): Promise<void> {
  await tx
    .deleteFrom('directory.holds_waiting')
    .where('org_id', '=', orgId)
    .where('subject_type', '=', subjectType)
    .where('object_id', '=', objectId)
    .execute();
}

/** Far past what the app writes (a row for each record found tampered with and not yet recorded), and quick to read. */
export const HOLDS_READ_AT_ONCE = 1000;

/**
 * The most findings of a process's own it keeps in memory once their rows carry them: 5 MB, at about 1 KB each. Far past
 * what honest work finds, as each is a hold not yet recorded, or a second record found under a hold.
 */
export const MOST_KEPT_OWN = 5000;

/**
 * The holds waiting, on one trip, at most HOLDS_READ_AT_ONCE, in the key's order, from after `afterOrg` when given: an
 * empty table is the usual answer.
 */
export function holdsWaiting(db: Kysely<AuditTables>, afterOrg?: string): Promise<readonly HoldWaiting[]> {
  const all = db.selectFrom('directory.holds_waiting').select(['org_id', 'subject_type', 'object_id', 'reason']);
  return readAloneOnOneTrip(
    db,
    (afterOrg === undefined ? all : all.where('org_id', '>', afterOrg))
      .orderBy('org_id')
      .orderBy('subject_type')
      .orderBy('object_id')
      .limit(HOLDS_READ_AT_ONCE),
  );
}
