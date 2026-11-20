// The people who sign in (0010): one row per issuer and subject, made at the
// person's first sign-in and found by it at every one after. The row is never
// changed or deleted: memberships and audit events will point at its ID.
//
// Each row carries a MAC with `session-mac` over its ID, issuer, subject and
// when it was made (row-macs.ts, 0100; S205): a person is believed only where
// it holds. Without it the database's owner could move an admin's row to its
// own login account's subject and then sign in, through the login service
// itself, as that admin. A row whose MAC doesn't hold is no person: a sign-in
// or step-up with it is refused, nothing new is made, and the integrity alarm
// is raised. A row with no MAC is never believed either, and nothing ever
// gives it one: S205's start-up backfill for the people made before 0100 was
// deleted (S207, R-15) once staging's ran, since an owner who nulled an admin's
// MAC and moved their subject could have had it sealed at the next start.
import type { Kysely, Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { checkSubject, type Subject } from '../domain/sign-in.ts';
import { macHolds, macOf, type RowMacs, rowForged, userMessage } from './row-macs.ts';
import type { IdentityTables } from './tables.ts';

type Handle = Kysely<IdentityTables> | Transaction<IdentityTables>;

/** A person's row whose MAC doesn't hold: no sign-in or step-up may go on as them. */
export class UserUnbelieved extends Error {
  override readonly name = 'UserUnbelieved';
}

/** The columns a person's MAC is made from, with the MAC itself. */
const SEALED = ['id', 'issuer', 'subject', 'created_at', 'mac', 'mac_key_version'] as const;

interface UserRow {
  readonly id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly created_at: Date;
}

const messageOf = (row: UserRow) =>
  userMessage({ id: row.id, issuer: row.issuer, subject: row.subject, createdAt: row.created_at });

/** Whether the row is the app's own: one whose MAC doesn't hold, or has none, raises the alarm. */
function genuine(
  { keys, logger }: RowMacs,
  row: UserRow & { readonly mac: Buffer | null; readonly mac_key_version: number | null },
): boolean {
  if (macHolds(keys, messageOf(row), row)) return true;
  rowForged(logger, 'user', { id: row.id, user_id: row.id });
  return false;
}

/**
 * The user's ID for this issuer and subject, made now if they have none: in
 * one statement, so two first sign-ins at once make one user, not two. Throws
 * SignInRefused for a subject that can't be stored, and UserUnbelieved for a
 * row of theirs whose MAC doesn't hold.
 */
export async function userForSubject(
  db: Kysely<IdentityTables>,
  who: Subject,
  { ids, clock, keys, logger }: RowMacs & { readonly ids: IdGenerator; readonly clock: Clock },
): Promise<string> {
  checkSubject(who);
  const { issuer, subject } = who;
  const row = { id: ids.next(), issuer, subject, created_at: clock.now() };
  // DO NOTHING rather than DO UPDATE: the app may not change a user, and a
  // statement that inserts nothing returns nothing, so the row is read after.
  const made = await db
    .insertInto('identity.users')
    .values({ ...row, ...macOf(keys, messageOf(row)) })
    .onConflict((conflict) => conflict.columns(['issuer', 'subject']).doNothing())
    .returning('id')
    .executeTakeFirst();
  if (made !== undefined) return made.id;
  const found = await db
    .selectFrom('identity.users')
    .select(SEALED)
    .where('issuer', '=', issuer)
    .where('subject', '=', subject)
    .executeTakeFirstOrThrow();
  if (!genuine({ keys, logger }, found)) throw new UserUnbelieved("the person's row is not one the app wrote");
  return found.id;
}

/**
 * The user's ID for this issuer and subject, if they have signed in; undefined
 * otherwise, or for a row whose MAC doesn't hold, and nothing is made (B6-2b:
 * the login service's events name the subject).
 */
export async function userOfSubject(
  db: Kysely<IdentityTables>,
  who: Subject,
  macs: RowMacs,
): Promise<string | undefined> {
  const found = await db
    .selectFrom('identity.users')
    .select(SEALED)
    .where('issuer', '=', who.issuer)
    .where('subject', '=', who.subject)
    .executeTakeFirst();
  return found !== undefined && genuine(macs, found) ? found.id : undefined;
}

/**
 * The issuer and subject a user signs in as, by their ID (B5-3: the address
 * book asks the login service by the subject); undefined for no such user, or
 * a row whose MAC doesn't hold.
 */
export async function subjectOfUser(db: Handle, userId: string, macs: RowMacs): Promise<Subject | undefined> {
  const found = await db.selectFrom('identity.users').select(SEALED).where('id', '=', userId).executeTakeFirst();
  return found !== undefined && genuine(macs, found) ? { issuer: found.issuer, subject: found.subject } : undefined;
}

/**
 * Whether a person has this ID, as a process without `session-mac` can ask
 * it (the operator's exports): it names no one to anything, so their MAC
 * isn't needed.
 */
export async function isUser(db: Handle, userId: string): Promise<boolean> {
  const found = await db.selectFrom('identity.users').select('id').where('id', '=', userId).executeTakeFirst();
  return found !== undefined;
}
