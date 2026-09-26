// The people who sign in (0010): one row per issuer and subject, made at the
// person's first sign-in and found by it at every one after. The row is never
// changed or deleted: memberships and audit events will point at its ID.
import type { Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { checkSubject, type Subject } from '../domain/sign-in.ts';
import type { IdentityTables } from './tables.ts';

/**
 * The user's ID for this issuer and subject, made now if they have none: in
 * one statement, so two first sign-ins at once make one user, not two. Throws
 * SignInRefused for a subject that can't be stored.
 */
export async function userForSubject(
  db: Kysely<IdentityTables>,
  who: Subject,
  { ids, clock }: { readonly ids: IdGenerator; readonly clock: Clock },
): Promise<string> {
  checkSubject(who);
  const { issuer, subject } = who;
  // DO NOTHING rather than DO UPDATE: the app may not change a user, and a
  // statement that inserts nothing returns nothing, so the row is read after.
  const made = await db
    .insertInto('identity.users')
    .values({ id: ids.next(), issuer, subject, created_at: clock.now() })
    .onConflict((conflict) => conflict.columns(['issuer', 'subject']).doNothing())
    .returning('id')
    .executeTakeFirst();
  if (made !== undefined) return made.id;
  const found = await db
    .selectFrom('identity.users')
    .select('id')
    .where('issuer', '=', issuer)
    .where('subject', '=', subject)
    .executeTakeFirstOrThrow();
  return found.id;
}

/**
 * The issuer and subject a user signs in as, by their ID (B5-3: the address
 * book asks the login service by the subject); undefined for no such user.
 */
export async function subjectOfUser(db: Kysely<IdentityTables>, userId: string): Promise<Subject | undefined> {
  return db.selectFrom('identity.users').select(['issuer', 'subject']).where('id', '=', userId).executeTakeFirst();
}
