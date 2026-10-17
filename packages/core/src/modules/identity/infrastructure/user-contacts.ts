// A person's kept name and verified email (0049, decision 25): what the login
// service vouched for at their latest sign-in, each encrypted with the person
// and the field as its associated data, so a value opens neither in another
// person's row nor as the other field. The audit log names a person by them
// when the login service can't answer, or no longer has the person.
//
// Each sign-in refreshes the row. A value the login service didn't give this
// time (no name, or no verified address) leaves the one kept before: what was
// vouched for once still says who acted then. A sign-in that gives neither,
// for a person with no row, keeps nothing.
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, sql, type Transaction } from 'kysely';

import { invitationEmail } from '../domain/invitation.ts';
import { personName } from '../domain/person-name.ts';
import type { IdentityTables } from './tables.ts';

type Handle = Kysely<IdentityTables> | Transaction<IdentityTables>;

type Field = 'name' | 'email';

/** A field's associated data: its person and its own name, so it opens nowhere else. */
export const contactData = (userId: string, field: Field) =>
  ['identity.user_contacts', userId.toLowerCase(), field] as const;

/** What a sign-in vouched for: either may be missing. */
export interface ContactGiven {
  readonly name: string | undefined;
  readonly verifiedEmail: string | undefined;
}

/**
 * Keeps the person's name and verified address as of `at`, in the sign-in's
 * own transaction. Throws a RangeError for a value that isn't a name or one
 * address: the OIDC client gives only ones it has checked.
 */
export async function keepUserContact(
  db: Handle,
  keys: KeyProvider,
  userId: string,
  given: ContactGiven,
  at: Date,
): Promise<void> {
  const name = given.name === undefined ? undefined : personName(given.name);
  const email = given.verifiedEmail === undefined ? undefined : invitationEmail(given.verifiedEmail);
  if (name === undefined && given.name !== undefined) throw new RangeError("A person's name refused: it is not one");
  if (email === undefined && given.verifiedEmail !== undefined) {
    throw new RangeError("A person's address refused: it is not one");
  }
  if (name === undefined && email === undefined) return;
  const sealed = (value: string | undefined, field: Field) =>
    value === undefined
      ? undefined
      : keys.encrypt('field-encryption', Buffer.from(value, 'utf8'), contactData(userId, field));
  const sealedName = sealed(name, 'name');
  const sealedEmail = sealed(email, 'email');
  await db
    .insertInto('identity.user_contacts')
    .values({
      user_id: userId,
      name_ciphertext: sealedName?.ciphertext ?? null,
      name_key_version: sealedName?.keyVersion ?? null,
      email_ciphertext: sealedEmail?.ciphertext ?? null,
      email_key_version: sealedEmail?.keyVersion ?? null,
      updated_at: at,
    })
    // Each field's pair moves together: a value missing this time keeps the one before, with its key.
    .onConflict((conflict) =>
      conflict.column('user_id').doUpdateSet({
        name_ciphertext: sql`coalesce(excluded.name_ciphertext, user_contacts.name_ciphertext)`,
        name_key_version: sql`coalesce(excluded.name_key_version, user_contacts.name_key_version)`,
        email_ciphertext: sql`coalesce(excluded.email_ciphertext, user_contacts.email_ciphertext)`,
        email_key_version: sql`coalesce(excluded.email_key_version, user_contacts.email_key_version)`,
        updated_at: sql`excluded.updated_at`,
      }),
    )
    .execute();
}
