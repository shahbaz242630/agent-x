// A session's verified email address (0017, B4-4a): what the login service
// vouched for as the person signed in, encrypted with the session's ID as its
// associated data, kept as long as the session and no longer. An invitation
// is matched against it (B4-4c).
import type { KeyProvider } from '@agentx/platform/keys';
import type { Kysely, Transaction } from 'kysely';

import { invitationEmail } from '../domain/invitation.ts';
import type { IdentityTables } from './tables.ts';

type Handle = Kysely<IdentityTables> | Transaction<IdentityTables>;

/** The address's associated data: its session, so it opens for no other. */
const associatedData = (sessionId: string) => ['identity.session_emails', sessionId.toLowerCase()] as const;

/**
 * Keeps the session's verified address, in the transaction that opens the
 * session. Throws a RangeError for anything that isn't one address: the OIDC
 * client gives only one it has checked.
 */
export async function recordSessionEmail(
  db: Handle,
  keys: KeyProvider,
  sessionId: string,
  email: string,
): Promise<void> {
  const address = invitationEmail(email);
  if (address === undefined) throw new RangeError("A session's address refused: it is not one");
  const sealed = keys.encrypt('field-encryption', Buffer.from(address, 'utf8'), associatedData(sessionId));
  await db
    .insertInto('identity.session_emails')
    .values({ session_id: sessionId, email_ciphertext: sealed.ciphertext, email_key_version: sealed.keyVersion })
    .execute();
}

/** A session's address that won't open: changed, or copied from another session. */
export class SessionEmailUnreadable extends Error {
  constructor(options: ErrorOptions) {
    super("A session's address can't be opened", options);
    this.name = 'SessionEmailUnreadable';
  }
}

/**
 * The session's verified address, or undefined when the login service gave
 * none (or the session opened before B4-4a). Throws SessionEmailUnreadable
 * for one that won't open.
 */
export async function sessionEmailOf(db: Handle, keys: KeyProvider, sessionId: string): Promise<string | undefined> {
  const row = await db
    .selectFrom('identity.session_emails')
    .select(['email_ciphertext', 'email_key_version'])
    .where('session_id', '=', sessionId)
    .executeTakeFirst();
  if (row === undefined) return undefined;
  try {
    return keys
      .decrypt(
        'field-encryption',
        { keyVersion: row.email_key_version, ciphertext: row.email_ciphertext },
        associatedData(sessionId),
      )
      .toString('utf8');
  } catch (error) {
    throw new SessionEmailUnreadable({ cause: error });
  }
}
