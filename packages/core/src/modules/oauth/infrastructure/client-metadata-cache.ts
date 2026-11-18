// The client metadata documents Agent X fetched, kept a day (0095, 6E3c):
// a client named by its document's address is fetched at most once a day
// while it is in use, never on every request. A global table, as
// oauth.clients is; a document grants nothing. Swept once its day is past.
import { limitStatements } from '@agentx/platform/db';
import type { Kysely } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { isGrantType } from './client-metadata.ts';
import type { ClientMetadataDocument } from './client-metadata-document.ts';
import type { OauthTables } from './tables.ts';

/** How long a document is kept before it is fetched again (6E3 plan §6). */
export const CLIENT_METADATA_KEPT_MS = DAY_MS;

/** The document kept for this client, while its day lasts at `now`; undefined for none, or one past its day. */
export async function keptClientMetadata(
  db: Kysely<OauthTables>,
  clientId: string,
  now: Date,
): Promise<ClientMetadataDocument | undefined> {
  const row = await db
    .selectFrom('oauth.client_metadata')
    .select(['client_id', 'name', 'redirect_uris', 'grant_types'])
    .where('client_id', '=', clientId)
    .where('expires_at', '>', now)
    .executeTakeFirst();
  if (row === undefined) return undefined;
  return {
    clientId: row.client_id,
    name: row.name,
    redirectUris: row.redirect_uris,
    grantTypes: row.grant_types.filter(isGrantType),
  };
}

/** Keeps the document fetched at `now` for a day, over the one kept before it, if any. */
export async function keepClientMetadata(
  db: Kysely<OauthTables>,
  document: ClientMetadataDocument,
  now: Date,
): Promise<void> {
  const kept = {
    name: document.name,
    redirect_uris: [...document.redirectUris],
    grant_types: [...document.grantTypes],
    fetched_at: now,
    expires_at: new Date(now.getTime() + CLIENT_METADATA_KEPT_MS),
  };
  await db
    .insertInto('oauth.client_metadata')
    .values({ client_id: document.clientId, ...kept })
    .onConflict((conflict) => conflict.column('client_id').doUpdateSet(kept))
    .execute();
}

/**
 * Deletes up to `most` documents past their day at `now`, and says how many, in a transaction of its own whose
 * statement is limited to 10 seconds. One still in use is fetched again on its next request.
 */
export async function sweepClientMetadata(db: Kysely<OauthTables>, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one document at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const ended = tx.selectFrom('oauth.client_metadata').select('client_id').where('expires_at', '<=', now).limit(most);
    const rows = await tx
      .deleteFrom('oauth.client_metadata')
      .where('client_id', 'in', ended)
      .returning('client_id')
      .execute();
    return rows.length;
  });
}
