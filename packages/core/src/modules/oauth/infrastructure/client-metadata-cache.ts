// The client metadata documents Agent X fetched, kept a day (0095, 6E3c):
// a client named by its document's address is fetched at most once a day
// while it is in use, never on every request. A global table, as
// oauth.clients is; a document grants nothing.
//
// Past its day a document is stale, kept a further 7 days (6E3c review): if
// fetching it again fails for a reason of the network or the site, or is held
// back by the per-origin cap, the stale one still names the client, so no one
// can lock a real client out by making its fetches fail. Swept after those 7
// days.
//
// Each document is kept sealed (S207 H3, 0107; client-seals.ts): one read
// with no seal, or one not its own, is never believed, fresh or stale; the
// caller fetches it again from its own address.
import { limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Kysely } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { isGrantType } from './client-metadata.ts';
import type { ClientMetadataDocument } from './client-metadata-document.ts';
import { type ClientJudged, documentJudged, documentSealed, sealIn } from './client-seals.ts';
import type { OauthTables } from './tables.ts';

/** How long a document is kept before it is fetched again (6E3 plan §6). */
export const CLIENT_METADATA_KEPT_MS = DAY_MS;

/** How long past its day a document may still stand in while it can't be fetched again, and is kept. */
export const CLIENT_METADATA_STALE_MS = 7 * DAY_MS;

/** A document kept: fresh within its day, or stale within the 7 days after. */
export interface KeptDocument {
  readonly outcome: 'kept';
  readonly document: ClientMetadataDocument;
  readonly fresh: boolean;
}

/** A document kept but not believed, and why (client-seals.ts), for the caller's line. */
export interface UnsealedDocument {
  readonly outcome: 'unsealed';
  readonly judged: Exclude<ClientJudged, 'sound'>;
}

/**
 * The document kept for this client at `now`, fresh or stale, where its seal is its own; `unsealed` where it isn't;
 * undefined for none, or one past its 7 stale days.
 */
export async function keptClientMetadata(
  db: Kysely<OauthTables>,
  keys: KeyProvider,
  clientId: string,
  now: Date,
): Promise<KeptDocument | UnsealedDocument | undefined> {
  const row = await db
    .selectFrom('oauth.client_metadata')
    .select(['client_id', 'name', 'redirect_uris', 'grant_types', 'fetched_at', 'expires_at', 'mac', 'mac_key_version'])
    .where('client_id', '=', clientId)
    .where('expires_at', '>', new Date(now.getTime() - CLIENT_METADATA_STALE_MS))
    .executeTakeFirst();
  if (row === undefined) return undefined;
  const fields = {
    clientId: row.client_id,
    name: row.name,
    redirectUris: row.redirect_uris,
    grantTypes: row.grant_types,
    fetchedAt: row.fetched_at,
    expiresAt: row.expires_at,
  };
  const judged = documentJudged(keys, fields, sealIn(row.mac, row.mac_key_version));
  if (judged !== 'sound') return { outcome: 'unsealed', judged };
  return {
    outcome: 'kept',
    document: {
      clientId: fields.clientId,
      name: fields.name,
      redirectUris: fields.redirectUris,
      grantTypes: fields.grantTypes.filter(isGrantType),
    },
    fresh: fields.expiresAt.getTime() > now.getTime(),
  };
}

/** Keeps the document fetched at `now` for a day, sealed, over the one kept before it, if any. */
export async function keepClientMetadata(
  db: Kysely<OauthTables>,
  keys: KeyProvider,
  document: ClientMetadataDocument,
  now: Date,
): Promise<void> {
  const expiresAt = new Date(now.getTime() + CLIENT_METADATA_KEPT_MS);
  const seal = documentSealed(keys, { ...document, fetchedAt: now, expiresAt });
  const kept = {
    name: document.name,
    redirect_uris: [...document.redirectUris],
    grant_types: [...document.grantTypes],
    fetched_at: now,
    expires_at: expiresAt,
    mac: seal.mac,
    mac_key_version: seal.keyVersion,
  };
  await db
    .insertInto('oauth.client_metadata')
    .values({ client_id: document.clientId, ...kept })
    .onConflict((conflict) => conflict.column('client_id').doUpdateSet(kept))
    .execute();
}

/**
 * Retires the document kept for this client at `now` (6E3c review): its site now publishes one refused for what it
 * says, so the old one never stands in again. Its times are set past the 7 stale days, so it reads as none, the client
 * counts as never valid, and the sweep takes the row. Its seal no longer matches either.
 */
export async function retireClientMetadata(db: Kysely<OauthTables>, clientId: string, now: Date): Promise<void> {
  const ended = now.getTime() - CLIENT_METADATA_STALE_MS - DAY_MS;
  await db
    .updateTable('oauth.client_metadata')
    .set({ fetched_at: new Date(ended - 1), expires_at: new Date(ended) })
    .where('client_id', '=', clientId)
    .execute();
}

/**
 * Deletes up to `most` documents past their day and their 7 stale days at `now`, and says how many, in a transaction
 * of its own whose statement is limited to 10 seconds. One still in use is fetched again on its next request.
 */
export async function sweepClientMetadata(db: Kysely<OauthTables>, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one document at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const ended = tx
      .selectFrom('oauth.client_metadata')
      .select('client_id')
      .where('expires_at', '<=', new Date(now.getTime() - CLIENT_METADATA_STALE_MS))
      .limit(most);
    const rows = await tx
      .deleteFrom('oauth.client_metadata')
      .where('client_id', 'in', ended)
      .returning('client_id')
      .execute();
    return rows.length;
  });
}
