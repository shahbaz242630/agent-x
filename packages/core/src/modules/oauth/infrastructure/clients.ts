// The clients that registered themselves (0093, RFC 7591; SEC-OAUTH-13): a
// global table, as a client registers before anyone is known. A registration
// grants nothing: a connection is made only by a person's consent. So it is
// held only against filling the table: a day's cap for the whole server,
// counted under one lock (and each address's own limit, in the API), and a
// client that never connects is swept a day after it registered; one that
// did, 90 days after it last connected (0094, 6E3b), when no connection of
// its can be refreshed any more.
import { holdTransactionLock, limitStatements } from '@agentx/platform/db';
import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import { type ClientRegistration, isGrantType } from './client-metadata.ts';
import { newClientId } from './codes.ts';
import type { OauthTables } from './tables.ts';

/** The most clients that may register in any 24 hours, from every address together. */
export const MOST_REGISTRATIONS_A_DAY = 500;

/** A registered client, as kept. */
export interface Client extends ClientRegistration {
  readonly clientId: string;
  readonly createdAt: Date;
}

/** Registered, with its ID and when; or the day's cap reached, nothing kept. */
export type Registered = { readonly outcome: 'registered'; readonly client: Client } | { readonly outcome: 'capped' };

/**
 * Registers the client, in a transaction of its own whose statements are limited to 10 seconds: the day's count
 * taken under the registrations' one lock, so two at once can't both take the last place.
 */
export async function registerClient(
  db: Kysely<OauthTables>,
  registration: ClientRegistration,
  now: Date,
): Promise<Registered> {
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    await holdTransactionLock(tx, 'oauth_clients');
    const { registered } = await tx
      .selectFrom('oauth.clients')
      .select(sql<number>`pg_catalog.count(*)::int`.as('registered'))
      .where('created_at', '>', new Date(now.getTime() - DAY_MS))
      .executeTakeFirstOrThrow();
    if (registered >= MOST_REGISTRATIONS_A_DAY) return { outcome: 'capped' };
    const client: Client = { ...registration, clientId: newClientId(), createdAt: now };
    await tx
      .insertInto('oauth.clients')
      .values({
        client_id: client.clientId,
        name: client.name,
        redirect_uris: [...client.redirectUris],
        application_type: client.applicationType,
        grant_types: [...client.grantTypes],
        software_id: client.softwareId,
        software_version: client.softwareVersion,
        created_at: now,
        first_connected_at: null,
      })
      .execute();
    return { outcome: 'registered', client };
  });
}

/** The client this ID names, as registered, or undefined. */
export async function clientOf(
  db: Kysely<OauthTables> | Transaction<OauthTables>,
  clientId: string,
): Promise<Client | undefined> {
  const row = await db.selectFrom('oauth.clients').selectAll().where('client_id', '=', clientId).executeTakeFirst();
  if (row === undefined) return undefined;
  return {
    clientId: row.client_id,
    name: row.name,
    redirectUris: row.redirect_uris,
    applicationType: row.application_type === 'native' ? 'native' : 'web',
    grantTypes: row.grant_types.filter(isGrantType),
    softwareId: row.software_id,
    softwareVersion: row.software_version,
    createdAt: row.created_at,
  };
}

/** How long after its last connection a client is swept: past a refresh token's 30 idle days and a connection's 90. */
export const CLIENT_KEPT_DAYS = 90;

/**
 * The statement noting that the client connected at `now` (a code or a refresh issued tokens), for the caller to send
 * in its own transaction on the trip that issues them: it changes the row only when its last connection is an hour old
 * or more, or it has none, so a busy client's row is written at most once an hour; its first connection is kept.
 */
export function clientSeen(db: Kysely<OauthTables> | Transaction<OauthTables>, clientId: string, now: Date) {
  return db
    .updateTable('oauth.clients')
    .set({ first_connected_at: sql<Date>`coalesce(first_connected_at, ${now})`, last_connected_at: now })
    .where('client_id', '=', clientId)
    .where((eb) =>
      eb.or([eb('last_connected_at', 'is', null), eb('last_connected_at', '<=', new Date(now.getTime() - HOUR_MS))]),
    );
}

/** The clients unused at `now`: registered a day ago and never connected, or last connected CLIENT_KEPT_DAYS ago. */
const clientUnused = (now: Date) => (eb: ExpressionBuilder<OauthTables, 'oauth.clients'>) =>
  eb.or([
    eb.and([eb('last_connected_at', 'is', null), eb('created_at', '<=', new Date(now.getTime() - DAY_MS))]),
    eb('last_connected_at', '<=', new Date(now.getTime() - CLIENT_KEPT_DAYS * DAY_MS)),
  ]);

/**
 * Deletes up to `most` clients unused at `now` (clientUnused), and says how many, in a transaction of its own whose
 * statement is limited to 10 seconds.
 */
export async function sweepClients(db: Kysely<OauthTables>, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one client at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const unused = tx.selectFrom('oauth.clients').select('client_id').where(clientUnused(now)).limit(most);
    const rows = await tx.deleteFrom('oauth.clients').where('client_id', 'in', unused).returning('client_id').execute();
    return rows.length;
  });
}
