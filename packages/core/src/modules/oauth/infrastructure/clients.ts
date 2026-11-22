// The clients that registered themselves (0093, RFC 7591; SEC-OAUTH-13): a
// global table, as a client registers before anyone is known. A registration
// grants nothing: a connection is made only by a person's consent. So it is
// held only against filling the table: a day's cap for the whole server and
// one for each network (6F1 G4), counted under one lock (and each address's
// own limit, in the API), the network cleared once its day is past (AG8), and a
// client that never connects is swept a day after it registered; one that
// did, 90 days after it last connected (0094, 6E3b), when no connection of
// its can be refreshed any more.
//
// What it registered is sealed as it registers (S207 H3, 0107;
// client-seals.ts): a client read with no seal, or one not its own, is never
// believed, so no one without the app's keys can add a redirect address or a
// grant type to it. One registered before 0107 has none: it must register
// again.
import { holdTransactionLock, limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import { type ClientRegistration, isGrantType } from './client-metadata.ts';
import { type ClientJudged, registeredJudged, registeredSealed, sealIn } from './client-seals.ts';
import { newClientId } from './codes.ts';
import type { OauthTables } from './tables.ts';

/**
 * The clients that may register in any 24 hours, from every address together, past which only a busy network's are
 * refused (S210 TR-7, R2-1): the table's backstop, never a lockout. A crowd of networks filling it would otherwise
 * refuse every organisation's next app for the day (no fixed user ceiling: load may slow the system, never break it).
 */
export const MOST_REGISTRATIONS_A_DAY = 2000;

/**
 * The most clients that may register in any 24 hours from one network (6F1 G4): an IPv4 /24 or an IPv6 /48, so a few
 * addresses, or one network's many, can't take the whole day's MOST_REGISTRATIONS_A_DAY from every organisation.
 * Room for a hosted client (6F1 G4 review): its servers register a client for each organisation that adds Agent X,
 * from one vendor network, so the share is well above one person's needs.
 */
export const MOST_REGISTRATIONS_A_NETWORK_A_DAY = 150;

/**
 * How many registrations in 24 hours make a network busy: past MOST_REGISTRATIONS_A_DAY only a busy network is refused
 * (S210 TR-7, R2-1), any other still held to its own MOST_REGISTRATIONS_A_NETWORK_A_DAY. A third of that share: a
 * shared network (a hosted agent platform, an office's one address) adding a few dozen organisations' apps a day stays
 * under it, while filling the server's cap takes at least 14 networks at their full 150, each far past it.
 */
export const BUSY_NETWORK_REGISTRATIONS = MOST_REGISTRATIONS_A_NETWORK_A_DAY / 3;

/** A registered client, as kept. */
export interface Client extends ClientRegistration {
  readonly clientId: string;
  readonly createdAt: Date;
}

/**
 * Registered, with its ID and when; or a day's cap reached, nothing kept: this network's, or the whole server's with
 * this network busy.
 */
export type Registered =
  | { readonly outcome: 'registered'; readonly client: Client }
  | { readonly outcome: 'capped'; readonly cap: 'server' | 'network' };

/**
 * Registers the client from `network` (6F1 G4: its client address's /24, or /48 for IPv6), in a transaction of its own
 * whose statements are limited to 10 seconds: the day's counts, the server's and the network's, taken under the
 * registrations' one lock, so two at once can't both take the last place. Past the server's cap only a network holding
 * BUSY_NETWORK_REGISTRATIONS that day is refused (S210 TR-7, R2-1).
 */
export async function registerClient(
  db: Kysely<OauthTables>,
  keys: KeyProvider,
  registration: ClientRegistration,
  now: Date,
  network: string,
): Promise<Registered> {
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    await holdTransactionLock(tx, 'oauth_clients');
    const { registered, fromNetwork } = await tx
      .selectFrom('oauth.clients')
      .select([
        sql<number>`pg_catalog.count(*)::int`.as('registered'),
        sql<number>`(pg_catalog.count(*) filter (where network = ${network}))::int`.as('fromNetwork'),
      ])
      .where('created_at', '>', new Date(now.getTime() - DAY_MS))
      .executeTakeFirstOrThrow();
    if (fromNetwork >= MOST_REGISTRATIONS_A_NETWORK_A_DAY) return { outcome: 'capped', cap: 'network' };
    if (registered >= MOST_REGISTRATIONS_A_DAY && fromNetwork >= BUSY_NETWORK_REGISTRATIONS) {
      return { outcome: 'capped', cap: 'server' };
    }
    const client: Client = { ...registration, clientId: newClientId(), createdAt: now };
    const seal = registeredSealed(keys, client);
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
        network,
        mac: seal.mac,
        mac_key_version: seal.keyVersion,
      })
      .execute();
    return { outcome: 'registered', client };
  });
}

/** A registered client read, as it registered; or one kept but not believed, and why (client-seals.ts). */
export type ClientRead =
  | { readonly outcome: 'known'; readonly client: Client }
  | { readonly outcome: 'unsealed'; readonly judged: Exclude<ClientJudged, 'sound'> };

/** The client this ID names, as registered, where its seal is its own; `unsealed` where it isn't; undefined for none. */
export async function clientOf(
  db: Kysely<OauthTables> | Transaction<OauthTables>,
  keys: KeyProvider,
  clientId: string,
): Promise<ClientRead | undefined> {
  const row = await db.selectFrom('oauth.clients').selectAll().where('client_id', '=', clientId).executeTakeFirst();
  if (row === undefined) return undefined;
  const fields = {
    clientId: row.client_id,
    name: row.name,
    applicationType: row.application_type,
    redirectUris: row.redirect_uris,
    grantTypes: row.grant_types,
    softwareId: row.software_id,
    softwareVersion: row.software_version,
    createdAt: row.created_at,
  };
  const judged = registeredJudged(keys, fields, sealIn(row.mac, row.mac_key_version));
  if (judged !== 'sound') return { outcome: 'unsealed', judged };
  return {
    outcome: 'known',
    client: {
      ...fields,
      applicationType: fields.applicationType === 'native' ? 'native' : 'web',
      grantTypes: fields.grantTypes.filter(isGrantType),
    },
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

/**
 * Clears the network up to `most` clients registered from, once their day is past at `now` (AG8): it is kept only for
 * its network's day's count (MOST_REGISTRATIONS_A_NETWORK_A_DAY), and a client that connects lives on for months.
 * Says how many, in a transaction of its own whose statement is limited to 10 seconds; the clients themselves stay.
 */
export async function sweepClientNetworks(db: Kysely<OauthTables>, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep clears at least one network at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const past = tx
      .selectFrom('oauth.clients')
      .select('client_id')
      .where('network', 'is not', null)
      .where('created_at', '<=', new Date(now.getTime() - DAY_MS))
      .limit(most);
    const rows = await tx
      .updateTable('oauth.clients')
      .set({ network: null })
      .where('client_id', 'in', past)
      .returning('client_id')
      .execute();
    return rows.length;
  });
}
