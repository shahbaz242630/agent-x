// MCP connections (0093, 6E3a, ADR-016): a connection is a key of an agent's,
// its secret thrown away, beside a row saying which OAuth client it was made
// for, at which MCP resource, sending its browser back where. An authority
// table made once (ADR-012 §2, 0032's `made_once`): its agent, client,
// resource and redirect address must equal its signed event, at lock level 3b,
// after its key's 3a. It has no status of its own: its key's status and expiry
// are its own, so revoking a connection is revoking its key (revokeKey).
//
// Made in the consent's transaction, withSignedStates' for its organisation:
// its key first (addAgentKey, which lists it in the directory), then its row,
// then its first signed state. The insert is the one query on this table
// outside the audit module's steps, as for a key's row (agent-keys.ts).
import { sql } from 'kysely';

import {
  type AuditActor,
  checkOf,
  type RecordedState,
  type SignedStates,
  type TamperSign,
  type VerifiedState,
} from '../../audit/index.ts';
import { DAY_MS } from '../../../shared-kernel/index.ts';
import { AGENT_KEYS, agentKeyOf, type AgentKeyRecord, keyRecordOf } from './agent-keys.ts';
import { CONNECTIONS } from './connection-table.ts';
import type { AgentsTransaction } from './agents.ts';

export { CONNECTIONS } from './connection-table.ts';

/** How a connection was made: a browser's code (6E3a), or a device's (6E3c). */
export type ConnectionVia = 'code' | 'device';

export interface NewConnection {
  readonly orgId: string;
  /** Its key's ID, the key issued in this same transaction. */
  readonly keyId: string;
  readonly agentId: string;
  readonly clientId: string;
  /** What the client's name said on the consent page: shown, never trusted. */
  readonly clientName: string;
  readonly resource: string;
  /** Where its code was sent; null for a device's. */
  readonly redirectUri: string | null;
  readonly via: ConnectionVia;
  /** The membership of the person who made it. */
  readonly madeBy: string;
  readonly createdAt: Date;
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up it was confirmed with. */
  readonly details?: Readonly<Record<string, unknown>>;
}

/**
 * Makes the connection, in the caller's transaction, which must be withSignedStates' for its organisation and have
 * just issued its key (addAgentKey): a key that is no key of that agent's is refused by the row's foreign key.
 */
export async function addConnection(
  tx: AgentsTransaction,
  states: SignedStates,
  {
    orgId,
    keyId,
    agentId,
    clientId,
    clientName,
    resource,
    redirectUri,
    via,
    madeBy,
    createdAt,
    actor,
    details = {},
  }: NewConnection,
): Promise<RecordedState> {
  const fields = { agent_id: agentId, client_id: clientId, resource, redirect_uri: redirectUri };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(CONNECTIONS.table)
    .values({
      org_id: orgId,
      id: keyId,
      client_name: clientName,
      via,
      made_by: madeBy,
      created_at: createdAt,
      ...fields,
    })
    .execute();
  return states.record(tx, CONNECTIONS, { orgId, id: keyId }, 'new', fields, {
    actor,
    action: 'connection.made',
    details: { ...details, agentId, keyId, clientId, resource, via },
  });
}

/** A connection, as its signed state says. */
export interface ConnectionRecord {
  /** Its key's ID. */
  readonly keyId: string;
  readonly agentId: string;
  readonly clientId: string;
  readonly resource: string;
  readonly redirectUri: string | null;
}

/** A connection read by its key's ID and verified; missing (the key is no connection); or tampered with. */
export type ConnectionCheck =
  | { readonly outcome: 'found'; readonly connection: ConnectionRecord }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The connection whose key this is, read (`share`) and verified, in the caller's transaction, which must be
 * withSignedStates' for its organisation and have read the key first (3a, then 3b). Tampered with, the alarm is
 * raised and the organisation held, as every signed state's read does.
 */
export async function connectionOf(
  tx: AgentsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<ConnectionCheck> {
  const state = await states.verifiedState(tx, CONNECTIONS, key, 'share');
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', connection: connectionRecordOf(key.id, state) };
}

/** The connection a verified signed state of CONNECTIONS says: its fields, each held to its kind. */
function connectionRecordOf(id: string, state: VerifiedState): ConnectionRecord {
  const agentId = state.fields.get('agent_id');
  const clientId = state.fields.get('client_id');
  const resource = state.fields.get('resource');
  const redirectUri = state.fields.get('redirect_uri');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    typeof agentId !== 'string' ||
    typeof clientId !== 'string' ||
    typeof resource !== 'string' ||
    redirectUri === undefined
  ) {
    throw new Error(`A verified connection holds a field that isn't one of its own: ${id}`);
  }
  return { keyId: id.toLowerCase(), agentId, clientId, resource, redirectUri };
}

/** The agent's connections as a count: how many there are in all, and how many of them still work at `now`. */
export interface ConnectionCount {
  readonly all: number;
  readonly live: number;
}

/**
 * How many connections the agent has, ended ones included, and how many work at `now` (their key ACTIVE and not
 * expired), in one statement: for its limits, never a decision on any one of them (each is read through its signed
 * state where one is). In the caller's transaction, withSignedStates' for the organisation, under the agent's lock.
 */
export async function connectionsCounted(
  tx: AgentsTransaction,
  orgId: string,
  agentId: string,
  now: Date,
): Promise<ConnectionCount> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a limit; no connection is decided on from it
    .selectFrom(`${CONNECTIONS.table} as c`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same count's key status, for the live ones
    .innerJoin(`${AGENT_KEYS.table} as k`, (join) => join.onRef('k.org_id', '=', 'c.org_id').onRef('k.id', '=', 'c.id'))
    .select([
      sql<number>`pg_catalog.count(*)::int`.as('all'),
      sql<number>`pg_catalog.count(*) filter (where k.status = 'ACTIVE' and k.expires_at > ${now})::int`.as('live'),
    ])
    .where('c.org_id', '=', orgId)
    .where('c.agent_id', '=', agentId)
    .executeTakeFirstOrThrow();
  return { all: row.all, live: row.live };
}

/**
 * Whether the key is an MCP connection's, in one statement: a key route answers such a key as no key of its agent's
 * (its connection is revoked as a connection, 6E3b), so a person can't rotate a connection into a key they hold.
 */
export async function isConnectionKey(tx: AgentsTransaction, orgId: string, keyId: string): Promise<boolean> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- whether a row is there alone; nothing is granted from it
    .selectFrom(CONNECTIONS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('id', '=', keyId)
    .executeTakeFirst();
  return row !== undefined;
}

/** How many connections the organisation made after `since`: its day's budget's count, in one statement. */
export async function connectionsMadeSince(tx: AgentsTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no connection is decided on from it
    .selectFrom(CONNECTIONS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('made'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.made;
}

/** The most connections an agent's list shows: its 10 live ones and those ended lately, newest first. */
export const MOST_CONNECTIONS_LISTED = 50;

/**
 * How long an ended connection stays on its agent's list: until 30 days after its key's expiry (or when it would have
 * expired, for one revoked). Inside its tokens' 120 days (0093's retention: a key's 90 days and these 30), so the
 * newest token, which says when it last connected, is still kept while it is listed.
 */
export const ENDED_CONNECTIONS_SHOWN_DAYS = 30;

/** A connection as its agent's list shows it: as its signed state and its key's say, and what it was made with. */
export interface ConnectionListed {
  readonly connection: ConnectionRecord;
  /** Its key, as its signed state says: the connection's status, scopes and expiry are its key's. */
  readonly key: AgentKeyRecord;
  /** What the consent page called the client: shown, never trusted. */
  readonly clientName: string;
  readonly via: ConnectionVia;
  /** The membership of the person who made it. */
  readonly madeBy: string;
  readonly createdAt: Date;
  /** When it was last given tokens (its newest token's issue), or null if never. */
  readonly lastConnectedAt: Date | null;
}

/**
 * The agent's connections, newest first, at most MOST_CONNECTIONS_LISTED: every live one, and those ended (revoked or
 * expired) whose key expired, or would have, less than ENDED_CONNECTIONS_SHOWN_DAYS before `now`. One statement for
 * the rows and when each last had tokens, then the keys' signed states (3a) and the connections' (3b), each table's in
 * one read (`share`). In the caller's transaction, withSignedStates' for the organisation, which read the agent first.
 * A row whose sealed agent is another is left out; tampered with, the first found is answered, its alarm raised.
 */
export async function connectionsListed(
  tx: AgentsTransaction,
  states: SignedStates,
  orgId: string,
  agentId: string,
  now: Date,
): Promise<
  | { readonly outcome: 'listed'; readonly connections: readonly ConnectionListed[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look and what it was made with, which grant nothing; each connection is then read through its signed state
    .selectFrom(`${CONNECTIONS.table} as c`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same rows' keys' expiry, to leave long-ended ones out; each key is then read through its signed state
    .innerJoin(`${AGENT_KEYS.table} as k`, (join) => join.onRef('k.org_id', '=', 'c.org_id').onRef('k.id', '=', 'c.id'))
    .select((eb) => [
      'c.id',
      'c.client_name',
      'c.via',
      'c.made_by',
      'c.created_at',
      eb
        .selectFrom('agents.connection_tokens as t')
        .select(sql<Date>`pg_catalog.max(t.created_at)`.as('last'))
        .whereRef('t.org_id', '=', 'c.org_id')
        .whereRef('t.key_id', '=', 'c.id')
        .as('last_connected_at'),
    ])
    .where('c.org_id', '=', orgId)
    .where('c.agent_id', '=', agentId)
    .where('k.expires_at', '>', new Date(now.getTime() - ENDED_CONNECTIONS_SHOWN_DAYS * DAY_MS))
    .orderBy('c.created_at', 'desc')
    .orderBy('c.id', 'desc')
    .limit(MOST_CONNECTIONS_LISTED)
    .execute();
  if (rows.length === 0) return { outcome: 'listed', connections: [] };
  const ids = rows.map(({ id }) => id);
  const keyChecks = await states.verifiedStates(tx, AGENT_KEYS, orgId, ids);
  const connectionChecks = await states.verifiedStates(tx, CONNECTIONS, orgId, ids);
  const connections: ConnectionListed[] = [];
  for (const row of rows) {
    const keyCheck = checkOf(keyChecks, row.id.toLowerCase());
    const connectionCheck = checkOf(connectionChecks, row.id.toLowerCase());
    if (keyCheck.outcome === 'tampered') return keyCheck;
    if (connectionCheck.outcome === 'tampered') return connectionCheck;
    // Neither is ever deleted, so both are there: one gone since its row was listed is no connection to show.
    if (keyCheck.outcome === 'missing' || connectionCheck.outcome === 'missing') continue;
    // Both rows name the agent (the list's own condition, and the connection's foreign key to the key with its
    // agent), and each equals its seal or was answered tampered just above. Held to it again from the seals, so a
    // list that ever reads wider still shows only this agent's.
    const key = keyRecordOf(row.id, keyCheck);
    const connection = connectionRecordOf(row.id, connectionCheck);
    if (connection.agentId !== agentId.toLowerCase() || key.agentId !== connection.agentId) continue;
    connections.push({
      connection,
      key,
      clientName: row.client_name,
      // The table's check holds it to the two.
      via: row.via as ConnectionVia,
      madeBy: row.made_by,
      createdAt: row.created_at,
      lastConnectedAt: row.last_connected_at,
    });
  }
  return { outcome: 'listed', connections };
}

/** The member's live connections (key ACTIVE, not expired at `now`) as rows: where to look alone. */
const liveMadeBy = (tx: AgentsTransaction, orgId: string, membershipId: string, now: Date) =>
  tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; each key is then read through its signed state
    .selectFrom(`${CONNECTIONS.table} as c`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same rows' keys, to leave ended ones out; each is then read through its signed state
    .innerJoin(`${AGENT_KEYS.table} as k`, (join) => join.onRef('k.org_id', '=', 'c.org_id').onRef('k.id', '=', 'c.id'))
    .where('c.org_id', '=', orgId)
    .where('c.made_by', '=', membershipId)
    .where('k.status', '=', 'ACTIVE')
    .where('k.expires_at', '>', now);

/**
 * The agents of the live connections the member made, in order of ID, by one unlocked statement: whose brakes (1b)
 * removing the member takes, in this order, before any row (ADR-006 §6). Where to look alone: the keys are then read,
 * locked, by liveConnectionsMadeBy.
 */
export async function agentsOfLiveConnectionsMadeBy(
  tx: AgentsTransaction,
  orgId: string,
  membershipId: string,
  now: Date,
): Promise<readonly string[]> {
  const rows = await liveMadeBy(tx, orgId, membershipId, now).select('c.agent_id').distinct().execute();
  // In code too, as the brakes' names are: lower-case IDs, the order every taker of more than one keeps.
  return rows.map(({ agent_id }) => agent_id.toLowerCase()).sort();
}

/**
 * The live keys of the connections the member made in the organisation (ACTIVE, not expired at `now`), in order of ID,
 * each read for change (3a) and verified: what removing the member revokes (decision 7). One statement for the IDs,
 * then each key's own read. In the caller's transaction, withSignedStates' for the organisation, before its first
 * event; tampered with, the first found is answered, its alarm raised.
 */
export async function liveConnectionsMadeBy(
  tx: AgentsTransaction,
  states: SignedStates,
  orgId: string,
  membershipId: string,
  now: Date,
): Promise<
  | { readonly outcome: 'listed'; readonly keys: readonly AgentKeyRecord[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const rows = await liveMadeBy(tx, orgId, membershipId, now).select('c.id').orderBy('c.id').execute();
  const keys: AgentKeyRecord[] = [];
  for (const { id } of rows) {
    const read = await agentKeyOf(tx, states, { orgId, id }, 'change');
    if (read.outcome === 'tampered') return read;
    if (read.outcome === 'found' && read.key.status === 'ACTIVE') keys.push(read.key);
  }
  return { outcome: 'listed', keys };
}
