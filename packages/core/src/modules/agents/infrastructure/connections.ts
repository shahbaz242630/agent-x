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

import type { AuditActor, RecordedState, SignedStates, TamperSign } from '../../audit/index.ts';
import { AGENT_KEYS } from './agent-keys.ts';
import { CONNECTIONS } from './connection-table.ts';
import type { AgentsTransaction } from './agents.ts';

export { CONNECTIONS } from './connection-table.ts';

/** How a connection was made: a browser's code (6E3a), or a device's (6E3c). */
type ConnectionVia = 'code' | 'device';

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
    throw new Error(`A verified connection holds a field that isn't one of its own: ${key.id}`);
  }
  return {
    outcome: 'found',
    connection: { keyId: key.id.toLowerCase(), agentId, clientId, resource, redirectUri },
  };
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
