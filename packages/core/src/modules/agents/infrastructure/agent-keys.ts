// Agent keys (0027): a key an agent sends as `axk_<keyId>_<secret>`, kept as
// HMAC-SHA-256 of its secret with the agent-key pepper (ADR-011 §1), never
// the secret. An authority table (ADR-012 §2), so its agent, status, scopes,
// secret's MAC, pepper version and expiry must equal the key's latest signed
// event: a secret planted by someone who knows it, a key moved to another
// agent, a revocation undone or an expiry stretched is caught at the next
// read. The description is on the product's authority-table list, after the
// agents' (ADR-006 §6: an agent at 3, its keys at 3a).
//
// A key is issued in one transaction, withSignedStates' for its organisation:
// its directory entry first (the row points at it), then its row, then its
// first signed state. The insert is the one query on this table outside the
// audit module's steps, as for an organisation's row (organizations.ts says
// why a plain insert is safe, and must stay plain).
//
// Its secret's MAC is sealed but never put in an event: a seal is a MAC over
// the fields, so the audit trail holds nothing a key could be guessed from.
import type { SignedStateTable } from '@agentx/platform/db';
import { sql } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { registerAgentKey } from '../../directory/index.ts';
import { AGENT_KEY, type AgentKeyStatus, type Scope, scopesOf, scopesText } from '../domain/agent.ts';
import type { AgentsTransaction } from './agents.ts';

/** A key's row, as the signed state reads, records and moves it. */
export const AGENT_KEYS = {
  table: 'agents.agent_keys',
  subject: 'agent_key',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'status', type: 'text' },
    { column: 'scopes', type: 'text' },
    { column: 'secret_mac', type: 'text' },
    { column: 'secret_key_version', type: 'integer' },
    { column: 'expires_at', type: 'timestamptz' },
  ],
  rules: AGENT_KEY,
} as const satisfies SignedStateTable & { readonly rules: typeof AGENT_KEY };

/** HMAC-SHA-256's length, in bytes. */
const MAC_BYTES = 32;

export interface NewAgentKey {
  readonly orgId: string;
  /** Its ID, made by the server: the one in the key the agent sends. */
  readonly id: string;
  /** The agent it is for, verified ACTIVE by the use case, in this transaction. */
  readonly agentId: string;
  /** Within its agent's scopes, which the use case checks. */
  readonly scopes: readonly Scope[];
  /** HMAC-SHA-256 of the secret with the agent-key pepper. */
  readonly secretMac: Buffer;
  /** The pepper's version it was made with. */
  readonly secretKeyVersion: number;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  /** Who is issuing it. */
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up and the key it rotates. */
  readonly details?: AuditDetails;
}

/**
 * Issues the key, ACTIVE, in the caller's transaction, which must be
 * withSignedStates' for its organisation and have read its agent first.
 * Scopes it can't have (`ScopesRefused`) and a MAC that isn't 32 bytes are
 * refused before any SQL runs; a key ID listed already is refused by the
 * directory's key.
 */
export async function addAgentKey(
  tx: AgentsTransaction,
  states: SignedStates,
  { orgId, id, agentId, scopes, secretMac, secretKeyVersion, expiresAt, createdAt, actor, details = {} }: NewAgentKey,
): Promise<RecordedState> {
  if (secretMac.length !== MAC_BYTES) throw new RangeError(`A key's MAC is ${String(MAC_BYTES)} bytes`);
  const fields = {
    agent_id: agentId,
    status: AGENT_KEY.initial,
    scopes: scopesText(scopes),
    secret_mac: secretMac.toString('hex'),
    secret_key_version: secretKeyVersion,
    expires_at: expiresAt,
  };
  await registerAgentKey(tx, { orgId, keyId: id });
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(AGENT_KEYS.table)
    .values({ org_id: orgId, id, created_at: createdAt, ...fields })
    .execute();
  return states.record(tx, AGENT_KEYS, { orgId, id }, 'new', fields, {
    actor,
    action: 'agent_key.issued',
    details: { ...details, agentId, scopes: fields.scopes, expiresAt: expiresAt.toISOString() },
  });
}

/** A key, as its signed state says. */
export interface AgentKeyRecord {
  readonly id: string;
  readonly agentId: string;
  readonly status: AgentKeyStatus;
  readonly scopes: readonly Scope[];
  readonly secretMac: Buffer;
  readonly secretKeyVersion: number;
  readonly expiresAt: Date;
}

/** A key read by its ID and verified, with the state a change records from; missing; or tampered with. */
export type AgentKeyCheck =
  | { readonly outcome: 'found'; readonly key: AgentKeyRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const MAC_HEX = /^[0-9a-f]{64}$/;
const WHOLE = /^[1-9][0-9]{0,9}$/;

/**
 * The key, by its ID, read and verified in the caller's transaction, which
 * must be withSignedStates' for its organisation and have read its agent
 * first: `share` for a decision, `change` for a change. Tampered with, the
 * alarm is raised and the organisation held; anything but `found` grants
 * nothing, and a found key grants nothing revoked or past its expiry.
 */
export async function agentKeyOf(
  tx: AgentsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<AgentKeyCheck> {
  const state = await states.verifiedState(tx, AGENT_KEYS, key, lock);
  if (state.outcome !== 'verified') return state;
  const agentId = state.fields.get('agent_id');
  const status = state.fields.get('status');
  const scopes = state.fields.get('scopes');
  const secretMac = state.fields.get('secret_mac');
  const secretKeyVersion = state.fields.get('secret_key_version');
  const expiresAt = new Date(state.fields.get('expires_at') ?? Number.NaN);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    typeof agentId !== 'string' ||
    (status !== 'ACTIVE' && status !== 'REVOKED') ||
    typeof scopes !== 'string' ||
    typeof secretMac !== 'string' ||
    !MAC_HEX.test(secretMac) ||
    typeof secretKeyVersion !== 'string' ||
    !WHOLE.test(secretKeyVersion) ||
    Number.isNaN(expiresAt.getTime())
  ) {
    throw new Error(`A verified agent key holds a field that isn't one of its own: ${key.id}`);
  }
  return {
    outcome: 'found',
    key: {
      id: key.id.toLowerCase(),
      agentId,
      status,
      scopes: scopesOf(scopes),
      secretMac: Buffer.from(secretMac, 'hex'),
      secretKeyVersion: Number(secretKeyVersion),
      expiresAt,
    },
    state,
  };
}

/** The most keys of one agent a list reads: more is refused, never cut short unseen. */
export const MOST_KEYS_LISTED = 100;

/** More keys than a list reads (MOST_KEYS_LISTED). */
export class TooManyAgentKeys extends Error {
  constructor() {
    super(`The agent has more than ${String(MOST_KEYS_LISTED)} keys, more than a list reads`);
    this.name = 'TooManyAgentKeys';
  }
}

/**
 * The agent's keys, revoked and expired ones included, in order of ID, each
 * read (`share`, or `change` for a change to them) and verified, in the
 * caller's transaction, which must be withSignedStates' for its organisation
 * and have read the agent first; or tampered with, at the first key that is. One statement for the IDs, then
 * each key's own read: the row's agent is only where to look, and a key
 * whose sealed agent is another is left out.
 */
export async function agentKeysOf(
  tx: AgentsTransaction,
  states: SignedStates,
  orgId: string,
  agentId: string,
  lock: 'share' | 'change' = 'share',
): Promise<
  | { readonly outcome: 'listed'; readonly keys: readonly AgentKeyRecord[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; each key is then read through its signed state
    .selectFrom(AGENT_KEYS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('agent_id', '=', agentId)
    .orderBy('id')
    .limit(MOST_KEYS_LISTED + 1)
    .execute();
  if (rows.length > MOST_KEYS_LISTED) throw new TooManyAgentKeys();
  const keys: AgentKeyRecord[] = [];
  for (const { id } of rows) {
    const read = await agentKeyOf(tx, states, { orgId, id }, lock);
    if (read.outcome === 'tampered') return read;
    if (read.outcome === 'missing' || read.key.agentId !== agentId.toLowerCase()) continue;
    keys.push(read.key);
  }
  return { outcome: 'listed', keys };
}

/**
 * Takes the organisation's lock for issuing keys by rotation or by a
 * handover until the transaction ends, so two issues at once can't both take
 * the last of the day's budget. Taken right after the idempotency key's claim, before any row lock.
 */
export async function oneKeyIssueAtATime(tx: AgentsTransaction, orgId: string): Promise<void> {
  const key = `agentx.agent_keys:${orgId.toLowerCase()}`;
  await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${key}, 0))`.execute(tx);
}

/** How many keys the organisation issued after `since`, first keys included: its budget's count, in one statement. */
export async function keysIssuedSince(tx: AgentsTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no key is decided on from it
    .selectFrom(AGENT_KEYS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('issued'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.issued;
}

/**
 * Brings the key's expiry forward to `expiresAt`, from `state`, the key's
 * state read for change in this transaction; never later than it was, which
 * is refused before any SQL runs. What a rotation does to the key it replaces.
 */
export async function bringKeyExpiryForward(
  tx: AgentsTransaction,
  states: SignedStates,
  {
    orgId,
    key,
    state,
    expiresAt,
    actor,
    action,
    details,
  }: {
    readonly orgId: string;
    readonly key: AgentKeyRecord;
    readonly state: VerifiedState;
    readonly expiresAt: Date;
    readonly actor: AuditActor;
    readonly action: string;
    readonly details: AuditDetails;
  },
): Promise<RecordedState> {
  if (expiresAt.getTime() > key.expiresAt.getTime())
    throw new RangeError("A key's expiry is only ever brought forward");
  return states.record(
    tx,
    AGENT_KEYS,
    { orgId, id: key.id },
    state,
    { expires_at: expiresAt },
    {
      actor,
      action,
      details: { ...details, expiresAt: expiresAt.toISOString() },
    },
  );
}
