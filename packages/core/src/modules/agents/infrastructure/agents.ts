// Agents (0027): an AI agent of an organisation. An authority table (ADR-012
// §2), so its owner, its status and its scopes must equal the agent's latest
// signed event, and every read a decision rests on goes through the audit
// module's verifiedState with the description below. The description is on
// the product's authority-table list (packages/core/src/authority-tables.ts),
// which CI, the lint rules and the live schema guard all read.
//
// An agent is added in one transaction, withSignedStates' for its
// organisation: its row, then its first signed state. The insert is the one
// query on this table outside the audit module's steps, as for an
// organisation's row (organizations.ts says why a plain insert is safe, and
// must stay plain). Its name is kept on the row alone, never in an event.
import { holdTransactionLock, type SignedStateTable } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import {
  type AuditActor,
  type AuditDetails,
  type AuditTables,
  type PageAsked,
  type RecordedState,
  type SignedStates,
  type TamperSign,
  verifiedPage,
  type VerifiedState,
} from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { AGENT, agentName, type AgentStatus, type Scope, scopesOf, scopesText } from '../domain/agent.ts';
import type { AgentsTables } from './tables.ts';

/** An agent's row, as the signed state reads, records and moves it. */
export const AGENTS = {
  table: 'agents.agents',
  subject: 'agent',
  fields: [
    { column: 'owner', type: 'uuid' },
    { column: 'status', type: 'text' },
    { column: 'scopes', type: 'text' },
  ],
  rules: AGENT,
} as const satisfies SignedStateTable & { readonly rules: typeof AGENT };

/** A transaction on the tables agents and their keys are added and read in, opened by withSignedStates for their organisation. */
export type AgentsTransaction = Transaction<AgentsTables & DirectoryTables & AuditTables>;

export interface NewAgent {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** What people call it; kept on the row alone, composed as agentName gives it. */
  readonly name: string;
  /** The membership of the member who owns it, checked active by the use case. */
  readonly owner: string;
  /** The most any of its keys may be given. */
  readonly scopes: readonly Scope[];
  readonly createdAt: Date;
  /** Who is adding it. */
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up it was confirmed with. */
  readonly details?: AuditDetails;
}

/**
 * Adds the agent, ACTIVE, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's.
 * A name (`AgentNameRefused`) or scopes (`ScopesRefused`) it can't have are
 * refused before any SQL runs.
 */
export async function addAgent(
  tx: AgentsTransaction,
  states: SignedStates,
  { orgId, id, name, owner, scopes, createdAt, actor, details = {} }: NewAgent,
): Promise<RecordedState> {
  const fields = { owner, status: AGENT.initial, scopes: scopesText(scopes) };
  const kept = agentName(name);
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(AGENTS.table)
    .values({ org_id: orgId, id, name: kept, created_at: createdAt, ...fields })
    .execute();
  return states.record(tx, AGENTS, { orgId, id }, 'new', fields, {
    actor,
    action: 'agent.created',
    details: { ...details, owner, scopes: fields.scopes },
  });
}

/**
 * Takes the organisation's lock for adding agents until the transaction
 * ends, so two adds at once can't both take the last of the day's budget.
 * Taken right after the idempotency key's claim, before any row lock.
 */
export async function oneAgentAddAtATime(tx: AgentsTransaction, orgId: string): Promise<void> {
  await holdTransactionLock(tx, 'agents', orgId);
}

/** How many agents the organisation added after `since`: its budget's count, in one statement. */
export async function agentsAddedSince(tx: AgentsTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no agent is decided on from it
    .selectFrom(AGENTS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('added'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.added;
}

/** An agent, as its signed state says. */
export interface AgentRecord {
  readonly id: string;
  readonly owner: string;
  readonly status: AgentStatus;
  readonly scopes: readonly Scope[];
}

/** An agent read by its ID and verified, with the state a change records from; missing; or tampered with. */
export type AgentCheck =
  | { readonly outcome: 'found'; readonly agent: AgentRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The agent, by its ID, read and verified in the caller's transaction, which
 * must be withSignedStates' for its organisation: `share` for a decision,
 * `change` for a change (its state then what `record` takes). Tampered with,
 * the alarm is raised and the organisation held; anything but `found` grants
 * nothing.
 */
export async function agentOf(
  tx: AgentsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<AgentCheck> {
  const state = await states.verifiedState(tx, AGENTS, key, lock);
  if (state.outcome !== 'verified') return state;
  const owner = state.fields.get('owner');
  const status = state.fields.get('status');
  const scopes = state.fields.get('scopes');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (typeof owner !== 'string' || (status !== 'ACTIVE' && status !== 'SUSPENDED') || typeof scopes !== 'string') {
    throw new Error(`A verified agent holds a field that isn't one of its own: ${key.id}`);
  }
  return {
    outcome: 'found',
    agent: { id: key.id.toLowerCase(), owner, status, scopes: scopesOf(scopes) },
    state,
  };
}

/**
 * Hands the agent to another owner, a membership the use case checked may
 * own it and isn't its owner already, in the caller's transaction, which
 * must be withSignedStates' for its organisation: `state` is the one agentOf
 * gave for change there. Only the owner changes; the agent's status, scopes
 * and keys stay as they are.
 */
export async function handAgentOver(
  tx: AgentsTransaction,
  states: SignedStates,
  {
    orgId,
    agent,
    state,
    owner,
    actor,
    details,
  }: {
    readonly orgId: string;
    readonly agent: AgentRecord;
    readonly state: VerifiedState;
    /** The membership taking it over. */
    readonly owner: string;
    readonly actor: AuditActor;
    /** More facts for its event, such as the step-up it was confirmed with. */
    readonly details: AuditDetails;
  },
): Promise<RecordedState> {
  const to = owner.toLowerCase();
  return states.record(
    tx,
    AGENTS,
    { orgId, id: agent.id },
    state,
    { owner: to },
    { actor, action: 'agent.owner_changed', details: { ...details, ownerFrom: agent.owner, ownerTo: to } },
  );
}

/** An agent as a list or an answer shows it: its signed state, with its name and when it was added. */
export interface AgentShown extends AgentRecord {
  readonly name: string;
  readonly createdAt: Date;
}

/**
 * Each verified agent with its name and creation time, read for all of them
 * in one statement: what people call them, never what they may do, which
 * their signed states say.
 */
export async function agentsShown(
  tx: AgentsTransaction,
  orgId: string,
  agents: readonly AgentRecord[],
): Promise<AgentShown[]> {
  if (agents.length === 0) return [];
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- names and times alone, shown beside each agent's verified state
    .selectFrom(AGENTS.table)
    .select(['id', 'name', 'created_at'])
    .where('org_id', '=', orgId)
    .where(
      'id',
      'in',
      agents.map((agent) => agent.id),
    )
    .execute();
  const named = new Map(rows.map((row) => [row.id, row]));
  return agents.map((agent) => {
    const row = named.get(agent.id);
    if (row === undefined) throw new Error(`A verified agent has no row to name it: ${agent.id}`);
    return { ...agent, name: row.name, createdAt: row.created_at };
  });
}

/** The most agents a page gives. */
export const MOST_AGENTS_A_PAGE = 50;

/**
 * A page of the organisation's agents, in order of ID, each read (`share`) and
 * verified, in the caller's transaction, which must be withSignedStates' for
 * it: at most `limit` (1 to MOST_AGENTS_A_PAGE) after the agent `after`, with
 * the ID to ask the next page after, or null at the end; or tampered with, at
 * the first agent that is, and then no page at all. Besides each agent's own
 * read, three statements a page: the tenant check, its IDs and its names.
 */
export async function agentsPage(
  tx: AgentsTransaction,
  states: SignedStates,
  orgId: string,
  page: PageAsked,
): Promise<
  | { readonly outcome: 'listed'; readonly agents: readonly AgentShown[]; readonly next: string | null }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const listed = await verifiedPage(
    tx,
    AGENTS,
    orgId,
    page,
    { most: MOST_AGENTS_A_PAGE, rows: 'agents' },
    async (id) => {
      const read = await agentOf(tx, states, { orgId, id }, 'share');
      return read.outcome === 'found' ? { outcome: 'found', item: read.agent } : read;
    },
  );
  if (listed.outcome === 'tampered') return listed;
  return { outcome: 'listed', agents: await agentsShown(tx, orgId, listed.items), next: listed.next };
}
