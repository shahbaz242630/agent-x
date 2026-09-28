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
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { AGENT, type AgentStatus, type Scope, scopesOf, scopesText } from '../domain/agent.ts';
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
  /** What people call it, already checked by the use case; kept on the row alone. */
  readonly name: string;
  /** The membership of the member who owns it, checked active by the use case. */
  readonly owner: string;
  /** The most any of its keys may be given. */
  readonly scopes: readonly Scope[];
  readonly createdAt: Date;
  /** Who is adding it. */
  readonly actor: AuditActor;
}

/**
 * Adds the agent, ACTIVE, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's.
 * Scopes it can't have are refused before any SQL runs (`ScopesRefused`).
 */
export async function addAgent(
  tx: AgentsTransaction,
  states: SignedStates,
  { orgId, id, name, owner, scopes, createdAt, actor }: NewAgent,
): Promise<RecordedState> {
  const fields = { owner, status: AGENT.initial, scopes: scopesText(scopes) };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(AGENTS.table)
    .values({ org_id: orgId, id, name, created_at: createdAt, ...fields })
    .execute();
  return states.record(tx, AGENTS, { orgId, id }, 'new', fields, {
    actor,
    action: 'agent.created',
    details: { owner, scopes: fields.scopes },
  });
}

/** An agent, as its signed state says. */
interface AgentRecord {
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
