// The authorization flows under way (0093; RFC 6749 §4.1, OAuth 2.1): a flow
// is opened when a client sends a person's browser to us, decided once (the
// person allows it, with the organisation and connection key it made, or
// denies it), and its code used once. A global table: the flow comes before
// anyone is signed in, and names its organisation and key by ID alone.
//
// - Only the browser that opened a flow reads or decides it: the flow keeps
//   the SHA-256 of that browser's cookie (browser_hash).
// - Decided once: the decision's UPDATE takes only an undecided flow still in
//   time, in the consent's own transaction.
// - Its code used once (SEC-OAUTH-04): codeTaken fills in its use in one
//   statement, only where none was, so two exchanges at once can't both have
//   it; the second finds it used (codeUsedBefore), and its connection is
//   revoked by the API.
import { limitStatements } from '@agentx/platform/db';
import { type Kysely, type Transaction } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type Scope, scopesOf, scopesText } from '../../agents/index.ts';
import type { OauthTables } from './tables.ts';

/** How long a person has to sign in and decide (plan §3): long enough to register an agent first. */
export const FLOW_SECONDS = 15 * 60;

/** How long a code may wait to be exchanged (OAuth 2.1 §4.1.2: short). */
export const CODE_SECONDS = 60;

/** A browser's flow, as opened. */
export interface CodeFlow {
  readonly id: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** The client's own `state`, sent back unchanged; null for none. */
  readonly state: string | null;
  readonly codeChallenge: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly browserHash: string;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/** A flow as read: opened, and whether it was decided and its code used. */
export interface FlowRead extends CodeFlow {
  readonly decided: 'allowed' | 'denied' | null;
  readonly orgId: string | null;
  readonly keyId: string | null;
  readonly codeEndsAt: Date | null;
  readonly usedAt: Date | null;
}

type Database = Kysely<OauthTables>;
/** The database, or a transaction on it holding these tables among others (the consent's own). */
type Handle = Database | Transaction<OauthTables>;

/** Opens the flow, for FLOW_SECONDS from its creation. */
export async function openCodeFlow(db: Database, flow: Omit<CodeFlow, 'endsAt'>): Promise<void> {
  await db
    .insertInto('oauth.flows')
    .values({
      id: flow.id,
      kind: 'code',
      client_id: flow.clientId,
      redirect_uri: flow.redirectUri,
      state: flow.state,
      code_challenge: flow.codeChallenge,
      scopes_asked: scopesText(flow.scopesAsked),
      resource: flow.resource,
      browser_hash: flow.browserHash,
      created_at: flow.createdAt,
      ends_at: new Date(flow.createdAt.getTime() + FLOW_SECONDS * 1000),
    })
    .execute();
}

const COLUMNS = [
  'id',
  'client_id',
  'redirect_uri',
  'state',
  'code_challenge',
  'scopes_asked',
  'resource',
  'browser_hash',
  'created_at',
  'ends_at',
  'outcome',
  'org_id',
  'key_id',
  'code_ends_at',
  'used_at',
] as const;

type FlowRow = {
  readonly [Column in (typeof COLUMNS)[number]]: OauthTables['oauth.flows'][Column];
};

/** A code flow's row as read; undefined for a device's (6E3c), which has no browser. */
function flowOf(row: FlowRow | undefined): FlowRead | undefined {
  if (row === undefined || row.redirect_uri === null || row.code_challenge === null || row.browser_hash === null) {
    return undefined;
  }
  return {
    id: row.id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    state: row.state,
    codeChallenge: row.code_challenge,
    scopesAsked: scopesOf(row.scopes_asked),
    resource: row.resource,
    browserHash: row.browser_hash,
    createdAt: row.created_at,
    endsAt: row.ends_at,
    decided: row.outcome === 'allowed' || row.outcome === 'denied' ? row.outcome : null,
    orgId: row.org_id,
    keyId: row.key_id,
    codeEndsAt: row.code_ends_at,
    usedAt: row.used_at,
  };
}

/** The code flow this ID names, decided or not, in time or not; undefined for none. */
export async function flowById(db: Handle, id: string): Promise<FlowRead | undefined> {
  return flowOf(await db.selectFrom('oauth.flows').select(COLUMNS).where('id', '=', id).executeTakeFirst());
}

/** How a flow was decided. */
export type FlowDecision =
  | { readonly outcome: 'allowed'; readonly orgId: string; readonly keyId: string; readonly codeHash: string }
  | { readonly outcome: 'denied' };

/**
 * Decides the flow, if it is still undecided and in time at `now`, in the caller's transaction: whether this call
 * decided it. An allowed flow keeps its code's hash for CODE_SECONDS.
 */
export async function flowDecided(db: Handle, id: string, decision: FlowDecision, now: Date): Promise<boolean> {
  const allowed = decision.outcome === 'allowed' ? decision : undefined;
  const row = await db
    .updateTable('oauth.flows')
    .set({
      decided_at: now,
      outcome: decision.outcome,
      org_id: allowed?.orgId ?? null,
      key_id: allowed?.keyId ?? null,
      code_hash: allowed?.codeHash ?? null,
      code_ends_at: allowed === undefined ? null : new Date(now.getTime() + CODE_SECONDS * 1000),
    })
    .where('id', '=', id)
    .where('kind', '=', 'code')
    .where('decided_at', 'is', null)
    .where('ends_at', '>', now)
    .returning('id')
    .executeTakeFirst();
  return row !== undefined;
}

/**
 * Uses the code whose hash this is, once: the flow it was given in, if this call is the one that used it, whether or
 * not it is still in time (the caller judges that); undefined if no flow has it, or it was used before.
 */
export async function codeTaken(db: Database, codeHash: string, now: Date): Promise<FlowRead | undefined> {
  return flowOf(
    await db
      .updateTable('oauth.flows')
      .set({ used_at: now })
      .where('code_hash', '=', codeHash)
      .where('used_at', 'is', null)
      .returning(COLUMNS)
      .executeTakeFirst(),
  );
}

/** The flow whose code this is, if it was used before: a second use, whose connection is then revoked. */
export async function codeUsedBefore(db: Database, codeHash: string): Promise<FlowRead | undefined> {
  return flowOf(
    await db
      .selectFrom('oauth.flows')
      .select(COLUMNS)
      .where('code_hash', '=', codeHash)
      .where('used_at', 'is not', null)
      .executeTakeFirst(),
  );
}

/**
 * Deletes up to `most` flows that ended more than a day before `now`, and says how many, in a transaction of its own
 * whose statement is limited to 10 seconds. The day keeps a used code's flow for its reuse to be caught.
 */
export async function sweepFlows(db: Database, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one flow at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const ended = tx
      .selectFrom('oauth.flows')
      .select('id')
      .where('ends_at', '<=', new Date(now.getTime() - DAY_MS))
      .limit(most);
    const rows = await tx.deleteFrom('oauth.flows').where('id', 'in', ended).returning('id').execute();
    return rows.length;
  });
}
