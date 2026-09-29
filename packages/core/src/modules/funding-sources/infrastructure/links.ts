// Links (0029): a link to the business's bank account that Agent X started
// through the partner, and how it ended. A link grants nothing (the source it
// makes is the authority), so it is a plain tenant table: added when the
// partner gives its session, and settled once, from the partner's answer
// server to server (SEC-PTR-08), never from anything that came back through
// the browser. Locked at the funding source's level (ADR-006 §6: 5), before
// the source it makes.
import { sql, type Transaction } from 'kysely';

import { LINK_OUTCOMES, type LinkOutcomeKind, PARTNER_NAME } from '../domain/source.ts';
import type { FundingSourcesTables } from './tables.ts';

/** A transaction on the funding sources' tables, withTenant's (or withSignedStates') for their organisation. */
type LinksTransaction = Transaction<FundingSourcesTables>;

export interface NewLink {
  readonly orgId: string;
  /** Our link ID, made by the server: the partner's idempotency key for it. */
  readonly id: string;
  /** The membership of the member who started it, checked active by the use case. */
  readonly startedBy: string;
  readonly partner: string;
  /** The partner's session for it. */
  readonly sessionRef: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

/** Adds the link, not yet settled, in the caller's transaction. A partner's name that isn't one is refused before any SQL runs. */
export async function addLink(
  tx: LinksTransaction,
  { orgId, id, startedBy, partner, sessionRef, expiresAt, createdAt }: NewLink,
): Promise<void> {
  if (!PARTNER_NAME.test(partner)) throw new RangeError('A partner is named in lower-case words');
  await tx
    .insertInto('funding_sources.links')
    .values({
      org_id: orgId,
      id,
      started_by: startedBy,
      partner,
      session_ref: sessionRef,
      expires_at: expiresAt,
      created_at: createdAt,
    })
    .execute();
}

/** The most links an organisation may start in 24 hours: links are never retired, so starting them is bounded (the B8-1 lesson). */
export const MOST_LINKS_STARTED_A_DAY = 20;

/**
 * Takes the organisation's lock for starting links until the transaction
 * ends, so two starts at once can't both take the last of the day's budget.
 * Taken right after the idempotency key's claim, before any row lock.
 */
export async function oneLinkStartAtATime(tx: LinksTransaction, orgId: string): Promise<void> {
  const key = `agentx.funding-links:${orgId.toLowerCase()}`;
  await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${key}, 0))`.execute(tx);
}

/** How many links the organisation started after `since`: its budget's count, in one statement. */
export async function linksStartedSince(tx: LinksTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    .selectFrom('funding_sources.links')
    .select(sql<number>`pg_catalog.count(*)::int`.as('started'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.started;
}

/** A link, and how it ended: `open` until it is settled. */
export interface LinkRecord {
  readonly id: string;
  readonly startedBy: string;
  readonly partner: string;
  readonly sessionRef: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly outcome: 'open' | LinkOutcomeKind;
  /** The source it made, once `linked`. */
  readonly sourceId: string | null;
  readonly settledAt: Date | null;
}

const isOutcome = (value: string): value is LinkOutcomeKind => LINK_OUTCOMES.some((outcome) => outcome === value);

/**
 * The link, by its ID, in the caller's transaction for its organisation,
 * locked to its end: `share` to read it, `change` to settle it. Undefined when
 * the organisation has none of that ID.
 */
export async function linkOf(
  tx: LinksTransaction,
  { orgId, id }: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<LinkRecord | undefined> {
  const query = tx
    .selectFrom('funding_sources.links')
    .select([
      'id',
      'started_by',
      'partner',
      'session_ref',
      'expires_at',
      'created_at',
      'outcome',
      'source_id',
      'settled_at',
    ])
    .where('org_id', '=', orgId)
    .where('id', '=', id);
  const row = await (lock === 'share' ? query.forShare() : query.forNoKeyUpdate()).executeTakeFirst();
  if (row === undefined) return undefined;
  const outcome = row.outcome ?? 'open';
  // The table's check holds the outcome to its words.
  if (outcome !== 'open' && !isOutcome(outcome)) throw new Error(`A link holds an outcome that isn't one: ${id}`);
  return {
    id: row.id,
    startedBy: row.started_by,
    partner: row.partner,
    sessionRef: row.session_ref,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    outcome,
    sourceId: row.source_id,
    settledAt: row.settled_at,
  };
}

/** The link can't be settled: it is settled already, or there is no such link. */
export class LinkNotOpen extends Error {
  constructor() {
    super('The link is settled already, or there is no such link');
    this.name = 'LinkNotOpen';
  }
}

/**
 * Settles the link once, in the caller's transaction, which has read it with
 * `change`: `linked` names the source it made (added in the same
 * transaction), any other end names none. A link settled already is
 * refused (`LinkNotOpen`), so an end is never rewritten.
 */
export async function settleLink(
  tx: LinksTransaction,
  { orgId, id }: { readonly orgId: string; readonly id: string },
  end:
    | { readonly outcome: 'linked'; readonly sourceId: string }
    | { readonly outcome: Exclude<LinkOutcomeKind, 'linked'> },
  settledAt: Date,
): Promise<void> {
  const settled = await tx
    .updateTable('funding_sources.links')
    .set({ outcome: end.outcome, source_id: end.outcome === 'linked' ? end.sourceId : null, settled_at: settledAt })
    .where('org_id', '=', orgId)
    .where('id', '=', id)
    .where('outcome', 'is', null)
    .executeTakeFirst();
  if (settled.numUpdatedRows !== 1n) throw new LinkNotOpen();
}
