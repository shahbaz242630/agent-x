// Reading an organisation's own security events (Phase 6 6E1b, CO7b; 0091),
// for its admins' page. Inside the organisation's transaction, so the
// table's row-level security holds the read too: another organisation's
// events, and those tied to none (0012's), are never reached.
//
// A page is the counts whose minute began in [from, to), of one kind when
// one is named, newest first by (window start, ID) on 0091's index; `next`
// names the last row's window start and ID, where the next page starts
// before.
//
// S206 V6: each row's MAC is checked as the page is read (at most a page of
// them), and its ID held to when it says it was written (the seal's DATED).
// A row that fails either, planted or edited by the database's owner, or one
// with no MAC at all (from before 0105 or not: S208), is left off the page and
// raises the integrity alarm, one line a row; the page's `next` is still where
// the rows read end, so no row is read twice.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { sql, type Transaction } from 'kysely';

import { DATED, eventMacHolds, securityLogAlarm } from './event-seals.ts';
import { ORG_EVENT_KINDS } from './security-events.ts';
import type { SecurityEventsTables } from './tables.ts';

type OrgEventKind = (typeof ORG_EVENT_KINDS)[number];

/** A row's place on the page, newest first: its window's start, then its ID. */
export interface OrgEventCursor {
  readonly at: Date;
  readonly id: string;
}

/** A page to read: [from, to) by window start, one kind when named, where it starts before, and how many at most. */
export interface OrgEventsToRead {
  readonly from: Date;
  readonly to: Date;
  readonly kind?: OrgEventKind | undefined;
  readonly before?: OrgEventCursor | undefined;
  readonly limit: number;
}

/** Who an event is about: a person or an agent of the organisation; null when neither is known. */
interface OrgEventActor {
  readonly type: 'user' | 'agent';
  readonly id: string;
}

/** One count of the organisation's security events. */
export interface OrgSecurityEvent {
  readonly id: string;
  readonly kind: OrgEventKind;
  readonly reason: string;
  /** The client's address: a clue, never proof; null when none could be read. */
  readonly ip: string | null;
  readonly actor: OrgEventActor | null;
  readonly windowStart: Date;
  readonly count: number;
}

/** `kind` as one the organisation's table holds, or RangeError: 0091 checks it, so another is a bug. */
const kindOf = (kind: string): OrgEventKind => {
  const found = ORG_EVENT_KINDS.find((each) => each === kind);
  if (found === undefined) throw new RangeError(`an organisation's security event has a kind it doesn't know: ${kind}`);
  return found;
};

/** The actor a row names: 0091 lets a row name at most one. */
const actorOf = (userId: string | null, agentId: string | null): OrgEventActor | null => {
  if (userId !== null) return { type: 'user', id: userId };
  return agentId === null ? null : { type: 'agent', id: agentId };
};

/** What a page's rows are checked with: the MAC key, and the alarm's logger. */
export interface OrgEventsChecked {
  readonly keys: KeyProvider;
  readonly logger: Logger;
}

/**
 * A page of the organisation's security events, newest first, and where the next starts before (null at the end):
 * only rows whose MAC holds and whose ID agrees with when they were written, each other raising the alarm.
 */
export async function orgSecurityEventsPage(
  tx: Transaction<SecurityEventsTables>,
  orgId: string,
  asked: OrgEventsToRead,
  checked: OrgEventsChecked,
): Promise<{ readonly rows: readonly OrgSecurityEvent[]; readonly next: OrgEventCursor | null }> {
  const { keys, logger } = checked;
  let query = tx
    .selectFrom('security.org_events')
    .select([
      'org_id',
      'id',
      'kind',
      'reason',
      'ip',
      'user_id',
      'agent_id',
      'window_start',
      'count',
      'created_at',
      'mac',
      'mac_key_version',
      DATED.as('dated'),
    ])
    .where('org_id', '=', orgId.toLowerCase())
    .where('window_start', '>=', asked.from)
    .where('window_start', '<', asked.to);
  if (asked.kind !== undefined) query = query.where('kind', '=', asked.kind);
  const { before } = asked;
  if (before !== undefined) query = query.where(sql<boolean>`(window_start, id) < (${before.at}, ${before.id}::uuid)`);
  // One more than the page, to know whether another follows.
  const found = await query
    .orderBy('window_start', 'desc')
    .orderBy('id', 'desc')
    .limit(asked.limit + 1)
    .execute();
  const read = found.slice(0, asked.limit);
  const believed = read.filter((row) => {
    const facts = {
      id: row.id,
      orgId: row.org_id,
      kind: row.kind,
      reason: row.reason,
      ip: row.ip,
      userId: row.user_id,
      agentId: row.agent_id,
      windowStart: row.window_start,
      count: row.count,
      createdAt: row.created_at,
    };
    if (!eventMacHolds(keys, facts, row)) {
      securityLogAlarm(logger, { orgId }, 'mac', null, row.id);
      return false;
    }
    if (!row.dated) {
      securityLogAlarm(logger, { orgId }, 'misdated', null, row.id);
      return false;
    }
    return true;
  });
  const rows = believed.map((row): OrgSecurityEvent => ({
    id: row.id,
    kind: kindOf(row.kind),
    reason: row.reason,
    ip: row.ip,
    actor: actorOf(row.user_id, row.agent_id),
    windowStart: row.window_start,
    count: row.count,
  }));
  // Where the rows read end, believed or not: a row left off is never read again on the next page.
  const last = read.at(-1);
  return {
    rows,
    next: found.length > asked.limit && last !== undefined ? { at: last.window_start, id: last.id } : null,
  };
}
