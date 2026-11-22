// What one person may add to the shared platform chain in a day (S210 TR-7, B3).
//
// The platform chain belongs to no organisation, and every organisation's
// hand-off walks past what it holds between two anchors: past MOST_WALKED_WITHIN
// every hand-off is held `too_far` until the next anchor. A signed-in member adds
// to it without any other cap: each session's end (a sign-out, or a sign-in that
// replaces the browser's session) is `identity.session_ended`, and each step-up
// `identity.session_rotated` (signed-ends.ts). So each is held to a day's cap per
// person, counted from durable records under the person's own lock, as their own
// log's downloads are (TR-13, my-activity.ts):
//
// - sessions opened: the person's sessions opened in the last 24 hours still
//   kept, and their session ends signed in that time. A session ends at most
//   once, so its sign-out is bounded by the sign-in that opened it, and a
//   sign-out itself is never refused (sign-in-flow.ts: it never fails closed).
// - step-ups: the person's rotations signed in the last 24 hours.
//
// A session's opening is the app's clock (sessions.ts), a platform event's the
// database's (`recorded_at`, under the head's lock): each is counted by its own.
// Both read by index: 0084's of the platform events by action and person, 0010's
// of the sessions by person.
import { holdTransactionLock } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { SESSION_ENDED, SESSION_ROTATED } from './signed-ends.ts';
import type { IdentityTables } from './tables.ts';

/** The most sessions one person opens in any 24 hours: far above anyone signing in by hand. */
export const MOST_SESSIONS_A_DAY = 100;

/**
 * The most step-ups one person completes in any 24 hours: each confirms one change, so room for a busy approver
 * confirming one every few minutes all day.
 */
export const MOST_STEP_UPS_A_DAY = 200;

/** The advisory lock a person's sign-ins and step-ups count their day's caps under (ADR-006 §6). */
export const PERSON_CHAIN_LOCK = 'identity-person-chain';

/** The person's platform events of `action` signed in the database's last 24 hours, as a subquery. */
const signedToday = (action: string, userId: string) =>
  sql<number>`(select pg_catalog.count(*)::int from platform_controls.audit_events
    where action = ${action} and (details::jsonb ->> 'person') = ${userId.toLowerCase()}
      and recorded_at > pg_catalog.now() - interval '1 day')`;

/**
 * Whether the person has opened `most` sessions in the 24 hours to `now`, read under their lock, held to the end of the
 * transaction, so two sign-ins at once can't both take the last place. First of the sign-in's locks.
 */
export async function sessionsSpent(
  tx: Transaction<IdentityTables>,
  userId: string,
  now: Date,
  most: number,
): Promise<boolean> {
  await holdTransactionLock(tx, PERSON_CHAIN_LOCK, userId);
  const { opened } = await tx
    .selectFrom('identity.sessions')
    .select(sql<number>`pg_catalog.count(*)::int + ${signedToday(SESSION_ENDED, userId)}`.as('opened'))
    .where('user_id', '=', userId)
    .where('created_at', '>', new Date(now.getTime() - DAY_MS))
    .executeTakeFirstOrThrow();
  return opened >= most;
}

/**
 * Whether the person has completed `most` step-ups in the last 24 hours, read under their lock as sessionsSpent, first
 * of the step-up's locks: asked as it starts, to answer early, and as it completes, so two at once can't both take the
 * last place.
 */
export async function stepUpsSpent(tx: Transaction<IdentityTables>, userId: string, most: number): Promise<boolean> {
  await holdTransactionLock(tx, PERSON_CHAIN_LOCK, userId);
  const { rotated } = await tx
    .selectNoFrom(signedToday(SESSION_ROTATED, userId).as('rotated'))
    .executeTakeFirstOrThrow();
  return rotated >= most;
}
