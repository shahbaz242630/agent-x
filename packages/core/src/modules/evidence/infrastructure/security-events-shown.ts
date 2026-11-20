// An organisation's security events as its admins are shown them (Phase 6
// 6E1b, CO7b): the rate-limit hits and failed step-ups of its own people and
// agents (0091), each actor named as on the audit log (actor-names.ts), the
// address labelled a clue, never proof, as on the activity log (decision 26).
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import type { SignedStates } from '../../audit/index.ts';
import {
  type OrgEventsChecked,
  type OrgEventCursor,
  type OrgEventsToRead,
  orgSecurityEventsPage,
  type OrgSecurityEvent,
  type SecurityEventsTables,
} from '../../security-events/index.ts';

import { type ActorName, type ActorsHeld, actorsHeld, nameOf } from './actor-names.ts';
import type { LogReadTables } from './log-shown.ts';

/** The tables a page of security events reads: its rows, and what names their actors. */
export type SecurityEventsReadTables = SecurityEventsTables & LogReadTables;

/** Who each of `rows` is about, for a namer: those that name no one are left out. */
export const securityEventActorsOf = (rows: readonly OrgSecurityEvent[]) =>
  rows.flatMap((row) => (row.actor === null ? [] : [row.actor]));

/** A row as an organisation's admins are shown it, its actor named. */
export const securityEventShown = (row: OrgSecurityEvent, names: ReadonlyMap<string, ActorName>) => ({
  id: row.id,
  kind: row.kind,
  reason: row.reason,
  ip: row.ip,
  actor: row.actor === null ? null : { type: row.actor.type, id: row.actor.id, name: nameOf(names, row.actor).name },
  windowStart: row.windowStart.toISOString(),
  count: row.count,
});

/** A page of security events and what Agent X holds to name their actors. */
interface HeldSecurityEventsPage {
  readonly rows: readonly OrgSecurityEvent[];
  readonly next: OrgEventCursor | null;
  readonly held: ActorsHeld;
}

/**
 * A page of the organisation's security events and what Agent X holds to name
 * their actors, in the organisation's transaction; `tampered` for an agent
 * that can't be believed (its signed state), the alarm raised as on the logs.
 * Only rows whose MAC holds are on it (S206 V6, `checked`).
 */
export async function heldSecurityEventsPage(
  tx: DatabaseTransaction<SecurityEventsReadTables>,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  asked: OrgEventsToRead,
  checked: OrgEventsChecked,
): Promise<HeldSecurityEventsPage | 'tampered'> {
  const page = await orgSecurityEventsPage(tx, orgId, asked, checked);
  const held = await actorsHeld(tx, states, keys, orgId, securityEventActorsOf(page.rows));
  if (held === 'tampered') return 'tampered';
  return { ...page, held };
}
