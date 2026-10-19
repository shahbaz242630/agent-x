// The audit log as an organisation is shown it (Phase 3 E10; decisions 24 and
// 25), in one place for the API's page and download and the operator's
// export for a case (E10c, ADR-005 §6):
//
// - Shown whole but for the seals that are the platform's alone: a signed
//   state's keyed fingerprint and its key's version are taken out of the
//   details (the MAC and its key's version are never read out at all). The
//   hashes stay, so each event's link to the one before can be checked.
// - Each actor named beside their ID (actor-names.ts).
// - A batch read in the organisation's transaction, each event believed only
//   whole (logPageOf), with what Agent X holds to name its actors: `tampered`
//   for an event or an agent that can't be believed, the alarm raised.
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import type { AgentsTables } from '../../agents/index.ts';
import type { AuditTables, LogEvent, LogPageToRead, SignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import type { IdentityTables } from '../../identity/index.ts';

import { type ActorName, type ActorsHeld, actorsHeld, nameOf } from './actor-names.ts';

/** The tables a batch of the log reads: its events, and what names their actors. */
export type LogReadTables = AuditTables & IdentityTables & DirectoryTables & AgentsTables;

/** The details a signed state's event carries that are the platform's seal, not the organisation's record. */
const SEALS_NOT_SHOWN: ReadonlySet<string> = new Set(['stateFingerprint', 'stateKeyVersion']);

/** An event's facts as an organisation is shown them, page or download: the platform's own seals left out. */
export const factsShown = (details: LogEvent['event']['details']) =>
  Object.entries(details).filter(([name]) => !SEALS_NOT_SHOWN.has(name));

/** An event's own fields as an organisation is shown them, page or download, its actor named, beside its facts in the form each needs. */
export const eventShown = (
  { seq, id, recordedAt, event, hash, prevHash }: LogEvent,
  names: ReadonlyMap<string, ActorName>,
) => ({
  seq: seq.toString(),
  id,
  recordedAt: recordedAt.toISOString(),
  actor: { ...event.actor, ...nameOf(names, event.actor) },
  action: event.action,
  subject: event.subject,
  hash,
  prevHash,
});

/** An event as an NDJSON download holds it: one line, its facts as an object and its chain hashes, to check outside Agent X. */
export const ndjsonLine = (logged: LogEvent, names: ReadonlyMap<string, ActorName>): string =>
  JSON.stringify({ ...eventShown(logged, names), details: Object.fromEntries(factsShown(logged.event.details)) });

/** Who acted in each of `events`, for a namer. */
export const actorsOf = (events: readonly LogEvent[]) => events.map(({ event }) => event.actor);

/** A batch of the log and what Agent X holds to name its actors. */
export interface HeldLogPage {
  readonly events: readonly LogEvent[];
  readonly next: bigint | null;
  readonly held: ActorsHeld;
}

/**
 * A batch of the log and what Agent X holds to name its actors, in the
 * organisation's transaction, a page, a download's batch or an export's alike;
 * `tampered` for an event or an agent that can't be believed.
 */
export async function heldLogPage(
  tx: DatabaseTransaction<LogReadTables>,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  asked: LogPageToRead,
): Promise<HeldLogPage | 'tampered'> {
  const page = await states.logPageOf(tx, orgId, asked);
  if (page.outcome === 'tampered') return 'tampered';
  const held = await actorsHeld(tx, states, keys, orgId, actorsOf(page.events));
  if (held === 'tampered') return 'tampered';
  return { events: page.events, next: page.next, held };
}
