// A newest-first history read held to what its object's verified state names (TR-3 residual 75, state-trail.ts):
// the digest holds an object's newest event alone, so an older one moved off its object below F would else be missed
// by the read and by the walk from F both. Its own module: the reads that use it (suspensions, consent expiry, the
// carry) import each other's constants.
import { newestCovered, type SignedStates, type VerifiedState } from '@agentx/core/modules/audit';
import type { SignedStateTable } from '@agentx/platform/db';

/**
 * Whether a newest-first read of at most `limit` (`events`) holds every event the object's state names
 * (historyHeld): true with no state to hold it to (a reader with none, read from the log alone as before). One
 * missing has raised the alarm, and the caller refuses.
 */
export function heldTo(
  states: SignedStates,
  orgId: string,
  events: Parameters<SignedStates['historyHeld']>[1],
  object: readonly [SignedStateTable, string, VerifiedState] | undefined,
  actions: readonly string[],
  limit: number,
): boolean {
  if (object === undefined) return true;
  const [table, id, state] = object;
  return states.historyHeld(orgId, events, {
    on: [{ table, id, state }],
    actions,
    after: newestCovered(events, limit),
  });
}
