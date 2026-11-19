// A download's retries answered from its idempotency key (6E1a review round 1; AG10, 6F1): a retry spends no
// download budget, yet its file is built again, so each person's are held to their own hourly count, in this process's
// memory. My activity's downloads count them by person; an organisation's audit and activity log downloads by admin
// in that organisation, as their budget is.
import type { AuditActor } from '@agentx/core/modules/audit';
import { type Clock, HOUR_MS } from '@agentx/core/shared-kernel';

/** The most retries one person's downloads are answered from their keys in an hour: as many as their downloads. */
export const MOST_REPLAYS_AN_HOUR = 5;

export interface ReplayCount {
  /** Counts a retry of `who`'s answered from its key: true when it is past their hour's count, so refused, uncounted. */
  spent(who: string): boolean;
  /** How many people's retries are kept now: for the tests. */
  kept(): number;
}

export function createReplayCount(
  clock: Clock,
  most = MOST_REPLAYS_AN_HOUR,
  /** How many people's retries are kept before the stale are swept: then twice as many as remain, or this. */
  sweepFrom = 1_024,
): ReplayCount {
  // Each person's retries in the last hour, newest last; a person with none is no entry (review round 2: bounded by
  // the people active in the hour, however many there are).
  const replays = new Map<string, number[]>();
  let sweepAt = sweepFrom;
  /** Every person's retries older than the hour forgotten, and anyone left with none. */
  const sweep = (since: number) => {
    for (const [who, times] of replays) {
      const recent = times.filter((at) => at > since);
      if (recent.length === 0) replays.delete(who);
      else replays.set(who, recent);
    }
    sweepAt = Math.max(sweepFrom, replays.size * 2);
  };
  return {
    spent(who) {
      const now = clock.now().getTime();
      const since = now - HOUR_MS;
      if (replays.size >= sweepAt) sweep(since);
      const recent = (replays.get(who) ?? []).filter((at) => at > since);
      if (recent.length >= most) return true;
      replays.set(who, [...recent, now]);
      return false;
    },
    kept: () => replays.size,
  };
}

/** Whose retries an organisation's download counts: the admin's, in that organisation, as their budget is. */
export const downloaderOf = (member: { readonly orgId: string; readonly userId: string }): string =>
  `${member.orgId.toLowerCase()}:${member.userId.toLowerCase()}`;

/**
 * Whether the record a download's key answered with is this admin's download of this kind (AG10): a key is a
 * person's own, so one naming anyone or anything else was changed past the app, and no file is built from it.
 */
export const madeBy = <Read extends { readonly event: { readonly action: string; readonly actor: AuditActor } }>(
  event: Read | undefined,
  member: { readonly userId: string },
  action: string,
): event is Read =>
  event?.event.action === action &&
  event.event.actor.type === 'user' &&
  event.event.actor.id.toLowerCase() === member.userId.toLowerCase();
