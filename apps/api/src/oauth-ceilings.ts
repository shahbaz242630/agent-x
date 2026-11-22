// Alarm-only hard ceilings on the OAuth server's two tables anyone can fill (S210 final; SEC-OAUTH-13). Past the day's
// registrations cap, or the open flows' cap, only a busy network or source is refused (S210 TR-7, R2-1): a quiet one
// ignores the server's cap altogether, by design, so no flood locks every organisation out. Many quiet networks
// together can so take either table far past its cap, refused nowhere. These say so: at most once a minute each, the
// table is counted, no further than one past its ceiling and under no lock, and an error is written when it holds more
// than CEILING_TIMES its cap. Nobody is refused by it.
import {
  MOST_OPEN_FLOWS,
  MOST_REGISTRATIONS_A_DAY,
  type OauthTables,
  openFlowsHeld,
  registrationsSince,
} from '@agentx/core/modules/oauth';
import { type Clock, DAY_MS } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { Logger, ProblemEvent } from '@agentx/platform/observability';

/** How many times its cap a table holds before the error. */
export const CEILING_TIMES = 5;

/** How often each table is counted at most, so the error comes at most once a minute too. */
const CHECK_EVERY_MS = 60_000;

/** A count of a table's rows that count toward its cap at `now`, stopping at `most`. */
type Count = (now: Date, most: number) => Promise<number>;

/** The two tables' counts: the day's registrations, and the flows not ended. */
export interface OauthTableCounts {
  readonly registrations: Count;
  readonly flows: Count;
}

/** The counts, read from the database, each by its index, as the caps read them. */
export const oauthTableCounts = (database: Database<OauthTables>): OauthTableCounts => ({
  registrations: async (now, most) => {
    const since = new Date(now.getTime() - DAY_MS);
    return (await registrationsSince(database, since, most).executeTakeFirstOrThrow()).registered;
  },
  flows: (now, most) => openFlowsHeld(database, now, most),
});

/** Each never rejects, a failed count said as a warning, so a request may start it and not wait for it. */
export interface OauthCeilings {
  /** Counts the day's registrations, at most once a minute, and says when they are past the ceiling. */
  registrations(): Promise<void>;
  /** Counts the flows not ended, at most once a minute, and says when they are past the ceiling. */
  flows(): Promise<void>;
}

export function createOauthCeilings({
  counts,
  clock,
  logger,
}: {
  readonly counts: OauthTableCounts;
  readonly clock: Clock;
  readonly logger: Logger;
}): OauthCeilings {
  const watch = (event: ProblemEvent, cap: number, count: Count) => {
    const ceiling = cap * CEILING_TIMES;
    let checkedAt = Number.NEGATIVE_INFINITY;
    return async (): Promise<void> => {
      const now = clock.now();
      if (now.getTime() - checkedAt < CHECK_EVERY_MS) return;
      // Taken before the count, so requests meanwhile don't count again.
      checkedAt = now.getTime();
      try {
        if ((await count(now, ceiling + 1)) > ceiling) logger.error(event, { cap, ceiling });
      } catch (error) {
        // An alarm's count is no reason to fail the request it rode on; the next minute counts again.
        logger.warn('oauth.ceiling_unread', { err: error });
      }
    };
  };
  return {
    registrations: watch('oauth.registrations_past_ceiling', MOST_REGISTRATIONS_A_DAY, counts.registrations),
    flows: watch('oauth.flows_past_ceiling', MOST_OPEN_FLOWS, counts.flows),
  };
}
