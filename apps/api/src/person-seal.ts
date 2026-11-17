// The person log's daily seal, recorded (Phase 6 6E1a, CO8, PL-48; decision
// 26's L8): the API's job, on a timer of its own, sealing each closed UTC day
// of `access.person_requests` (every person's rows together) into one
// `access_log.person_sealed` event on the platform chain (person-seal.ts in
// the activity module says what a day and its digest are).
//
// The organisations' seal's steps (seal-days.ts), for one log: a run starts at
// the day after the newest seal, or at the day the first row was written when
// there is none, and seals each closed day after it in order, at most
// MOST_DAYS_A_RUN a run, quiet days too; each recorded under the person seal's
// lock (ADR-006 §6, then the platform chain head's, last) only if the newest
// seal and the day's count still stand; a day that moved is left for the next
// run, an error.
//
// The newest seal is believed only once its content, MAC and signature check
// (platformEventSealed): one planted or edited past the app raises the alarm
// and nothing past it is sealed. A day holding a row written past the app
// (its ID's time far from its own: `misdated`) is never sealed, the alarm
// raised (`audit.integrity_failed`, check `person_log`). There is no hold
// (decision D3): no organisation owns the log, so there is none to hold.
//
// A run never throws: a failure is logged, and the next run starts again.
import {
  type ActivityTables,
  countOfDay,
  firstDayIn,
  nextDay,
  personDigestOfDay,
  personLogAlarm,
  PERSON_SEAL_FORM,
  PERSON_SEALED,
} from '@agentx/core/modules/activity';
import { newestPersonSeal } from '@agentx/core/modules/evidence';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, holdTransactionLock, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type DaySealing, sealDay, sealDaysFrom } from './seal-days.ts';

/** How often a run seals the person log's closed days, once the last run has ended. */
export const PERSON_SEAL_EVERY_MS = 15 * 60_000;

/** How many rows one read of a day's digest takes. */
const SEAL_BATCH = 5_000;

/** The advisory lock the person log's seals are recorded under (ADR-006 §6), before the platform chain head's. */
export const PERSON_SEAL_LOCK = 'access-log-person-seal';

const ACTOR = { type: 'system', id: 'api' } as const;

export type PersonSealTables = ActivityTables & PlatformControlsTables;
type SealTx = DatabaseTransaction<PersonSealTables>;

/** The person log's newest sealed day (`day` null for none), believed; `tampered` (its alarm raised) for one that isn't. */
async function newestPersonDay(
  tx: SealTx,
  keys: KeyProvider,
  log: Logger,
): Promise<{ readonly day: string | null } | 'tampered'> {
  const newest = await newestPersonSeal(tx, keys);
  if (newest !== 'unsealed') return newest;
  personLogAlarm(log, 'unsealed', null);
  return 'tampered';
}

export interface PersonSeal {
  /** Seals the person log's closed days, up to MOST_DAYS_A_RUN, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createPersonSeal({
  database,
  keys,
  ids,
  clock,
  logger,
  batch = SEAL_BATCH,
}: {
  readonly database: Database<PersonSealTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** SEAL_BATCH, but for the tests. */
  readonly batch?: number;
}): PersonSeal {
  const platform = createPlatformChain({ keys, ids });
  /** One limited transaction: each statement within its limit, so a stalled database fails the run, not the timer. */
  const inTx = <T>(work: (tx: SealTx) => Promise<T>): Promise<T> => limitedTransaction(database, work);

  return {
    async run(signal) {
      const log = logger.child({ correlationId: ids.next() });
      try {
        const newest = await inTx((tx) => newestPersonDay(tx, keys, log));
        if (newest === 'tampered') return;
        const first = newest.day === null ? await inTx((tx) => firstDayIn(tx, 'person')) : nextDay(newest.day);
        const sealing: DaySealing<SealTx> = {
          digest: (day: string) => personDigestOfDay(inTx, day, batch),
          misdated: (day: string) => {
            personLogAlarm(log, 'misdated', day);
            return Promise.resolve();
          },
          locked: <T>(work: (tx: SealTx) => Promise<T>) =>
            inTx(async (tx) => {
              await holdTransactionLock(tx, PERSON_SEAL_LOCK);
              return work(tx);
            }),
          newest: (tx: SealTx) => newestPersonDay(tx, keys, log),
          count: (tx: SealTx, day: string) => countOfDay(tx, 'person', day),
          record: async (tx: SealTx, details: Readonly<Record<string, string | number | null>>) => {
            await platform.record(tx, { actor: ACTOR, action: PERSON_SEALED, details });
          },
          form: PERSON_SEAL_FORM,
          log,
          lines: { moved: 'person_log_seal.moved', sealed: 'person_log.sealed' },
        };
        await sealDaysFrom(first, (day) => sealDay(sealing, day), clock, signal);
      } catch (error) {
        log.error('person_log_seal.failed', { err: error });
      }
    },
  };
}
