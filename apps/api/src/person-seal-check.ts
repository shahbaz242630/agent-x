// The person log's seals, checked (Phase 6 6E1a, CO8, PL-48; decision 26's
// L8): the API's job, on a timer of its own, digesting sealed days of
// `access.person_requests` again and comparing each with its seal on the
// platform chain, so a row changed, deleted or slipped into a sealed day past
// the app is found.
//
// As the organisations' check (activity-seal-check.ts), for the one log: each
// run checks the newest two seals and a few more read from a point picked at
// random among the older ones, each seal believed only once its content, MAC
// and signature check (platformEventSealed); each day digested again and
// compared with what its seal holds, and each seal's day the one before the
// next newer seal's on the page, so none is missing between them. A page that
// reaches the oldest seal also finds no row written before its day, which no
// seal would ever hold. Nothing is kept between runs: over runs, every seal is
// checked, the newest every run.
//
// A mismatch raises the alarm (`audit.integrity_failed`, check `person_log`),
// and nothing is held (decision D3: no organisation owns the log). A run
// never throws: a failure is logged.
import { randomInt } from 'node:crypto';

import { PERSON_SEAL_FORM, personDigestOfDay, writtenBeforeIn } from '@agentx/core/modules/activity';
import { type PersonLogEvent, personSealsPage } from '@agentx/core/modules/evidence';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { personLogAlarm, type PersonSealTables } from './person-seal.ts';
import { brokenSealIn } from './seal-days.ts';

/** How often a run checks the person log's seals, once the last run has ended. */
export const PERSON_SEAL_CHECK_EVERY_MS = 30 * 60_000;

/** How many older seals one run checks, beside the newest two. */
const OLDER_A_RUN = 6;

/** How many rows one read of a day's digest takes. */
const CHECK_BATCH = 5_000;

type CheckTx = DatabaseTransaction<PersonSealTables>;

export interface PersonSealCheck {
  /** Checks a few of the person log's seals. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createPersonSealCheck({
  database,
  keys,
  ids,
  logger,
  olderARun = OLDER_A_RUN,
  batch = CHECK_BATCH,
  pick = (below: bigint) => BigInt(randomInt(1, Number(below) + 1)),
}: {
  readonly database: Database<PersonSealTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** OLDER_A_RUN and CHECK_BATCH, but for the tests. */
  readonly olderARun?: number;
  readonly batch?: number;
  /** Where the older seals are read from: a seq from 1 to `below`, at random; a test names its own. */
  readonly pick?: (below: bigint) => bigint;
}): PersonSealCheck {
  const inTx = <T>(work: (tx: CheckTx) => Promise<T>): Promise<T> => limitedTransaction(database, work);

  /** Checks a page of seals, newest first: why the first that doesn't hold doesn't, or undefined (seal-days.ts). */
  const checkPage = (events: readonly PersonLogEvent[], oldestReached: boolean) =>
    brokenSealIn(
      events.map(({ details }) => details),
      oldestReached,
      {
        digest: (day) => personDigestOfDay(inTx, day, batch),
        form: PERSON_SEAL_FORM,
        writtenBefore: (day) => inTx((tx) => writtenBeforeIn(tx, 'person', day)),
      },
    );

  /** The newest seals, then a few older ones from a point picked at random. */
  const check = async (log: Logger): Promise<void> => {
    const newest = await inTx((tx) => personSealsPage(tx, keys, { limit: 2 }));
    if (newest === 'unsealed') {
      personLogAlarm(log, 'unsealed', null);
      return;
    }
    const [first] = newest.events;
    if (first === undefined) return;
    const older = await inTx((tx) => personSealsPage(tx, keys, { beforeSeq: pick(first.seq), limit: olderARun }));
    if (older === 'unsealed') {
      personLogAlarm(log, 'unsealed', null);
      return;
    }
    const found =
      (await checkPage(newest.events, newest.next === null)) ?? (await checkPage(older.events, older.next === null));
    if (found !== undefined) personLogAlarm(log, found.why, found.day);
  };

  return {
    async run() {
      const log = logger.child({ correlationId: ids.next() });
      try {
        await check(log);
      } catch (error) {
        log.error('person_log_seal_check.failed', { err: error });
      }
    },
  };
}
