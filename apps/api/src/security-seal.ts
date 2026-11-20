// The security events' daily seals, recorded and checked (S206 V6,
// Threat-Model R-15): the API's job, on a timer of its own (core's
// event-seals.ts says what a day, its digest and a row's MAC are).
//
// Each run, for the global table (its seals on the platform chain) and then
// for each organisation listed (on its own chain):
//
// - Seals: from the day after the newest seal (or the first day still well
//   inside the retention, for none or one older), each closed day holding rows,
//   in order, at most MOST_DAYS_A_RUN, by the activity log's steps
//   (seal-days.ts sealDay: digested in batches, then recorded under the seal's
//   lock only if the newest seal and the day's count still stand). A row whose
//   MAC doesn't hold raises the alarm, then its day is sealed as it stands
//   (one from before 0105 still waiting for its MAC excused: core's
//   legacyRowsAt, read once a run, says when, so the seal never depends on
//   which of the two jobs ran first); a
//   row misdated (an ID far from its time written) is left out of its day,
//   the alarm raised, and the day sealed without it.
// - Checks: the newest two seals and a few older from a point picked at
//   random, each day digested again and held to its seal, and no row in a day
//   between two seals (core's brokenSecuritySeal), while the day is well inside
//   the retention. Nothing is kept between runs: over runs every seal inside
//   the retention is checked, the newest every visit.
// - Reach: a row the seal can never reach though it says it was written
//   recently (core's outOfRange) raises the alarm.
// - Tally: each day not yet sealed is logged (`security_seal.tally`: its day,
//   its dated rows and last ID), as each day sealed is (`security_events.sealed`).
//   The log is off the database: an alert fires when a day is sealed with
//   fewer rows than a tally of it counted, so rows deleted before their seal show.
//   Yesterday's and today's rows are also counted every 5 minutes, a fall the
//   alarm at once (security-tally.ts), so those are found within a run of it.
//
// A seal or a chain that can't be believed raises the alarm (the platform
// chain's here, an organisation's by its signed states, which hold it, as any
// read of its chain does). A broken seal of these rows raises the alarm alone
// (`audit.integrity_failed`, check `security_event`): no hold, as these rows
// grant nothing.
//
// The write path is untouched: a security event stays one INSERT, and the
// seal's lock is taken by this job alone, never by a writer. An organisation
// with no rows and no seals costs one short read, not its chain's.
//
// Organisations are listed by the activity seal check's rotation (each every
// 6 hours), so an organisation's deleted or edited sealed rows are found
// within about 6 hours, the global table's within a run (30 minutes). A run
// never throws: each failure is logged, naming the organisation.
import { randomInt } from 'node:crypto';

import { nextDay, sealable } from '@agentx/core/modules/activity';
import { type AuditTables, createAuditTrail, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { personSealsPage } from '@agentx/core/modules/evidence';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import {
  brokenSecuritySeal,
  anythingToSeal,
  firstCheckableDay,
  legacyRowsAt,
  type LegacyRows,
  nextDayWithRows,
  outOfRange,
  rowsBetween,
  SECURITY_EVENTS_SEALED,
  SECURITY_LOG_SUBJECT,
  SECURITY_SEAL_FORM,
  securityCountOfDay,
  securityDigestOfDay,
  type SecurityEventsTables,
  type SecurityLog,
  securityLogAlarm,
  tallyFrom,
} from '@agentx/core/modules/security-events';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import {
  type Database,
  type DatabaseTransaction,
  holdTransactionLock,
  limitedTransaction,
  withTenant,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type DaySealing, sealDay } from './seal-days.ts';

/** How often a run seals and checks, once the last run has ended. */
export const SECURITY_SEAL_EVERY_MS = 30 * 60_000;

/** The advisory lock a log's seals are recorded under (ADR-006 §6), before its chain head's: this job's alone. */
export const SECURITY_SEAL_LOCK = 'security-events-seal';

/** The most days one run seals a log, so one asleep for long doesn't hold up the rest. */
const MOST_DAYS_A_RUN = 31;

/** How many older seals one run checks a log, beside its newest two. */
const OLDER_A_RUN = 6;

/** How many rows one read of a day's digest takes. */
const BATCH = 5_000;

/** The widest range a page of an organisation's seals is read in: every seal ever made. */
const EVER = { from: new Date('2000-01-01T00:00:00.000Z'), to: new Date('2200-01-01T00:00:00.000Z') };

const ACTOR = { type: 'system', id: 'api' } as const;

export type SecuritySealTables = SecurityEventsTables & PlatformControlsTables & AuditTables;
type SealTx = DatabaseTransaction<SecuritySealTables>;

/** A page of a log's seals, newest first: each its seq and details, and whether an older one follows. */
interface SealsPage {
  readonly seals: readonly { readonly seq: bigint; readonly details: Readonly<Record<string, unknown>> }[];
  readonly next: bigint | null;
}

/** One log's chain: how a transaction on it is opened, its seals read and recorded, and what it logs. */
interface SealChain<Held> {
  readonly log: SecurityLog;
  readonly logger: Logger;
  /** A transaction that reaches the log's rows and its chain: an organisation's inside its wall, with its signed states. */
  readonly inChain: <T>(work: (held: Held) => Promise<T>) => Promise<T>;
  readonly txOf: (held: Held) => SealTx;
  /** A page of its seals, before `beforeSeq` when named; undefined for one that can't be believed, its alarm raised. */
  readonly pageIn: (held: Held, limit: number, beforeSeq?: bigint) => Promise<SealsPage | undefined>;
  /** The seal's lock, taken first in the recording transaction. */
  readonly lock: (held: Held) => Promise<void>;
  readonly record: (held: Held, details: Readonly<Record<string, string | number | null>>) => Promise<void>;
}

/** An organisation's transaction, with its signed states. */
interface OrgHeld {
  readonly tx: SealTx;
  readonly states: SignedStates;
}

/** What one run reads by: its time, the first day still checked, and what is said of a row from before 0105 with no MAC. */
interface RunMoment {
  readonly now: Date;
  readonly checkableFrom: string;
  readonly legacy: LegacyRows;
}

export interface SecuritySeal {
  /** Seals and checks the global table's days, then the listed organisations', until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createSecuritySeal({
  list,
  done = () => undefined,
  database,
  keys,
  ids,
  clock,
  logger,
  retentionDays,
  batch = BATCH,
  olderARun = OLDER_A_RUN,
  pick = (below: bigint) => BigInt(randomInt(1, Number(below) + 1)),
}: {
  /** The organisations this run: the activity seal check's rotation. */
  readonly list: () => Promise<readonly string[]>;
  /** One sealed and checked this run: owed no visit until listed again. */
  readonly done?: (orgId: string) => void;
  readonly database: Database<SecuritySealTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** AGENTX_SECURITY_EVENT_RETENTION_DAYS: a day older than it allows is never sealed, nor its seal checked. */
  readonly retentionDays: number;
  /** BATCH and OLDER_A_RUN, but for the tests. */
  readonly batch?: number;
  readonly olderARun?: number;
  /** Where the older seals are read from: a seq from 1 to `below`, at random; a test names its own. */
  readonly pick?: (below: bigint) => bigint;
}): SecuritySeal {
  const platform = createPlatformChain({ keys, ids });

  /** The global table's chain: the platform's. */
  const globalChain = (log: Logger): SealChain<SealTx> => ({
    log: 'global',
    logger: log,
    inChain: (work) => limitedTransaction(database, work),
    txOf: (tx) => tx,
    pageIn: async (tx, limit, beforeSeq) => {
      const page = await personSealsPage(tx, keys, { beforeSeq, limit, action: SECURITY_EVENTS_SEALED });
      if (page === 'unsealed') {
        securityLogAlarm(log, 'global', 'unsealed', null);
        return undefined;
      }
      return { seals: page.events.map(({ seq, details }) => ({ seq, details })), next: page.next };
    },
    lock: (tx) => holdTransactionLock(tx, SECURITY_SEAL_LOCK),
    record: async (tx, details) => {
      await platform.record(tx, { actor: ACTOR, action: SECURITY_EVENTS_SEALED, details });
    },
  });

  /** An organisation's chain: its own, read through its signed states. */
  const orgChain = (orgId: string, correlationId: string): SealChain<OrgHeld> => {
    const trail = createAuditTrail({ keys, ids, correlationId });
    return {
      log: { orgId },
      logger: logger.child({ correlationId, orgId }),
      inChain: (work) =>
        withSignedStates(database, orgId, { keys, ids, logger, correlationId }, (tx, states) => work({ tx, states })),
      txOf: ({ tx }) => tx,
      pageIn: async ({ tx, states }, limit, beforeSeq) => {
        const page = await states.logPageOf(tx, orgId, {
          ...EVER,
          actions: [SECURITY_EVENTS_SEALED],
          ...(beforeSeq === undefined ? {} : { beforeSeq }),
          limit,
        });
        // One that can't be believed: the alarm raised and the hold set already.
        if (page.outcome !== 'read') return undefined;
        return { seals: page.events.map(({ seq, event }) => ({ seq, details: event.details })), next: page.next };
      },
      lock: ({ tx }) => holdTransactionLock(tx, SECURITY_SEAL_LOCK, orgId),
      record: async ({ tx }, details) => {
        await trail.record(tx, orgId, {
          actor: ACTOR,
          action: SECURITY_EVENTS_SEALED,
          subject: { type: SECURITY_LOG_SUBJECT, id: orgId, version: 1 },
          details,
        });
      },
    };
  };

  /**
   * Whether the organisation has anything to seal or check: a row, or a seal on its chain (one deleted past the app
   * fails the chain's own check). One statement in its transaction, so a quiet organisation costs no more.
   */
  const anythingFor = (orgId: string) =>
    withTenant(database, orgId, (tx) => anythingToSeal(tx, orgId), { limited: true });

  /** A reader of the log's rows, each read in a transaction of its own. */
  const readerOf =
    <Held>(chain: SealChain<Held>) =>
    <T>(work: (tx: SealTx) => Promise<T>): Promise<T> =>
      chain.inChain((held) => work(chain.txOf(held)));

  /** A page of the log's seals, in a transaction of its own. */
  const pageOf = <Held>(chain: SealChain<Held>, limit: number, beforeSeq?: bigint) =>
    chain.inChain((held) => chain.pageIn(held, limit, beforeSeq));

  /** The day the newest seal names (null for none), or undefined for one that can't be believed, its alarm raised. */
  const newestIn = async <Held>(chain: SealChain<Held>, held: Held) => {
    const page = await chain.pageIn(held, 1);
    if (page === undefined) return undefined;
    const day = page.seals[0]?.details.day;
    return { day: typeof day === 'string' ? day : null };
  };

  /**
   * The day's digest; a row whose MAC doesn't hold, or one left out misdated, raising the alarm: as the day is sealed
   * (it is sealed as it stands), and as its seal is checked, so one planted into a day sealed already shows too.
   */
  const digestOf = async <Held>(chain: SealChain<Held>, day: string, legacy: LegacyRows) => {
    const digest = await securityDigestOfDay(readerOf(chain), keys, chain.log, day, { batch, legacy });
    if (digest.forged !== null) securityLogAlarm(chain.logger, chain.log, 'mac', day, digest.forged);
    if (digest.leftOut !== null) securityLogAlarm(chain.logger, chain.log, 'misdated', day, digest.leftOut);
    return digest;
  };

  /** The log's seal, its steps on its own chain under its own lock (seal-days.ts). */
  const sealingOf = <Held>(chain: SealChain<Held>, legacy: LegacyRows): DaySealing<Held> => ({
    digest: (day) => digestOf(chain, day, legacy),
    // Never asked: a misdated row is left out of its day's digest (core's securityDigestOfDay), not a reason to stop.
    misdated: () => Promise.resolve(),
    locked: (work) =>
      chain.inChain(async (held) => {
        await chain.lock(held);
        return work(held);
      }),
    newest: async (held) => (await newestIn(chain, held)) ?? 'tampered',
    count: (held, day) => securityCountOfDay(chain.txOf(held), chain.log, day),
    record: chain.record,
    form: SECURITY_SEAL_FORM,
    log: chain.logger,
    lines: { moved: 'security_event_seal.moved', sealed: 'security_events.sealed' },
  });

  /**
   * Seals the log's closed days holding rows, oldest first, up to MOST_DAYS_A_RUN; then logs each day not yet sealed.
   * Whether it is finished.
   */
  const seal = async <Held>(chain: SealChain<Held>, moment: RunMoment, signal: AbortSignal | undefined) => {
    const newest = await chain.inChain((held) => newestIn(chain, held));
    if (newest === undefined) return true;
    // A day older than the retention allows is never sealed: the sweep may be part way through it.
    const { checkableFrom, now } = moment;
    let from = newest.day === null || nextDay(newest.day) < checkableFrom ? checkableFrom : nextDay(newest.day);
    const sealing = sealingOf(chain, moment.legacy);
    let finished = false;
    for (let sealed = 0; sealed < MOST_DAYS_A_RUN && signal?.aborted !== true; sealed += 1) {
      const day = await readerOf(chain)((tx) => nextDayWithRows(tx, chain.log, from));
      if (day === undefined || !sealable(day, now)) {
        finished = true;
        break;
      }
      if (!(await sealDay(sealing, day))) break;
      from = nextDay(day);
    }
    // The days left unsealed, as they stand: an alert holds each day's seal to the highest count logged of it.
    for (const tally of await readerOf(chain)((tx) => tallyFrom(tx, chain.log, from))) {
      chain.logger.info('security_seal.tally', { day: tally.day, rows: tally.rows, idTo: tally.idTo });
    }
    return finished;
  };

  /** Checks the newest two seals, then a few older ones from a point picked at random. */
  const check = async <Held>(chain: SealChain<Held>, moment: RunMoment): Promise<void> => {
    // The newest two: rows slipped into a day between them show.
    const newest = await pageOf(chain, 2);
    const first = newest?.seals[0];
    if (newest === undefined || first === undefined) return;
    const older = await pageOf(chain, olderARun, pick(first.seq));
    if (older === undefined) return;
    const rules = {
      digest: (day: string) => digestOf(chain, day, moment.legacy),
      between: (from: string, to: string) => readerOf(chain)((tx) => rowsBetween(tx, chain.log, from, to)),
      checkableFrom: moment.checkableFrom,
    };
    const detailsOf = (page: SealsPage) => page.seals.map(({ details }) => details);
    const found =
      (await brokenSecuritySeal(detailsOf(newest), rules)) ?? (await brokenSecuritySeal(detailsOf(older), rules));
    if (found !== undefined) securityLogAlarm(chain.logger, chain.log, found.why, found.day);
  };

  /** Seals, then checks, the log, and looks for a row out of the seal's reach: whether its sealing is finished. */
  const visit = async <Held>(chain: SealChain<Held>, moment: RunMoment, signal: AbortSignal | undefined) => {
    const finished = await seal(chain, moment, signal);
    await check(chain, moment);
    const stray = await readerOf(chain)((tx) => outOfRange(tx, chain.log, moment.now, moment.checkableFrom));
    if (stray !== undefined) securityLogAlarm(chain.logger, chain.log, 'out_of_range', null, stray);
    return finished;
  };

  /**
   * What the run is told of a row from before 0105 with no MAC, from the platform chain's records of their pass; for
   * a record that can't be believed, the alarm, and no row excused.
   */
  const legacyRowsOf = async (log: Logger, now: Date): Promise<LegacyRows> => {
    const found = await limitedTransaction(database, (tx) => legacyRowsAt(tx, keys, now));
    if (found !== 'unsealed') return found;
    securityLogAlarm(log, 'global', 'unsealed', null);
    return { excusedBefore: null };
  };

  return {
    async run(signal) {
      const log = logger.child({ correlationId: ids.next() });
      const now = clock.now();
      let moment: RunMoment;
      try {
        moment = { now, checkableFrom: firstCheckableDay(now, retentionDays), legacy: await legacyRowsOf(log, now) };
      } catch (error) {
        // Nothing is sealed or checked without it: a row from before 0105 could raise a false alarm.
        log.error('security_event_seal.failed', { err: error });
        return;
      }
      try {
        await visit(globalChain(log), moment, signal);
      } catch (error) {
        log.error('security_event_seal.failed', { err: error });
      }
      try {
        for (const orgId of await list()) {
          if (signal?.aborted === true) return;
          try {
            // A quiet organisation is finished at once: nothing to seal, check or tally.
            if (!(await anythingFor(orgId)) || (await visit(orgChain(orgId, ids.next()), moment, signal))) done(orgId);
          } catch (error) {
            logger.child({ orgId }).error('security_event_seal.failed', { err: error });
          }
        }
      } catch (error) {
        logger.error('security_event_seal.run_failed', { err: error });
      }
    },
  };
}
