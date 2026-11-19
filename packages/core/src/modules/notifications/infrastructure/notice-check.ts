// The notice check (S206 V4, Threat-Model R-15): each notice queued is
// recorded on its organisation's chain (`notice.queued`, outbox.ts), and the
// API's job (job-list.ts) holds those records to the outbox's rows, so a
// warning the database's owner deleted before it went, marked sent or given
// up, moved to another person or contact, or held back, is found.
//
// For one organisation, it reads its records of the last NOTICE_DEADLINE_MS
// and the `lookbackMs` before (the time between two of its visits, and more),
// a page at a time through the signed states' logPageOf (each record believed
// only whole; one that isn't raises the alarm and holds the organisation
// itself), and each page's notices in one statement. A record's notice:
//
// - gone (deleted: the outbox keeps a notice 30 days, past this window);
// - sealed wrongly as queued (moved to another recipient, or rewritten);
// - ended without the app's end seal (marked sent or given up by another);
// - given up because its tries were spent (`lease_expired`: its tries count
//   is no seal's, so the owner can spend them; a real crash loop on one
//   notice is worth a person's look as well);
// - still unsent NOTICE_DEADLINE_MS on (its next try put off): every try and
//   wait of a notice ends within 15 hours.
//
// Each raises the integrity alarm (`audit.integrity_failed`, check `notice`,
// the notice's ID and why) and the check goes on. A record removed from the
// chain itself is the chain's check's to find (the anchor check walks every
// event, DB-6); one hidden only while a page is read and put back after is
// not seen by that read (R-15). Nothing is held: the alarm is the remedy, as
// a notice's own sender can't be made to send what the owner took away.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import { type LogEvent, type SignedStates, withSignedStates } from '../../audit/index.ts';
import { type Clock, DAY_MS, type IdGenerator } from '../../../shared-kernel/index.ts';
import { endJudged, queuedJudged } from './notice-seals.ts';
import { LEASE_EXPIRED, NOTICE_QUEUED, type OutboxTables } from './outbox.ts';

/** How long a notice may stay unsent before the check calls it held back: its tries and waits end within 15 hours. */
export const NOTICE_DEADLINE_MS = DAY_MS;

/** How many records one page reads, and one statement's notices. */
const PAGE = 500;

/** The most pages one organisation's visit reads: past it, the rest wait for its next visit, logged. */
const MOST_PAGES = 10;

/** Why a recorded notice raised the alarm. */
export type NoticeFault = 'gone' | 'seal' | 'end_seal' | 'tries_spent' | 'unsent';

/** The widest window a visit reads: NOTICE_DEADLINE_MS and the lookback before it, up to now. */
const windowOf = (now: Date, lookbackMs: number) => ({
  from: new Date(now.getTime() - NOTICE_DEADLINE_MS - lookbackMs),
  to: now,
});

/** The notices the records name, as the outbox keeps them, in one statement. */
const noticesNamed = (tx: Transaction<OutboxTables>, ids: readonly string[]) =>
  tx
    .selectFrom('notifications.outbox')
    .select([
      'id',
      'org_id',
      'recipient_user_id',
      'recipient_contact_id',
      'to_contacts',
      'kind',
      'membership_id',
      'role',
      'about_id',
      'created_at',
      'mac',
      'mac_key_version',
      'next_attempt_at',
      'sent_at',
      'given_up_at',
      'last_failure',
      'end_mac',
      'end_key_version',
    ])
    .where('id', 'in', ids)
    .execute();

type NoticeRow = Awaited<ReturnType<typeof noticesNamed>>[number];

/** What is wrong with a recorded notice, as read now, if anything. */
function faultOf(keys: KeyProvider, record: LogEvent, row: NoticeRow | undefined, now: Date): NoticeFault | undefined {
  if (row === undefined) return 'gone';
  // Its seal binds its organisation too: a notice moved to another is not this one's. None is from before seals.
  if (queuedJudged(keys, row) !== 'sound') return 'seal';
  const end = endJudged(keys, row);
  if (end === 'tampered') return 'end_seal';
  if (end === 'sound')
    return row.given_up_at !== null && row.last_failure === LEASE_EXPIRED ? 'tries_spent' : undefined;
  // Still to be sent: held back once its deadline is past and its next try is still to come.
  const late = record.recordedAt.getTime() <= now.getTime() - NOTICE_DEADLINE_MS;
  return late && row.next_attempt_at.getTime() > now.getTime() ? 'unsent' : undefined;
}

export interface NoticeCheck {
  /** Checks each listed organisation's notices, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createNoticeCheck({
  list,
  done = () => undefined,
  database,
  keys,
  ids,
  clock,
  logger,
  lookbackMs,
  page = PAGE,
  mostPages = MOST_PAGES,
}: {
  /** The organisations to check this run: job-list.ts's rotation. */
  readonly list: () => Promise<readonly string[]>;
  /** One checked this run: owed no visit until listed again. */
  readonly done?: (orgId: string) => void;
  readonly database: Kysely<OutboxTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How far before the deadline a visit reads: more than the most time between two visits of one organisation. */
  readonly lookbackMs: number;
  /** PAGE and MOST_PAGES, but for the tests. */
  readonly page?: number;
  readonly mostPages?: number;
}): NoticeCheck {
  /** One page of the organisation's records, before `beforeSeq` when named, judged: undefined once one can't be believed. */
  const pageOf = async (
    tx: Transaction<OutboxTables>,
    states: SignedStates,
    orgId: string,
    now: Date,
    beforeSeq: bigint | undefined,
  ) => {
    const read = await states.logPageOf(tx, orgId, {
      ...windowOf(now, lookbackMs),
      actions: [NOTICE_QUEUED],
      limit: page,
      ...(beforeSeq === undefined ? {} : { beforeSeq }),
    });
    // A record that can't be believed: the alarm raised and the hold set already.
    if (read.outcome !== 'read') return undefined;
    const named = read.events.map((record) => record.event.subject.id.toLowerCase());
    const rows = named.length === 0 ? [] : await noticesNamed(tx, named);
    const byId = new Map(rows.map((row) => [row.id.toLowerCase(), row]));
    const faults = read.events.flatMap((record) => {
      const id = record.event.subject.id.toLowerCase();
      const fault = faultOf(keys, record, byId.get(id), now);
      return fault === undefined ? [] : [{ noticeId: id, reason: fault }];
    });
    return { faults, next: read.next };
  };

  /** Checks the organisation's recorded notices, a page at a time, raising the alarm for each at fault. */
  const checkFor = async (orgId: string): Promise<void> => {
    const correlationId = ids.next();
    const log = logger.child({ orgId, correlationId });
    const now = clock.now();
    let beforeSeq: bigint | undefined;
    for (let pages = 0; pages < mostPages; pages += 1) {
      const read = await withSignedStates(database, orgId, { keys, ids, logger, correlationId }, (tx, states) =>
        pageOf(tx, states, orgId, now, beforeSeq),
      );
      if (read === undefined) return;
      for (const fault of read.faults) log.error('audit.integrity_failed', { check: 'notice', ...fault });
      if (read.next === null) return;
      beforeSeq = read.next;
    }
    log.warn('notification.check_cut_short', { pages: mostPages });
  };

  return {
    async run(signal) {
      try {
        for (const orgId of await list()) {
          if (signal?.aborted === true) return;
          try {
            await checkFor(orgId);
            done(orgId);
          } catch (error) {
            logger.child({ orgId }).error('notification.check_failed', { err: error });
          }
        }
      } catch (error) {
        logger.error('notification.check_run_failed', { err: error });
      }
    },
  };
}
