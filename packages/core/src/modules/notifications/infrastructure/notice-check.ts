// The notice check (S206 V4, Threat-Model R-15): each notice queued is
// recorded on its organisation's chain (`notice.queued`, outbox.ts), and the
// API's job (job-list.ts) holds those records to the outbox's rows, so a
// warning the database's owner deleted before it went, marked sent or given
// up, moved to another person or contact, or held back, is found.
//
// Each visit goes on from where the last one stopped, which it recorded on the
// organisation's own chain (`notice_check.passed`: the place it reached, and
// the notices it saw still to be sent): it walks the chain from there to the
// head through the trail's ranged check (walkFrom: every event in its place,
// linked, hashed and MACed, the stretch ending at the head's own hash), and
// takes the `notice.queued` records that walk read. So every record is seen
// once, by a walk that would fail at a gap: one deleted or edited, even for a
// moment around that walk, is the chain's alarm then; one put back after its
// walk has already been seen. A record of where it stopped can't be forged or
// moved on past a notice, as it is a chained event; one taken off the top of
// the chain only sends the next visit further back, to see more again.
//
// The notices it saw, and those it carried, are judged, all in one read:
//
// - gone (deleted: the outbox keeps a notice 30 days);
// - sealed wrongly as queued (moved to another recipient, rewritten, planted);
// - ended without the app's end seal (marked sent or given up by another);
// - given up because its tries were spent (`lease_expired`: its tries count is
//   no seal's, so the owner can spend them; a real crash loop on one notice is
//   worth a person's look as well);
// - not as its record says (kind, recipient): a notice from before seals
//   sealed at a start over a row the owner changed first;
// - still unsent NOTICE_DEADLINE_MS on, whatever its next try says (put off,
//   or its row held locked so no sender can take it): every try and wait of a
//   notice ends within 15 hours.
//
// Each raises the integrity alarm (`audit.integrity_failed`, check `notice`,
// the notice's ID and why) once. One still open, and not yet late, is carried
// in the next record of where the check stopped; one ended soundly, or found
// at fault, is not. Nothing is held: the alarm is the remedy, as a notice's own
// sender can't be made to send what the owner took away.
//
// And each run, across every organisation: a notice with no seal still unsent
// a day on (`unsealed`), never claimed and with no record to walk: one from
// before seals a start couldn't seal, or one the owner wrote.
//
// A first visit starts just before the organisation's oldest record (read as
// it is: a wrong place fails the walk's first step); a record hidden at that
// one moment is the one thing it can't see (R-15).
import { CHAIN_START, type CheckedPoint } from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { limitedTransaction } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import { createAuditTrail, type WalkedEvent, withSignedStates } from '../../audit/index.ts';
import { type Clock, DAY_MS, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import { endJudged, queuedJudged } from './notice-seals.ts';
import { LEASE_EXPIRED, NOTICE_QUEUED, type OutboxTables, recipientOf } from './outbox.ts';

/** How long a notice may stay unsent before the check calls it held back: its tries and waits end within 15 hours. */
export const NOTICE_DEADLINE_MS = DAY_MS;

/** The check's record of where it stopped, on the organisation's chain, about the organisation itself. */
export const NOTICE_CHECK_PASSED = 'notice_check.passed';
const CHECK_SUBJECT = 'notice_check';

/** Who records it. */
const CHECK_ACTOR = { type: 'system', id: 'api' } as const;

/** The most events one walk reads; a visit takes up to MOST_WALKS of them. */
const WALK = 5_000;
const MOST_WALKS = 4;

/** The most notices carried open in one record: a detail holds 1,024 characters, 19 of `ID@time` (51) and spaces. */
const MOST_CARRIED = 19;

/** A walk past this many events records where it stopped, even with no notice in it, so the next walks less. */
const RECORD_PAST = 50;

/** The most notices with no seal one run raises the alarm for. */
const UNSEALED_A_RUN = 100;

/** A notice recorded longer ago than this may have been swept (30 days after it is done): a walk passes it by. */
const JUDGED_WITHIN_MS = 20 * DAY_MS;

/** Why a recorded notice raised the alarm (beside `chain`, a walk that failed, and `record`, a record of its own). */
export type NoticeFault = 'gone' | 'seal' | 'not_as_recorded' | 'end_seal' | 'tries_spent' | 'unsent';

/** Where the last visit stopped, and the notices it carried, as its record says. */
interface Passed {
  readonly from: CheckedPoint;
  readonly carried: readonly Carried[];
}

/** A notice seen still to be sent, and when it was recorded; as its record names it, when it was just walked past. */
interface Carried {
  readonly id: string;
  readonly recordedAt: Date;
  readonly recorded?: string;
}

/**
 * Whether the notice is to whom and of what its record says (S206 V4 review): its record is the chain's, its seal the
 * outbox's, and a notice from before seals sealed at a start (notice-legacy.ts) would hold a seal over a row changed
 * first; the record can't be.
 */
function asRecorded(recorded: string, row: NoticeRow): boolean {
  let said: unknown;
  try {
    said = JSON.parse(recorded);
  } catch {
    return false;
  }
  const { recipient, recipientId } = recipientOf(row);
  const { kind: saidKind, recipient: saidRecipient, recipientId: saidId } = (said ?? {}) as Record<string, unknown>;
  return saidKind === row.kind && saidRecipient === recipient && saidId === recipientId;
}

/** The notices, as the outbox keeps them, in one statement. */
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

/** What is wrong with a notice, as read now; `open` for one still to be sent and not late; undefined for one done. */
function judged(
  keys: KeyProvider,
  notice: Carried,
  row: NoticeRow | undefined,
  now: Date,
): NoticeFault | 'open' | undefined {
  if (row === undefined) return 'gone';
  // Its seal binds its organisation too: a notice moved to another is not this one's.
  if (queuedJudged(keys, row) !== 'sound') return 'seal';
  if (notice.recorded !== undefined && !asRecorded(notice.recorded, row)) return 'not_as_recorded';
  const end = endJudged(keys, row);
  if (end === 'tampered') return 'end_seal';
  if (end === 'sound')
    return row.given_up_at !== null && row.last_failure === LEASE_EXPIRED ? 'tries_spent' : undefined;
  // Still unsent past its deadline, whatever its next try says: one held locked by someone, or put off, never goes.
  return notice.recordedAt.getTime() <= now.getTime() - NOTICE_DEADLINE_MS ? 'unsent' : 'open';
}

/**
 * The place of the event at `seq` (the chain's start for 0), read as it stands: the walk from it holds it to the
 * event's own seal first, so a place read wrong fails that walk, never passes.
 */
async function placeAt(tx: Transaction<OutboxTables>, orgId: string, seq: bigint): Promise<CheckedPoint> {
  if (seq === 0n) return CHAIN_START;
  const { rows } = await sql<{ hash: Buffer; mac_key_version: number }>`
    select e.hash, e.mac_key_version from audit.events e where e.org_id = ${orgId} and e.seq = ${seq}
  `.execute(tx);
  const [row] = rows;
  return { seq, hash: row?.hash ?? Buffer.alloc(32), macKeyVersion: row?.mac_key_version ?? 0 };
}

/** The record of where the last visit stopped, as its details say; undefined for details that don't read as one. */
function passedOf(details: Readonly<Record<string, unknown>>): Passed | undefined {
  const { seq, hash, keyVersion, carried } = details;
  if (typeof seq !== 'string' || !/^\d+$/.test(seq) || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
    return undefined;
  }
  if (typeof keyVersion !== 'number' || typeof carried !== 'string') return undefined;
  const notices = carried === '' ? [] : carried.split(' ').map((each) => each.split('@'));
  if (notices.some(([id, at]) => id === undefined || !UUID.test(id) || at === undefined || !/^\d+$/.test(at))) {
    return undefined;
  }
  return {
    from: { seq: BigInt(seq), hash: Buffer.from(hash, 'hex'), macKeyVersion: keyVersion },
    carried: notices.map(([id = '', at = '0']) => ({ id, recordedAt: new Date(Number(at)) })),
  };
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
  walk = WALK,
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
  /** WALK, but for the tests. */
  readonly walk?: number;
}): NoticeCheck {
  const trail = createAuditTrail({ keys, ids });

  /**
   * Where the last visit stopped: its record, the newest, believed only whole; with none, just before the oldest
   * `notice.queued` record, read as it stands (a wrong place fails the walk); undefined for an organisation with none.
   */
  const startOf = (orgId: string, correlationId: string): Promise<Passed | 'unbelieved' | undefined> =>
    withSignedStates(database, orgId, { keys, ids, logger, correlationId }, async (tx) => {
      const read = await trail.recordedEvents(tx, orgId, {
        subjectTypes: [CHECK_SUBJECT],
        subjectId: orgId,
        actions: [NOTICE_CHECK_PASSED],
        newest: true,
        limit: 1,
      });
      if (read.kind !== 'recorded') return 'unbelieved';
      const [last] = read.events;
      if (last !== undefined) return passedOf(last.event.details) ?? 'unbelieved';
      const { rows } = await sql<{ seq: bigint }>`
        select e.seq from audit.events e
        where e.org_id = ${orgId} and e.action = ${NOTICE_QUEUED} order by e.seq limit 1
      `.execute(tx);
      const [oldest] = rows;
      return oldest === undefined ? undefined : { from: await placeAt(tx, orgId, oldest.seq - 1n), carried: [] };
    });

  /** Walks on from `from`, a few walks at most: the notices recorded since, and where it reached; `broken` for none. */
  const walked = async (orgId: string, from: CheckedPoint) => {
    let at = from;
    const seen: WalkedEvent[] = [];
    for (let walks = 0; walks < MOST_WALKS; walks += 1) {
      const { step, kept } = await trail.walkFrom(database, orgId, at, walk, [NOTICE_QUEUED]);
      if (!step.ok) return { broken: step.problem } as const;
      seen.push(...kept);
      at = { seq: step.seq, hash: step.hash, macKeyVersion: step.macKeyVersion };
      if (step.seq >= step.to) break;
    }
    return { reached: at, seen } as const;
  };

  /** Records where this visit stopped and the notices it carries. */
  const passed = (orgId: string, correlationId: string, at: CheckedPoint, carried: readonly Carried[]) =>
    withSignedStates(database, orgId, { keys, ids, logger, correlationId }, (tx) =>
      trail.record(tx, orgId, {
        actor: CHECK_ACTOR,
        action: NOTICE_CHECK_PASSED,
        subject: { type: CHECK_SUBJECT, id: orgId, version: 1 },
        details: {
          seq: at.seq.toString(),
          hash: at.hash.toString('hex'),
          keyVersion: at.macKeyVersion,
          carried: carried.map(({ id, recordedAt }) => `${id}@${String(recordedAt.getTime())}`).join(' '),
        },
      }),
    );

  /** Checks the organisation's notices recorded since the last visit, and those it carried. */
  const checkFor = async (orgId: string): Promise<void> => {
    const correlationId = ids.next();
    const log = logger.child({ orgId, correlationId });
    const alarm = (fields: Readonly<Record<string, unknown>>): void => {
      log.error('audit.integrity_failed', { check: 'notice', ...fields });
    };
    const now = clock.now();
    const start = await startOf(orgId, correlationId);
    if (start === undefined) return;
    // A record of its own that can't be believed, or reads as no record of where it stopped: nothing to go on from.
    if (start === 'unbelieved') {
      alarm({ reason: 'record' });
      return;
    }
    const walk = await walked(orgId, start.from);
    if ('broken' in walk) {
      alarm({ reason: 'chain', seq: walk.broken.seq.toString(), problem: walk.broken.reason });
      return;
    }
    const since = now.getTime() - JUDGED_WITHIN_MS;
    const fresh = walk.seen
      .filter(({ recordedAt }) => recordedAt.getTime() >= since)
      .map(({ subjectId, recordedAt, details }) => ({ id: subjectId.toLowerCase(), recordedAt, recorded: details }));
    const notices = [...start.carried, ...fresh];
    const rows =
      notices.length === 0
        ? []
        : await withSignedStates(database, orgId, { keys, ids, logger, correlationId }, (tx) =>
            noticesNamed(
              tx,
              notices.map(({ id }) => id),
            ),
          );
    const byId = new Map(rows.map((row) => [row.id.toLowerCase(), row]));
    const open: Carried[] = [];
    for (const notice of notices) {
      const found = judged(keys, notice, byId.get(notice.id), now);
      if (found === 'open') open.push(notice);
      else if (found !== undefined) alarm({ noticeId: notice.id, reason: found });
    }
    // The oldest open first; past what a record carries, it stops just before the first it can't, to see it again.
    const carried = open.slice(0, MOST_CARRIED).map(({ id, recordedAt }) => ({ id, recordedAt }));
    const cut = fresh.find((notice) => open.indexOf(notice) >= MOST_CARRIED);
    const cutAt = cut === undefined ? undefined : walk.seen.find(({ subjectId }) => subjectId.toLowerCase() === cut.id);
    const reached = cutAt === undefined ? walk.reached : await placeBefore(orgId, cutAt.seq);
    const moved = reached.seq - start.from.seq;
    const carriedNow = carried.map(({ id }) => id).join(' ');
    const carriedChanged = carriedNow !== start.carried.map(({ id }) => id).join(' ');
    // Written only when it says something new: a visit held where the last stopped, carrying the same, writes nothing.
    if (carriedChanged || (moved > 0n && (fresh.length > 0 || moved > BigInt(RECORD_PAST)))) {
      await passed(orgId, correlationId, reached, carried);
    }
  };

  /** The place just before the event at `seq`: its link names the event before, and a wrong one fails the next walk. */
  const placeBefore = (orgId: string, seq: bigint): Promise<CheckedPoint> =>
    withSignedStates(database, orgId, { keys, ids, logger }, (tx) => placeAt(tx, orgId, seq - 1n));

  /**
   * The integrity alarm for each notice with no seal still unsent NOTICE_DEADLINE_MS on (S206 V4 review): never claimed
   * and with no record to walk, so nothing else would ever say so. A notice from before seals a start couldn't seal,
   * or one the owner wrote. One statement across every organisation, the oldest first, at most UNSEALED_A_RUN.
   */
  const unsealedLate = async (): Promise<void> => {
    const due = new Date(clock.now().getTime() - NOTICE_DEADLINE_MS);
    const rows = await limitedTransaction(database, (tx) =>
      tx
        .selectFrom('notifications.outbox')
        .select(['id', 'org_id'])
        .where('mac', 'is', null)
        .where('sent_at', 'is', null)
        .where('given_up_at', 'is', null)
        .where('created_at', '<=', due)
        .orderBy('created_at')
        .limit(UNSEALED_A_RUN)
        .execute(),
    );
    for (const { id, org_id: orgId } of rows) {
      logger.child({ orgId }).error('audit.integrity_failed', { check: 'notice', reason: 'unsealed', noticeId: id });
    }
  };

  return {
    async run(signal) {
      try {
        await unsealedLate();
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
