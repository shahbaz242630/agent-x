// The one way product code gets signed states (ADR-012 §2): withTenant for the
// organisation, with that transaction's own signed states. Every tamper sign
// they find puts the organisation on its integrity hold
// (domain/integrity-hold.ts) once that transaction has ended, committed or
// rolled back, in a transaction of its own. Never:
// - inside the transaction that found it, which may roll back (a failed
//   change throws out of withTenant), taking the hold with it
// - beside it, on another connection, while it is still open: the hold takes
//   the chain head's lock, which the open transaction may hold already (a
//   change that failed after recording its event), and each would wait on
//   the other for ever
//
// A hold that can't be set raises the integrity alarm again (`check: hold`),
// and the work's own result or error still goes back to the caller. That
// happens on a chain that refuses new events (its head fails its check, or it
// holds events past its head), where every read of the hold is denied anyway
// (audit-trail.ts); or when the chain head stays locked past 5 seconds (the
// owner holding it, or decisions queued on it), since a hold that waited for
// ever would hang the request. Such a hold waits two ways (4D2e D5):
// - in this process: every read of it here answers `tampered` with the sign
//   that found it, and a later withSignedStates for the organisation tries
//   again, one at a time, so a head held locked can't take a connection for
//   every request; so does each run of the anchor check (holdOrganisation)
// - in directory.holds_waiting (0069), IDs and the sign, naming its record as
//   the hold will, so clearing checks the same thing whichever process records
//   it, and another process and this one after a restart know of it: Tx A reads
//   the row itself, under the head's lock; every process polls it each 5 seconds
//   (pollHoldsWaiting), tries a new one, and then keeps it as its own
// The memory stays because the database may be just what is in trouble: a row
// that can't be written says so (`audit.hold_not_kept`), and the process retries
// both. A hold recorded takes its row with it, in the same transaction.
//
// One row a record, and here one entry a record. A hold names one record and
// clearing checks that one, so a finding meeting a hold on another record writes
// its row in that same transaction, and that row becomes the next hold once this
// one is cleared. A row only adds caution, and really does: a row forged sets the
// hold. So a row raises the alarm (`from_row`) when its hold is set from it, and
// once when a process first finds its record isn't the one held: one foothold can
// hold every organisation. That one then rests (about a minute, or until a read here
// finds the hold clear), tried by no poll or request, while Tx A reads the row itself. A row gone from the table
// leaves each process that held that record to try once more: finding the hold
// recorded is the usual way, and nothing is said; recording it means the row was
// deleted with no hold, the alarm (`row_gone`); a finding of its own meeting a hold on
// another record writes its row back.
//
// A poll is bounded. It reads at most HOLDS_READ_AT_ONCE rows, in order: after one that
// hits that limit the next reads after the last organisation reached, so a crowded one
// hides no other, each reached within one poll for each crowded one; one under it, and
// the next starts over. Only a read from the beginning that came back under the limit
// has seen every row, so only that judges a row gone. From MANY_ROWS up, and on every page
// of such a rotation, it says the table is past what honest work leaves
// (`audit.holds_waiting_past_limit`). It keeps at
// most MOST_KEPT_FROM_ROWS from rows alone, and past that one an organisation with none,
// so it still reads as waiting; the rest stay in the table and come in as those here go
// (`audit.holds_waiting_past_memory`, at most once a poll while it lasts). What this process found itself is kept to
// MOST_KEPT_OWN likewise, once its row carries it, with one an organisation: a poll brings
// it in by the rows' rules, as one known from its row, said at most once for each poll in
// which one is left out. With no row to carry it, it is always
// kept: bounded only by what is found during database trouble. So while one hold stands, rows past that bound raise no alarm of their own
// until a place comes free, and each still becomes a hold in turn. It tries at most
// MOST_TRIES_A_POLL holds, one an organisation in turn, starting after the last one
// tried, and a try that fails ends that organisation's turn: so on locked heads a poll
// takes about 20 s (4 tries at 5 s each), and what isn't reached comes next poll.
//
// What stays open: a reader without the head's lock learns of another process's
// hold at its next poll; a row-recorded hold has no count or chain failure, which
// are in the alarm's line; one transaction's findings name its first alone; a process
// frozen past a whole clearing that held an entry sets it again on waking, with
// `row_gone` or as a row for the next hold, as it can't tell that from a row deleted
// (a new row is looked for again first, so isn't); a row deleted once every process
// that knew it has restarted is gone, leaving the alarm's line, with the hold set
// when the tampering is next found. One known from its row alone goes likewise when its
// row is deleted under a hold on another record, or before its try: the alarm (`row_gone`),
// and an operator's delete of a forged row stands. If its finder has restarted too, that gives
// it up, with the organisation on a hold anyway; the tampering sets its hold when next found.
// A try that fails on a locked head still writes that row back, as caution while no hold
// can be recorded. A clear made while a process still holds entries for deleted rows brings
// back one hold, for a deleted record: safe, and it can be cleared, so the words say to wait
// until `row_gone` stops; that path is what saves a real finding whose row was deleted.
// A hold's transaction is bounded by the head's lock (5 s) and each statement's
// time (10 s).
//
// A work whose recording meets a chain that refuses new events has met
// tampering too, and raises the alarm (`check: record`) before its error goes
// back.
//
// A hold set marks the hold history's work for its organisation (4D2e D10), in
// the hold's own transaction, last: so the mark commits with the hold or not at
// all. No trigger can do it, as none goes on the audit tables, and this module
// doesn't know the marks: the process gives it how (`markHoldsWith`, at boot).
// One given none marks nothing, and the hourly look finds the hold unmarked.
// The hold must always land, so the mark is tried inside a savepoint of its own,
// its waits bounded (HOLD_MARK_LIMITS): one that fails or waits too long is
// rolled back alone, said (`org_work.hold_mark_skipped`), and the hold commits;
// the hourly look marks it.
import { ChainBroken } from '@agentx/platform/audit-chain';
import { withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { IdGenerator } from '../../../shared-kernel/index.ts';
import { createAuditTrail } from './audit-trail.ts';
import {
  holdNoLongerWaiting,
  holdStillWaiting,
  HOLDS_READ_AT_ONCE,
  holdsWaiting,
  type HoldWaiting,
  keepHoldWaiting,
  keepHoldWaitingHere,
  MOST_KEPT_OWN,
  namedAsTheAppWrites,
  type NamedRecord,
} from './holds-waiting.ts';
import {
  CHAIN_SUBJECT,
  createSignedStates,
  type SignedStates,
  signOfWaiting,
  type TamperFinding,
} from './signed-states.ts';
import type { AuditTables } from './tables.ts';

/** What the work's signed states are built from. */
export interface SignedStatesServices {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The request's or job's logger, a child carrying its correlation ID (Rule Book §8). */
  readonly logger: Logger;
  /** The request's correlation ID, sealed into every event the work records (ADR-011 §7); none for most jobs. */
  readonly correlationId?: string | undefined;
}

/** The first finding for an organisation, with how many there were. */
interface Found {
  readonly finding: TamperFinding;
  readonly count: number;
  /** Its row in the holds waiting was written or seen: with it gone, it was recorded, or deleted. */
  readonly inTable?: boolean;
  /** This process knows it from its row alone: whoever found it may have raised the alarm, or no one did (a row forged). */
  readonly fromRow?: boolean;
  /** Its row's own naming, where the app could not have written it: the finding then names the fixed name instead. */
  readonly row?: NamedRecord;
  /**
   * For the poll: how many polls to wait before trying it, 0 for its next (a new row, or one whose hold was read clear).
   * Unset after a try that failed: left to the next request and the anchor check, so a locked head isn't tried each poll.
   */
  readonly pollsToWait?: number | undefined;
  /** The alarm for a row whose record isn't the one held was raised here. */
  readonly raised?: boolean;
}

/** How often every process looks for holds another left waiting. */
export const HOLDS_WAITING_EVERY_MS = 5_000;
/** The most holds one poll tries: each can wait 5 s on a locked head, with every other organisation behind it. */
const MOST_TRIES_A_POLL = 4;
/** About a minute: how long a record not the one held waits, rather than a transaction a row each poll. */
const POLLS_NAMED_ELSEWHERE_WAITS = 60_000 / HOLDS_WAITING_EVERY_MS;
/**
 * The most this process keeps from rows alone, beyond one an organisation: rows are read again each poll, and Tx A reads
 * them itself, so memory is only for a reader without the head's lock and a database in trouble. At about 1 KB an entry,
 * 0.5 MB, and 1 MB more for each 1,000 organisations with a row.
 */
const MOST_KEPT_FROM_ROWS = 500;
/** Far past what honest work leaves: a row is a hold that couldn't be written, or a second record found under a hold. */
const MANY_ROWS = 100;

/** Holds this process found or polled but couldn't record yet, by organisation (lower case), then by record, with their findings. */
const unrecorded = new Map<string, Map<string, Found>>();
/**
 * How many holds this process is recording now, by organisation: a waiting
 * one is tried only while none is, so by one request at a time.
 */
const recording = new Map<string, number>();
/** How a hold set marks the hold history's work, in the hold's transaction (the header): none until a process gives it. */
let markHold: ((tx: Transaction<AuditTables>, orgId: string) => Promise<void>) | undefined;

/** How this process marks a hold set from now on, or (undefined) that it marks none: once, at boot. */
export function markHoldsWith(
  mark: ((tx: Transaction<AuditTables>, orgId: string) => Promise<void>) | undefined,
): void {
  markHold = mark;
}

/** The hold's mark's own savepoint: a name no other step uses. */
const HOLD_MARK_SAVEPOINT = 'agentx_hold_mark';

/**
 * How long the mark may wait for a lock, and take in all, before it gives way: a mark row a commit or a settle holds
 * waits a trip; the hold's own 5 s head wait stays the hold's.
 */
const HOLD_MARK_LIMITS = { lock: '500ms', statement: '1s' } as const;

/**
 * The hold history's mark for a hold just set, in the hold's transaction, inside a savepoint with its waits bounded:
 * any failure is rolled back alone and said, so the hold commits all the same. The transaction's own limits come back
 * after it, either way.
 */
async function markHeld(tx: Transaction<AuditTables>, held: string, log: Logger): Promise<void> {
  if (markHold === undefined) return;
  const savepoint = sql.id(HOLD_MARK_SAVEPOINT);
  const { rows } = await sql<{ lock: string; statement: string }>`select
      pg_catalog.current_setting('lock_timeout') as lock, pg_catalog.current_setting('statement_timeout') as statement`.execute(
    tx,
  );
  const [was = { lock: '0', statement: '0' }] = rows;
  await sql`savepoint ${savepoint}`.execute(tx);
  try {
    await sql`select pg_catalog.set_config('lock_timeout', ${HOLD_MARK_LIMITS.lock}, true),
      pg_catalog.set_config('statement_timeout', ${HOLD_MARK_LIMITS.statement}, true)`.execute(tx);
    // Left unreleased on success: the commit ends it, a trip fewer.
    await markHold(tx, held);
  } catch (error) {
    await sql`rollback to savepoint ${savepoint}`.execute(tx);
    log.warn('org_work.hold_mark_skipped', { err: error });
  }
  // Nothing follows the mark in the hold's transaction now; put back so nothing added later is held to its limits.
  await sql`select pg_catalog.set_config('lock_timeout', ${was.lock}, true),
    pg_catalog.set_config('statement_timeout', ${was.statement}, true)`.execute(tx);
}

/** The organisation a poll last tried: the next starts after it, so no organisation is always the last reached. */
let lastTried = '';
/** Whether a finding of this process's own was left to its row since the last poll: a burst of them says so once. */
let leftOwnOut = false;
/** Where the next poll reads from: after the last organisation a read that hit its limit reached, or the beginning. */
let readAfter: string | undefined;

/** What tells one record's entry from another's, as its row is named. */
const entryName = ({ row, finding }: Found): string => `${(row ?? finding).subjectType}|${(row ?? finding).objectId}`;

function keepEntry(held: string, found: Found): void {
  const entries = unrecorded.get(held) ?? new Map<string, Found>();
  unrecorded.set(held, entries);
  entries.set(entryName(found), found);
}

function forgetEntry(held: string, found: Found): void {
  const entries = unrecorded.get(held);
  entries?.delete(entryName(found));
  if (entries?.size === 0) unrecorded.delete(held);
}

const keptNow = (fromRows: boolean): number =>
  [...unrecorded.values()]
    .flatMap((entries) => [...entries.values()])
    .filter(({ fromRow }) => (fromRow === true) === fromRows).length;

/**
 * Past MOST_KEPT_OWN, a finding of this process's own that its row now carries goes from memory, unless it is all its
 * organisation has here, which must go on reading as waiting. The next poll reads the row, and brings it in by the rows' rules.
 */
function leftToItsRow(held: string, found: Found, log: Logger): void {
  const kept = keptNow(false);
  if (found.fromRow === true || kept <= MOST_KEPT_OWN || (unrecorded.get(held)?.size ?? 0) <= 1) return;
  forgetEntry(held, found);
  if (!leftOwnOut) log.error('audit.holds_waiting_past_memory', { ownLeft: 1, kept: kept - 1 });
  leftOwnOut = true;
}

const isResting = ({ pollsToWait }: Found): boolean => pollsToWait !== undefined && pollsToWait > 0;

/** The one a request's or the anchor check's next try takes: never one resting, or each request would be a transaction. */
const dueWaiting = (held: string): Found | undefined =>
  [...(unrecorded.get(held)?.values() ?? [])].find((found) => !isResting(found));

/**
 * What a read of a clear hold answers with: the first waiting. Anything resting because another record was held needn't
 * rest any more, as that hold has moved: tried next.
 */
function waitingOnAClearHold(held: string): TamperFinding | undefined {
  const entries = unrecorded.get(held);
  for (const [name, found] of entries ?? []) {
    if (isResting(found)) entries?.set(name, { ...found, pollsToWait: 0 });
  }
  return entries?.values().next().value?.finding;
}

/** The first finding for each organisation, with how many there were. */
function byOrganisation(found: readonly TamperFinding[]): Map<string, Found> {
  const each = new Map<string, Found>();
  for (const finding of found) {
    const seen = each.get(finding.orgId);
    each.set(finding.orgId, seen === undefined ? { finding, count: 1 } : { ...seen, count: seen.count + 1 });
  }
  return each;
}

type HoldOutcome = 'set' | 'already' | 'named_elsewhere' | 'failed';

/**
 * Keeps a hold that couldn't be recorded, in this process and then in its row;
 * a row that can't be written leaves it in this process alone, and says so.
 */
async function keepWaiting(db: Kysely<AuditTables>, held: string, found: Found, log: Logger): Promise<void> {
  const failed = { ...found, pollsToWait: undefined };
  // A row the app couldn't have written is never written again: it stands or it doesn't, and this entry says which.
  if (found.row !== undefined) {
    keepEntry(held, failed);
    return;
  }
  keepEntry(held, { ...failed, inTable: false });
  try {
    await keepHoldWaiting(db, found.finding, found.finding.sign);
    keepEntry(held, { ...failed, inTable: true });
    leftToItsRow(held, found, log);
  } catch (error) {
    log.error('audit.hold_not_kept', { reason: found.finding.sign, err: error });
  }
}

const rowGoneAlarm = (log: Logger): void => {
  log.error('audit.integrity_failed', { chain: 'organisation', check: 'hold', reason: 'row_gone' });
};

/**
 * Records the organisation's hold for a finding, in withTenant's transaction
 * for it, bounded by the head's lock (5 s) and each statement's time (10 s),
 * so neither a locked head nor a slow database holds the caller up for long.
 * One that can't be recorded raises the alarm (`check: hold`) and waits, here
 * and in its row. `rowMustStand`: one this process knows from its row alone is looked
 * for again first, so one frozen between that read and this try doesn't hold over a
 * clearing: gone with the hold naming it reads `already`; gone otherwise is the alarm
 * (`row_gone`), and goes. A finding of this process's own never goes that way: it isn't
 * dropped because its row was. Never throws: what it came to, or `failed`.
 */
async function setHold(
  db: Kysely<AuditTables>,
  held: string,
  found: Found,
  { keys, ids, logger, correlationId }: SignedStatesServices,
  {
    rowMustStand = false,
    answeredWithinMs,
  }: { readonly rowMustStand?: boolean; readonly answeredWithinMs?: number | undefined } = {},
): Promise<HoldOutcome> {
  const { finding, count } = found;
  const log = logger.child({ orgId: held });
  recording.set(held, (recording.get(held) ?? 0) + 1);
  try {
    // Its own signed states: a hold that can't be believed is set over, right here, not handed on again.
    const holder = createSignedStates({
      keys,
      trail: createAuditTrail({ keys, ids, correlationId }),
      logger,
      onTamper: () => undefined,
      // It sets the hold, and reads none: nothing waiting could change what it does.
      unrecorded: () => undefined,
    });
    const outcome = await withTenant<AuditTables, 'set' | 'already' | 'named_elsewhere' | 'row_gone'>(
      db,
      held,
      async (tx) => {
        await sql`set local lock_timeout = '5s'`.execute(tx);
        const itsRow = found.row ?? finding;
        // Its row gone: the hold now naming it took it, the usual way. Otherwise someone deleted it.
        if (rowMustStand && !(await holdStillWaiting(tx, itsRow))) {
          return (await holder.holdNames(tx, finding)) ? 'already' : 'row_gone';
        }
        const recorded = await holder.hold(tx, finding, count);
        if (recorded !== 'named_elsewhere') await holdNoLongerWaiting(tx, itsRow);
        // Clearing won't check this record: a row stays to be the next hold, and a finding of this process's own that
        // has none writes one now. One known from its row alone never does: an operator's delete of a forged row stands.
        else if (found.fromRow !== true) await keepHoldWaitingHere(tx, finding, finding.sign);
        // Last, after the head: the hold history's work, which only a hold set makes (the header).
        if (recorded === 'set') await markHeld(tx, held, log);
        return recorded;
      },
      // Never in line behind the work it stops: bounded by the head's lock and each statement's time, as above.
      { limited: true, unshared: true, ...(answeredWithinMs === undefined ? {} : { answeredWithinMs }) },
    );
    if (outcome === 'named_elsewhere') {
      keepEntry(held, { ...found, inTable: true, raised: true, pollsToWait: POLLS_NAMED_ELSEWHERE_WAITS });
      leftToItsRow(held, found, log);
    } else {
      forgetEntry(held, found);
    }
    if (outcome === 'row_gone') rowGoneAlarm(log);
    if (outcome === 'set') {
      log.warn('audit.integrity_hold_set', {
        reason: finding.sign,
        subjectType: finding.subjectType,
        findings: count,
      });
    }
    if (found.fromRow === true && (outcome === 'set' || (outcome === 'named_elsewhere' && found.raised !== true))) {
      log.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'hold',
        reason: 'from_row',
        subjectType: finding.subjectType,
        objectId: finding.objectId,
      });
    }
    return outcome === 'row_gone' ? 'already' : outcome;
  } catch (error) {
    log.error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'hold',
      reason: 'not_recorded',
      err: error,
    });
    await keepWaiting(db, held, found, log);
    return 'failed';
  } finally {
    const still = (recording.get(held) ?? 1) - 1;
    if (still > 0) recording.set(held, still);
    else recording.delete(held);
  }
}

/**
 * What a row says of a hold this process hadn't heard of: how many were found, and how a chain failed, stay in the
 * alarm's line. A row the app couldn't have written (0069's checks dropped) is still caution, but `hold` couldn't
 * write what it names, so it is recorded on the organisation's chain as a row not as the app writes one.
 */
function foundInRow(row: HoldWaiting): Found {
  const { org_id: orgId, subject_type: subjectType, object_id: objectId, reason } = row;
  const own = { count: 1, fromRow: true };
  if (namedAsTheAppWrites(row))
    return { ...own, finding: { orgId, subjectType, objectId, sign: signOfWaiting(reason) } };
  const finding: TamperFinding = { orgId, subjectType: CHAIN_SUBJECT, objectId: orgId, sign: 'row' };
  return { ...own, finding, row: { orgId, subjectType, objectId } };
}

/**
 * Tries once more a hold this process knew of whose row isn't there. Recorded
 * elsewhere reads `already`, the usual way. Its row seen, and the hold now set
 * here, means the row was deleted with no hold: the alarm, and nothing lost. Known
 * from its row alone, with the hold naming another record, it was deleted too: the
 * alarm, and it goes, so an operator's delete of a forged row stands.
 */
async function goneFromTable(
  db: Kysely<AuditTables>,
  held: string,
  found: Found,
  services: SignedStatesServices,
): Promise<HoldOutcome> {
  const outcome = await setHold(db, held, found, services);
  const deleted = outcome === 'named_elsewhere' && found.fromRow === true;
  if (deleted) forgetEntry(held, found);
  if (deleted || (outcome === 'set' && found.inTable === true)) rowGoneAlarm(services.logger.child({ orgId: held }));
  return outcome;
}

/** A try a poll owes: `gone`, its row wasn't there. */
interface PollTry {
  readonly found: Found;
  readonly gone: boolean;
}

/** An entry this poll reached: a poll nearer its turn if it rests, or the try it owes (none for a failed one whose row stands). */
function turnOf(entries: Map<string, Found>, name: string, found: Found, stands: boolean): PollTry | undefined {
  const waits = found.pollsToWait ?? 0;
  if (waits > 0) entries.set(name, { ...found, pollsToWait: waits - 1 });
  else if (!stands || found.pollsToWait === 0) return { found, gone: !stands };
  return undefined;
}

const triedBefore = ({ found }: PollTry): number => (found.raised === true ? 1 : 0);

/**
 * The tries this poll owes, by organisation. `known`: what was here before the read: one kept while it was on its way
 * is new to it, not gone. `judgeGone`: whether the read saw every row.
 */
function triesDue(
  known: ReadonlySet<string>,
  standing: ReadonlySet<string>,
  judgeGone: boolean,
): Map<string, PollTry[]> {
  const due = new Map<string, PollTry[]>();
  for (const [held, entries] of unrecorded) {
    // Left to the try under way, rather than queue on the head beside it.
    if (recording.has(held)) continue;
    const reached = [...entries].filter(
      ([name]) => standing.has(`${held}|${name}`) || (judgeGone && known.has(`${held}|${name}`)),
    );
    const tries = reached.flatMap(
      ([name, found]) => turnOf(entries, name, found, standing.has(`${held}|${name}`)) ?? [],
    );
    // Those not yet tried first: those coming back from their rest can't keep the rest of the organisation's out.
    if (tries.length > 0)
      due.set(
        held,
        tries.toSorted((one, other) => triedBefore(one) - triedBefore(other)),
      );
  }
  return due;
}

/**
 * The tries, one an organisation in turn, starting after the one last tried, at most MOST_TRIES_A_POLL: so no number of
 * rows for one organisation, and no list order, keeps another from its try for long. One that fails ends its turn.
 */
async function triedInTurn(
  db: Kysely<AuditTables>,
  due: ReadonlyMap<string, PollTry[]>,
  services: SignedStatesServices,
): Promise<void> {
  const organisations = [...due].toSorted(([one], [other]) => (one < other ? -1 : 1));
  const after = organisations.filter(([held]) => held > lastTried);
  const inTurn = [...after, ...organisations.slice(0, organisations.length - after.length)]
    .flatMap(([held, tries]) => tries.map((one, round) => ({ ...one, held, round })))
    .toSorted((one, other) => one.round - other.round);
  const ended = new Set<string>();
  let tried = 0;
  for (const { held, found, gone } of inTurn) {
    if (tried === MOST_TRIES_A_POLL) return;
    if (ended.has(held)) continue;
    tried += 1;
    lastTried = held;
    const outcome = gone
      ? await goneFromTable(db, held, found, services)
      : await setHold(db, held, found, services, { rowMustStand: found.fromRow === true });
    if (outcome === 'failed') ended.add(held);
  }
}

/**
 * Keeps here what the rows say, up to MOST_KEPT_FROM_ROWS, and past it the one that lets an organisation with none read
 * as waiting: the others stay in the table, read again next poll, and come in as those here go. Gives back every row read.
 */
function keptFromRows(rows: readonly HoldWaiting[], services: SignedStatesServices): ReadonlySet<string> {
  let kept = keptNow(true);
  let rowsLeft = 0;
  const standing = new Set<string>();
  for (const row of rows) {
    const inRow: Found = { ...foundInRow(row), inTable: true, pollsToWait: 0 };
    const name = entryName(inRow);
    standing.add(`${row.org_id}|${name}`);
    const here = unrecorded.get(row.org_id)?.get(name);
    if (here !== undefined) {
      keepEntry(row.org_id, { ...here, inTable: true });
    } else if (kept < MOST_KEPT_FROM_ROWS || !unrecorded.has(row.org_id)) {
      keepEntry(row.org_id, inRow);
      kept += 1;
    } else {
      rowsLeft += 1;
    }
  }
  if (rowsLeft > 0) services.logger.error('audit.holds_waiting_past_memory', { rowsLeft, kept });
  return standing;
}

/**
 * One look at the holds waiting (4D2e D5), for every process: the rows are kept
 * here, up to a bound, and what is due of them tried, as is each hold known here
 * with no row, within this poll's limits (above). Only caution comes of it: nothing here lifts
 * a hold, as an entry goes only when its hold is recorded. One trip while the
 * table is empty and nothing waits here. Never throws.
 */
export async function pollHoldsWaiting(db: Kysely<AuditTables>, services: SignedStatesServices): Promise<void> {
  const known = new Set(
    [...unrecorded].flatMap(([held, entries]) => [...entries.keys()].map((name) => `${held}|${name}`)),
  );
  const startedAfter = readAfter;
  let rows: readonly HoldWaiting[];
  try {
    rows = await holdsWaiting(db, startedAfter);
  } catch (error) {
    // Tx A reads the rows itself, so nothing is let through: this process learns of another's a little later.
    services.logger.warn('audit.holds_waiting_unread', { err: error });
    return;
  }
  const atReadLimit = rows.length >= HOLDS_READ_AT_ONCE;
  readAfter = atReadLimit ? rows.at(-1)?.org_id : undefined;
  leftOwnOut = false;
  const standing = keptFromRows(rows, services);
  // A short page after a long one is still a long table.
  if (rows.length >= MANY_ROWS || startedAfter !== undefined) {
    services.logger.error('audit.holds_waiting_past_limit', {
      rows: rows.length,
      kept: keptNow(true),
      atReadLimit,
    });
  }
  await triedInTurn(db, triesDue(known, standing, !atReadLimit && startedAfter === undefined), services);
}

/**
 * Puts the organisation on its integrity hold for its audit chain failing the
 * anchor check (B1d-3), recorded as the sign `chain` on the subject
 * `audit_chain`, with how it failed (`failure`, the alarm's reason). Given no
 * failure, tries again a hold waiting in this process, if one is and none is
 * being recorded, so one that met a locked head is retried every run, even
 * with no request for the organisation. Never throws: every outcome is logged.
 */
export async function holdOrganisation(
  db: Kysely<AuditTables>,
  orgId: string,
  services: SignedStatesServices,
  failure: string | undefined,
  answeredWithinMs?: number,
): Promise<void> {
  const held = orgId.toLowerCase();
  const waiting = dueWaiting(held);
  if (failure !== undefined) {
    const finding: TamperFinding = {
      orgId: held,
      subjectType: CHAIN_SUBJECT,
      objectId: held,
      sign: 'chain',
      chainFailure: failure,
    };
    await setHold(db, held, { finding, count: 1 }, services, { answeredWithinMs });
  } else if (waiting !== undefined && !recording.has(held)) {
    await setHold(db, held, waiting, services, { answeredWithinMs });
  }
}

/**
 * Runs `work` in withTenant's transaction for the organisation, with signed
 * states of its own and each statement limited (withTenant's `limited`), and then
 * puts the organisation on hold for anything they found tampered with.
 * Returns what `work` returns, or throws what it throws.
 */
export async function withSignedStates<Tables extends AuditTables, Result>(
  // Both: the work's transaction has every table the caller's has, the hold's the audit tables.
  db: Kysely<Tables> & Kysely<AuditTables>,
  orgId: string,
  services: SignedStatesServices,
  work: (tx: Transaction<Tables>, states: SignedStates) => Promise<Result>,
): Promise<Result> {
  const { keys, ids, logger, correlationId } = services;
  const trail = createAuditTrail({ keys, ids, correlationId });
  const found: TamperFinding[] = [];
  const states = createSignedStates({
    keys,
    trail,
    logger,
    onTamper: (finding) => found.push(finding),
    unrecorded: (id) => waitingOnAClearHold(id.toLowerCase()),
  });
  // Whether the work's transaction began: one refused outright (nested, a bad ID) found nothing, and tries nothing.
  const opened = { began: false };
  try {
    return await withTenant(
      db,
      orgId,
      (tx) => {
        opened.began = true;
        return work(tx, states);
      },
      { limited: true },
    );
  } catch (error) {
    // Named by the chain that refused: the work may record on the platform's
    // too (an operator action records on both, ADR-006 §6).
    if (error instanceof ChainBroken && error.chain.kind === 'platform') {
      logger.error('audit.integrity_failed', { chain: 'platform', check: 'record' });
    } else if (error instanceof ChainBroken) {
      logger
        .child({ orgId: orgId.toLowerCase() })
        .error('audit.integrity_failed', { chain: 'organisation', check: 'record' });
    }
    throw error;
  } finally {
    const due = byOrganisation(found);
    const own = orgId.toLowerCase();
    const waiting = dueWaiting(own);
    if (opened.began && waiting !== undefined && !due.has(own) && !recording.has(own)) due.set(own, waiting);
    for (const [held, one] of due) await setHold(db, held, one, services);
  }
}
