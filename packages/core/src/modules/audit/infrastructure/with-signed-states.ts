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
//   (pollHoldsWaiting), tries a new one at once, and then keeps it as its own
// The memory stays because the database may be just what is in trouble: a row
// that can't be written says so (`audit.hold_not_kept`), and the process retries
// both. A hold recorded takes its row with it, in the same transaction.
//
// One row a record. A hold names one record and clearing checks that one, so a
// row for another record stays while the hold stands, tried by each poll (a
// transaction each 5 seconds, a process), and becomes the next hold once it is
// cleared. A row only adds caution, and really does: a row forged sets the hold.
// So a hold set from a row alone raises the alarm (`from_row`), as one foothold
// can hold every organisation. A row gone from the table leaves each process that
// held it to try once more: finding the hold recorded is the usual way, and nothing
// is said; recording it means the row was deleted with no hold, the alarm (`row_gone`).
// What stays open: a reader without the head's lock learns of another process's
// hold at its next poll; a row-recorded hold has no count or chain failure, which
// are in the alarm's line; a process frozen past a whole clearing that held an
// entry re-holds on waking, with `row_gone`, as it can't tell that from a row
// deleted (a new row is looked for again first, so isn't re-held); and a row
// deleted once every process that knew it has restarted is gone, leaving the
// alarm's line, with the hold set when the tampering is next found. A hold's
// transaction is bounded by the head's lock (5 s) and each statement's time (10 s).
//
// A work whose recording meets a chain that refuses new events has met
// tampering too, and raises the alarm (`check: record`) before its error goes
// back.
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
  holdsWaiting,
  type HoldWaiting,
  keepHoldWaiting,
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
}

/** How often every process looks for holds another left waiting. */
export const HOLDS_WAITING_EVERY_MS = 5_000;

/** Holds this process found or polled but couldn't record yet, by organisation (lower case), with their findings. */
const unrecorded = new Map<string, Found>();
/**
 * How many holds this process is recording now, by organisation: a waiting
 * one is tried only while none is, so by one request at a time.
 */
const recording = new Map<string, number>();

/** The first finding for each organisation, with how many there were. */
function byOrganisation(found: readonly TamperFinding[]): Map<string, Found> {
  const each = new Map<string, Found>();
  for (const finding of found) {
    const seen = each.get(finding.orgId);
    each.set(finding.orgId, seen === undefined ? { finding, count: 1 } : { ...seen, count: seen.count + 1 });
  }
  return each;
}

/**
 * Keeps a hold that couldn't be recorded, in this process and then in its row;
 * a row that can't be written leaves it in this process alone, and says so.
 */
async function keepWaiting(db: Kysely<AuditTables>, held: string, found: Found, log: Logger): Promise<void> {
  unrecorded.set(held, { ...found, inTable: false });
  // A row the app couldn't have written is never written again: it stands or it doesn't, and this entry says which.
  if (found.row !== undefined) {
    unrecorded.set(held, found);
    return;
  }
  try {
    await keepHoldWaiting(db, found.finding, found.finding.sign);
    unrecorded.set(held, { ...found, inTable: true });
  } catch (error) {
    log.error('audit.hold_not_kept', { reason: found.finding.sign, err: error });
  }
}

/**
 * Records the organisation's hold for a finding, in withTenant's transaction
 * for it, bounded by the head's lock (5 s) and each statement's time (10 s),
 * so neither a locked head nor a slow database holds the caller up for long.
 * One that can't be recorded raises the alarm (`check: hold`) and waits, here
 * and in its row. `rowMustStand`: one just read from its row is looked for again
 * first, so one frozen between that read and this try doesn't hold over a clearing:
 * gone means recorded, and reads `already`. Never throws: what it came to, or `failed`.
 */
async function setHold(
  db: Kysely<AuditTables>,
  held: string,
  found: Found,
  { keys, ids, logger, correlationId }: SignedStatesServices,
  rowMustStand = false,
): Promise<'set' | 'already' | 'named_elsewhere' | 'failed'> {
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
    const outcome = await withTenant<AuditTables, 'set' | 'already' | 'named_elsewhere'>(
      db,
      held,
      async (tx) => {
        await sql`set local lock_timeout = '5s'`.execute(tx);
        const itsRow = found.row ?? finding;
        if (rowMustStand && !(await holdStillWaiting(tx, itsRow))) return 'already';
        const recorded = await holder.hold(tx, finding, count);
        // Named elsewhere: clearing won't check this record, so its row stays to be the next hold.
        if (recorded !== 'named_elsewhere') await holdNoLongerWaiting(tx, itsRow);
        return recorded;
      },
      // Never in line behind the work it stops: bounded by the head's lock and each statement's time, as above.
      { limited: true, unshared: true },
    );
    unrecorded.delete(held);
    if (outcome === 'set') {
      log.warn('audit.integrity_hold_set', {
        reason: finding.sign,
        subjectType: finding.subjectType,
        findings: count,
      });
      if (found.fromRow === true) {
        log.error('audit.integrity_failed', {
          chain: 'organisation',
          check: 'hold',
          reason: 'from_row',
          subjectType: finding.subjectType,
          objectId: finding.objectId,
        });
      }
    }
    return outcome;
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
 * here, means the row was deleted with no hold: the alarm, and nothing lost.
 */
async function goneFromTable(
  db: Kysely<AuditTables>,
  held: string,
  found: Found,
  services: SignedStatesServices,
): Promise<void> {
  const outcome = await setHold(db, held, found, services);
  if (outcome === 'set' && found.inTable === true) {
    services.logger
      .child({ orgId: held })
      .error('audit.integrity_failed', { chain: 'organisation', check: 'hold', reason: 'row_gone' });
  }
}

/**
 * One look at the holds waiting (4D2e D5), for every process: each row is kept
 * here, and one new here tried at once; each hold known here with no row is
 * tried once more. Only caution comes of it: nothing here lifts a hold, as an
 * entry goes only when its hold is recorded. One trip while the table is empty
 * and nothing waits here. Never throws.
 */
export async function pollHoldsWaiting(db: Kysely<AuditTables>, services: SignedStatesServices): Promise<void> {
  // Read first: one kept while the read was on its way is new to it, not gone.
  const known = new Map(unrecorded);
  let rows: readonly HoldWaiting[];
  try {
    rows = await holdsWaiting(db);
  } catch (error) {
    // Tx A reads the rows itself, so nothing is let through: this process learns of another's a little later.
    services.logger.warn('audit.holds_waiting_unread', { err: error });
    return;
  }
  const inTable = new Set(rows.map(({ org_id: orgId }) => orgId));
  const fresh: [string, Found][] = [];
  for (const row of rows) {
    const inRow: Found = { ...foundInRow(row), inTable: true };
    const here = unrecorded.get(row.org_id);
    unrecorded.set(row.org_id, here === undefined ? inRow : { ...here, inTable: true });
    // Each row of an organisation not known here: a hold named elsewhere must not keep the next row from its try.
    if (!known.has(row.org_id) && !recording.has(row.org_id)) fresh.push([row.org_id, inRow]);
  }
  for (const [held, found] of fresh) await setHold(db, held, found, services, true);
  for (const [held, found] of known) {
    if (!inTable.has(held) && !recording.has(held)) await goneFromTable(db, held, found, services);
  }
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
): Promise<void> {
  const held = orgId.toLowerCase();
  const waiting = unrecorded.get(held);
  if (failure !== undefined) {
    const finding: TamperFinding = {
      orgId: held,
      subjectType: CHAIN_SUBJECT,
      objectId: held,
      sign: 'chain',
      chainFailure: failure,
    };
    await setHold(db, held, { finding, count: 1 }, services);
  } else if (waiting !== undefined && !recording.has(held)) {
    await setHold(db, held, waiting, services);
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
    unrecorded: (id) => unrecorded.get(id.toLowerCase())?.finding,
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
    const waiting = unrecorded.get(own);
    if (opened.began && waiting !== undefined && !due.has(own) && !recording.has(own)) due.set(own, waiting);
    for (const [held, one] of due) await setHold(db, held, one, services);
  }
}
