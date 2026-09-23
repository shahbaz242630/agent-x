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
// ever would hang the request. Such a hold is remembered in this process:
// every read of it here answers `tampered` with the sign that found it, and a
// later withSignedStates for the organisation tries again, one at a time, so
// a head held locked can't take a connection for every request; so does each
// run of the anchor check (holdOrganisation, B1d-3). It is kept in this
// process alone: another replica reads the log's `clear` meanwhile, and a
// process stopped before it is recorded (staging's API scales to zero when
// idle) forgets it, leaving the alarm lines. The hold is then set only when
// the tampering is next found; keeping it outside the process is carried
// forward. A hold's transaction is bounded by the head's lock (5 s) and each
// statement's time (10 s).
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
import { createSignedStates, type SignedStates, type TamperFinding } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

/** What the work's signed states are built from. */
export interface SignedStatesServices {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The request's or job's logger, a child carrying its correlation ID (Rule Book §8). */
  readonly logger: Logger;
}

/** The first finding for an organisation, with how many there were. */
interface Found {
  readonly finding: TamperFinding;
  readonly count: number;
}

/** Holds this process found but couldn't record yet, by organisation (lower case), with their findings. */
const unrecorded = new Map<string, Found>();
/**
 * How many holds this process is recording now, by organisation: a waiting
 * one is tried only while none is, so by one request at a time.
 */
const recording = new Map<string, number>();

/** What a hold names as found tampered with when the organisation's whole chain failed the anchor check. */
const CHAIN_SUBJECT = 'audit_chain';

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
 * Records the organisation's hold for a finding, in withTenant's transaction
 * for it, bounded by the head's lock (5 s) and each statement's time (10 s),
 * so neither a locked head nor a slow database holds the caller up for long.
 * One that can't be recorded raises the alarm (`check: hold`) and waits in
 * this process. Never throws.
 */
async function setHold(
  db: Kysely<AuditTables>,
  held: string,
  { finding, count }: Found,
  { keys, ids, logger }: SignedStatesServices,
): Promise<void> {
  const log = logger.child({ orgId: held });
  recording.set(held, (recording.get(held) ?? 0) + 1);
  try {
    // Its own signed states: a hold that can't be believed is set over, right here, not handed on again.
    const holder = createSignedStates({
      keys,
      trail: createAuditTrail({ keys, ids }),
      logger,
      onTamper: () => undefined,
    });
    const outcome = await withTenant<AuditTables, 'set' | 'already'>(db, held, async (tx) => {
      await sql`set local lock_timeout = '5s'`.execute(tx);
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return holder.hold(tx, finding, count);
    });
    unrecorded.delete(held);
    if (outcome === 'set') {
      log.warn('audit.integrity_hold_set', {
        reason: finding.sign,
        subjectType: finding.subjectType,
        findings: count,
      });
    }
  } catch (error) {
    unrecorded.set(held, { finding, count });
    log.error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'hold',
      reason: 'not_recorded',
      err: error,
    });
  } finally {
    const still = (recording.get(held) ?? 1) - 1;
    if (still > 0) recording.set(held, still);
    else recording.delete(held);
  }
}

/**
 * Puts the organisation on its integrity hold for its audit chain failing the
 * anchor check (B1d-3), recorded as the sign `chain` on the subject
 * `audit_chain`. With `failed` false, tries again a hold waiting in this
 * process, if one is and none is being recorded, so one that met a locked
 * head is retried every run, even with no request for the organisation.
 * Never throws: every outcome is logged.
 */
export async function holdOrganisation(
  db: Kysely<AuditTables>,
  orgId: string,
  services: SignedStatesServices,
  failed: boolean,
): Promise<void> {
  const held = orgId.toLowerCase();
  const waiting = unrecorded.get(held);
  if (failed) {
    const finding: TamperFinding = { orgId: held, subjectType: CHAIN_SUBJECT, objectId: held, sign: 'chain' };
    await setHold(db, held, { finding, count: 1 }, services);
  } else if (waiting !== undefined && !recording.has(held)) {
    await setHold(db, held, waiting, services);
  }
}

/**
 * Runs `work` in withTenant's transaction for the organisation, with signed
 * states of its own, and then puts the organisation on hold for anything they
 * found tampered with. Returns what `work` returns, or throws what it throws.
 */
export async function withSignedStates<Tables extends AuditTables, Result>(
  // Both: the work's transaction has every table the caller's has, the hold's the audit tables.
  db: Kysely<Tables> & Kysely<AuditTables>,
  orgId: string,
  { keys, ids, logger }: SignedStatesServices,
  work: (tx: Transaction<Tables>, states: SignedStates) => Promise<Result>,
): Promise<Result> {
  const trail = createAuditTrail({ keys, ids });
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
    return await withTenant(db, orgId, (tx) => {
      opened.began = true;
      return work(tx, states);
    });
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
    for (const [held, one] of due) await setHold(db, held, one, { keys, ids, logger });
  }
}
