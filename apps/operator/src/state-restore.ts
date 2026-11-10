// An organisation's authority rows repaired from their recovery plan (PL-29
// follow-up, Carry-Forward S175; playbook H), as chain-restore.ts repairs its
// chain. The operator reads a plan (state-recovery.ts) and asks for it by its
// digest; this makes the plan again, against the drill's copy and the live
// server as they stand now, and applies it only if it is the same plan: a
// plan file is never trusted, and one gone stale is refused.
//
// PL-29's key property holds here as in the plan: what is written is only the
// copy's original rows, as read, and planted rows removed; nothing here makes
// a seal, a MAC or a hash. Every write is in one transaction, as the owner
// (the only role that may delete a row, or write past the database's guards),
// and:
// 1. on each table it writes, in the lock order (ADR-006 §6), the guards
//    that would refuse an original put back are switched off: that takes the
//    table's lock, so nothing else writes it until this commits (state-repair.ts)
// 2. each row it writes is locked for change, and must still be the live row
//    the plan read, its object's latest signed event the same: an event
//    about an object needs its row changed first, which now waits
// 3. the rows are written, the guards switched on again, and each row read
//    back must be the copy's exactly, or gone where it was removed
// 4. every row written is judged by the app's own verifier (verifiedState),
//    then every authority object of the organisation (verifyAll), then the
//    whole chain against its anchor. Anything short of verified rolls it all
//    back.
// It takes no chain head's lock: it writes no event, and the rows it writes
// are held by their tables' locks. A deadlock with the organisation's own
// work (rare while it is on hold) rolls it back too; run it again.
//
// Refused, nothing written:
// - `plan`: the plan made now is itself refused (state-recovery.ts's reasons)
// - `stale`: the plan made now isn't the one asked for (its digest differs)
// - `moved`: a row, or its latest signed event, changed after the plan
// - `write_refused`: the database refused a write (a foreign key, a check):
//   rolled back, with the database's code alone
// - `unverified`: what was written didn't read back as planned, a trigger
//   was left otherwise than it was, or the verifier found anything tampered
//   with: rolled back
//
// The organisation's integrity hold is left as it is: its admin clears it
// with a step-up once the investigation is recorded, as for any hold.
import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import {
  type AuditTables,
  type AuditTransaction,
  columnsOf,
  createAuditTrail,
  firePendingChecks,
  guardsOff,
  guardsOn,
  readRowsAlike,
  rowsAsStored,
  type SignedStates,
  STATES_READ_AT_ONCE,
  triggersOf,
  withSignedStates,
  writeStateRow,
} from '@agentx/core/modules/audit';
import { OBJECTS_CHECKED } from '@agentx/core/modules/identity';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { Database, SignedStateTable } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import {
  type PlannedState,
  planStateRecovery,
  stateCounts,
  type StatePlan,
  statePlanDigest,
  type StateRecoverySides,
} from './state-recovery.ts';

type Planned = Extract<StatePlan, { ok: true }>;

/** Which check of the rows as written failed. */
type UnverifiedCheck = 'written' | 'guards' | 'state' | 'whole' | 'chain';

export type StateRestoreOutcome =
  | { readonly ok: true; readonly plan: Planned }
  | { readonly ok: false; readonly reason: 'plan'; readonly plan: Extract<StatePlan, { ok: false }> }
  | { readonly ok: false; readonly reason: 'stale'; readonly digest: string }
  | { readonly ok: false; readonly reason: 'moved'; readonly subjectType: string; readonly objectId: string }
  | {
      readonly ok: false;
      readonly reason: 'write_refused';
      /** The row whose write was refused; none for a check left to the end (a deferred foreign key). */
      readonly subjectType?: string;
      readonly objectId?: string;
      /** The database's error code alone, never its message, which could hold a row's values. */
      readonly code: string;
    }
  | {
      readonly ok: false;
      readonly reason: 'unverified';
      readonly check: UnverifiedCheck;
      /** The object it failed on, where one is, and the sign the verifier gave it. */
      readonly subjectType?: string;
      readonly objectId?: string;
      readonly sign?: string;
    };

export interface StateRestoreSides extends Pick<
  StateRecoverySides,
  'keys' | 'orgId' | 'anchor' | 'tables' | 'mostRows' | 'pageSize'
> {
  /** The drill's copy, read-only. */
  readonly copy: Database<AuditTables>;
  /** The live server as the owner: read for the plan, written in the repair's transaction. */
  readonly live: Database<AuditTables>;
  /** The digest of the plan the operator read (statePlanDigest). */
  readonly digest: string;
  /** The job's logger: the verifier's alarm goes through it, if what was written still reads tampered. */
  readonly logger: Logger;
}

/** Thrown inside the repair's transaction to roll it back with this outcome. */
class Stopped extends Error {
  readonly outcome: Exclude<StateRestoreOutcome, { ok: true }>;

  constructor(outcome: Stopped['outcome']) {
    super(`a state repair stopped: ${outcome.reason}`);
    this.outcome = outcome;
  }
}

/** Makes the plan again and applies it if it is the one asked for: never throws for what it finds. */
export async function restoreStates(sides: StateRestoreSides): Promise<StateRestoreOutcome> {
  const orgId = sides.orgId.toLowerCase();
  const plan = await planStateRecovery({ ...sides, orgId });
  if (!plan.ok) return { ok: false, reason: 'plan', plan };
  const madeNow = statePlanDigest(plan, orgId, sides.anchor);
  if (madeNow !== sides.digest) return { ok: false, reason: 'stale', digest: madeNow };
  try {
    return await withSignedStates(
      sides.live,
      orgId,
      { keys: sides.keys, ids: uuidV7Ids, logger: sides.logger },
      (tx, states) => repairIn(tx, states, { ...sides, orgId }, plan),
    );
  } catch (error) {
    if (error instanceof Stopped) return error.outcome;
    throw error;
  }
}

/** A table the plan writes, with its rows. */
interface Touched {
  readonly table: SignedStateTable;
  readonly rows: readonly PlannedState[];
}

/** The plan's rows by table, in the lock order. */
const touchedTables = (tables: readonly SignedStateTable[], plan: Planned): readonly Touched[] =>
  tables
    .map((table) => ({ table, rows: plan.rows.filter((row) => row.table.table === table.table) }))
    .filter(({ rows }) => rows.length > 0);

/** Splits a table's rows into reads of at most STATES_READ_AT_ONCE. */
const batches = (rows: readonly PlannedState[]): PlannedState[][] =>
  Array.from({ length: Math.ceil(rows.length / STATES_READ_AT_ONCE) }, (_, at) =>
    rows.slice(at * STATES_READ_AT_ONCE, (at + 1) * STATES_READ_AT_ONCE),
  );

const about = ({ table, id }: PlannedState) => ({ subjectType: table.subject, objectId: id });

/** The repair's one transaction: locked, compared, written, read back and verified; Stopped rolls it back. */
async function repairIn(
  tx: AuditTransaction,
  states: SignedStates,
  sides: StateRestoreSides,
  plan: Planned,
): Promise<StateRestoreOutcome> {
  const { orgId, tables = AUTHORITY_TABLES } = sides;
  const touched = touchedTables(tables, plan);
  await readRowsAlike(tx);
  // 1. Each table's guards off, in the lock order, each table's triggers as they were kept to compare after.
  const switched = [];
  for (const { table } of touched) {
    const before = await triggersOf(tx, table);
    switched.push({ table, before, off: await guardsOff(tx, table) });
  }
  // 2. Each row locked and compared with what the plan read.
  await stillAsPlanned(tx, sides, touched);
  // 3. Removed first, the latest tables first, then put back in the lock order: a planted row named by another goes
  // before what it names, and an original before what names it.
  for (const { rows } of touched.toReversed()) {
    for (const row of rows.filter(({ action }) => action === 'remove')) await written(tx, orgId, row, []);
  }
  for (const { table, rows } of touched) {
    const columns = await columnsOf(tx, table, true);
    for (const row of rows.filter(({ action }) => action === 'put_back')) await written(tx, orgId, row, columns);
  }
  // What the writes left for the end runs now: a table with events pending can't have its guards switched on.
  await refusedAs({}, () => firePendingChecks(tx));
  for (const { table, before, off } of switched) {
    await guardsOn(tx, table, off);
    const after = await triggersOf(tx, table);
    if (after.size !== before.size || [...before].some(([name, state]) => after.get(name) !== state)) {
      throw new Stopped({ ok: false, reason: 'unverified', check: 'guards', subjectType: table.subject });
    }
  }
  // 4. Read back, then judged by the app's own verifier.
  await asWritten(tx, states, orgId, touched);
  const whole = await states.verifyAll(tx, orgId, tables, OBJECTS_CHECKED, { counted: () => undefined });
  if (whole.outcome === 'tampered') {
    // The first finding names where: a tampered outcome always has one.
    const named = whole.findings
      .slice(0, 1)
      .map(({ subjectType, objectId, sign }) => ({ subjectType, objectId, sign }));
    throw new Stopped({ ok: false, reason: 'unverified', check: 'whole', ...named[0] });
  }
  // The trail's IDs are never used: the check writes nothing.
  const report = await createAuditTrail({ keys: sides.keys, ids: uuidV7Ids }).verify(tx, orgId, sides.anchor);
  if (!report.ok) throw new Stopped({ ok: false, reason: 'unverified', check: 'chain' });
  return { ok: true, plan };
}

/** Runs `check` on each table's rows a read at a time, in the lock order. */
async function eachBatch(
  touched: readonly Touched[],
  check: (table: SignedStateTable, batch: readonly PlannedState[], ids: readonly string[]) => Promise<void>,
): Promise<void> {
  for (const { table, rows } of touched) {
    for (const batch of batches(rows))
      await check(
        table,
        batch,
        batch.map(({ id }) => id),
      );
  }
}

/** The latest signed event's ID as a plan names it: null for none, undefined for a log that can't be judged now. */
const eventIdOf = (latest: { readonly kind: string; readonly id?: string } | undefined): string | null | undefined => {
  if (latest?.kind === 'none') return null;
  return latest?.kind === 'signed' ? latest.id?.toLowerCase() : undefined;
};

/** Each row the plan writes, locked for change: still the live row the plan read, with the same latest signed event. */
async function stillAsPlanned(
  tx: AuditTransaction,
  { keys, orgId }: StateRestoreSides,
  touched: readonly Touched[],
): Promise<void> {
  // The trail's IDs are never used: this reads only.
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  await eachBatch(touched, async (table, batch, ids) => {
    const now = await rowsAsStored(tx, table, orgId, ids, 'change');
    const latest = await trail.latestSignedStates(tx, orgId, table.subject, ids);
    const moved = batch.find(
      (row) => (now.get(row.id) ?? null) !== row.live || eventIdOf(latest.get(row.id)) !== row.liveEventId,
    );
    if (moved !== undefined) throw new Stopped({ ok: false, reason: 'moved', ...about(moved) });
  });
}

/** Whether an error is the database refusing a write on a constraint (class 23): its code, or undefined. */
const constraintCode = (error: unknown): string | undefined => {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : '';
  return code.startsWith('23') ? code : undefined;
};

/** Runs `write`; a constraint's refusal stops the repair, naming the row (where one is) and the code alone. */
async function refusedAs(
  row: { readonly subjectType?: string; readonly objectId?: string },
  write: () => Promise<void>,
): Promise<void> {
  try {
    await write();
  } catch (error) {
    const code = constraintCode(error);
    if (code === undefined) throw error;
    throw new Stopped({ ok: false, reason: 'write_refused', ...row, code });
  }
}

/** One row written: the copy's original put back over the live row or where it is gone, or the live row removed. */
const written = (tx: AuditTransaction, orgId: string, row: PlannedState, columns: readonly string[]) =>
  refusedAs(about(row), () =>
    writeStateRow(
      tx,
      orgId,
      row.action === 'remove'
        ? { action: 'remove', table: row.table, id: row.id }
        : { action: 'put_back', table: row.table, id: row.id, stored: String(row.copy), exists: row.live !== null },
      columns,
    ),
  );

/** Each row as written: the copy's exactly, or gone; then each judged by verifiedState, verified or missing. */
async function asWritten(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  touched: readonly Touched[],
): Promise<void> {
  await eachBatch(touched, async (table, batch, ids) => {
    const now = await rowsAsStored(tx, table, orgId, ids);
    const otherwise = batch.find((row) => (now.get(row.id) ?? null) !== row.copy);
    if (otherwise !== undefined) {
      throw new Stopped({ ok: false, reason: 'unverified', check: 'written', ...about(otherwise) });
    }
    const checks = await states.verifiedStates(tx, table, orgId, ids);
    for (const row of batch) {
      const check = checks.get(row.id);
      if (check?.outcome !== (row.action === 'put_back' ? 'verified' : 'missing')) {
        const sign = check?.outcome === 'tampered' ? { sign: check.sign } : {};
        throw new Stopped({ ok: false, reason: 'unverified', check: 'state', ...about(row), ...sign });
      }
    }
  });
}

/** What the evidence store keeps of a repair's run, beside its plan's own file. */
export interface StateRestoreFacts {
  readonly restoreId: string;
  readonly planId: string;
  readonly orgId: string;
  readonly digest: string;
  readonly release: string;
  readonly run: string | null;
}

/** The outcome as one line of plain facts: no row's contents (the plan's file holds them). */
export function stateOutcomeLine(outcome: StateRestoreOutcome): Readonly<Record<string, unknown>> {
  if (outcome.ok) return { ok: true, ...stateCounts(outcome.plan.rows), objects: outcome.plan.objects };
  switch (outcome.reason) {
    case 'plan': {
      const { reason, subjectType, objectId, sign, problem } = outcome.plan;
      return {
        ok: false,
        reason: 'plan',
        planRefused: reason,
        subjectType: subjectType ?? null,
        objectId: objectId ?? null,
        sign: sign ?? null,
        problem: problem ?? null,
      };
    }
    case 'stale':
      return { ok: false, reason: 'stale', digestNow: outcome.digest };
    case 'moved':
      return { ok: false, reason: 'moved', subjectType: outcome.subjectType, objectId: outcome.objectId };
    case 'write_refused':
      return {
        ok: false,
        reason: 'write_refused',
        subjectType: outcome.subjectType ?? null,
        objectId: outcome.objectId ?? null,
        code: outcome.code,
      };
    case 'unverified':
      return {
        ok: false,
        reason: 'unverified',
        check: outcome.check,
        subjectType: outcome.subjectType ?? null,
        objectId: outcome.objectId ?? null,
        sign: outcome.sign ?? null,
      };
  }
}

/** The repair's record in the evidence store: one NDJSON line, the run's facts and its outcome. */
export const stateRestoreFile = (outcome: StateRestoreOutcome, facts: StateRestoreFacts): Buffer =>
  Buffer.from(`${JSON.stringify({ k: 'state_restore', ...facts, ...stateOutcomeLine(outcome) })}\n`);
