// An organisation's authority rows recovery plan (PL-29 follow-up,
// Carry-Forward S175; playbook H): given rows the app reads as tampered on the
// live server (changed, deleted, or planted past it) and a restored copy of
// the database from before the damage (the restore drill's copy, a
// point-in-time restore), which of the copy's original rows would be put
// back, and which planted rows removed. Read only on both sides: it plans,
// and state-restore.ts applies. The chain's own plan (chain-recovery.ts)
// comes first: a live chain that fails its check is refused here.
//
// PL-29's key property: what is written is only the copy's original rows, as
// read, never a new seal, MAC, fingerprint or hash, so it can't bless a
// forgery. Every row is judged as every reader judges it (judgeSignedRow, the
// verifier's own judgement), with no lock and no alarm: both connections are
// read-only, and the findings are the incident's already.
//
// For each authority table, every live object (its rows and every object its
// log names) that reads tampered is:
// - put back: the copy's row with the same key verifies on the copy, and
//   against the live chain's latest signed event for the object too, so the
//   copy's row is exactly the state the live log last signed
// - removed: the live log holds no signed event for it and the copy holds no
//   row: nothing signed ever made it (a planted row). Its columns are kept in
//   the plan.
// Otherwise the plan is refused, never bent:
// - `copy_broken`: the copy's chain fails its own check
// - `chain_broken`: the live chain fails its check, or its anchor: repair the
//   chain first (chain-recovery-plan, then chain-restore)
// - `not_grown_from_copy`: the live chain isn't the copy's grown on, so the
//   copy isn't an earlier state of this organisation's
// - `newer_than_copy`: the live log signed a state after the copy was taken
//   that the copy's row can't match: restore a later copy
// - `copy_differs`: the copy's row doesn't verify there, or against the live
//   log, though the live log signed nothing newer
// - `unrepairable`: a row reads tampered and fits neither rule (its log can't
//   be believed, or a planted row the copy holds too)
// - `schema_differs`: the copy's table has other columns than the live one's
// - `backlog`: an object has more events since its newest signed one than one
//   read takes, which the app refuses to judge too
// - `too_large`: more rows than one plan writes
import { createHash } from 'node:crypto';

import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import {
  type AuditTables,
  type AuditTrail,
  columnsOf,
  createAuditTrail,
  judgeSignedRow,
  readRowsAlike,
  rowsAsStored,
  type StateAsRead,
  stateObjectIds,
  STATES_READ_AT_ONCE,
  statesAsRead,
  type TamperSign,
} from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { ChainReport, CheckedPoint } from '@agentx/platform/audit-chain';
import { type Database, JOB_ANSWER_WITHIN_MS, type SignedStateTable, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

/** The most rows one plan writes: its file is made in memory, and damage wider than this is past one plan. */
const MOST_PLANNED_ROWS = 10_000;

/** A job's transaction: each statement limited, each trip's answer too. */
const JOB_LIMITS = { limited: true, answeredWithinMs: JOB_ANSWER_WITHIN_MS } as const;

type StateRefusal =
  | 'copy_broken'
  | 'chain_broken'
  | 'not_grown_from_copy'
  | 'newer_than_copy'
  | 'copy_differs'
  | 'unrepairable'
  | 'schema_differs'
  | 'backlog'
  | 'too_large';

/** A row the plan writes: the copy's original put back, or a planted live row removed. */
export interface PlannedState {
  readonly action: 'put_back' | 'remove';
  readonly table: SignedStateTable;
  /** The object's ID, in lower case. */
  readonly id: string;
  /** How the live row read: the sign the app's verifier gives it. */
  readonly sign: TamperSign;
  /** The live object's latest signed event, by its ID, or null for none: a repair writes only while it is still this. */
  readonly liveEventId: string | null;
  /** The live row as stored, Postgres's JSON of it; null where it is gone. What a repair writes over, kept as evidence. */
  readonly live: string | null;
  /** The copy's row as stored, put back exactly as read; null for a row removed. */
  readonly copy: string | null;
}

export type StatePlan =
  | {
      readonly ok: true;
      readonly rows: readonly PlannedState[];
      /** The copy's chain head, and the live chain's, as the plan checked them. */
      readonly copyHead: CheckedPoint;
      readonly liveHead: CheckedPoint;
      /** Every object judged on the live server. */
      readonly objects: number;
    }
  | {
      readonly ok: false;
      readonly reason: StateRefusal;
      /** The object refused, where one is: its type and ID, and the sign it read with. */
      readonly subjectType?: string;
      readonly objectId?: string;
      readonly sign?: TamperSign;
      /** For a chain's refusal, its check's reason and where. */
      readonly problem?: string;
    };

type Refused = Extract<StatePlan, { ok: false }>;

export interface StateRecoverySides {
  /** The restored copy and the live server, read-only. */
  readonly copy: Database<AuditTables>;
  readonly live: Database<AuditTables>;
  readonly keys: KeyProvider;
  readonly orgId: string;
  /** The store's latest anchor for the organisation's chain, its signature checked; undefined where it has none. */
  readonly anchor: CheckedPoint | undefined;
  /** The authority tables, in the lock order: the product's AUTHORITY_TABLES, but for a test. */
  readonly tables?: readonly SignedStateTable[];
  readonly mostRows?: number;
  /** How many objects a page of the live tables reads: STATES_READ_AT_ONCE, but for a test. */
  readonly pageSize?: number;
}

const refused = (reason: StateRefusal, about: Omit<Refused, 'ok' | 'reason'> = {}): Refused => ({
  ok: false,
  reason,
  ...about,
});

const chainProblem = (report: Extract<ChainReport, { ok: false }>): string =>
  `${report.problem.reason} at ${report.problem.seq.toString()}`;

/** A live object that reads tampered, as the plan found it. */
interface Found {
  readonly id: string;
  readonly sign: TamperSign;
  readonly latest: StateAsRead['latest'];
}

/** Plans the recovery of one organisation's authority rows from the copy: never writes, and never throws for what it finds. */
export async function planStateRecovery(sides: StateRecoverySides): Promise<StatePlan> {
  const orgId = sides.orgId.toLowerCase();
  const { copy, live, anchor, tables = AUTHORITY_TABLES, mostRows = MOST_PLANNED_ROWS } = sides;
  // The IDs are never used: nothing is written. The trail needs a source all the same.
  const trail = createAuditTrail({ keys: sides.keys, ids: uuidV7Ids });
  const copied = await trail.verifyAlone(copy, orgId, undefined);
  if (!copied.ok) return refused('copy_broken', { problem: chainProblem(copied) });
  const anchored = await trail.verifyAlone(live, orgId, anchor);
  if (!anchored.ok) return refused('chain_broken', { problem: chainProblem(anchored) });
  // The copy's head as the anchor: the live chain is the copy's grown on, so every event the copy holds is live too.
  const grown = await trail.verifyAlone(live, orgId, copied);
  if (!grown.ok) return refused('not_grown_from_copy', { problem: chainProblem(grown) });
  const planner = { ...sides, orgId, trail, copyHead: copied };
  const rows: PlannedState[] = [];
  let objects = 0;
  for (const table of tables) {
    const scanned = await tamperedIn(planner, table);
    if ('reason' in scanned) return scanned;
    objects += scanned.objects;
    for (let at = 0; at < scanned.found.length; at += STATES_READ_AT_ONCE) {
      const planned = await judged(planner, table, scanned.found.slice(at, at + STATES_READ_AT_ONCE));
      if ('reason' in planned) return planned;
      rows.push(...planned);
      const last = rows.at(-1);
      if (rows.length > mostRows && last !== undefined) {
        return refused('too_large', { subjectType: table.subject, objectId: last.id });
      }
    }
  }
  return { ok: true, rows, copyHead: point(copied), liveHead: point(grown), objects };
}

const point = ({ seq, hash, macKeyVersion }: CheckedPoint): CheckedPoint => ({ seq, hash, macKeyVersion });

interface Planner extends StateRecoverySides {
  readonly trail: AuditTrail;
  readonly copyHead: CheckedPoint;
}

/** Every live object of the table that reads tampered, a page at a time; or a backlog's refusal. */
async function tamperedIn(
  { live, keys, orgId, trail, pageSize = STATES_READ_AT_ONCE }: Planner,
  table: SignedStateTable,
): Promise<{ readonly found: readonly Found[]; readonly objects: number } | Refused> {
  const found: Found[] = [];
  let objects = 0;
  let after: string | null = null;
  do {
    const { listed, read } = await withTenant(
      live,
      orgId,
      async (tx) => {
        const page = await stateObjectIds(tx, trail, table, orgId, after, pageSize);
        return { listed: page, read: await statesAsRead(tx, trail, keys, table, orgId, page.ids) };
      },
      JOB_LIMITS,
    );
    for (const id of listed.ids) {
      const state = read.get(id);
      // statesAsRead answers every ID asked; one it didn't would be a bug, never an object to pass over.
      if (state === undefined) throw new Error('An object was listed and not read');
      if (state.check === undefined) return refused('backlog', { subjectType: table.subject, objectId: id });
      if (state.check.outcome === 'tampered') found.push({ id, sign: state.check.sign, latest: state.latest });
    }
    objects += listed.ids.length;
    after = listed.next;
  } while (after !== null);
  return { found, objects };
}

/** The copy's side of some tampered live objects of one table, and the live rows as stored: what each plans, or a refusal. */
async function judged(
  { copy, live, keys, orgId, trail, copyHead }: Planner,
  table: SignedStateTable,
  found: readonly Found[],
): Promise<readonly PlannedState[] | Refused> {
  const ids = found.map(({ id }) => id);
  const onCopy = await withTenant(
    copy,
    orgId,
    async (tx) => {
      await readRowsAlike(tx);
      return {
        read: await statesAsRead(tx, trail, keys, table, orgId, ids),
        stored: await rowsAsStored(tx, table, orgId, ids),
      };
    },
    JOB_LIMITS,
  );
  const onLive = await withTenant(
    live,
    orgId,
    async (tx) => {
      await readRowsAlike(tx);
      return { stored: await rowsAsStored(tx, table, orgId, ids), columns: await columnsOf(tx, table) };
    },
    JOB_LIMITS,
  );
  const planned: PlannedState[] = [];
  for (const one of found) {
    const copied = onCopy.read.get(one.id);
    // statesAsRead answers every ID asked.
    if (copied === undefined) throw new Error('An object was asked of the copy and not read');
    const stored = { live: onLive.stored.get(one.id) ?? null, copy: onCopy.stored.get(one.id) ?? null };
    const decided = decide({ keys, orgId, copyHead }, table, one, copied, stored, onLive.columns);
    if ('reason' in decided) return decided;
    planned.push(decided);
  }
  return planned;
}

/** What one tampered live object's row plans, by the two rules, or the refusal it meets. */
function decide(
  { keys, orgId, copyHead }: Pick<Planner, 'keys' | 'orgId' | 'copyHead'>,
  table: SignedStateTable,
  { id, sign, latest }: Found,
  copied: StateAsRead,
  stored: { readonly live: string | null; readonly copy: string | null },
  liveColumns: readonly string[],
): PlannedState | Refused {
  const about = { subjectType: table.subject, objectId: id, sign };
  const base = { table, id, sign, live: stored.live };
  if (latest.kind === 'none') {
    // Nothing signed ever made it: no signed event live (so none on the copy, whose chain the live one grew from),
    // and no row on the copy.
    if (stored.live === null || copied.row.outcome !== 'missing') return refused('unrepairable', about);
    return { ...base, action: 'remove' as const, liveEventId: null, copy: null };
  }
  if (latest.kind !== 'signed') return refused('unrepairable', about);
  const againstLive = judgeSignedRow(keys, table, { orgId, id }, copied.row, latest);
  if (copied.check?.outcome !== 'verified' || againstLive.outcome !== 'verified' || stored.copy === null) {
    return refused(latest.seq > copyHead.seq ? 'newer_than_copy' : 'copy_differs', about);
  }
  if (!sameColumns(stored.copy, liveColumns)) return refused('schema_differs', about);
  return { ...base, action: 'put_back' as const, liveEventId: latest.id.toLowerCase(), copy: stored.copy };
}

/** Whether the copy's row has exactly the live table's columns: what a repair writes, column by column. */
function sameColumns(stored: string, columns: readonly string[]): boolean {
  const held = Object.keys(JSON.parse(stored) as Record<string, unknown>).sort();
  const live = [...columns].sort();
  return held.length === live.length && held.every((column, at) => column === live[at]);
}

/** What a plan's file says about it, beside its rows. */
export interface StatePlanFacts {
  readonly planId: string;
  readonly orgId: string;
  readonly release: string;
  readonly run: string | null;
  readonly anchor: CheckedPoint | undefined;
}

const hex = (bytes: Buffer): string => bytes.toString('hex');

const pointLine = (at: CheckedPoint | undefined) =>
  at === undefined ? null : { seq: at.seq.toString(), hash: hex(at.hash), macKeyVersion: at.macKeyVersion };

/** How many of a plan's rows are of each action. */
export const stateCounts = (rows: readonly PlannedState[]) => ({
  putBack: rows.filter((row) => row.action === 'put_back').length,
  removed: rows.filter((row) => row.action === 'remove').length,
});

/**
 * The plan's lines as its file holds them, but for who made it and when: its
 * summary, then each row it would write, each live and copied row as
 * Postgres's JSON text of it, exactly as read. What its digest covers.
 */
function planLines(plan: StatePlan, orgId: string, anchor: CheckedPoint | undefined): object[] {
  const about = { k: 'state_plan', orgId, anchor: pointLine(anchor) };
  if (!plan.ok) {
    const { ok, reason, subjectType, objectId, sign, problem } = plan;
    return [{ ...about, ok, reason, subjectType, objectId, sign, problem }];
  }
  return [
    {
      ...about,
      ok: true,
      rows: plan.rows.length,
      ...stateCounts(plan.rows),
      objects: plan.objects,
      copyHead: pointLine(plan.copyHead),
      liveHead: pointLine(plan.liveHead),
    },
    ...plan.rows.map(({ action, table, id, sign, liveEventId, live, copy }) => ({
      k: 'row',
      action,
      table: table.table,
      subjectType: table.subject,
      id,
      sign,
      liveEventId,
      live,
      copy,
    })),
  ];
}

const ndjson = (lines: readonly object[]): string => lines.map((line) => `${JSON.stringify(line)}\n`).join('');

/**
 * A plan's digest: SHA-256, in hex, of its lines but for who made it and when.
 * A repair is asked with the digest of the plan the operator read, makes the
 * plan again and applies it only if the digest is the same: the same rows,
 * read the same on both sides, under the same chains' heads and anchor.
 */
export const statePlanDigest = (plan: StatePlan, orgId: string, anchor: CheckedPoint | undefined): string =>
  createHash('sha256')
    .update(ndjson(planLines(plan, orgId, anchor)))
    .digest('hex');

/**
 * The plan as the evidence store keeps it, NDJSON: its summary first, naming
 * its digest, which a repair is asked with (state-restore.ts), then each row
 * it would write. A refused plan is its summary alone, naming why.
 */
export function statePlanFile(plan: StatePlan, facts: StatePlanFacts): Buffer {
  const [summary, ...rest] = planLines(plan, facts.orgId, facts.anchor);
  const made = { planId: facts.planId, release: facts.release, run: facts.run };
  const digest = statePlanDigest(plan, facts.orgId, facts.anchor);
  return Buffer.from(ndjson([{ ...summary, ...made, digest }, ...rest]));
}
