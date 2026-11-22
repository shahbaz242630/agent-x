// Each tracked object recorded before the names given them (TR-3 residual 75, state-trail.ts): the API's job, on a
// timer of its own, as the grant summaries' backfill is. For each organisation the directory lists, every run, it
// first looks (one `share` read) whether the organisation's own state names its history from its start: born after
// the names, or named here already, it is done. Otherwise it walks the organisation's whole chain from its start,
// keeping the events of the tracked actions as the walk read them; only a chain that checks out whole is named, and
// only from what that walk read, so nothing moved after it can be named over. Then each tracked object whose state
// doesn't reach its start is recorded again, unchanged, its event naming the newest of each tracked action the walk
// kept of it (namesFromHistory), a page at a time; one changed since the walk is left for the next run; the
// organisation's own state last, only once every other one is named. From then, a state from before that naming with no names is tampering (trailGap's `namedAt`).
// So the organisation's naming waits for the next run if any named table holds a state with no names written since
// the walk (the app's older code during a deploy, TR-16): named over it, that state would read as tampering.
//
// An object's older events of an action than its newest stay unnamed (legacy, never more than the chain checked
// whole here held): only staging holds such objects, and the request-voids job settles any request they stopped.
// Spend requests aren't named again: a new event on one would move the times its waits and checks run from.
//
// It is the API's, not the operator command's: the operator's role may not write these tables (0079), and the API's
// writes are witnessed as any are. A chain that fails the whole walk raises the integrity alarm and puts the
// organisation on its integrity hold, as the anchor check does (TR-10). A run never throws: each failure is logged,
// naming the organisation, and the run goes on. Retire it, as the grant summaries' build will be, once every environment's objects are named.
import { AGENTS } from '@agentx/core/modules/agents';
import {
  type AuditTables,
  CHAIN_START,
  type CheckedPoint,
  createAuditTrail,
  historyNamedOf,
  holdOrganisation,
  namedFromStart,
  namesFromHistory,
  type SignedStates,
  type SignedStatesServices,
  TRACKED_BEFORE,
  type TrailEvent,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { ChainProblem } from '@agentx/platform/audit-chain';
import {
  type Database,
  type DatabaseTransaction,
  oldestEventAgeMs,
  type SignedStateTable,
  signedRowsLackingSince,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often every organisation is looked at for objects not yet named, once the last run has ended. */
export const STATE_NAMES_EVERY_MS = 60 * 60_000;

/** The tables named, the organisation's own last: its names reaching its start say every other's do. */
const NAMED_TABLES: readonly SignedStateTable[] = [AGENTS, MANDATES, SOURCES, SUPPLIERS, ORGANIZATIONS];

/** How many objects one transaction names. */
const OBJECTS_A_PAGE = 50;

/** How many events one step of the walk from the chain's start reads (each step its own transaction, as the checks'). */
const EVENTS_A_STEP = 5_000;

/** Every action a named table tracks: what the walk keeps. */
const TRACKED_ACTIONS = [...new Set(NAMED_TABLES.flatMap((table) => table.tracks ?? []))];

type NamesTables = AuditTables & DirectoryTables;
type NamesTx = DatabaseTransaction<NamesTables>;

export interface StateNames {
  /** Names each listed organisation's objects recorded before the names, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** What the walk from the chain's start read: where it reached, and the tracked events it kept, by object. */
interface Walked {
  readonly reached: bigint;
  readonly kept: ReadonlyMap<string, TrailEvent[]>;
}

/** A row of another table than the organisation's own, found pointing at an event since the walk with no names. */
interface Pointed {
  readonly table: SignedStateTable;
  readonly id: string;
  /** The event it was found pointing at. */
  readonly seq: bigint;
}

/**
 * Those rows as they verified: at the event they were found at, with no names (the older image's, which holds the
 * naming back), or at an older state than it (never the app: a row's state only moves on, so someone put it back).
 * One that can't be believed isn't here: it is the tamper finding, its alarm, and the hold as its transaction ends.
 * One that verifies at a newer state than it is the app's own later write, retried next run.
 */
interface Judged {
  readonly unnamed: readonly Pointed[];
  readonly movedBack: readonly Pointed[];
}

/** The tables such a row is looked for in: every named one but the organisation's own, whose state its naming writes. */
const OTHER_TABLES = NAMED_TABLES.filter((table) => table !== ORGANIZATIONS);

/** How many such rows of a table one look reads and verifies: one is enough to hold the naming back. */
const ROWS_LOOKED_AT = 50;

/** The actions an object is named with: the oldest of them in a chain is when its naming began (TR-16). */
const NAMING_ACTIONS = NAMED_TABLES.map((table) => historyNamedOf(table.subject));

/** How long an organisation's naming may go on without ending before it is an error: a day of the hourly runs. */
const UNNAMED_TOO_LONG_MS = 24 * 60 * 60_000;

/** The naming undone: rows pointing at a state with no names, written since the walk after the first look (TR-16). */
class UnnamedSinceWalk extends Error {
  readonly rows: readonly Pointed[];
  constructor(rows: readonly Pointed[]) {
    super('A state with no names was written since the walk');
    this.rows = rows;
  }
}

/** Each row of the other tables pointing at an event since the walk with no names: by its pointer alone. */
async function pointedSinceWalk(tx: NamesTx, orgId: string, walked: Walked): Promise<Pointed[]> {
  const found: Pointed[] = [];
  for (const table of OTHER_TABLES) {
    const rows = await signedRowsLackingSince(tx, table, orgId, walked.reached, TRACKED_BEFORE, ROWS_LOOKED_AT);
    found.push(...rows.map(({ id, seq }) => ({ table, id, seq })));
  }
  return found;
}

/** Each row verified, `share`, and judged as Judged says. */
async function judged(tx: NamesTx, states: SignedStates, orgId: string, rows: readonly Pointed[]): Promise<Judged> {
  const unnamed: Pointed[] = [];
  const movedBack: Pointed[] = [];
  for (const row of rows) {
    const state = await states.verifiedState(tx, row.table, { orgId, id: row.id }, 'share');
    if (state.outcome !== 'verified') continue;
    const trail = state.trail;
    if (trail === undefined || trail.seq < row.seq) movedBack.push(row);
    else if (trail.seq === row.seq && trail.tracked === undefined) unnamed.push(row);
  }
  return { unnamed, movedBack };
}

const objectKey = (type: string, id: string) => `${type}:${id.toLowerCase()}`;

/**
 * The object's state recorded again, naming the newest of each tracked action the walk kept of it, unless it reaches
 * its start already (`named`) or moved past the walk (`left`, for the next run).
 */
async function namedOne(
  tx: NamesTx,
  states: SignedStates,
  table: SignedStateTable,
  { orgId, id }: { readonly orgId: string; readonly id: string },
  walked: Walked,
): Promise<'named' | 'as_is' | 'left'> {
  const key = { orgId, id };
  const state = await states.verifiedState(tx, table, key, 'change');
  if (state.outcome !== 'verified') throw new Error(`An object to name can't be believed: ${table.subject} ${id}`);
  if (namedFromStart(state.trail)) return 'as_is';
  // Its state recorded since the walk: its events past it weren't read whole by it, so it waits for the next walk.
  if (state.trail === undefined || state.trail.seq > walked.reached) return 'left';
  const events = walked.kept.get(objectKey(table.subject, id)) ?? [];
  await states.renamed(tx, table, key, state, namesFromHistory(table, events), {
    actor: { type: 'system', id: 'api' },
    action: historyNamedOf(table.subject),
    details: {},
  });
  return 'named';
}

export function createStateNames({
  list,
  database,
  keys,
  ids,
  logger,
  walked: beforeNaming = () => Promise.resolve(),
  looked = () => Promise.resolve(),
  unnamedTooLongMs = UNNAMED_TOO_LONG_MS,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<NamesTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** Done after an organisation's walk, before each table is named (tests: a move made just then). */
  readonly walked?: (next: SignedStateTable) => Promise<void>;
  /** Done before a look verifies the rows it found (`read`), and after a first look that found none (`judged`): tests. */
  readonly looked?: (at: 'read' | 'judged') => Promise<void>;
  /** How long a naming may go on unended before it is an error (tests: shorter). */
  readonly unnamedTooLongMs?: number;
}): StateNames {
  const trail = createAuditTrail({ keys, ids });

  /** The organisation's whole chain walked from its start, its tracked events kept as read; the problem, if it fails. */
  const walkedWhole = async (orgId: string): Promise<Walked | ChainProblem> => {
    let at: CheckedPoint = CHAIN_START;
    const kept = new Map<string, TrailEvent[]>();
    for (;;) {
      const { step, kept: read } = await trail.walkFrom(database, orgId, at, EVENTS_A_STEP, TRACKED_ACTIONS);
      if (!step.ok) return step.problem;
      for (const event of read) {
        const at = objectKey(event.subjectType, event.subjectId);
        const subject = { type: event.subjectType, id: event.subjectId, version: event.subjectVersion };
        kept.set(at, [
          ...(kept.get(at) ?? []),
          { seq: event.seq, event: { action: event.action, subject, details: {} } },
        ]);
      }
      at = { seq: step.seq, hash: step.hash, macKeyVersion: step.macKeyVersion };
      if (step.seq >= step.to) return { reached: step.seq, kept };
    }
  };

  /** Rows found and verified in the caller's transaction (the hook between: tests restore a row just then). */
  const lookedAt = async (tx: NamesTx, states: SignedStates, orgId: string, rows: readonly Pointed[]) => {
    if (rows.length > 0) await looked('read');
    return judged(tx, states, orgId, rows);
  };

  /** What a look judged, acted on: a row moved back is the alarm and the hold; each state with no names, its warning. */
  const settled = async (
    services: SignedStatesServices,
    orgId: string,
    log: Logger,
    { unnamed, movedBack }: Judged,
  ) => {
    for (const { table, id } of movedBack) {
      log.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'state_names',
        reason: 'moved_back',
        table: table.subject,
        id,
      });
    }
    if (movedBack.length > 0) await holdOrganisation(database, orgId, services, 'moved_back');
    for (const { table, id } of unnamed) log.warn('state_names.unnamed_since_walk', { table: table.subject, id });
  };

  /**
   * The organisation's own state named, last (TR-16): not while any other table holds a state with no names written
   * since the walk (the older image's, in a deploy), which the naming would make read as tampering. The first look, its
   * rows found and verified `share`, is a transaction of its own: those tables come after the organisation's in ADR-006
   * §6's order, so their locks are never held while its row is locked for its naming. The naming's own transaction
   * locks no row of them: once its event holds the head's lock (every event before it committed, so seen), a row
   * written since the first look undoes it, and is verified and judged in a transaction of its own.
   */
  const ownNamed = async (services: SignedStatesServices, orgId: string, walked: Walked, log: Logger) => {
    const first = await withSignedStates(database, orgId, services, async (tx, states) => {
      const rows = await pointedSinceWalk(tx, orgId, walked);
      return { rows, ...(await lookedAt(tx, states, orgId, rows)) };
    });
    if (first.rows.length > 0) {
      await settled(services, orgId, log, first);
      return 'left';
    }
    await looked('judged');
    let late: readonly Pointed[];
    try {
      return await withSignedStates(database, orgId, services, async (tx, states) => {
        const came = await namedOne(tx, states, ORGANIZATIONS, { orgId, id: orgId }, walked);
        const since = came === 'named' ? await pointedSinceWalk(tx, orgId, walked) : [];
        if (since.length > 0) throw new UnnamedSinceWalk(since);
        return came;
      });
    } catch (error) {
      if (!(error instanceof UnnamedSinceWalk)) throw error;
      late = error.rows;
    }
    const after = await withSignedStates(database, orgId, services, (tx, states) => lookedAt(tx, states, orgId, late));
    await settled(services, orgId, log, after);
    return 'left';
  };

  /** Each of the table's objects named, a page a transaction: how many were, and how many were left for the next run. */
  const namedIn = async (services: SignedStatesServices, orgId: string, table: SignedStateTable, walked: Walked) => {
    const counted = { named: 0, left: 0 };
    let after: string | null = null;
    do {
      const page: { readonly ids: readonly string[]; readonly next: string | null } = await withSignedStates(
        database,
        orgId,
        services,
        async (tx, states) => {
          const listed = await states.objectIds(tx, orgId, table, after, OBJECTS_A_PAGE);
          for (const id of listed.ids) {
            const came = await namedOne(tx, states, table, { orgId, id }, walked);
            if (came !== 'as_is') counted[came] += 1;
          }
          return listed;
        },
      );
      after = page.next;
    } while (after !== null);
    return counted;
  };

  /** A table named: the organisation's own by ownNamed, as a count; every other's a page at a time. */
  const tableNamed = async (
    services: SignedStatesServices,
    orgId: string,
    table: SignedStateTable,
    walked: Walked,
    log: Logger,
  ): Promise<{ readonly named: number; readonly left: number }> => {
    if (table !== ORGANIZATIONS) return namedIn(services, orgId, table, walked);
    const came = await ownNamed(services, orgId, walked, log);
    return { named: came === 'named' ? 1 : 0, left: came === 'left' ? 1 : 0 };
  };

  /**
   * An organisation left unnamed this run: an error once its naming began (its first object named, by the database's
   * clock) longer ago than a day of runs, read from its chain so no restart or change of leader resets it (TR-16).
   */
  const tooLong = async (services: SignedStatesServices, orgId: string, log: Logger) => {
    const ageMs = await withSignedStates(database, orgId, services, (tx) =>
      oldestEventAgeMs(tx, orgId, NAMING_ACTIONS),
    );
    if (ageMs !== null && ageMs >= unnamedTooLongMs)
      log.error('state_names.unnamed_too_long', { hours: Math.floor(ageMs / 3_600_000) });
  };

  const nameIn = async (orgId: string, signal: AbortSignal | undefined): Promise<void> => {
    const log = logger.child({ orgId });
    const services: SignedStatesServices = { keys, ids, logger: log };
    try {
      const done = await withSignedStates(database, orgId, services, async (tx, states) => {
        const own = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
        // Tampered with (its alarm raised): nothing named this run.
        return own.outcome !== 'verified' || namedFromStart(own.trail);
      });
      if (done) return;
      const walked = await walkedWhole(orgId);
      if (!('kept' in walked)) {
        // A chain that fails its whole walk is tampering, as the anchor check's: the alarm, and the same hold (TR-10).
        log.error('audit.integrity_failed', {
          chain: 'organisation',
          check: 'state_names',
          reason: walked.reason,
          seq: walked.seq,
        });
        await holdOrganisation(database, orgId, services, walked.reason);
        return;
      }
      let named = 0;
      let left = 0;
      for (const table of NAMED_TABLES) {
        if (signal?.aborted === true) return;
        // The organisation's own state last, and only once no other was left: its names then reach its start.
        if (table === ORGANIZATIONS && left > 0) break;
        await beforeNaming(table);
        const count = await tableNamed(services, orgId, table, walked, log);
        named += count.named;
        left += count.left;
      }
      if (left > 0) await tooLong(services, orgId, log);
      log.info('state_names.named', { named, left });
    } catch (error) {
      log.error('state_names.failed', { err: error });
    }
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('state_names.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        if (signal?.aborted === true) return;
        await nameIn(orgId, signal);
      }
    },
  };
}
