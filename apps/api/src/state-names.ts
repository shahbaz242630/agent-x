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

/** The organisation's naming undone: a state with no names was written since the walk (TR-16), so it waits a run. */
class UnnamedSinceWalk extends Error {}

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
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<NamesTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** Done after an organisation's walk, before each table is named (tests: a move made just then). */
  readonly walked?: (next: SignedStateTable) => Promise<void>;
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

  /**
   * Whether any named table holds a state with no names written since the walk (TR-16). Asked once the organisation's
   * own event is recorded, under its chain's head lock: every event before it has committed, so this read sees them.
   */
  const unnamedSinceWalk = async (tx: NamesTx, orgId: string, walked: Walked): Promise<boolean> => {
    for (const table of NAMED_TABLES) {
      if (await signedRowsLackingSince(tx, table, orgId, walked.reached, TRACKED_BEFORE)) return true;
    }
    return false;
  };

  /** Each of the table's objects named, a page a transaction: how many were, and how many were left for the next run. */
  const namedIn = async (services: SignedStatesServices, orgId: string, table: SignedStateTable, walked: Walked) => {
    const counted = { named: 0, left: 0 };
    let after: string | null = null;
    do {
      let page: {
        readonly ids: readonly string[];
        readonly next: string | null;
        readonly named: number;
        readonly left: number;
      };
      try {
        page = await withSignedStates(database, orgId, services, async (tx, states) => {
          const listed = await states.objectIds(tx, orgId, table, after, OBJECTS_A_PAGE);
          const came = { named: 0, left: 0 };
          for (const id of listed.ids) {
            const one = await namedOne(tx, states, table, { orgId, id }, walked);
            if (one !== 'as_is') came[one] += 1;
          }
          // Named over a state with no names written since the walk, the organisation would be held for it: undone.
          if (table === ORGANIZATIONS && came.named > 0 && (await unnamedSinceWalk(tx, orgId, walked)))
            throw new UnnamedSinceWalk();
          return { ...listed, ...came };
        });
      } catch (error) {
        if (!(error instanceof UnnamedSinceWalk)) throw error;
        return { named: counted.named, left: counted.left + 1 };
      }
      counted.named += page.named;
      counted.left += page.left;
      after = page.next;
    } while (after !== null);
    return counted;
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
        const counted = await namedIn(services, orgId, table, walked);
        named += counted.named;
        left += counted.left;
      }
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
