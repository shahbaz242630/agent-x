// Each tracked object recorded before the names given them (TR-3 residual 75, state-trail.ts): the API's job, on a
// timer of its own, as the grant summaries' backfill is. For each organisation the directory lists, every run, it
// first looks (one `share` read) whether the organisation's own state names its history from its start: born after
// the names, or named here already, it is done. Otherwise it checks the organisation's whole chain from its start;
// only a chain that checks out whole is named. Then each tracked object whose state doesn't reach its start is
// recorded again, unchanged, its event naming the newest of each tracked action its whole history holds
// (namesFromHistory), a page at a time; the organisation's own state last, so it names its start only once every
// other one does. From then, a state with no names in that organisation is tampering (trailGap's `allNamed`).
//
// An object's older events of an action than its newest stay unnamed (legacy, never more than the chain checked
// whole here held): only staging holds such objects, and the request-voids job settles any request they stopped.
// Spend requests aren't named again: a new event on one would move the times its waits and checks run from.
//
// It is the API's, not the operator command's: the operator's role may not write these tables (0079), and the API's
// writes are witnessed as any are. A run never throws: each failure is logged, naming the organisation, and the run
// goes on. Retire it, as the grant summaries' build will be, once every environment's objects are named.
import { AGENTS } from '@agentx/core/modules/agents';
import {
  type AuditTables,
  createAuditTrail,
  namedFromStart,
  namesFromHistory,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction, SignedStateTable } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often every organisation is looked at for objects not yet named, once the last run has ended. */
export const STATE_NAMES_EVERY_MS = 60 * 60_000;

/** The tables named, the organisation's own last: its names reaching its start say every other's do. */
const NAMED_TABLES: readonly SignedStateTable[] = [AGENTS, MANDATES, SOURCES, SUPPLIERS, ORGANIZATIONS];

/** How many objects one transaction names. */
const OBJECTS_A_PAGE = 50;

/** The most events of its tracked actions one object's history may hold to be named (each a person's or a lapse's). */
const MOST_TRACKED_EVENTS = 1_000;

type NamesTables = AuditTables & DirectoryTables;
type NamesTx = DatabaseTransaction<NamesTables>;

export interface StateNames {
  /** Names each listed organisation's objects recorded before the names, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** The object's state recorded again, naming its whole history, unless it reaches its start already; whether it did. */
async function namedOne(tx: NamesTx, states: SignedStates, table: SignedStateTable, orgId: string, id: string) {
  const key = { orgId, id };
  const state = await states.verifiedState(tx, table, key, 'change');
  if (state.outcome !== 'verified') throw new Error(`An object to name can't be believed: ${table.subject} ${id}`);
  if (namedFromStart(state.trail)) return false;
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [table.subject],
    subjectId: id,
    actions: table.tracks ?? [],
    limit: MOST_TRACKED_EVENTS,
  });
  if (history.outcome !== 'read') throw new Error(`An object's history to name can't be believed: ${id}`);
  await states.renamed(tx, table, key, state, namesFromHistory(table, history.events), {
    actor: { type: 'system', id: 'api' },
    action: `${table.subject}.history_named`,
    details: {},
  });
  return true;
}

export function createStateNames({
  list,
  database,
  keys,
  ids,
  logger,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<NamesTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): StateNames {
  const trail = createAuditTrail({ keys, ids });

  /** Each of the table's objects named, a page a transaction; how many were. */
  const namedIn = async (services: SignedStatesServices, orgId: string, table: SignedStateTable): Promise<number> => {
    let named = 0;
    let after: string | null = null;
    do {
      const page: { readonly ids: readonly string[]; readonly next: string | null } = await withSignedStates(
        database,
        orgId,
        services,
        async (tx, states) => {
          const listed = await states.objectIds(tx, orgId, table, after, OBJECTS_A_PAGE);
          for (const id of listed.ids) if (await namedOne(tx, states, table, orgId, id)) named += 1;
          return listed;
        },
      );
      after = page.next;
    } while (after !== null);
    return named;
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
      const checked = await trail.verifyAlone(database, orgId, undefined);
      if (!checked.ok) {
        log.warn('state_names.chain_unverified', { reason: checked.problem.reason, seq: checked.problem.seq });
        return;
      }
      let named = 0;
      for (const table of NAMED_TABLES) {
        if (signal?.aborted === true) return;
        named += await namedIn(services, orgId, table);
      }
      log.info('state_names.named', { named });
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
