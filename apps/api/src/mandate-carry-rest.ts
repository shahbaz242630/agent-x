// The rest of a carry past 20 (Phase 4 A3; PRD §4.1; BR-05, BR-09; partner
// decision 6, S135; PL-47): the API's job, on a timer of its own. An admin
// accepting a new version who chose to carry the pending requests has the
// oldest 20 settled at the confirm (mandate-carry.ts); the rest stay on the
// version replaced, and the acceptance's signed event says so (`carryRest`).
// A later acceptance with carry weighs every pending request of the mandate,
// whatever its version, so its own rest takes in any the job hadn't reached.
// This weighs them as the confirm would have, under
// the version now in force, 20 at a time, oldest first, against what the ones
// carried before them hold, and carries or cancels each (`carryPlan`,
// `carryOut`, decision 17's outcomes), as the API's, naming the acceptance.
//
// For each organisation the directory lists, the candidates are mandates with
// requests pending on a version that isn't theirs in force, by their rows, a
// page at a time; then each in a transaction of its own, in ADR-006's lock
// order: the organisation and agent read through their signed states (2, 3),
// the mandate (4), then the carry's own reads. Taken only while the version in
// force is still one whose acceptance left a rest (`carriesRest`) and the
// mandate ACTIVE: a later acceptance that chose cancel (or carried all), a
// suspension or an ending leaves them to the request-voids job, which judges
// them as ever. A frozen
// organisation, or an agent not ACTIVE, leaves them where they are until it is
// again (the voids job judges a stop chosen to cancel meanwhile). Until carried,
// one can't be approved or handed off: both ask for the version in force.
//
// A run never throws: each failure is logged, naming the organisation and
// mandate, and the run goes on to the next.
import { agentOf } from '@agentx/core/modules/agents';
import {
  type AuditTables,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { MANDATES, mandateOf } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { PENDING_STATUSES } from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { carryOut, carryPlan } from './mandate-carry.ts';
import type { DecisionTables } from './spend-request-decisions.ts';

/** How often the rest of a carry is looked for, once the last run has ended: carried within this. */
export const CARRY_REST_EVERY_MS = 5 * 60_000;

/** How many turns of 20 one run takes a mandate: the rest wait for the next run. */
const TURNS_A_RUN = 5;

/** How many candidate mandates one run takes an organisation. */
const MANDATES_A_RUN = 100;

type CarryRestTables = DecisionTables & AuditTables;
type CarryRestTx = DatabaseTransaction<CarryRestTables>;

/** The acceptance a version in force carries the rest from, as its signed event names it. */
const ACCEPTED = 'mandate.accepted';

/**
 * Whether the mandate's version in force still carries requests from older
 * versions: its newest acceptance made it the version in force and left
 * requests for the job (`carryRest`). Throws for a history that can't be
 * believed (its alarm raised).
 */
export async function carriesRest(
  tx: DatabaseTransaction<AuditTables>,
  states: SignedStates,
  orgId: string,
  mandate: { readonly id: string; readonly currentVersionId: string | null },
): Promise<boolean> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [MANDATES.subject],
    subjectId: mandate.id,
    actions: [ACCEPTED],
    limit: 1,
    newest: true,
  });
  if (history.outcome !== 'read') throw new Error(`A mandate's acceptances can't be believed: ${mandate.id}`);
  // A version in force came with an acceptance: none read is a history that can't be believed, as one unread.
  // The newest acceptance made the version in force (its signed state is that event's): its own words decide.
  return history.events.at(-1)?.event.details.carryRest === true;
}

/** A mandate with requests on a version not its own in force, as its rows name them. */
interface Candidate {
  readonly mandateId: string;
  readonly agentId: string;
}

/**
 * The organisation's mandates with pending requests on another version, by
 * their rows, unverified, at most MANDATES_A_RUN: the rest on a later run. One
 * left (stopped) stays a candidate until it can go on, or the voids job ends
 * its requests; an organisation's mandates in force are one an agent, so few.
 */
async function candidatesOf(tx: CarryRestTx, orgId: string): Promise<Candidate[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before anything moves
    .selectFrom('spend_requests.requests as r')
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a filter alone: the mandate is read through its signed state
    .innerJoin('mandates.mandates as m', (join) =>
      join.onRef('m.org_id', '=', 'r.org_id').onRef('m.id', '=', 'r.mandate_id'),
    )
    .select(['r.mandate_id', 'r.agent_id'])
    .distinct()
    .where('r.org_id', '=', orgId)
    .where('r.status', 'in', PENDING_STATUSES)
    .where('m.current_version_id', 'is not', null)
    .where('r.mandate_version_id', 'is not', null)
    .whereRef('r.mandate_version_id', '<>', 'm.current_version_id')
    .$narrowType<{ mandate_id: string }>()
    .orderBy('r.mandate_id')
    .limit(MANDATES_A_RUN)
    .execute();
  return rows.map(({ mandate_id, agent_id }) => ({ mandateId: mandate_id, agentId: agent_id }));
}

/** What one turn came to: carried and cancelled, how many still wait; or left, for the reason given. */
type Turn =
  | { readonly outcome: 'taken'; readonly carried: number; readonly cancelled: number; readonly later: number }
  | { readonly outcome: 'left'; readonly why: 'not_carried' | 'stopped' };

export interface CarryRest {
  /** Takes each organisation's carries past 20 on, up to TURNS_A_RUN turns a mandate, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createCarryRest({
  list,
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<CarryRestTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): CarryRest {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** One turn of 20 for the mandate, in lock order, if its version in force still carries a rest. */
  const turn = async (tx: CarryRestTx, states: SignedStates, orgId: string, candidate: Candidate): Promise<Turn> => {
    const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
    const agent = await agentOf(tx, states, { orgId, id: candidate.agentId }, 'share');
    const mandate = await mandateOf(tx, states, { orgId, id: candidate.mandateId }, 'share');
    if (organization.outcome !== 'verified' || agent.outcome !== 'found' || mandate.outcome !== 'found') {
      throw new Error(`What a carry names can't be believed: ${candidate.mandateId}`);
    }
    const { currentVersionId } = mandate.mandate;
    if (
      currentVersionId === null ||
      mandate.mandate.status !== 'ACTIVE' ||
      !(await carriesRest(tx, states, orgId, mandate.mandate))
    ) {
      return { outcome: 'left', why: 'not_carried' };
    }
    if (organization.fields.get('status') !== 'ACTIVE' || agent.agent.status !== 'ACTIVE') {
      return { outcome: 'left', why: 'stopped' };
    }
    const now = clock.now();
    const { plan, later } = await carryPlan(tx, states, {
      orgId,
      agentId: candidate.agentId,
      mandateId: candidate.mandateId,
      now,
      decides: true,
      under: { version: 'inForce', currentVersionId },
    });
    await carryOut(tx, states, keys, orgId, plan, {
      draftId: currentVersionId,
      actor: { type: 'system', id: 'api' },
      details: { via: 'carry_rest' },
      now,
    });
    const carried = plan.filter(({ outcome }) => outcome === 'carry').length;
    return { outcome: 'taken', carried, cancelled: plan.length - carried, later };
  };

  /** The mandate's turns, up to TURNS_A_RUN, each in a transaction of its own, logged; false if the signal stopped it. */
  const carriedOn = async (orgId: string, candidate: Candidate, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    const { mandateId } = candidate;
    let carried = 0;
    let cancelled = 0;
    try {
      for (let turns = 0; turns < TURNS_A_RUN; turns += 1) {
        if (signal?.aborted === true) return false;
        const done = await withSignedStates(database, orgId, services(log), (tx, states) =>
          turn(tx, states, orgId, candidate),
        );
        if (done.outcome === 'left') break;
        carried += done.carried;
        cancelled += done.cancelled;
        if (done.later === 0) break;
      }
    } catch (error) {
      log.error('mandate_carry.failed', { mandateId, err: error, carried, cancelled });
      return true;
    }
    if (carried + cancelled > 0) log.info('mandate_carry.carried', { mandateId, carried, cancelled });
    return true;
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('mandate_carry.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        let candidates: Candidate[];
        try {
          candidates = await withSignedStates(database, orgId, services(logger), (tx) => candidatesOf(tx, orgId));
        } catch (error) {
          logger.child({ orgId }).error('mandate_carry.failed', { err: error });
          continue;
        }
        for (const candidate of candidates) {
          if (!(await carriedOn(orgId, candidate, signal))) return;
        }
      }
    },
  };
}
