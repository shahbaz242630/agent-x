// Pending spend requests voided once their authority no longer stands (PRD
// §4.2, §11; BR-09, BR-11; ADR-006 §10; Phase 3 C1): the API's job, on a
// timer of its own, denying each request waiting, approved or ready whose
// agent is suspended, whose mandate is no longer in force or superseded,
// whose source can't fund, or whose supplier is no longer verified or has
// new details (voidCauses), a suspension only when it was chosen to cancel
// (decision 7: one that pauses, or the bank's own, voids nothing; consent the
// bank ended always does), recorded as the API's with its causes, its
// reservation and order claim released in the same transaction. The brakes
// void their own requests as they stop (C2); this finds the rest, and any a
// brake left past its batch.
//
// For each organisation the directory lists, the candidates are found by
// their rows (pending, 0046's index, joined to their agent's, mandate's,
// source's and supplier's rows), a page at a time, each page after the last,
// so requests refused on every run (tampered with) can't fill a page and keep
// the rest; then each in a transaction of its own, in ADR-006's lock order:
// its agent, mandate, source and supplier read through their signed states
// (levels 3–6, share), then the request itself (`voidRequest`: 8, 11, 12),
// judged by what those say, and by the suspension in force of each one
// suspended (pausedOf). A row that only looks stopped is left standing.
//
// The candidates leave out a subject suspended with its requests paused, by
// its newest suspend event read in the query, unverified: a filter alone, so
// paused requests aren't judged again every run. An event tampered with to
// read as a pause hides its requests until the chain's check finds it, as a
// row tampered back to ACTIVE does; nothing can be approved or handed off
// under a suspension meanwhile.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next.
import { agentOf, type AgentsTables } from '@agentx/core/modules/agents';
import {
  type AuditTables,
  newestDetail,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type FundingSourcesTables, sourceOf } from '@agentx/core/modules/funding-sources';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { mandateOf, type MandatesTables } from '@agentx/core/modules/mandates';
import {
  type AuthorityNow,
  PENDING_STATUSES,
  type SpendRequestsTables,
  type Voided,
  voidRequest,
} from '@agentx/core/modules/spend-requests';
import { supplierOf, type SuppliersTables } from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { eachOrganisation, expireInPages } from './expiry-pages.ts';
import { pausedOf, SUSPENDS } from './suspensions.ts';

/** How often pending requests are looked over, once the last run has ended: a request a brake left is voided within this. */
export const REQUEST_VOIDS_EVERY_MS = 5 * 60_000;

/** How many of an organisation's requests one run voids, and how many candidates a page holds: the rest wait for the next run. */
const MOST_VOIDED_A_RUN = 100;

type VoidTables = SpendRequestsTables &
  LimitReservationsTables &
  AuditTables &
  AgentsTables &
  DirectoryTables &
  MandatesTables &
  FundingSourcesTables &
  SuppliersTables;
type VoidTx = DatabaseTransaction<VoidTables>;

/** The newest suspend's choice for the object a candidate's column `idColumn` names, unverified: null for none. */
const choiceOf = (which: keyof typeof SUSPENDS, idColumn: string) =>
  newestDetail({ ...SUSPENDS[which], idColumn, orgColumn: 'r.org_id', key: 'pendingRequests' });

/**
 * The IDs of the organisation's pending requests whose rows look stopped, in
 * order of ID, after `after` when given, at most `most`: each to be judged by
 * the signed states of what it names.
 */
async function stoppedByTheirRows(
  tx: VoidTx,
  orgId: string,
  now: Date,
  most: number,
  after: string | undefined,
): Promise<readonly string[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each judged through its signed states before anything moves
    .selectFrom('spend_requests.requests as r')
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a candidate's row alone, judged through its signed state before anything moves
    .innerJoin('agents.agents as a', (join) => join.onRef('a.org_id', '=', 'r.org_id').onRef('a.id', '=', 'r.agent_id'))
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a candidate's row alone, judged through its signed state before anything moves
    .innerJoin('mandates.mandates as m', (join) =>
      join.onRef('m.org_id', '=', 'r.org_id').onRef('m.id', '=', 'r.mandate_id'),
    )
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a candidate's row alone, judged through its signed state before anything moves
    .innerJoin('funding_sources.sources as s', (join) =>
      join.onRef('s.org_id', '=', 'r.org_id').onRef('s.id', '=', 'r.funding_source_id'),
    )
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a candidate's row alone, judged through its signed state before anything moves
    .innerJoin('suppliers.suppliers as p', (join) =>
      join.onRef('p.org_id', '=', 'r.org_id').onRef('p.id', '=', 'r.supplier_id'),
    )
    .select('r.id')
    .where('r.org_id', '=', orgId)
    .where('r.status', 'in', PENDING_STATUSES)
    .where((where) => (after === undefined ? where.lit(true) : where('r.id', '>', after)))
    .where((where) => {
      /** Not `standing`, unless SUSPENDED by a suspension whose newest event, unverified, paused its requests. */
      const looksStopped = (
        status: 'a.status' | 'm.status' | 's.status' | 'p.status',
        standing: string,
        which: keyof typeof SUSPENDS,
        idColumn: string,
      ) =>
        where.and([
          where(status, '<>', standing),
          where.not(
            where.and([
              where(status, '=', 'SUSPENDED'),
              where(where.fn.coalesce(choiceOf(which, idColumn), where.val('cancel')), '=', 'pause'),
            ]),
          ),
        ]);
      return where.or([
        looksStopped('a.status', 'ACTIVE', 'agent', 'a.id'),
        looksStopped('m.status', 'ACTIVE', 'mandate', 'm.id'),
        where('m.current_version_id', 'is distinct from', where.ref('r.mandate_version_id')),
        looksStopped('s.status', 'ACTIVE', 'source', 's.id'),
        // The bank's availability needs no filter: its end (UNAVAILABLE) ends the source too (updateFromPartner).
        where('s.consent_expires_at', '<=', now),
        looksStopped('p.status', 'VERIFIED', 'supplier', 'p.id'),
        where('p.current_version_id', 'is distinct from', where.ref('r.supplier_version_id')),
      ]);
    })
    .orderBy('r.id')
    .limit(most)
    .execute();
  return rows.map(({ id }) => id);
}

/**
 * What the request's row names, unlocked: each then read through its signed
 * state, and checked by voidRequest. Found as a candidate, and requests are
 * never deleted (0039's grants); pending, it was decided under a mandate
 * (0039's check on an allowed or waiting decision's versions).
 */
async function namedBy(tx: VoidTx, orgId: string, requestId: string) {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- what it names alone, each read through its signed state, and checked against the request's own by voidRequest
    .selectFrom('spend_requests.requests')
    .select(['agent_id', 'mandate_id', 'funding_source_id', 'supplier_id'])
    .where('org_id', '=', orgId)
    .where('id', '=', requestId)
    .where('mandate_id', 'is not', null)
    .$narrowType<{ mandate_id: string }>()
    .executeTakeFirstOrThrow();
  return {
    agentId: row.agent_id,
    mandateId: row.mandate_id,
    fundingSourceId: row.funding_source_id,
    supplierId: row.supplier_id,
  };
}

export interface RequestVoids {
  /** Voids the pending requests whose authority no longer stands, up to MOST_VOIDED_A_RUN an organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createRequestVoids({
  list,
  database,
  keys,
  ids,
  clock,
  logger,
  most = MOST_VOIDED_A_RUN,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<VoidTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** MOST_VOIDED_A_RUN, but for the tests. */
  readonly most?: number;
}): RequestVoids {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** The request judged by what it names, in lock order, and voided if that no longer stands. */
  const judged = async (
    tx: VoidTx,
    states: SignedStates,
    key: { readonly orgId: string; readonly id: string },
  ): Promise<Voided> => {
    const { orgId } = key;
    const named = await namedBy(tx, orgId, key.id);
    const now = clock.now();
    const agent = await agentOf(tx, states, { orgId, id: named.agentId }, 'share');
    const mandate = await mandateOf(tx, states, { orgId, id: named.mandateId }, 'share');
    const source = await sourceOf(tx, states, { orgId, id: named.fundingSourceId }, 'share');
    const supplier = await supplierOf(tx, states, { orgId, id: named.supplierId }, 'share');
    // Nothing is judged on what can't be believed (each read tampered with has raised its own alarm) or isn't
    // there (each held by the request's foreign keys, 0039, and never deleted): the run logs it and goes on.
    if (
      agent.outcome !== 'found' ||
      mandate.outcome !== 'found' ||
      source.outcome !== 'found' ||
      supplier.outcome !== 'found'
    ) {
      throw new Error(`What a pending request names can't be believed: ${key.id}`);
    }
    const suspended = (
      [
        ['agent', agent.agent],
        ['mandate', mandate.mandate],
        ['source', source.source],
        ['supplier', supplier.supplier],
      ] as const
    ).filter(([, { status }]) => status === 'SUSPENDED');
    const authority: AuthorityNow = {
      agentStatus: agent.agent.status,
      mandate: mandate.mandate,
      source: {
        status: source.source.status,
        availability: source.source.availability,
        consentPast: source.source.consentExpiresAt <= now,
      },
      supplier: supplier.supplier,
      paused: await pausedOf(
        tx,
        states,
        orgId,
        suspended.map(([which, { id }]) => [which, id] as const),
      ),
    };
    return voidRequest(tx, states, keys, key, { named, authority }, now);
  };

  /** Voids the request if its authority no longer stands, logging what came of it; whether it did. Never throws. */
  const voidedLogged = async (log: Logger, orgId: string, requestId: string): Promise<boolean> => {
    try {
      const voided = await withSignedStates(database, orgId, services(log), (tx, states) =>
        judged(tx, states, { orgId, id: requestId }),
      );
      if (voided.outcome === 'voided') log.info('request_void.voided', { requestId, causes: voided.causes.join(',') });
      // A tampered read has raised its alarm; the rest moved meanwhile, or stand.
      return voided.outcome === 'voided';
    } catch (error) {
      // A history that can't be read, or a write that failed.
      log.error('request_void.failed', { requestId, err: error });
      return false;
    }
  };

  /** Voids the organisation's pending requests whose authority no longer stands, up to its share; false if the signal stopped it. */
  const voidIn = (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    return expireInPages({
      most,
      signal,
      page: (left, after) =>
        withSignedStates(database, orgId, services(log), (tx) =>
          stoppedByTheirRows(tx, orgId, clock.now(), left, after),
        ),
      expire: (requestId) => voidedLogged(log, orgId, requestId),
      unreadable: (error) => {
        log.error('request_void.unreadable', { err: error });
      },
    });
  };

  return {
    run: (signal) =>
      eachOrganisation(
        list,
        (error) => {
          logger.error('request_void.run_failed', { err: error });
        },
        (orgId) => voidIn(orgId, signal),
      ),
  };
}
