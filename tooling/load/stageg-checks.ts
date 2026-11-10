// Stage G's checks of what the database holds after a step (4D2e design item
// 8, PL-62, PL-63): a few statements over the whole throwaway copy, never one
// organisation at a time as checks.ts goes, which at 10,000 organisations would
// be 10,000 transactions a check. Each request of the step recorded once, none
// lost, no row in another organisation, every month the step touched within
// its limit, holdings exactly matching decisions, no integrity hold in any
// organisation since the run's first step began. Then checks.ts's per-organisation checks on the active cohort
// only, through each one's tenant wall as the app's role.
//
// The set-based statements read every organisation, so they need a role past
// the tenant walls (agentx_backup: BYPASSRLS and SELECT only). They must only
// ever be given the throwaway copy's connection, never staging's: the guard
// that refuses staging is the throwaway wiring's (design item 5), not this file's.
import type { Database, DatabaseTransaction } from '../../packages/platform/src/db/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import type { CohortAgent } from './stageg-seed.ts';

/** The step as its k6 summary (load.stageg_summary) gives it: its label, its count of new requests and when it ran. */
export interface StageGCheckedStep {
  readonly label: string;
  readonly created: number;
  readonly startedAt: string;
  readonly endedAt: string;
  /** When the run's first step began on this copy: a hold set any time since, in any organisation, fails the step. */
  readonly since: string;
  /**
   * How many requests may be made but never answered: a climb that stops itself (k6's abortOnFail) cuts off those in
   * flight, at most one a VU (S178's breaking: 4). 0 for every other step, whose every request is answered.
   */
  readonly unansweredAtMost: number;
}

export interface StageGCheckResult {
  readonly name: string;
  /** What it found wrong, in plain words: none when the check holds. */
  readonly failures: readonly string[];
}

/** A request's time is the API's clock, k6's start is dated back from its end: a minute either side holds both. */
const WINDOW_MARGIN_MS = 60_000;

/** Each statement names this many of what it found, and counts the rest. */
const EXAMPLES = 5;

/** The statuses holding money before a hand-off, and those that ended without one. */
const HOLDING = ['APPROVED', 'APPROVAL_REQUIRED'] as const;
const ENDED = ['DENIED', 'EXPIRED', 'CANCELLED'] as const;

type Tx = DatabaseTransaction<MandateWorldTables>;

/** The step's own requests: k6 names every order `G-<label>-<run>-...` (stage-g.k6.js), made in the step's window. */
const stepRequests = (tx: Pick<Tx, 'selectFrom'>, step: StageGCheckedStep) =>
  tx
    .selectFrom('spend_requests.requests as r')
    .selectAll('r')
    .where((eb) =>
      eb(eb.fn<boolean>('pg_catalog.starts_with', ['r.order_reference', eb.val(`G-${step.label}-`)]), '=', true),
    )
    .where('r.created_at', '>=', new Date(Date.parse(step.startedAt) - WINDOW_MARGIN_MS))
    .where('r.created_at', '<=', new Date(Date.parse(step.endedAt) + WINDOW_MARGIN_MS));

/** The plain words for the first rows a statement found, and how many more it found in all (`total`). */
function said<Row extends { readonly total: string | number | bigint }>(
  rows: readonly Row[],
  words: (row: Row) => string,
): string[] {
  const [first] = rows;
  if (first === undefined) return [];
  const more = Number(first.total) - rows.length;
  return [...rows.map(words), ...(more > 0 ? [`And ${String(more)} more like these.`] : [])];
}

interface SetCheck {
  readonly name: string;
  readonly run: (tx: Tx, step: StageGCheckedStep) => Promise<string[]>;
}

const SET_CHECKS: readonly SetCheck[] = [
  {
    name: 'recorded each request of the step once: no key twice, no order holding money twice',
    async run(tx, step) {
      const keys = await tx
        .selectFrom(stepRequests(tx, step).as('s'))
        .select((eb) => [
          's.org_id',
          's.idempotency_key',
          eb.fn.countAll<string>().as('n'),
          eb.fn.countAll<string>().over().as('total'),
        ])
        .groupBy(['s.org_id', 's.agent_id', 's.idempotency_key'])
        .having((eb) => eb.fn.countAll(), '>', 1)
        .orderBy('s.org_id')
        .orderBy('s.idempotency_key')
        .limit(EXAMPLES)
        .execute();
      const orders = await tx
        .selectFrom(stepRequests(tx, step).as('s'))
        .select((eb) => [
          's.org_id',
          's.order_key',
          eb.fn.countAll<string>().as('n'),
          eb.fn.countAll<string>().over().as('total'),
        ])
        .where('s.held_source_id', 'is not', null)
        .groupBy(['s.org_id', 's.supplier_id', 's.order_key'])
        .having((eb) => eb.fn.countAll(), '>', 1)
        .orderBy('s.org_id')
        .orderBy('s.order_key')
        .limit(EXAMPLES)
        .execute();
      return [
        ...said(
          keys,
          ({ org_id, idempotency_key, n }) =>
            `Organisation ${org_id} recorded ${n} requests under the key ${idempotency_key}: a replay made a request again.`,
        ),
        ...said(
          orders,
          ({ org_id, order_key, n }) =>
            `Organisation ${org_id} holds money for the order ${order_key} ${n} times: a duplicate under another key was not denied.`,
        ),
      ];
    },
  },
  {
    name: 'lost no request: the step’s own requests are as many as k6 was answered 201 for',
    async run(tx, step) {
      // NaN too: a runner that passed no count must fail, never compare.
      if (!Number.isFinite(step.created) || step.created <= 0) {
        return [`k6 recorded no new request in step ${step.label}, so nothing could be checked.`];
      }
      const { n } = await tx
        .selectFrom(stepRequests(tx, step).as('s'))
        .select((eb) => eb.fn.countAll<string>().as('n'))
        .executeTakeFirstOrThrow();
      const held = Number(n);
      if (held >= step.created && held <= step.created + step.unansweredAtMost) return [];
      const inFlight =
        step.unansweredAtMost === 0 ? '' : ` (and at most ${String(step.unansweredAtMost)} cut off in flight)`;
      return [
        `The database holds ${n} requests of step ${step.label}, but k6 was answered 201 for ${String(step.created)} new ones${inFlight}.`,
      ];
    },
  },
  {
    name: 'put no row in another organisation',
    async run(tx, step) {
      const twice = await tx
        .selectFrom('spend_requests.requests as r')
        .select((eb) => [
          'r.id',
          eb.fn.count<string>('r.org_id').distinct().as('n'),
          eb.fn.countAll<string>().over().as('total'),
        ])
        .groupBy('r.id')
        .having((eb) => eb.fn.count('r.org_id').distinct(), '>', 1)
        .orderBy('r.id')
        .limit(EXAMPLES)
        .execute();
      const misplaced = await tx
        .selectFrom('limit_reservations.reservations as v')
        .select((eb) => ['v.org_id', 'v.request_id', eb.fn.countAll<string>().over().as('total')])
        .where((eb) =>
          eb.not(
            eb.exists(
              eb
                .selectFrom('spend_requests.requests as r')
                .select('r.id')
                .whereRef('r.org_id', '=', 'v.org_id')
                .whereRef('r.id', '=', 'v.request_id'),
            ),
          ),
        )
        .orderBy('v.org_id')
        .orderBy('v.request_id')
        .limit(EXAMPLES)
        .execute();
      // The step's requests only: each one's own event is found by the chain's subject index.
      const unsigned = await tx
        .selectFrom(stepRequests(tx, step).as('s'))
        .select((eb) => ['s.org_id', 's.id', eb.fn.countAll<string>().over().as('total')])
        .where((eb) =>
          eb.not(
            eb.exists(
              eb
                .selectFrom('audit.events as e')
                .select('e.seq')
                .whereRef('e.org_id', '=', 's.org_id')
                .where('e.subject_type', '=', 'spend_request')
                .whereRef('e.subject_id', '=', 's.id'),
            ),
          ),
        )
        .orderBy('s.org_id')
        .orderBy('s.id')
        .limit(EXAMPLES)
        .execute();
      return [
        ...said(twice, ({ id, n }) => `The request ${id} is recorded in ${n} organisations.`),
        ...said(
          misplaced,
          ({ org_id, request_id }) =>
            `Organisation ${org_id} holds a reservation for the request ${request_id}, which is not its own.`,
        ),
        ...said(
          unsigned,
          ({ org_id, id }) => `Organisation ${org_id}'s request ${id} has no event in its own audit chain.`,
        ),
      ];
    },
  },
  {
    name: 'kept every month the step touched within its agent’s limit',
    async run(tx, step) {
      // The step's agents' months first, then each month's holdings by its index (0081's): a correlated EXISTS
      // rescanned the organisation's reservations for every one of them, which never ended at 10,000 (S177).
      const over = await tx
        .with(
          (cte) => cte('touched').materialized(),
          (db) =>
            db
              .selectFrom(stepRequests(db, step).as('s'))
              .innerJoin('limit_reservations.reservations as t', (join) =>
                join.onRef('t.org_id', '=', 's.org_id').onRef('t.request_id', '=', 's.id'),
              )
              .select(['t.org_id', 't.agent_id', 't.month'])
              .distinct(),
        )
        .selectFrom('touched as x')
        .innerJoin('limit_reservations.reservations as v', (join) =>
          join
            .onRef('v.org_id', '=', 'x.org_id')
            .onRef('v.agent_id', '=', 'x.agent_id')
            .onRef('v.month', '=', 'x.month'),
        )
        .innerJoin('mandates.mandates as m', (join) =>
          join.onRef('m.org_id', '=', 'v.org_id').onRef('m.id', '=', 'v.mandate_id'),
        )
        .innerJoin('mandates.versions as ver', (join) =>
          join.onRef('ver.org_id', '=', 'm.org_id').onRef('ver.id', '=', 'm.current_version_id'),
        )
        .select((eb) => [
          'v.org_id',
          'v.agent_id',
          'v.month',
          eb.fn.sum<string>('v.amount_minor').as('held'),
          eb.fn.max<string>('ver.monthly_limit_minor').as('limit'),
          eb.fn.countAll<string>().over().as('total'),
        ])
        .where('v.state', '<>', 'RELEASED')
        .groupBy(['v.org_id', 'v.agent_id', 'v.month'])
        .having((eb) => eb(eb.fn.sum('v.amount_minor'), '>', eb.fn.max('ver.monthly_limit_minor')))
        .orderBy('v.org_id')
        .orderBy('v.agent_id')
        .orderBy('v.month')
        .limit(EXAMPLES)
        .execute();
      return said(
        over,
        ({ org_id, agent_id, month, held, limit }) =>
          `Organisation ${org_id}'s agent ${agent_id} holds ${held} fils in ${month}, over its limit of ${limit}.`,
      );
    },
  },
  {
    name: 'holds exactly one reservation and one open claim for each request holding money, and none for one that ended',
    async run(tx) {
      // Handed-off requests and those about to be keep their holdings until the payment settles: neither side.
      const wrong = await tx
        .selectFrom('spend_requests.requests as r')
        .leftJoin('limit_reservations.reservations as v', (join) =>
          join.onRef('v.org_id', '=', 'r.org_id').onRef('v.request_id', '=', 'r.id'),
        )
        .leftJoin('spend_requests.order_claims as c', (join) =>
          join.onRef('c.org_id', '=', 'r.org_id').onRef('c.request_id', '=', 'r.id'),
        )
        .select((eb) => [
          'r.org_id',
          'r.id',
          'r.status',
          'v.state',
          'c.id as claim',
          'c.released_at',
          eb.fn.countAll<string>().over().as('total'),
        ])
        .where((eb) =>
          eb.or([
            eb.and([
              eb('r.status', 'in', HOLDING),
              eb.or([
                eb('v.state', 'is distinct from', 'HELD'),
                eb('c.id', 'is', null),
                eb('c.released_at', 'is not', null),
              ]),
            ]),
            eb.and([
              eb('r.status', 'in', ENDED),
              eb.or([
                eb('v.state', '=', 'HELD'),
                eb.and([eb('c.id', 'is not', null), eb('c.released_at', 'is', null)]),
              ]),
            ]),
          ]),
        )
        .orderBy('r.org_id')
        .orderBy('r.id')
        .limit(EXAMPLES)
        .execute();
      return said(wrong, ({ org_id, id, status, state, claim, released_at }) => {
        const claimed = claim === null ? 'no claim' : released_at === null ? 'claim open' : 'claim released';
        return `Organisation ${org_id}'s request ${id} is ${status} but holds this: ${state ?? 'no reservation'}, ${claimed}.`;
      });
    },
  },
  {
    name: 'put no organisation on an integrity hold since the run’s first step began',
    async run(tx, step) {
      const held = await tx
        .selectFrom('audit.events as e')
        .select((eb) => ['e.org_id', eb.fn.countAll<string>().over().as('total')])
        .where('e.action', '=', 'integrity_hold.set')
        .where('e.recorded_at', '>=', new Date(step.since))
        .groupBy('e.org_id')
        .orderBy('e.org_id')
        .limit(EXAMPLES)
        .execute();
      return said(
        held,
        ({ org_id }) => `Organisation ${org_id} was put on an integrity hold since the run's first step began.`,
      );
    },
  },
];

/** checks.ts's per-organisation checks but its count of the whole run, which only PL-38's run can compare. */
const COHORT_CHECKS = LOAD_CHECKS.filter(({ countsTheRun }) => countsTheRun !== true);

/** Thrown when the set-based checks are given a role the tenant walls bind: it would see nothing and find nothing wrong. */
export class WalledCheckRole extends Error {
  constructor() {
    super(
      "Stage G's checks were given a database role the tenant walls bind, so they would read no organisation and find nothing wrong. Give them the throwaway copy's agentx_backup connection.",
    );
    this.name = 'WalledCheckRole';
  }
}

/**
 * Every Stage G check of the step, each with what it found wrong. The set-based
 * ones read `everyOrganisation`, which must be a role past the tenant walls on
 * the throwaway copy only (this file's opening says why), in one read-only
 * snapshot; the cohort's go through `app`, each organisation's wall in turn.
 */
export async function stageGChecks(
  copy: { readonly everyOrganisation: Database<MandateWorldTables>; readonly app: Database<MandateWorldTables> },
  step: StageGCheckedStep,
  cohort: readonly CohortAgent[],
): Promise<StageGCheckResult[]> {
  const sets = await copy.everyOrganisation
    .transaction()
    .setIsolationLevel('repeatable read')
    .setAccessMode('read only')
    .execute(async (tx) => {
      const { walled } = await tx
        .selectNoFrom((eb) =>
          eb
            .fn<boolean>('pg_catalog.row_security_active', [eb.cast(eb.val('spend_requests.requests'), 'text')])
            .as('walled'),
        )
        .executeTakeFirstOrThrow();
      if (walled) throw new WalledCheckRole();
      const results: StageGCheckResult[] = [];
      for (const check of SET_CHECKS) results.push({ name: check.name, failures: await check.run(tx, step) });
      return results;
    });
  const cohorts: StageGCheckResult[] = [];
  for (const check of COHORT_CHECKS) {
    cohorts.push({
      name: `the active cohort: ${check.name}`,
      failures: await check.run(copy.app, cohort, step.created),
    });
  }
  return [...sets, ...cohorts];
}
