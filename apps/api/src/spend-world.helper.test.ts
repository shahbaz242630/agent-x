// The world the tests of ending a spend request share (Phase 2 D7, D8): the
// mandate test world, whose agent has a key and a mandate in force (approval
// above AED 1,000) and both suppliers verified; the agent's requests decided
// through decideAndReserve; and reads of where a request stands, what it
// holds and the agent's month.
import type { FixedClock, TestDatabase } from '@agentx/testing';
import { AGENTS } from '@agentx/core/modules/agents';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { monthSpent } from '@agentx/core/modules/limit-reservations';
import { policyOf, setPolicy } from '@agentx/core/modules/mandates';
import {
  type ApprovalWaitHours,
  type Pausable,
  type PendingChoice,
  requestOf,
} from '@agentx/core/modules/spend-requests';
import {
  changeDetails,
  nextVersionNumber,
  SUPPLIERS,
  supplierOf,
  suspendSupplier,
  versionOf,
} from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import { waitChoiceDetails } from './approval-wait-choice.ts';
import { type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import { capChoiceDetails, SUGGESTED_MONTHLY_CAP_MINOR } from './monthly-cap-choice.ts';
import { AED, mandateWorld, type MandateWorldTables, OPERATOR, type World } from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';
import { choiceDetails, SUSPENDS } from './suspensions.ts';

export type SpendWorldTables = MandateWorldTables;

/**
 * The request's claim or reservation released, or its reservation's amount
 * halved, by the tables' owner with their guards off: as only something past
 * the app could (G2).
 */
export async function changedPastTheApp(
  database: TestDatabase,
  org: string,
  requestId: string,
  what: 'claim released' | 'reservation released' | 'amount halved',
): Promise<void> {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [org]);
    await owner.query('begin');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await owner.query('alter table spend_requests.order_claims disable trigger user');
    if (what === 'claim released') {
      await owner.query('update spend_requests.order_claims set released_at = now() where request_id = $1', [
        requestId,
      ]);
    } else if (what === 'reservation released') {
      await owner.query(
        "update limit_reservations.reservations set state = 'RELEASED', settled_at = now() where request_id = $1",
        [requestId],
      );
    } else {
      await owner.query(
        'update limit_reservations.reservations set amount_minor = amount_minor / 2 where request_id = $1',
        [requestId],
      );
    }
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('alter table spend_requests.order_claims enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d7';

export function spendWorld({
  app,
  clock,
  ids,
  name,
  registry,
  decisions,
  keyring,
}: {
  readonly app: () => Database<SpendWorldTables>;
  readonly clock: () => FixedClock;
  readonly ids: IdGenerator;
  readonly name: string;
  readonly registry: () => MandateRegistry;
  readonly decisions: () => SpendRequestDecisions;
  /** The keys the records are signed with: a running stack's for the tamper suite (mandateWorld's `keyring`). */
  readonly keyring?: KeyProvider;
}) {
  const shared = mandateWorld({ app, clock, ids, name, ...(keyring === undefined ? {} : { keyring }) });

  /** A world whose agent has a key and a mandate in force (approval above AED 1,000), both suppliers verified. */
  async function ready() {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry(), w, { approvalThreshold: AED(100_000n) });
    return { w, acting: await shared.agentKey(w) };
  }

  let keysUsed = 0;
  /** The agent's request, decided: AED 2,000 to the first supplier by default, so it waits for approval. */
  const ask = async (acting: AgentActing, w: World, overrides: Partial<SpendAskedByAgent> = {}) => {
    keysUsed += 1;
    const asked: SpendAskedByAgent = {
      amount: AED(200_000n),
      supplierId: w.suppliers[0] ?? '',
      fundingSourceId: w.source,
      orderReference: `INV-${String(keysUsed)}`,
      purpose: 'Printer paper',
      ...overrides,
    };
    const answer = await decisions().decideAndReserve(
      acting,
      {
        orgId: acting.orgId,
        client: { kind: 'agent', id: acting.agentId },
        operation: DECIDE_OPERATION,
        key: `${name}-${String(keysUsed)}`,
        payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
      },
      asked,
      CORRELATION,
    );
    if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
    return answer.request;
  };

  /** The request's status, as its signed state says. */
  const statusOf = (w: World, id: string) =>
    withSignedStates(app(), w.org, shared.quiet(), async (tx, states) => {
      const read = await requestOf(tx, states, { orgId: w.org, id });
      return read.outcome === 'found' ? read.request.status : read.outcome;
    });

  /** What the request holds: its reservation's state and whether its claim is released. */
  const holdingsOf = (w: World, id: string) =>
    withTenant(app(), w.org, async (tx) => {
      const reservation = await tx
        .selectFrom('limit_reservations.reservations')
        .select('state')
        .where('request_id', '=', id)
        .executeTakeFirstOrThrow();
      const claim = await tx
        .selectFrom('spend_requests.order_claims')
        .select('released_at')
        .where('request_id', '=', id)
        .executeTakeFirstOrThrow();
      return { reservation: reservation.state, released: claim.released_at !== null };
    });

  /** What the agent's month holds: every reservation but a released one. */
  const spentOf = (w: World, acting: AgentActing) =>
    withTenant(app(), w.org, async (tx) => {
      const { month } = await tx
        .selectFrom('limit_reservations.reservations')
        .select('month')
        .where('agent_id', '=', acting.agentId)
        .executeTakeFirstOrThrow();
      return monthSpent(tx, { agentId: acting.agentId, month, currency: 'AED' });
    });

  /** A change past the use cases, signed, as each brake or edit would make it, in the organisation's transaction. */
  const signed = <T>(
    w: World,
    change: (tx: DatabaseTransaction<SpendWorldTables>, states: SignedStates) => Promise<T>,
  ) => withSignedStates(app(), w.org, shared.quiet(), change);

  /**
   * The organisation's approval wait chosen as `hours` past the use case (E6),
   * its rules and cap choice as the world's own: requests decided after it
   * seal it.
   */
  const waitChosen = (w: World, hours: ApprovalWaitHours) =>
    signed(w, async (tx, states) => {
      const read = await policyOf(tx, states, { orgId: w.org, id: w.org }, 'change');
      return setPolicy(tx, states, {
        orgId: w.org,
        existing: read.outcome === 'found' ? read : null,
        scope: 'organization',
        mandateId: null,
        versionId: ids.next(),
        rules: {
          currency: 'AED',
          perOrderCap: null,
          monthlyCap: AED(BigInt(SUGGESTED_MONTHLY_CAP_MINOR)),
          approvalThreshold: null,
          supplierIds: null,
        },
        madeBy: w.admin.membershipId,
        madeAt: clock().now(),
        actor: { type: 'user', id: w.admin.userId },
        details: { ...capChoiceDetails('amount'), ...waitChoiceDetails(hours) },
      });
    });

  /** The world's own one: its agent, the mandate named, its source, its first supplier. */
  const idOf = (w: World, mandateId: string, which: Pausable): string =>
    ({ organization: w.org, agent: w.agent, mandate: mandateId, source: w.source, supplier: w.suppliers[0] ?? '' })[
      which
    ];

  /** Suspends it with the choice, as its use case records one (suspensions.ts), or lifts it; past the use case. */
  const moved = (w: World, mandateId: string, which: Pausable, choice: PendingChoice | 'resume') =>
    signed(w, async (tx, states): Promise<unknown> => {
      const key = { orgId: w.org, id: idOf(w, mandateId, which) };
      const suspend = choice !== 'resume';
      const change = {
        actor: OPERATOR,
        action: suspend ? SUSPENDS[which].action : `${SUSPENDS[which].type}.resumed`,
        details: suspend ? choiceDetails(choice) : {},
      };
      switch (which) {
        case 'organization':
          return states.changeStatus(tx, ORGANIZATIONS, key, suspend ? 'freeze' : 'unfreeze', change);
        case 'agent':
          return states.changeStatus(tx, AGENTS, key, suspend ? 'suspend' : 'reactivate', change);
        case 'mandate':
          return states.changeStatus(tx, MANDATES, key, suspend ? 'suspend' : 'resume', change);
        case 'source':
          return states.changeStatus(tx, SOURCES, key, suspend ? 'suspend' : 'reactivate', change);
        case 'supplier':
          return states.changeStatus(tx, SUPPLIERS, key, suspend ? 'suspend' : 'reactivate_verified', change);
      }
    });

  /** The agent's mandate in force: the world's only one. */
  const mandateIdOf = (w: World) =>
    withTenant(app(), w.org, async (tx) => {
      const { id } = await tx.selectFrom('mandates.mandates').select('id').executeTakeFirstOrThrow();
      return id;
    });

  /**
   * The supplier's details changed (a new version) with its event's `details`, then verified again: only its version
   * differs, and its email where one is given.
   */
  async function detailsChanged(
    w: World,
    supplierId: string,
    details?: Record<string, string>,
    email: string | null = null,
  ) {
    await signed(w, async (tx, states) => {
      const found = await supplierOf(tx, states, { orgId: w.org, id: supplierId }, 'change');
      if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
      const current = await versionOf(tx, states, { orgId: w.org, id: found.supplier.currentVersionId }, supplierId);
      if (current.outcome !== 'found') throw new Error(`no version: ${current.outcome}`);
      await changeDetails(tx, states, shared.quiet().keys, { orgId: w.org, id: supplierId }, found, {
        orgId: w.org,
        id: ids.next(),
        supplierId,
        version: await nextVersionNumber(tx, w.org, supplierId),
        supplier: {
          displayName: 'Gulf Office Supplies Trading LLC',
          contacts: { phone: '+971501234567', email, tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
        enteredBy: ids.next(),
        enteredAt: clock().now(),
        actor: OPERATOR,
        follows: current.version,
        ...(details === undefined ? {} : { details }),
      });
    });
    await shared.verified(w, supplierId);
  }

  /**
   * Each brake on what a request was decided under, made past its use case as
   * its route would, on the agent's mandate in force and the first supplier:
   * after each, the request's authority no longer stands (B4b, C1).
   */
  const STOPS = {
    'the mandate superseded': async (w: World, mandateId: string) => {
      const redrafted = await registry().redraft(
        w.admin,
        shared.keyed(w.admin, REDRAFT_OPERATION),
        mandateId,
        {
          terms: shared.termsOf(w, { purpose: 'Office supplies, renewed', approvalThreshold: AED(100_000n) }),
          overLimit: 'refuse',
        },
        CORRELATION,
      );
      if (redrafted.outcome !== 'drafted') throw new Error(`not drafted: ${redrafted.outcome}`);
      await shared.acceptedPastTheUseCase(w, mandateId);
    },
    'the mandate suspended': (w: World, mandateId: string) => shared.movedPastTheUseCase(w, mandateId, 'suspend'),
    'the supplier’s details changed': (w: World) => detailsChanged(w, w.suppliers[0] ?? ''),
    'the supplier suspended': (w: World) =>
      signed(w, async (tx, states) => {
        const key = { orgId: w.org, id: w.suppliers[0] ?? '' };
        const found = await supplierOf(tx, states, key, 'change');
        if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
        await suspendSupplier(tx, states, key, found, { actor: OPERATOR });
      }),
    'the source suspended by the partner': (w: World) => shared.partnerSays(w, { availability: 'SUSPENDED' }),
    'the source suspended by the organisation': (w: World) =>
      signed(w, (tx, states) =>
        states.changeStatus(tx, SOURCES, { orgId: w.org, id: w.source }, 'suspend', {
          actor: OPERATOR,
          action: 'funding_source.suspended',
          details: {},
        }),
      ),
    'the agent suspended': (w: World) =>
      signed(w, (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: {},
        }),
      ),
  } as const;

  return {
    ...shared,
    ready,
    ask,
    statusOf,
    holdingsOf,
    spentOf,
    signed,
    waitChosen,
    mandateIdOf,
    detailsChanged,
    idOf,
    moved,
    STOPS,
  };
}
