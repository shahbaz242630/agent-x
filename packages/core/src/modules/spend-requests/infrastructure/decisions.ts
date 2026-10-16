// A spend request made and moved by its decision (0039; PRD §4.2, §5.2;
// Phase 2 D4), and read back through its signed state.
//
// D4's decideAndReserve inserts the request VALIDATING with its decision
// (level 8), adds its reservation and order claim while it still is (level
// 11: 0039's `claim_guard` and 0040's `held_for_its_request` refuse them
// after), then signs it (`spend_request.received`, the chain head, level 12)
// and moves it where its decision leads in the same transaction, a second
// signed event: no request is ever left VALIDATING (D1's review). A plain
// insert is safe here as agents.ts says: the row is new, and record('new')
// refuses one the log already holds a state for.
import type { Transaction } from 'kysely';

import {
  type AuditActor,
  type AuditTables,
  type PageAsked,
  type SignedStates,
  type StateCheck,
  type TamperSign,
  type VerifiedPage,
  verifiedPage,
  type VerifiedState,
} from '../../audit/index.ts';
import { type Decision, DECISIONS } from '../../policies/index.ts';
import { isReasonCode, type Money, minorOf, money, oneOf, type ReasonCode } from '../../../shared-kernel/index.ts';
import type { HeldAs } from '../domain/holdings.ts';
import { SPEND_REQUEST, type SpendRequestStatus } from '../domain/spend-request.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type RequestsTransaction = Transaction<SpendRequestsTables & AuditTables>;

/** The decision's event: ALLOW approves, REQUIRE_APPROVAL waits for an approver, the others deny. */
const MOVED_BY: Readonly<Record<Decision, 'allow' | 'require_approval' | 'deny'>> = {
  ALLOW: 'allow',
  REQUIRE_APPROVAL: 'require_approval',
  REQUIRE_NEW_MANDATE: 'deny',
  DENY: 'deny',
};

/** Whether a decision holds capacity: a reservation and an order claim (ADR-006 §10). */
export const holdsCapacity = (decision: Decision): boolean => decision === 'ALLOW' || decision === 'REQUIRE_APPROVAL';

/** A request as decideAndReserve makes it: what the agent asked, what it was weighed against, and the decision. */
export interface NewRequest {
  readonly orgId: string;
  readonly id: string;
  readonly agentId: string;
  readonly agentKeyId: string;
  /** The agent's mandate and its version in force, or null for none. */
  readonly mandate: { readonly id: string; readonly versionId: string } | null;
  readonly organizationPolicyVersionId: string | null;
  readonly mandatePolicyVersionId: string | null;
  readonly supplierId: string;
  /** Null when the supplier isn't the organisation's. */
  readonly supplierVersionId: string | null;
  readonly fundingSourceId: string;
  readonly amount: Money;
  readonly purpose: string;
  readonly orderReference: string;
  readonly idempotencyKey: string;
  /** The keyed hash of decisionInputText, lower-case hex, and its key's version. */
  readonly inputHash: string;
  readonly inputHashKeyVersion: number;
  /** decisionFacts: what was weighed that no record keeps, sealed with the decision (G3). */
  readonly weighed: Readonly<Record<string, string | boolean | null>>;
  readonly decision: Decision;
  readonly reasons: readonly ReasonCode[];
  readonly createdAt: Date;
}

/** Inserts the request, VALIDATING with its decision, unsigned yet: its reservation and claim go in next, then `sign`. */
export async function insertRequest(tx: RequestsTransaction, request: NewRequest): Promise<void> {
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') in signRequest (see the top of this file)
    .insertInto(SPEND_REQUESTS.table)
    .values({ org_id: request.orgId, id: request.id, ...fieldsOf(request), created_at: request.createdAt })
    .execute();
}

/**
 * Signs the request just inserted (`spend_request.received`) and moves it
 * where its decision leads (`spend_request.decided`, with the reasons, and,
 * when it holds capacity, its reservation's month and instant and its payee
 * seal: `held`).
 */
export async function signRequest(
  tx: RequestsTransaction,
  states: SignedStates,
  request: NewRequest,
  actor: AuditActor,
  held: HeldAs | null,
): Promise<void> {
  const key = { orgId: request.orgId, id: request.id };
  await states.record(tx, SPEND_REQUESTS, key, 'new', fieldsOf(request), {
    actor,
    action: 'spend_request.received',
    details: { agentKeyId: request.agentKeyId },
  });
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, MOVED_BY[request.decision], {
    actor,
    action: 'spend_request.decided',
    details: {
      decision: request.decision,
      reasons: request.reasons.join(' '),
      ...request.weighed,
      // What its reservation and claim were made as, sealed with the decision, for the holdings check (E1, E1b).
      ...(held === null
        ? {}
        : {
            heldMonth: held.month,
            heldAt: held.reservedAt.toISOString(),
            payeeSeal: held.payee.mac,
            payeeSealKeyVersion: held.payee.keyVersion,
          }),
    },
  });
  // Just recorded VALIDATING by this transaction, its move its decision's: anything else is something past the app.
  if (moved.outcome !== 'changed') throw new Error(`A new spend request didn't move as decided: ${moved.outcome}`);
}

/** The authority fields of a new request, as the row and its first signed state hold them. */
const fieldsOf = (request: NewRequest) => ({
  agent_id: request.agentId,
  agent_key_id: request.agentKeyId,
  mandate_id: request.mandate?.id ?? null,
  mandate_version_id: request.mandate?.versionId ?? null,
  organization_policy_version_id: request.organizationPolicyVersionId,
  mandate_policy_version_id: request.mandatePolicyVersionId,
  supplier_id: request.supplierId,
  supplier_version_id: request.supplierVersionId,
  funding_source_id: request.fundingSourceId,
  amount_minor: request.amount.minor,
  currency: request.amount.currency,
  purpose: request.purpose,
  order_reference: request.orderReference,
  idempotency_key: request.idempotencyKey,
  input_hash: request.inputHash,
  input_hash_key_version: request.inputHashKeyVersion,
  decision: request.decision,
  reason_codes: request.reasons.length === 0 ? null : request.reasons.join(' '),
  status: SPEND_REQUEST.initial,
});

/** A spend request, as its signed state says. */
export interface SpendRequestRecord {
  readonly id: string;
  readonly agentId: string;
  readonly mandateId: string | null;
  readonly supplierId: string;
  readonly fundingSourceId: string;
  readonly amount: Money;
  /** The agent's own words, as it wrote them: shown only labelled as its (Phase 3 B3), never in an email. */
  readonly purpose: string;
  readonly orderReference: string;
  readonly decision: Decision;
  readonly reasons: readonly ReasonCode[];
  readonly status: SpendRequestStatus;
}

/**
 * What a request was decided against, by the versions its signed state names
 * (Phase 3 B4b): an approval weighs it again and refuses it if any is no
 * longer the one in force. Null for none (no mandate, or a supplier not the
 * organisation's). Not the policies: an approval weighs it under them as they
 * now are.
 */
export interface DecidedAgainst {
  readonly agentKeyId: string;
  readonly mandateVersionId: string | null;
  readonly supplierVersionId: string | null;
}

/** The versions the request's verified state names (requestOf's `state`). */
export function decidedAgainst(state: VerifiedState): DecidedAgainst {
  const field = (column: string): string | null => state.fields.get(column) ?? null;
  const agentKeyId = field('agent_key_id');
  // The table holds every request to the key it came with (0039's NOT NULL).
  if (agentKeyId === null) throw new Error('A verified spend request names no agent key');
  return {
    agentKeyId,
    mandateVersionId: field('mandate_version_id'),
    supplierVersionId: field('supplier_version_id'),
  };
}

/** A spend request read by its ID and verified; missing; or tampered with. */
export type SpendRequestCheck =
  | { readonly outcome: 'found'; readonly request: SpendRequestRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The request, by its ID, read and verified, locked `share` (or `change`, for
 * a move: D7, D8), in the caller's transaction, which must be
 * withSignedStates' for its organisation: missing for none of the
 * organisation's; tampered with, the alarm raised.
 */
export async function requestOf(
  tx: RequestsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change' = 'share',
): Promise<SpendRequestCheck> {
  return requestFrom(key, await states.verifiedState(tx, SPEND_REQUESTS, key, lock));
}

/**
 * Many requests of the organisation, as requestOf reads one, in two
 * statements (SignedStates.verifiedStates): each ID asked, in lower case,
 * with its check.
 */
export async function requestsOf(
  tx: RequestsTransaction,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
): Promise<ReadonlyMap<string, SpendRequestCheck>> {
  const checks = await states.verifiedStates(tx, SPEND_REQUESTS, orgId, ids);
  return new Map([...checks].map(([id, state]) => [id, requestFrom({ orgId, id }, state)]));
}

/** The most spend requests a page gives. */
export const MOST_REQUESTS_A_PAGE = 50;

/** A request as a list shows it: its signed state, and when that state was signed (its latest move, sealed). */
export interface SpendRequestListed {
  readonly request: SpendRequestRecord;
  readonly changedAt: Date;
  /** The supplier's details it was decided under (E5c: a waiting one moved since may need a re-check). */
  readonly supplierVersionId: string | null;
}

/**
 * A page of the organisation's spend requests, each read (`share`) and
 * verified, in the caller's transaction, which must be withSignedStates' for
 * it (verifiedPage): every request, newest first; or those waiting for
 * approval, oldest first, the soonest to expire at the top (Phase 3 B3).
 */
export async function requestsPage(
  tx: RequestsTransaction,
  states: SignedStates,
  orgId: string,
  page: PageAsked,
  which: 'all' | 'waiting',
): Promise<VerifiedPage<SpendRequestListed>> {
  return verifiedPage(
    tx,
    states,
    SPEND_REQUESTS,
    orgId,
    page,
    which === 'all'
      ? { most: MOST_REQUESTS_A_PAGE, rows: 'spend requests', order: 'newest' }
      : { most: MOST_REQUESTS_A_PAGE, rows: 'spend requests', statuses: ['APPROVAL_REQUIRED'] },
    (verified) => ({
      outcome: 'shown',
      items: verified.map(({ id, state }) => ({
        request: recordFrom(id, state),
        changedAt: state.recordedAt,
        supplierVersionId: decidedAgainst(state).supplierVersionId,
      })),
    }),
  );
}

/** The request a verified state holds; any other check as it is. */
function requestFrom(key: { readonly orgId: string; readonly id: string }, state: StateCheck): SpendRequestCheck {
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', request: recordFrom(key.id, state), state };
}

/** The request a verified state holds. */
function recordFrom(id: string, state: VerifiedState): SpendRequestRecord {
  const field = (column: string): string | undefined => state.fields.get(column) ?? undefined;
  const agentId = field('agent_id');
  const supplierId = field('supplier_id');
  const fundingSourceId = field('funding_source_id');
  const currency = field('currency');
  const purpose = field('purpose');
  const orderReference = field('order_reference');
  const minor = minorOf(state.fields.get('amount_minor'));
  const decision = oneOf(DECISIONS, state.fields.get('decision'));
  const status = oneOf(SPEND_REQUEST.states, state.fields.get('status'));
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    agentId === undefined ||
    supplierId === undefined ||
    fundingSourceId === undefined ||
    currency === undefined ||
    purpose === undefined ||
    orderReference === undefined ||
    minor === undefined ||
    decision === undefined ||
    status === undefined
  ) {
    throw new Error(`A verified spend request holds a field that isn't one of its own: ${id}`);
  }
  const reasons = field('reason_codes')?.split(' ') ?? [];
  if (!reasons.every(isReasonCode)) {
    throw new Error(`A verified spend request holds a reason that isn't one: ${id}`);
  }
  return {
    id: id.toLowerCase(),
    agentId,
    mandateId: field('mandate_id') ?? null,
    supplierId,
    fundingSourceId,
    amount: money(minor, currency),
    purpose,
    orderReference,
    decision,
    reasons,
    status,
  };
}
