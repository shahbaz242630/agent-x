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

import type { AuditActor, AuditTables, SignedStates } from '../../audit/index.ts';
import type { Decision } from '../../policies/index.ts';
import { isReasonCode, type Money, minorOf, money, oneOf, type ReasonCode } from '../../../shared-kernel/index.ts';
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
 * where its decision leads (`spend_request.decided`, with the reasons).
 */
export async function signRequest(
  tx: RequestsTransaction,
  states: SignedStates,
  request: NewRequest,
  actor: AuditActor,
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
    details: { decision: request.decision, reasons: request.reasons.join(' ') },
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
  readonly orderReference: string;
  readonly decision: Decision;
  readonly reasons: readonly ReasonCode[];
  readonly status: SpendRequestStatus;
}

const DECISIONS: readonly Decision[] = ['ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'REQUIRE_NEW_MANDATE'];

/**
 * The request, by its ID, read (`share`) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation: missing
 * for none of the organisation's; tampered with, the alarm raised.
 */
export async function requestOf(
  tx: RequestsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
) {
  const state = await states.verifiedState(tx, SPEND_REQUESTS, key, 'share');
  if (state.outcome !== 'verified') return state;
  const field = (column: string): string | undefined => state.fields.get(column) ?? undefined;
  const [agentId, supplierId, fundingSourceId, currency, orderReference] = [
    'agent_id',
    'supplier_id',
    'funding_source_id',
    'currency',
    'order_reference',
  ].map(field);
  const minor = minorOf(state.fields.get('amount_minor'));
  const decision = oneOf(DECISIONS, state.fields.get('decision'));
  const status = oneOf(SPEND_REQUEST.states, state.fields.get('status'));
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    agentId === undefined ||
    supplierId === undefined ||
    fundingSourceId === undefined ||
    currency === undefined ||
    orderReference === undefined ||
    minor === undefined ||
    decision === undefined ||
    status === undefined
  ) {
    throw new Error(`A verified spend request holds a field that isn't one of its own: ${key.id}`);
  }
  const codes = state.fields.get('reason_codes');
  const reasons = codes === null || codes === undefined ? [] : codes.split(' ');
  if (!reasons.every(isReasonCode))
    throw new Error(`A verified spend request holds a reason that isn't one: ${key.id}`);
  return {
    outcome: 'found' as const,
    request: {
      id: key.id.toLowerCase(),
      agentId,
      mandateId: field('mandate_id') ?? null,
      supplierId,
      fundingSourceId,
      amount: money(minor, currency),
      orderReference,
      decision,
      reasons,
      status,
    } satisfies SpendRequestRecord,
    state,
  };
}
