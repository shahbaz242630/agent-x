// Spend requests (0039): an authority table (ADR-012 §2: "any request
// decision"). Every sealed field below must equal the row's latest signed
// event, and every read goes through the audit module's verifiedState with
// this description. On the product's authority-table list at the request's
// level in the lock order (ADR-006 §6: 8).
//
// The steps that decide, add and move them come with D4 and Phase 3. Order
// claims are not sealed: a scheduled reconciliation checks them (E1).
import type { SignedStateTable } from '@agentx/platform/db';

import { SPEND_REQUEST } from '../domain/spend-request.ts';

/** Everything but the status: fixed when the request is made (0039's `fixed_at_creation`). */
const FIXED = [
  'agent_id',
  'agent_key_id',
  'mandate_id',
  'mandate_version_id',
  'organization_policy_version_id',
  'mandate_policy_version_id',
  'supplier_id',
  'supplier_version_id',
  'funding_source_id',
  'amount_minor',
  'currency',
  'purpose',
  'order_reference',
  'idempotency_key',
  'input_hash',
  'input_hash_key_version',
  'decision',
  'reason_codes',
] as const;

/** A spend request's row, as the signed state reads, records and moves it. */
export const SPEND_REQUESTS = {
  table: 'spend_requests.requests',
  subject: 'spend_request',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'agent_key_id', type: 'uuid' },
    { column: 'mandate_id', type: 'uuid' },
    { column: 'mandate_version_id', type: 'uuid' },
    { column: 'organization_policy_version_id', type: 'uuid' },
    { column: 'mandate_policy_version_id', type: 'uuid' },
    { column: 'supplier_id', type: 'uuid' },
    { column: 'supplier_version_id', type: 'uuid' },
    { column: 'funding_source_id', type: 'uuid' },
    { column: 'amount_minor', type: 'integer' },
    { column: 'currency', type: 'text' },
    { column: 'purpose', type: 'text' },
    { column: 'order_reference', type: 'text' },
    { column: 'idempotency_key', type: 'text' },
    { column: 'input_hash', type: 'text' },
    { column: 'input_hash_key_version', type: 'integer' },
    { column: 'decision', type: 'text' },
    { column: 'reason_codes', type: 'text' },
    { column: 'status', type: 'text' },
  ],
  rules: SPEND_REQUEST,
  fixedAtCreation: FIXED,
  // Each status held to the decisions that can reach it (0039): CI's A3c allows this one check over the status with other columns.
  statusConditions: ['a_status_on_its_decision'],
} as const satisfies SignedStateTable & {
  readonly rules: typeof SPEND_REQUEST;
  readonly fixedAtCreation: readonly string[];
  readonly statusConditions: readonly string[];
};
