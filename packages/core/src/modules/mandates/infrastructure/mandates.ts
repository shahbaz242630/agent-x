// Mandates and their versions (0035), and policies and theirs (0037). All are authority tables (ADR-012 §2):
// every sealed field below must equal the row's latest signed event, and every
// read goes through the audit module's verifiedState with these descriptions.
// On the product's authority-table list at the mandate's level in the lock
// order (ADR-006 §6: 4), the mandate before its versions, then policies
// before theirs.
//
// The steps that add, accept and move them come with their use cases (B2–B4).
import type { SignedStateTable } from '@agentx/platform/db';

import { MANDATE } from '../domain/mandate.ts';

/** A mandate's row, as the signed state reads, records and moves it. */
export const MANDATES = {
  table: 'mandates.mandates',
  subject: 'mandate',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'time_zone', type: 'text' },
    { column: 'split_window_hours', type: 'integer' },
    { column: 'status', type: 'text' },
    { column: 'current_version_id', type: 'uuid' },
    { column: 'pending_version_id', type: 'uuid' },
    { column: 'accepted_by', type: 'uuid' },
    { column: 'accepted_at', type: 'timestamptz' },
  ],
  rules: MANDATE,
  // Fixed when the mandate is made (SEC-LIM-08): 0035's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['agent_id', 'time_zone', 'split_window_hours'],
  // Live or ended with a version in force, waiting with one to accept (0035): CI's A3c
  // allows this one check over the status with other columns.
  statusConditions: ['a_status_on_its_versions'],
} as const satisfies SignedStateTable & {
  readonly rules: typeof MANDATE;
  readonly fixedAtCreation: readonly string[];
  readonly statusConditions: readonly string[];
};

/** A mandate version's row, as the signed state reads and records it: made once, never moved (0035's `made_once`). */
export const MANDATE_VERSIONS = {
  table: 'mandates.versions',
  subject: 'mandate_version',
  fields: [
    { column: 'mandate_id', type: 'uuid' },
    { column: 'version', type: 'integer' },
    { column: 'purpose', type: 'text' },
    { column: 'currency', type: 'text' },
    { column: 'per_order_limit_minor', type: 'integer' },
    { column: 'monthly_limit_minor', type: 'integer' },
    { column: 'approval_threshold_minor', type: 'integer' },
    { column: 'supplier_ids', type: 'text' },
    { column: 'funding_source_id', type: 'uuid' },
    { column: 'split_check', type: 'text' },
    { column: 'consent_limits', type: 'text' },
    { column: 'ends_at', type: 'timestamptz' },
    { column: 'terms_hash', type: 'text' },
    { column: 'drafted_by', type: 'uuid' },
    { column: 'drafted_at', type: 'timestamptz' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };

/** A policy's row, the organisation's or a mandate's (0037): no status, a version in force from the start. */
export const POLICIES = {
  table: 'mandates.policies',
  subject: 'policy',
  fields: [
    { column: 'scope', type: 'text' },
    { column: 'mandate_id', type: 'uuid' },
    { column: 'current_version_id', type: 'uuid' },
  ],
  // What it is a policy of, fixed when it is made: 0037's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['scope', 'mandate_id'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

/** A policy version's row, as the signed state reads and records it: made once, never moved (0037's `made_once`). */
export const POLICY_VERSIONS = {
  table: 'mandates.policy_versions',
  subject: 'policy_version',
  fields: [
    { column: 'policy_id', type: 'uuid' },
    { column: 'version', type: 'integer' },
    { column: 'currency', type: 'text' },
    { column: 'per_order_cap_minor', type: 'integer' },
    { column: 'over_per_order_cap', type: 'text' },
    { column: 'monthly_cap_minor', type: 'integer' },
    { column: 'approval_threshold_minor', type: 'integer' },
    { column: 'supplier_ids', type: 'text' },
    { column: 'rules_hash', type: 'text' },
    { column: 'made_by', type: 'uuid' },
    { column: 'made_at', type: 'timestamptz' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };
