// Mandates and their versions (0034). Both are authority tables (ADR-012 §2),
// so a mandate's agent, time zone, split window, status, version in force
// with its acceptance, and waiting draft, and everything a version says (its
// mandate and number, purpose, currency, limits, allow-list, source, split
// check, consent-limits setting, end, terms hash, and who drafted it and
// when) must equal the row's latest signed event, and every read goes through
// the audit module's verifiedState with the descriptions below. Both are on
// the product's authority-table list (packages/core/src/authority-tables.ts),
// at the mandate's level in the lock order (ADR-006 §6: 4), the mandate
// before its versions.
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
  // A live or ended mandate has a version in force; one waiting has one to accept (0034): CI's A3c allows this one check over the status with other columns.
  statusConditions: ['a_status_on_its_versions'],
} as const satisfies SignedStateTable & {
  readonly rules: typeof MANDATE;
  readonly statusConditions: readonly string[];
};

/** A mandate version's row, as the signed state reads and records it: made once, never moved (0034's `made_once`). */
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
