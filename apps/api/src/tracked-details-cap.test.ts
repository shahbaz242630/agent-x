// TR-3 residual 75 (S209): every tracked state event carries one detail more, its names of earlier events
// (trackedBefore). An event's details hold at most 32 entries of at most 1,024 characters (event-facts.ts): this holds
// the largest each tracked action is recorded with, plus what the platform adds, to both limits, its names written at
// the most a version and a seq can be, every action its table tracks named.
import { AGENTS } from '@agentx/core/modules/agents';
import { TRACKED_BEFORE, withTracked } from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import type { SignedStateTable } from '@agentx/platform/db';
import { describe, expect, it } from 'vitest';

import {
  choiceDetails,
  detailsChoiceDetails,
  reactivationChoiceDetails,
  sourceReactivationChoiceDetails,
  unfreezeChoiceDetails,
} from './suspensions.ts';

/** The most entries and the longest text an event's details may hold (event-facts.ts). */
const MOST_ENTRIES = 32;
const LONGEST_TEXT = 1024;

/** What the platform adds to every state event: its move, its seal, the request's correlation, and its names. */
const PLATFORM = ['statusFrom', 'statusTo', 'stateFingerprint', 'stateKeyVersion', 'correlationId', TRACKED_BEFORE];

/** A step-up's evidence (stepUpDetails). */
const STEP_UP = ['stepUpChallengeId', 'changeHash', 'signedInAt', 'methods', 'proofHash', 'verifiedAt'];

/** An approval's evidence: its step-up, the versions weighed under, and a re-check shown (spend-request-approvals.ts). */
const APPROVAL = [
  ...STEP_UP,
  'organizationPolicyVersionId',
  'mandatePolicyVersionId',
  'recheckedFromSupplierVersionId',
  'recheckedSupplierVersionId',
  'recheckedDecision',
  'recheckedReasons',
  'recheckStatementVersion',
];

const keysOf = (details: object) => Object.keys(details);

/** The largest details each tracked action is recorded with by the app, as its builders make them. */
const LARGEST: Readonly<Record<string, readonly string[]>> = {
  'organization.freeze': [...keysOf(choiceDetails('cancel')), 'reason'],
  'organization.unfreeze': [...STEP_UP, 'reason', ...keysOf(unfreezeChoiceDetails('cancel'))],
  'organization.history_named': [],
  'agent.suspended': [...keysOf(choiceDetails('cancel')), 'reason'],
  'mandate.suspended': [...STEP_UP, ...keysOf(choiceDetails('cancel')), 'reason'],
  'mandate.accepted': [...STEP_UP, 'termsHash', 'versionId', 'carryRest', 'draftId'],
  'funding_source.suspended': [...STEP_UP, ...keysOf(choiceDetails('cancel')), 'reason'],
  'funding_source.consent_lapsed': ['consentId', 'consentExpiresAt', 'pendingRequests', 'chosen'],
  'funding_source.consent_expiry_chosen': ['pendingRequests', 'pendingStatementVersion', 'lapsedConsentId'],
  'funding_source.reactivated': [...STEP_UP, ...keysOf(sourceReactivationChoiceDetails('cancel'))],
  'supplier.suspend': [...STEP_UP, ...keysOf(choiceDetails('cancel')), 'reason'],
  'supplier.unverify': [...STEP_UP, ...keysOf(choiceDetails('cancel')), 'reason', 'versionId'],
  'supplier.pending_requests_chosen': ['pendingRequests', 'pendingStatementVersion'],
  'supplier.reactivate': [...STEP_UP, ...keysOf(reactivationChoiceDetails('cancel'))],
  'supplier.reactivate_verified': [...STEP_UP, ...keysOf(reactivationChoiceDetails('cancel'))],
  'supplier.details_changed': [...STEP_UP, ...keysOf(detailsChoiceDetails('pause')), 'versionId', 'followsVersionId'],
  'supplier.payee_change_confirmed': [...STEP_UP, 'versionId', 'followsVersionId', 'path', 'nameCheck'],
  'spend_request.approved': APPROVAL,
  'spend_request.rejected': [...APPROVAL, 'causes', 'reason', 'capacityKept', 'keptAmountMinor'],
  'spend_request.voided': ['reason', 'causes', 'capacityKept', 'keptAmountMinor'],
  'spend_request.expired': ['reason', 'capacityKept', 'keptAmountMinor'],
  'spend_request.cancelled': [...STEP_UP, 'reason', 'capacityKept', 'keptAmountMinor'],
};

const TRACKING: readonly SignedStateTable[] = [ORGANIZATIONS, AGENTS, MANDATES, SOURCES, SUPPLIERS, SPEND_REQUESTS];

/** The names a tracked event carries at their longest: every tracked action named at the most a version and seq can be. */
function longestNames(table: SignedStateTable): string {
  const seq = 9_223_372_036_854_775_807n;
  const version = Number.MAX_SAFE_INTEGER;
  const tracks = table.tracks ?? [];
  const last = new Map(tracks.map((action) => [action, { version, seq }]));
  const { details } = withTracked(
    table,
    { version, trail: { seq, action: tracks[0] ?? 'x.y', tracked: { from: seq, last } } },
    {},
  );
  return String(details[TRACKED_BEFORE]);
}

describe('SEC-DB-20 each tracked state event’s details within their limits, its names added (TR-3 residual 75)', () => {
  it.each(TRACKING.map((table) => [table.subject, table] as const))(
    '%s: its names at their longest fit one detail’s text',
    (_subject, table) => {
      expect(longestNames(table).length).toBeLessThanOrEqual(LONGEST_TEXT);
    },
  );

  it('every tracked action is audited here, and none recorded with more entries than an event may hold', () => {
    const tracked = TRACKING.flatMap((table) => table.tracks ?? []);
    expect(Object.keys(LARGEST).sort()).toEqual([...tracked].sort());
    for (const [action, keys] of Object.entries(LARGEST)) {
      expect(new Set([...keys, ...PLATFORM]).size, action).toBeLessThanOrEqual(MOST_ENTRIES);
    }
  });
});
