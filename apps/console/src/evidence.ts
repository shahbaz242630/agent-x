// A spend request's evidence as the console reads it (6C2; BR-16; decision 24:
// admins only): POST /v1/spend-requests/{id}/evidence-exports answers the
// bundle whole (SpendRequestEvidence, spend-request-evidence.ts in the API),
// the download recorded in the audit log first. So it is asked for once a
// visit of its page, never refetched: one idempotency key a visit, kept outside
// the page so a remount (the shell swapped to a failure and back, StrictMode's
// second effect) sends the same key, which the API answers with the same
// record; a "try again" is the same download again too.
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';

import { api, isIntegrityFailed, isSignedOut, isUuid } from './api.ts';
import type { LogEvent } from './logs.ts';
import type { PaymentStatus } from './payments.ts';
import { refusalText } from './refusals.ts';
import type { Reason, Status } from './requests.ts';
import { endSession } from './session.tsx';
import { t } from './text.ts';

/** A person's step-up-confirmed approval or reject, from its signed event. */
interface PersonDecision {
  readonly eventId: string;
  readonly byUserId: string;
  readonly at: string;
  readonly changeHash: string | null;
  readonly stepUpChallengeId: string | null;
}

export interface Evidence {
  readonly id: string;
  readonly recordSeq: string;
  readonly upToSeq: string;
  readonly spendRequest: {
    readonly id: string;
    readonly status: Status;
    readonly decision: 'DENY' | 'REQUIRE_NEW_MANDATE' | 'REQUIRE_APPROVAL' | 'ALLOW';
    readonly reasons: readonly Reason[];
    readonly amountMinor: number;
    readonly currency: string;
    readonly orderReference: string;
    readonly bankReference: string;
    readonly purpose: string;
    readonly idempotencyKey: string | null;
    readonly inputHash: string | null;
    readonly decidedAt: string | null;
    readonly changedAt: string;
    readonly expiresAt: string | null;
  };
  readonly agent: { readonly id: string; readonly name: string; readonly keyId: string | null };
  readonly mandate: {
    readonly id: string;
    readonly versionId: string | null;
    readonly acceptance: LogEvent | null;
  } | null;
  readonly policies: {
    readonly organizationPolicyVersionId: string | null;
    readonly mandatePolicyVersionId: string | null;
  };
  readonly supplier: {
    readonly id: string;
    readonly name: string;
    readonly version: {
      readonly id: string;
      readonly number: number;
      readonly name: string;
      readonly verification: LogEvent | null;
    };
  };
  readonly fundingSource: {
    readonly id: string;
    readonly holderName: string;
    readonly hint: string;
    readonly partner: string;
  };
  readonly approval: PersonDecision | null;
  readonly rejection: (PersonDecision & { readonly reason: string }) | null;
  readonly voiding: { readonly eventId: string; readonly at: string; readonly reasons: readonly Reason[] } | null;
  readonly reservation: {
    readonly state: 'HELD' | 'FINALISED' | 'RELEASED' | 'BLOCKED_UNKNOWN';
    readonly amountMinor: number;
    readonly currency: string;
    readonly month: string;
    readonly reservedAt: string;
  } | null;
  readonly payment: {
    readonly instruction: {
      readonly id: string;
      readonly route: string;
      readonly routeReason: string;
      readonly partner: string;
      readonly partnerLegalEntityId: string;
      readonly partnerLicenceRef: string;
      readonly paymentReference: string;
      readonly intentHash: string;
      readonly createdAt: string;
    };
    readonly id: string;
    readonly status: PaymentStatus;
    readonly partnerReference: string | null;
    readonly bankStatus: string | null;
    readonly rejectCode: string | null;
    readonly bankChangedAt: string | null;
    readonly createdAt: string;
    readonly changedAt: string;
    readonly reconciliation: {
      readonly contradicted: boolean;
      readonly markableFrom: string | null;
      readonly openProposalId: string | null;
    };
  } | null;
  readonly events: readonly LogEvent[];
}

/** The payment in a bundle, once handed off: its instruction and where its reconciliation stands. */
export type EvidencePayment = NonNullable<Evidence['payment']>;

export interface EvidenceAnswer {
  readonly evidence: Evidence;
}

/** The evidence's refusals the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'EVIDENCE_EXPORTS_SPENT',
  'EVIDENCE_TOO_LARGE',
  'EVIDENCE_CHANGED_WHILE_READING',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** What a refused or failed evidence download says: a record failing its check (503) said as itself. */
export function evidenceRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('evidence.integrity');
  return refusalText(error, REFUSALS, 'evidence.refused');
}

/** How long a visit's key is kept for a remount: a deliberate visit after it is a new download. */
const VISIT_MS = 10 * 60_000;

/** Each page visit's idempotency key and when it was made, by organisation and request: a module's own, never stored. */
const visits = new Map<string, { readonly key: string; readonly at: number }>();

/** The key of this visit of the request's page: the one made within VISIT_MS, else a new one (the old dropped). */
function visitKey(organization: string, id: string, now: number = Date.now()): string {
  for (const [name, visit] of visits) if (now - visit.at > VISIT_MS) visits.delete(name);
  const name = `${organization}:${id}`;
  const kept = visits.get(name);
  if (kept !== undefined) return kept.key;
  const key = crypto.randomUUID();
  visits.set(name, { key, at: now });
  return key;
}

/**
 * The request's evidence, asked for once while `allowed` (an admin, a request's
 * ID): sent once a visit (a ref, kept over StrictMode's second run of the
 * effect), with one idempotency key the visit keeps, so `again` is the same
 * download, never a second one. A 401 ends the session.
 */
export function useEvidence(id: string, organization: string, allowed: boolean) {
  const queries = useQueryClient();
  const asked = useMutation({
    mutationFn: () =>
      api.post<EvidenceAnswer>(`/v1/spend-requests/${encodeURIComponent(id)}/evidence-exports`, {
        organization,
        body: {},
        idempotencyKey: visitKey(organization, id),
      }),
    onError: (error) => {
      if (isSignedOut(error)) endSession(queries);
    },
  });
  const sent = useRef(false);
  const { mutate } = asked;
  const wanted = allowed && isUuid(id);
  useEffect(() => {
    if (sent.current || !wanted) return;
    sent.current = true;
    mutate();
  }, [wanted, mutate]);
  return asked;
}
