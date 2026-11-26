// A spend request's evidence as the console reads and downloads it (6C2,
// 6C2c; BR-16; decision 24: admins only, and reading on screen is a page read,
// not logged, while a download is logged and capped):
// - GET /v1/spend-requests/{id}/evidence answers the bundle whole
//   (SpendRequestEvidenceRead, spend-request-evidence.ts in the API), writing
//   nothing: a query like any other, safe to ask again on a remount or a
//   return to the tab.
// - POST /v1/spend-requests/{id}/evidence-exports is the download, recorded in
//   the audit log first and capped at 20 an hour: one idempotency key a press,
//   kept after a failure so pressing again is the same download (the API
//   answers its record again), a fresh one after a download saved. Its answer
//   is saved as it came, `evidence-<id>.json`.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRef } from 'react';

import { api, isIntegrityFailed, isSignedOut, isUuid } from './api.ts';
import { saveJson } from './download.ts';
import { type LogEvent, readRetry } from './logs.ts';
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

/** The bundle as read on screen: the download's, with no record of its own. */
export interface Evidence {
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
  /** Its name and version null for a supplier the organisation doesn't have (S206 V8). */
  readonly supplier: {
    readonly id: string;
    readonly name: string | null;
    readonly version: {
      readonly id: string;
      readonly number: number;
      readonly name: string;
      /** The partner's opaque reference for those details' payee; null when none was registered. */
      readonly beneficiaryRef: string | null;
      readonly verification: LogEvent | null;
    } | null;
  };
  /** Its details null for one the organisation doesn't have (S206 V8). */
  readonly fundingSource: {
    readonly id: string;
    readonly holderName: string | null;
    readonly hint: string | null;
    readonly partner: string | null;
    /** The partner's opaque reference for the consent it is linked under now. */
    readonly accountConsentId: string | null;
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
      readonly accountConsentId: string;
      readonly beneficiaryRef: string;
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

/** The request's address in the API. */
const pathOf = (id: string): string => `/v1/spend-requests/${encodeURIComponent(id)}`;

/**
 * The request's evidence, read while `allowed` (an admin) and only by a
 * request's ID (any other address names none, shown as not found). Nothing is
 * logged, so it is asked again as any query is; a 401 ends the session (the
 * console's queries, app.tsx).
 */
export function useEvidence(id: string, organization: string, allowed: boolean) {
  return useQuery({
    queryKey: ['evidence', organization, id],
    enabled: allowed && isUuid(id),
    retry: readRetry,
    queryFn: () => api.get<EvidenceAnswer>(`${pathOf(id)}/evidence`, { organization }),
  });
}

/**
 * The request's evidence downloaded, logged, and saved as it came. `press`
 * sends it with the press's idempotency key: kept after a failure, so pressing
 * again is the same download, and dropped once one is saved. A 401 ends the
 * session.
 */
export function useEvidenceDownload(id: string, organization: string) {
  const queries = useQueryClient();
  const pressKey = useRef<string | undefined>(undefined);
  const download = useMutation({
    mutationFn: (idempotencyKey: string) =>
      api.post<unknown>(`${pathOf(id)}/evidence-exports`, { organization, body: {}, idempotencyKey }),
    onSuccess: (answer) => {
      pressKey.current = undefined;
      saveJson(`evidence-${id}.json`, answer);
    },
    onError: (error) => {
      if (isSignedOut(error)) endSession(queries);
    },
  });
  const press = () => {
    pressKey.current ??= crypto.randomUUID();
    download.mutate(pressKey.current);
  };
  return { press, download };
}
