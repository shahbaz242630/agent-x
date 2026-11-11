// CO3's shared table for the routes' HTTP tests: every change confirmed with
// a set of words (GET /v1/statements), the body field that sends back the
// version it was shown, and the choice it comes with when that is optional.
// statements.test.ts checks the table against the contract and refuses an
// old version, or none, on each; the routes' own tests send the version now
// (`worded`), so they keep testing what they test. A helper, not a test:
// Vitest leaves `*.helper.test.ts` out (vitest.config.ts).
import { SERVED_STATEMENTS, type StatementId } from './statements.ts';

/** The version of a set's words the API confirms changes with now. */
export const versionNow = (id: StatementId): number =>
  SERVED_STATEMENTS.find((statement) => statement.id === id)?.version ?? 0;

/** A set a confirm names: its body field, and the choice it comes with when that is optional. */
type Named = readonly [field: string, id: StatementId, choice?: readonly [field: string, value: unknown]];

/** Every change confirmed with a set of words, by its address as the contract names it. */
export const CONFIRMS: readonly (readonly [path: string, named: readonly Named[]])[] = [
  ['/v1/organization/freeze', [['statementVersion', 'freeze']]],
  ['/v1/organization/unfreeze/confirm', [['statementVersion', 'unfreeze']]],
  ['/v1/agents/{id}/suspend', [['statementVersion', 'suspend']]],
  ['/v1/agents/{id}/keys/{keyId}/rotate/confirm', [['statementVersion', 'old_key']]],
  ['/v1/mandates', [['statementVersion', 'over_limit']]],
  ['/v1/mandates/{id}/supersede', [['statementVersion', 'over_limit']]],
  ['/v1/mandates/{id}/suspend/confirm', [['statementVersion', 'suspend']]],
  ['/v1/mandates/{id}/accept/confirm', [['statementVersion', 'supersede', ['pendingRequests', 'carry']]]],
  ['/v1/mandates/{id}/over-limit/confirm', [['statementVersion', 'over_limit']]],
  ['/v1/funding-sources/link-sessions/{linkId}/confirm', [['statementVersion', 'consent_expiry']]],
  ['/v1/funding-sources/{id}/suspend', [['statementVersion', 'suspend']]],
  ['/v1/funding-sources/{id}/consent-expiry', [['statementVersion', 'consent_expiry']]],
  ['/v1/suppliers/{id}/suspend', [['statementVersion', 'suspend']]],
  ['/v1/suppliers/{id}/reactivate/confirm', [['statementVersion', 'reactivate']]],
  ['/v1/suppliers/{id}/details/confirm', [['statementVersion', 'supplier_details']]],
  ['/v1/suppliers/{id}/payee-registrations', [['statementVersion', 'payee']]],
  ['/v1/suppliers/{id}/payee-registrations/pass-through', [['statementVersion', 'payee']]],
  ['/v1/payments/{id}/failure-proposal/confirm', [['statementVersion', 'mark_failed']]],
  ['/v1/payments/{id}/failure-proposal/approve/confirm', [['statementVersion', 'mark_failed']]],
  ['/v1/spend-requests/{id}/approve/confirm', [['statementVersion', 'recheck', ['recheck', true]]]],
  [
    '/v1/policies/organization/change/confirm',
    [
      ['monthlyCapStatementVersion', 'monthly_cap'],
      ['approvalWaitStatementVersion', 'approval_wait'],
      ['waitingStatementVersion', 'waiting_requests', ['waitingRequests', 'reject']],
    ],
  ],
  [
    '/v1/mandates/{id}/policy/change/confirm',
    [['waitingStatementVersion', 'waiting_requests', ['waitingRequests', 'leave']]],
  ],
];

/** A confirm's body sending back each set it names at the version now, with the choice an optional one needs. */
export const confirmedBody = (named: readonly Named[]): Record<string, unknown> =>
  Object.fromEntries(
    named.flatMap(([field, id, choice]) => [[field, versionNow(id)], ...(choice === undefined ? [] : [choice])]),
  );

/** Each address as a pattern: any one segment where the contract names a parameter. */
const MATCHING = CONFIRMS.map(
  ([path, named]) => [new RegExp(`^${path.replaceAll(/\{\w+\}/g, '[^/?]+')}(?:\\?|$)`), named] as const,
);

/**
 * `payload` as a test of the route at `url` sends it: with the version now of
 * each set the route names, unless the test sent its own, and an optional
 * choice's only when the choice is sent. Anything but an object, as it is.
 */
export function worded(url: string, payload: unknown): unknown {
  const named = MATCHING.find(([pattern]) => pattern.test(url))?.[1];
  if (named === undefined || typeof payload !== 'object' || payload === null || Array.isArray(payload)) return payload;
  const sent = payload as Readonly<Record<string, unknown>>;
  const versions = named
    .filter(([field, , choice]) => !(field in sent) && (choice === undefined || sent[choice[0]] !== undefined))
    .map(([field, id]) => [field, versionNow(id)] as const);
  return { ...Object.fromEntries(versions), ...sent };
}
