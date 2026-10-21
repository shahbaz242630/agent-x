// What happens to a bank account's pending spend requests when its consent
// runs out (Phase 3 E7; partner decisions 15 and 21, S119; Rule Book §1.9):
// an admin chooses, for each source, cancel or hold until the consent is
// renewed. No one acts when a consent expires, so the choice is made ahead:
// at linking, and changed whenever an admin wants. It is kept on its own
// signed event about the source (`funding_source.consent_expiry_chosen`,
// with the version of the words), the source's signed state unchanged, as
// chosenAgain records a suspend's again.
//
// A source linked before E7 has none, and cancels (the rule then, decision
// 7), shown as not chosen. Only consent that ran out is held: revoked,
// consumed or rejected before its end still cancels (decision 21). Held
// requests can't be approved or paid (mayFund); waiting ones still expire at
// their wait (E6); once the renewal is refreshed they stand again at once.
import type { AuditDetails, AuditTransaction, SignedStates } from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { PENDING_CHOICES, type PendingChoice } from '@agentx/core/modules/spend-requests';
import { z } from 'zod';
import { IntegrityFailure } from './errors.ts';

/** The action of the event that keeps a source's choice: the newest is in force. */
export const CONSENT_EXPIRY_CHOSEN = 'funding_source.consent_expiry_chosen';

/** Where the choice in force is kept, for the request-voids job's filter: the newest choice event about the source. */
export const CONSENT_EXPIRY_EVENTS = { type: SOURCES.subject, actions: [CONSENT_EXPIRY_CHOSEN] } as const;

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const CONSENT_EXPIRY_STATEMENTS = {
  cancel:
    'When this account’s bank consent runs out, every request waiting for approval, approved or ready on it is ' +
    'cancelled and the money held for it freed. The agents ask again once the account is linked or renewed.',
  pause:
    'When this account’s bank consent runs out, its requests are held as they are: none can be approved or paid ' +
    'until the consent is renewed at the bank and refreshed in Agent X, when they stand again at once. Requests ' +
    'waiting for approval still expire when their wait ends. A consent revoked or ended early still cancels them.',
} as const satisfies Record<PendingChoice, string>;

/** The version of CONSENT_EXPIRY_STATEMENTS each event names: raised with any change to their words. */
const CONSENT_EXPIRY_STATEMENT_VERSION = 1;

/** The choice as a body names it: confirmed by the admin, no default. */
export const CONSENT_EXPIRY = z
  .enum(PENDING_CHOICES)
  .describe(
    'What happens to the account’s pending spend requests when its bank consent runs out, confirmed by an admin; ' +
      `there is no default. \`cancel\`: ${CONSENT_EXPIRY_STATEMENTS.cancel} \`pause\`: ${CONSENT_EXPIRY_STATEMENTS.pause}`,
  );

/** The choice as its event keeps it, with the words confirmed. */
export const consentExpiryDetails = (choice: PendingChoice) =>
  ({ pendingRequests: choice, pendingStatementVersion: CONSENT_EXPIRY_STATEMENT_VERSION }) as const;

/** The choice an event keeps, or null: none (a source linked before E7). */
const consentExpiryIn = (details: AuditDetails | undefined): PendingChoice | null => {
  const chosen = details?.pendingRequests;
  return chosen === 'cancel' || chosen === 'pause' ? chosen : null;
};

/**
 * The source's choice in force, its newest choice event believed only whole
 * (null: none chosen, so cancel). Throws for a history that can't be
 * believed, its alarm raised.
 */
export async function consentExpiryOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  sourceId: string,
): Promise<PendingChoice | null> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [SOURCES.subject],
    subjectId: sourceId,
    actions: [CONSENT_EXPIRY_CHOSEN],
    limit: 1,
    newest: true,
  });
  if (history.outcome !== 'read')
    throw new IntegrityFailure(`A source's consent-expiry choice can't be believed: ${sourceId}`);
  return consentExpiryIn(history.events.at(-1)?.event.details);
}

/** Whether the source holds its pending requests when its consent runs out. */
export const holdsOverExpiry = async (...read: Parameters<typeof consentExpiryOf>): Promise<boolean> =>
  (await consentExpiryOf(...read)) === 'pause';
