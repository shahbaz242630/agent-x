// A bank consent running out, logged as its own signed event about the source
// (Phase 3 E7c; the partner's S119 rule: nothing unlogged). No one acts when a
// consent runs out, so its admin's choice for that moment (decision 21,
// consent-expiry-choice.ts) would otherwise show only in what came of it.
// Each consent's lapse is recorded once (`funding_source.consent_lapsed`, as
// the API's), naming the consent, its end and the choice in force: cancel
// when none was chosen (a source linked before E7), `chosen` saying which.
//
// Recorded by whatever meets it first: the request-voids job, for a consent
// past its end by time alone, in its own transaction before it voids
// anything; a refresh, for one the partner says ran out or that passed before
// it, before it ends the source or takes a renewal; and a choice changed past
// the end, before the new choice. Those two record it after any requests they
// cancel, as the lock order has the chain head last (ADR-006 §6). Each holds
// the source for change, so the check and the record are one step.
import type { AuditTransaction, SignedStates, VerifiedState } from '@agentx/core/modules/audit';
import { SOURCES, type SourceRecord } from '@agentx/core/modules/funding-sources';

import { consentExpiryOf } from './consent-expiry-choice.ts';

/** The action of a consent's lapse: once per consent. */
export const CONSENT_LAPSED = 'funding_source.consent_lapsed';

/** A consent that ran out: the bank's ID for it and its end. */
export interface LapsedConsent {
  readonly id: string;
  readonly expiresAt: Date;
}

/**
 * Records the consent's lapse about the source, which the caller's
 * transaction read with `change` (`state`), unless its newest lapse already
 * names it: whether it did. Throws for a history that can't be believed, its
 * alarm raised.
 */
export async function lapseRecorded(
  tx: AuditTransaction,
  states: SignedStates,
  found: { readonly source: Pick<SourceRecord, 'id'>; readonly state: VerifiedState },
  orgId: string,
  consent: LapsedConsent,
): Promise<boolean> {
  const sourceId = found.source.id;
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [SOURCES.subject],
    subjectId: sourceId,
    actions: [CONSENT_LAPSED],
    limit: 1,
    newest: true,
  });
  if (history.outcome !== 'read') throw new Error(`A source's consent lapses can't be believed: ${sourceId}`);
  if (history.events.at(-1)?.event.details.consentId === consent.id) return false;
  const choice = await consentExpiryOf(tx, states, orgId, sourceId);
  await states.record(
    tx,
    SOURCES,
    { orgId, id: sourceId },
    found.state,
    {},
    {
      actor: { type: 'system', id: 'api' },
      action: CONSENT_LAPSED,
      details: {
        consentId: consent.id,
        consentExpiresAt: consent.expiresAt.toISOString(),
        pendingRequests: choice ?? 'cancel',
        chosen: choice !== null,
      },
    },
  );
  return true;
}

/** The consent the source holds, when it has run out by `now`: the one whose lapse is due. */
export const lapsedBy = (source: SourceRecord, now: Date): LapsedConsent | undefined =>
  source.status !== 'ENDED' && source.consentExpiresAt <= now
    ? { id: source.accountConsentId, expiresAt: source.consentExpiresAt }
    : undefined;
