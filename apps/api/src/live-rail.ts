// ADR-014 §4's second check, at the point of use (SEC-OPS-07, the S4 lesson):
// the live partner's adapter goes through liveOnly, so it refuses to hand over
// a payment unless this process's start was recorded live, whatever the wiring
// around it says. Start-up already refuses live outside production and without
// the gate reference; this catches a live adapter built into any other start.
import type { FinancialRailAdapter } from '@agentx/core/modules/providers';
import { startedLive } from '@agentx/platform/config';
import type { Logger } from '@agentx/platform/observability';

/** A payment the point-of-use check refused: nothing reached the partner. */
export class NotStartedLive extends Error {
  constructor() {
    super("the live partner's adapter refused a payment: this process's start wasn't recorded live");
    this.name = 'NotStartedLive';
  }
}

/**
 * The live adapter, refusing every payment while this process's start isn't
 * recorded live (startedLive). Each other part is handed to the adapter itself,
 * named one by one, so a class's methods keep their own `this` and a part the
 * contract gains can't pass by unseen: the object below must name it.
 */
export function liveOnly(rail: FinancialRailAdapter, logger: Logger): FinancialRailAdapter {
  return {
    identity: rail.identity,
    authoriseOrigin: rail.authoriseOrigin,
    formOrigin: rail.formOrigin,
    capabilities: () => rail.capabilities(),
    startSourceLink: (input) => rail.startSourceLink(input),
    confirmSourceLink: (input) => rail.confirmSourceLink(input),
    getSourceState: (ref) => rail.getSourceState(ref),
    registerBeneficiary: (input) => rail.registerBeneficiary(input),
    getBeneficiaryState: (ref) => rail.getBeneficiaryState(ref),
    // Asked on every payment, not once when built: what counts is the start this process recorded.
    submitApprovedIntent: (intent) => {
      if (startedLive()) return rail.submitApprovedIntent(intent);
      logger.error('partner.live_refused', { partner: rail.identity.partner });
      return Promise.reject(new NotStartedLive());
    },
    getExecution: (ref) => rail.getExecution(ref),
    verifyEvent: (body, headers) => rail.verifyEvent(body, headers),
  };
}
