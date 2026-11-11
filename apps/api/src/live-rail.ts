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

/** The live adapter, refusing every payment while this process's start isn't recorded live (startedLive). */
export function liveOnly(rail: FinancialRailAdapter, logger: Logger): FinancialRailAdapter {
  return {
    ...rail,
    // Asked on every payment, not once when built: what counts is the start this process recorded.
    submitApprovedIntent: (intent) => {
      if (startedLive()) return rail.submitApprovedIntent(intent);
      logger.error('partner.live_refused', { partner: rail.identity.partner });
      return Promise.reject(new NotStartedLive());
    },
  };
}
