// The hand-off's bank breaker (4D2e Stage F; ADR-007 §10; Claude's decision 1,
// S168): at concurrency a bank gone quiet makes UNKNOWNs many times as fast,
// each a payment whose money stays held until the bank says. So the answers to
// new payments are counted, and held back at two levels:
//
// - A lane: 3 unknowns in a row from one organisation with no answer between
//   holds that organisation 5 minutes, then its payments go one at a time, a
//   further unknown holding it again, until the bank answers one of them.
// - The platform: 5 unknowns from at least 3 organisations in 60 s holds every
//   new Tx A. That is the bank's outage, not an organisation's block (decision 1).
//   Neither time nor a payment can reopen it: it reopens when a status
//   lookup (`getExecution`) answers, `not_found` included, as that is the bank
//   answering, whatever it knows. A real payment is never the probe.
//
// In this process's memory: a restart forgets it, and the next unknowns count
// again. Nothing here decides a payment: a held one waits, APPROVED, its money
// held, and is judged whole by Tx A when it goes.
import type { FinancialRailAdapter } from '@agentx/core/modules/providers';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Logger } from '@agentx/platform/observability';

/** Unknowns in a row, with no answer between, that hold an organisation. */
const LANE_UNKNOWNS = 3;

/** How long a lane is held; then one at a time. */
const LANE_HOLD_MS = 5 * 60_000;

/** Unknowns, from at least PLATFORM_ORGANISATIONS, within PLATFORM_WINDOW_MS, that hold everyone. */
const PLATFORM_UNKNOWNS = 5;
const PLATFORM_ORGANISATIONS = 3;
const PLATFORM_WINDOW_MS = 60_000;

/** Who a hold is for: everyone (`bank`) or the organisation (`lane`). */
export type RailHold = 'bank' | 'lane';

export interface RailHealth {
  /** Why no new Tx A may start for this organisation now, or nothing where it may. */
  heldFor(orgId: string): RailHold | undefined;
  /** Whether this organisation's payments go one at a time now: past its hold, with no answer yet. */
  oneAtATime(orgId: string): boolean;
  /** A payment's submission whose outcome can't be known (a timeout, no answer, a 5xx). */
  unknown(orgId: string): void;
  /** The bank answered a payment's submission, either way: this organisation's row is broken. */
  answered(orgId: string): void;
  /** A status lookup answered, `not_found` included: the bank is back. */
  looked(): void;
}

export function createRailHealth({
  clock,
  logger,
  laneUnknowns = LANE_UNKNOWNS,
}: {
  readonly clock: Clock;
  readonly logger: Logger;
  /** Unknowns in a row that hold a lane (LANE_UNKNOWNS unless a test of something else names more). */
  readonly laneUnknowns?: number;
}): RailHealth {
  const lanes = new Map<string, { inRow: number; heldUntil: number }>();
  let recent: { readonly at: number; readonly orgId: string }[] = [];
  let bankHeld = false;

  const laneHeld = (orgId: string): boolean => (lanes.get(orgId)?.heldUntil ?? 0) > clock.now().getTime();

  /** This unknown noted among the platform's recent ones: holds everyone once they are enough, from enough. */
  const countForBank = (orgId: string, now: number): void => {
    if (bankHeld) return;
    recent = [...recent.filter(({ at }) => now - at < PLATFORM_WINDOW_MS), { at: now, orgId }];
    const organisations = new Set(recent.map((unknown) => unknown.orgId)).size;
    if (recent.length < PLATFORM_UNKNOWNS || organisations < PLATFORM_ORGANISATIONS) return;
    bankHeld = true;
    logger.warn('handoff.bank_held', { unknowns: recent.length, organisations });
  };

  return {
    heldFor: (orgId) => {
      if (bankHeld) return 'bank';
      return laneHeld(orgId) ? 'lane' : undefined;
    },
    oneAtATime: (orgId) => (lanes.get(orgId)?.inRow ?? 0) >= laneUnknowns,
    unknown: (orgId) => {
      const now = clock.now().getTime();
      const wasHeld = laneHeld(orgId);
      const lane = lanes.get(orgId) ?? { inRow: 0, heldUntil: 0 };
      lane.inRow += 1;
      lanes.set(orgId, lane);
      if (lane.inRow >= laneUnknowns) {
        lane.heldUntil = now + LANE_HOLD_MS;
        if (!wasHeld) logger.child({ orgId }).warn('handoff.lane_held', { unknowns: lane.inRow });
      }
      countForBank(orgId, now);
    },
    answered: (orgId) => {
      lanes.delete(orgId);
    },
    looked: () => {
      if (!bankHeld) return;
      bankHeld = false;
      recent = [];
      logger.info('handoff.bank_back', {});
    },
  };
}

/**
 * The rail, each status lookup that answers telling `health`: the bank check's
 * own calls are the probe, so nothing is sent to the bank for its sake alone.
 * A child of the rail, not a copy, so an adapter's methods keep working
 * whichever way it is built.
 */
export function watchedRail(rail: FinancialRailAdapter, health: Pick<RailHealth, 'looked'>): FinancialRailAdapter {
  return Object.assign(Object.create(rail) as FinancialRailAdapter, {
    getExecution: async (...lookup: Parameters<FinancialRailAdapter['getExecution']>) => {
      const answer = await rail.getExecution(...lookup);
      health.looked();
      return answer;
    },
  });
}
