// The hand-off's bank breaker (4D2e Stage F; ADR-007 §10; Claude's decision 1,
// S168, as amended after review): at concurrency a bank gone quiet makes
// UNKNOWNs many times as fast, each a payment whose money stays held until the
// bank says. So the answers to new payments are counted, and held back at two
// levels. Only an acceptance proves the way a payment takes is working; a
// lookup proves only that the bank's lookups are, so it opens the way no more
// than a crack.
//
// - A lane: 3 unknowns in a row from one organisation with no acceptance holds
//   it 5 minutes, then 10, 20, up to 60, a further unknown holding it again.
//   Past its hold, one payment at a time, and only once a lookup for that
//   organisation, begun since its last unknown, has answered: a fully hung
//   organisation sends nothing. A refusal is neutral: not an unknown, and it
//   clears nothing.
// - The platform: 5 unknowns from at least 3 organisations in 60 s holds every
//   new Tx A. That is the bank's outage, not an organisation's block (decision
//   1). A lookup begun since the trip that answers, `not_found` included, makes
//   it half-open, reopening in steps: 3 calls, then 6, 12, 24, then open. A step
//   ends when every one of its places was accepted (a refusal gives its place
//   back), so a bank that accepts only some never climbs. Any unknown goes back to held,
//   and a lookup can't reopen it for 1 minute, then 2, 4, up to 30; one answered
//   during that wait is kept for its end. It stays one outage, with one error line
//   and its wait still growing, until it has been open for 15 minutes.
//
// In this process's memory: a restart forgets it, and the next unknowns count
// again. Nothing here decides a payment: a held one waits, APPROVED, its money
// held, and is judged whole by Tx A when it goes.
import type { Clock } from '@agentx/core/shared-kernel';
import type { Logger } from '@agentx/platform/observability';

/** Unknowns in a row, with no acceptance between, that hold an organisation. */
const LANE_UNKNOWNS = 3;

/** A lane's hold, doubling with each further unknown, up to the most. */
const LANE_HOLD_MS = 5 * 60_000;
const LANE_HOLD_MOST_MS = 60 * 60_000;

/** Unknowns, from at least PLATFORM_ORGANISATIONS, within PLATFORM_WINDOW_MS, that hold everyone. */
const PLATFORM_UNKNOWNS = 5;
const PLATFORM_ORGANISATIONS = 3;
const PLATFORM_WINDOW_MS = 60_000;

/** The calls each step of reopening may start across the platform: a refused or unsent one gives its place back. */
const REOPEN_STEPS = [3, 6, 12, 24] as const;

/** How long it must stay open before a further trip is a new outage, with its wait started afresh. */
const HEALTHY_MS = 15 * 60_000;

/** Refusals in a row, with no acceptance, from at least REFUSING_ORGANISATIONS, before they are said: one's own are real. */
const REFUSALS_SAID = 10;
const REFUSING_ORGANISATIONS = 3;

/** How long a lookup can't reopen a hold after a trip from half-open, doubling each time, up to the most. */
const REOPEN_WAIT_MS = 60_000;
const REOPEN_WAIT_MOST_MS = 30 * 60_000;

/** How long a hold may stand before it is an error, and how often it is said again while it stands: the queue-age alert's. */
const HOLD_LASTING_MS = 15 * 60_000;

/** Who a hold is for: everyone (`bank`) or the organisation (`lane`). */
export type RailHold = 'bank' | 'lane';

/** How a call let through ended, for the breaker: a refusal is neutral, and one never sent gives its place back. */
type Settled = 'accepted' | 'refused' | 'unknown' | 'not_sent';

/** The answer to asking to start a payment: held, or let through with a place to settle once it ends. */
export type RailEntry =
  | {
      readonly hold: RailHold;
      /** The platform's outage this falls in: a trip again from half-open is the same outage. */
      readonly outage: number;
    }
  | { readonly settle: (how: Settled) => void };

export interface RailHealth {
  /** Why no new Tx A may start for this organisation now, or nothing where it may. Takes no place. */
  heldFor(orgId: string): RailHold | undefined;
  /** Asks to start a payment for this organisation: held (said if the hold has lasted), or let through. */
  enter(orgId: string): RailEntry;
  /** Whether this organisation's payments go one at a time now: held once, with no acceptance since. */
  oneAtATime(orgId: string): boolean;
  /** A status lookup for this organisation is starting: what to call if it answers, `not_found` included. */
  lookupBegun(orgId: string): () => void;
}

/** When a hold began, and when its lasting was last said. */
interface Lasting {
  heldSince: number;
  lastingSaid: number;
}

interface LaneState extends Lasting {
  inRow: number;
  heldUntil: number;
  /** The hold the next unknown past the row gives. */
  nextHoldMs: number;
  /** The unknown count at its last unknown: a lookup begun before it proves nothing since. */
  lastUnknown: number;
  /** A lookup for it has answered since its last unknown. */
  lookedSince: boolean;
  /** Its one payment past its hold is under way. */
  probing: boolean;
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
  const lanes = new Map<string, LaneState>();
  let recent: { readonly at: number; readonly orgId: string }[] = [];
  let platform: 'open' | 'held' | 'half_open' = 'open';
  // Every unknown counted: a lookup's start is placed against it, whatever the clock says.
  let unknowns = 0;
  let trippedAtUnknown = 0;
  let outage = 0;
  let reopensAt = 0;
  let nextWaitMs = REOPEN_WAIT_MS;
  // The reopening under way: which one (a call begun in an earlier one moves nothing), its step and what that step has
  // let through, has under way, and has had accepted.
  let reopening = 0;
  let step = 0;
  let letThrough = 0;
  let underWay = 0;
  // A lookup begun since the trip has answered: kept through the wait, for when it ends.
  let lookupHeard = false;
  // Until when a further trip is still the same outage.
  let healthyAt = Number.NEGATIVE_INFINITY;
  // The refusals since the last acceptance, whoever they were from, and when they were first said.
  let refusals = {
    count: 0,
    organisations: new Set<string>(),
    saidAt: undefined as number | undefined,
    lasting: false,
  };
  const bankHold: Lasting = { heldSince: 0, lastingSaid: 0 };

  const now = (): number => clock.now().getTime();

  const laneHoldsNow = (lane: LaneState | undefined): lane is LaneState =>
    lane !== undefined && lane.inRow >= laneUnknowns && (lane.heldUntil > now() || !lane.lookedSince || lane.probing);

  const beginStep = (next: number): void => {
    step = next;
    letThrough = 0;
    underWay = 0;
  };

  /** Held with a lookup heard since its trip, and its wait over: the first step of reopening. */
  const reopenIfDue = (): void => {
    if (platform !== 'held' || !lookupHeard || now() < reopensAt) return;
    platform = 'half_open';
    reopening += 1;
    beginStep(0);
    logger.info('handoff.bank_half_open', { calls: REOPEN_STEPS[0] });
  };

  const bankHoldsNow = (): boolean => {
    reopenIfDue();
    return platform === 'held' || (platform === 'half_open' && letThrough >= (REOPEN_STEPS[step] ?? 0));
  };

  /** Whether this hold, reached by a payment that really waits on it, has lasted past a blip and is due to be said. */
  const lastingDue = (hold: Lasting): boolean => {
    const at = now();
    if (at - hold.heldSince < HOLD_LASTING_MS || at - hold.lastingSaid < HOLD_LASTING_MS) return false;
    hold.lastingSaid = at;
    return true;
  };

  const held = (): void => {
    platform = 'held';
    trippedAtUnknown = unknowns;
    lookupHeard = false;
  };

  /** A trip within an outage (from half-open, or too soon after it opened): no new error, its wait growing. */
  const tripAgain = (at: number): void => {
    held();
    reopensAt = at + nextWaitMs;
    logger.info('handoff.bank_held_again', { waitMinutes: nextWaitMs / 60_000 });
    nextWaitMs = Math.min(nextWaitMs * 2, REOPEN_WAIT_MOST_MS);
  };

  /** This unknown noted among the platform's recent ones: holds everyone once they are enough, from enough. */
  const countForBank = (orgId: string, at: number): void => {
    if (platform === 'half_open') {
      tripAgain(at);
      return;
    }
    if (platform === 'held') return;
    recent = [...recent.filter((unknown) => at - unknown.at < PLATFORM_WINDOW_MS), { at, orgId }];
    const organisations = new Set(recent.map((unknown) => unknown.orgId)).size;
    if (recent.length < PLATFORM_UNKNOWNS || organisations < PLATFORM_ORGANISATIONS) return;
    if (at < healthyAt) {
      tripAgain(at);
      return;
    }
    held();
    outage += 1;
    bankHold.heldSince = at;
    bankHold.lastingSaid = at;
    reopensAt = at;
    nextWaitMs = REOPEN_WAIT_MS;
    logger.error('handoff.bank_held', { unknowns: recent.length, organisations });
  };

  const unknownIn = (orgId: string): void => {
    const at = now();
    unknowns += 1;
    const lane = lanes.get(orgId) ?? {
      inRow: 0,
      heldUntil: 0,
      nextHoldMs: LANE_HOLD_MS,
      lastUnknown: 0,
      lookedSince: false,
      probing: false,
      heldSince: 0,
      lastingSaid: 0,
    };
    lanes.set(orgId, lane);
    lane.inRow += 1;
    lane.lastUnknown = unknowns;
    lane.lookedSince = false;
    if (lane.inRow >= laneUnknowns) {
      // Only the unknown that starts a hold grows the next; one landing inside it extends nothing further.
      if (lane.heldUntil <= at) {
        if (lane.heldUntil === 0) {
          lane.heldSince = at;
          lane.lastingSaid = at;
        }
        lane.heldUntil = at + lane.nextHoldMs;
        logger.child({ orgId }).warn('handoff.lane_held', {
          unknowns: lane.inRow,
          holdMinutes: lane.nextHoldMs / 60_000,
        });
        lane.nextHoldMs = Math.min(lane.nextHoldMs * 2, LANE_HOLD_MOST_MS);
      }
    }
    countForBank(orgId, at);
  };

  /** A step's calls all ended, one accepted, none unknown: the next step, or open after the last. */
  const stepDone = (): void => {
    const next = step + 1;
    const calls = REOPEN_STEPS[next];
    if (calls !== undefined) {
      beginStep(next);
      logger.info('handoff.bank_step', { calls });
      return;
    }
    platform = 'open';
    recent = [];
    healthyAt = now() + HEALTHY_MS;
    logger.info('handoff.bank_back', {});
  };

  /** A call of the reopening under way ended, unknown aside (that goes back to held). */
  const countForStep = (how: Exclude<Settled, 'unknown'>): void => {
    underWay -= 1;
    if (how !== 'accepted') letThrough -= 1;
    // Every place used: a few quick acceptances would otherwise climb past a bank still losing calls (review).
    if (underWay === 0 && letThrough >= (REOPEN_STEPS[step] ?? 0)) stepDone();
  };

  /**
   * A refusal is neutral for payments, and one organisation's are real: a run of
   * them across several, with no acceptance, may be our own credentials or a
   * limit, so is said, a warning, then an error if it lasts. No payment stops on it.
   */
  const countRefusal = (orgId: string): void => {
    refusals.count += 1;
    refusals.organisations.add(orgId);
    if (refusals.count < REFUSALS_SAID || refusals.organisations.size < REFUSING_ORGANISATIONS) return;
    const at = now();
    const said = { refusals: refusals.count, organisations: refusals.organisations.size };
    if (refusals.saidAt === undefined) {
      refusals.saidAt = at;
      logger.warn('handoff.bank_refusing', said);
    } else if (!refusals.lasting && at - refusals.saidAt >= HOLD_LASTING_MS) {
      refusals.lasting = true;
      logger.error('handoff.bank_refusing', said);
    }
  };

  /** A place for one payment: its lane's and, half-open, the platform's. Assumes nothing holds it. */
  const placeFor = (orgId: string): RailEntry => {
    const lane = lanes.get(orgId);
    const probe = lane !== undefined && lane.inRow >= laneUnknowns;
    if (probe) lane.probing = true;
    const round = platform === 'half_open' ? reopening : undefined;
    if (round !== undefined) {
      letThrough += 1;
      underWay += 1;
    }
    return {
      settle: (how) => {
        if (probe) lane.probing = false;
        // Any acceptance clears its lane, one begun before a trip included.
        if (how === 'accepted') {
          lanes.delete(orgId);
          refusals = { count: 0, organisations: new Set(), saidAt: undefined, lasting: false };
        }
        if (how === 'refused') countRefusal(orgId);
        if (how === 'unknown') unknownIn(orgId);
        // Only a call of the reopening under way moves it: a stale one proves nothing of the way now.
        else if (round === reopening && platform === 'half_open') countForStep(how);
      },
    };
  };

  return {
    heldFor: (orgId) => {
      if (bankHoldsNow()) return 'bank';
      return laneHoldsNow(lanes.get(orgId)) ? 'lane' : undefined;
    },
    enter: (orgId) => {
      if (bankHoldsNow()) {
        if (lastingDue(bankHold)) {
          logger.error('handoff.hold_lasting', {
            hold: platform,
            minutes: Math.floor((now() - bankHold.heldSince) / 60_000),
          });
        }
        return { hold: 'bank', outage };
      }
      const lane = lanes.get(orgId);
      if (!laneHoldsNow(lane)) return placeFor(orgId);
      if (lastingDue(lane)) {
        logger.child({ orgId }).error('handoff.hold_lasting', {
          hold: 'lane',
          minutes: Math.floor((now() - lane.heldSince) / 60_000),
        });
      }
      return { hold: 'lane', outage };
    },
    oneAtATime: (orgId) => (lanes.get(orgId)?.inRow ?? 0) >= laneUnknowns,
    lookupBegun: (orgId) => {
      const begunAt = unknowns;
      return () => {
        const lane = lanes.get(orgId);
        if (lane !== undefined && begunAt >= lane.lastUnknown) lane.lookedSince = true;
        if (platform !== 'held' || begunAt < trippedAtUnknown) return;
        lookupHeard = true;
        reopenIfDue();
      };
    },
  };
}
