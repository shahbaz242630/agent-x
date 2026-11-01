// The fair gate before a decision's connection (4D2e C, PL-63, partner S165): one
// organisation's trouble must never touch another's speed. At most so many of an
// agent's decisions run at once in this process, at most so many of those any one
// organisation's, the rest waiting here, holding no connection, for a bounded time.
// A slot lasts the whole request, retries included. So a decision let in is never
// refused by the gate later: it can't answer busy once it has committed (S166).
//
// When a slot comes free it goes to the organisations in turn, not to whoever
// queued first: `ring` holds those with someone waiting and room under their own
// limit, oldest turn first (a Set keeps the order things were added; deleting and
// adding again moves one to the end, in constant time). So a calm organisation
// goes next past a busy one's queue.
//
// A limit slows only the organisation that hit it, with one case it can't cover: a
// platform truly full queues a calm organisation that hit nothing (design S168,
// finding 2). Taking turns keeps that short, and it is told apart, by `reason`, so
// it can have its own line and alert. An organisation is refused as itself when it
// is at its own limit, whether or not the platform is full too.
//
// Only agents' decisions enter. People's and jobs' transactions never do: refusing
// them is how an admin's freeze was told busy after it committed (S166). Counted
// per process, so across N copies the limits are N times these, and turns are fair
// within a copy, not across copies.
import { organisationShareOf } from '@agentx/platform/db';

/** What the gate holds to: each a limit in this process. */
export interface GateLimits {
  /** Decisions running at once. */
  readonly active: number;
  /** Of those, one organisation's. */
  readonly perOrganisation: number;
  /** An organisation's decisions waiting at once: past it they are refused at once, not queued. */
  readonly waitingPerOrganisation: number;
  /** How long one waits. */
  readonly waitMs: number;
}

/** Whose limit turned a decision away: its organisation's own, or the whole platform's. */
export type GateRefusal = 'organisation' | 'platform';

/** A decision the gate turned away, nothing of it made. */
export class DecisionGateRefused extends Error {
  readonly reason: GateRefusal;
  readonly waitedMs: number;

  constructor(reason: GateRefusal, waitedMs: number) {
    super(`A decision was turned away after ${String(waitedMs)} ms at the gate, by the ${reason}'s limit`);
    this.name = 'DecisionGateRefused';
    this.reason = reason;
    this.waitedMs = waitedMs;
  }
}

export interface DecisionGate {
  /** Takes a slot for the organisation: at once if it may, otherwise in its turn. Rejects with DecisionGateRefused, holding none. */
  enter(organisation: string): Promise<void>;
  /** Gives a slot back, to whichever organisation's turn it is. */
  leave(organisation: string): void;
  /** The organisations with a slot taken or waited for: none once all are given back, so the memory never grows with organisations seen. */
  organisationsInHand(): number;
}

interface Organisation {
  active: number;
  readonly waiting: (() => void)[];
}

export function createDecisionGate({
  active: mostActive,
  perOrganisation,
  waitingPerOrganisation,
  waitMs,
}: GateLimits): DecisionGate {
  let total = 0;
  const organisations = new Map<string, Organisation>();
  const ring = new Set<Organisation>();

  const refusal = (organisation: Organisation, waitedMs: number): DecisionGateRefused =>
    new DecisionGateRefused(organisation.active < perOrganisation ? 'platform' : 'organisation', waitedMs);

  /** Drops the organisation once nothing of it is in hand. */
  const forget = (key: string, organisation: Organisation): void => {
    if (organisation.active === 0 && organisation.waiting.length === 0) organisations.delete(key);
  };

  /** The slot just given back, to the organisation whose turn it is, which goes to the end of the ring if it can take another. */
  const nextTurn = (): void => {
    const [next] = ring;
    if (next === undefined) return;
    ring.delete(next);
    total += 1;
    next.active += 1;
    next.waiting.shift()?.();
    if (next.waiting.length > 0 && next.active < perOrganisation) ring.add(next);
  };

  return {
    organisationsInHand: () => organisations.size,
    enter(key) {
      let found = organisations.get(key);
      if (found === undefined) {
        found = { active: 0, waiting: [] };
        organisations.set(key, found);
      }
      const organisation = found;
      if (total < mostActive && organisation.active < perOrganisation) {
        total += 1;
        organisation.active += 1;
        return Promise.resolve();
      }
      if (organisation.waiting.length >= waitingPerOrganisation) {
        const refused = refusal(organisation, 0);
        forget(key, organisation);
        return Promise.reject(refused);
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          // The first in its list: all wait equally long, in the order they came.
          organisation.waiting.shift();
          if (organisation.waiting.length === 0) ring.delete(organisation);
          const refused = refusal(organisation, waitMs);
          forget(key, organisation);
          reject(refused);
        }, waitMs);
        function go(): void {
          clearTimeout(timer);
          resolve();
        }
        organisation.waiting.push(go);
        // Under its own limit it waits only for room; at its limit, its next leave puts it in the ring.
        if (organisation.active < perOrganisation) ring.add(organisation);
      });
    },
    leave(key) {
      const organisation = organisations.get(key);
      if (organisation === undefined) return;
      total -= 1;
      organisation.active -= 1;
      if (organisation.waiting.length > 0) ring.add(organisation);
      nextTurn();
      forget(key, organisation);
    },
  };
}

/**
 * The limits a process runs at: its settings where set. Until a load run sets the
 * numbers they stay wide, so the gate only takes turns and adds no refusal of its
 * own: as many decisions as connections, one organisation's as many as its share of them.
 */
export const gateLimitsOf = (
  poolMax: number,
  settings: {
    readonly active: number | null;
    readonly perOrganisation: number | null;
    readonly waitingPerOrganisation: number;
    readonly waitMs: number;
  },
): GateLimits => {
  const active = settings.active ?? poolMax;
  return {
    active,
    perOrganisation: settings.perOrganisation ?? Math.min(active, organisationShareOf(poolMax)),
    waitingPerOrganisation: settings.waitingPerOrganisation,
    waitMs: settings.waitMs,
  };
};

/** No limit at all: the race suites' and a test's own gate. */
export const NO_GATE_LIMITS: GateLimits = {
  active: Number.MAX_SAFE_INTEGER,
  perOrganisation: Number.MAX_SAFE_INTEGER,
  waitingPerOrganisation: Number.MAX_SAFE_INTEGER,
  waitMs: 2_147_483_647,
};
