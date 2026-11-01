import { afterEach, describe, expect, it, vi } from 'vitest';

import { createDecisionGate, DecisionGateRefused, gateLimitsOf, type GateLimits } from './decision-gate.ts';

const LIMITS: GateLimits = { active: 4, perOrganisation: 2, waitingPerOrganisation: 8, waitMs: 1_000 };

/** A gate with the order each organisation's places came recorded, and how many each still has. */
function gateWith(limits: Partial<GateLimits> = {}) {
  const gate = createDecisionGate({ ...LIMITS, ...limits });
  const granted: string[] = [];
  const outcomes: (DecisionGateRefused | string)[] = [];
  const enter = (organisation: string) => {
    const entered = gate.enter(organisation).then(
      () => {
        granted.push(organisation);
        outcomes.push(organisation);
      },
      (error: unknown) => {
        outcomes.push(error as DecisionGateRefused);
      },
    );
    return entered;
  };
  return { gate, granted, outcomes, enter };
}

/** Lets every settled promise's callbacks run. */
const settled = () => new Promise<void>((resolve) => setImmediate(resolve));

const times = (n: number, each: () => unknown) => {
  for (let at = 0; at < n; at += 1) each();
};

afterEach(() => {
  vi.useRealTimers();
});

describe('the limits a process runs at', () => {
  const asSet = { waitingPerOrganisation: 8, waitMs: 2_000 };

  it('stay wide until set: as many as the connections, an organisation as many as its share of them', () => {
    expect(gateLimitsOf(20, { active: null, perOrganisation: null, ...asSet })).toEqual({
      active: 20,
      perOrganisation: 6,
      ...asSet,
    });
    expect(gateLimitsOf(1, { active: null, perOrganisation: null, ...asSet })).toMatchObject({
      active: 1,
      perOrganisation: 1,
    });
  });

  it('take what is set, an organisation’s share never over the total set', () => {
    expect(gateLimitsOf(20, { active: 12, perOrganisation: 3, ...asSet })).toEqual({
      active: 12,
      perOrganisation: 3,
      ...asSet,
    });
    expect(gateLimitsOf(20, { active: 4, perOrganisation: null, ...asSet }).perOrganisation).toBe(4);
  });
});

describe('the fair gate (4D2e C, PL-63)', () => {
  it('lets decisions in at once up to an organisation’s limit, and exactly to it', async () => {
    const { enter, granted } = gateWith();
    times(3, () => void enter('a'));
    await settled();
    expect(granted).toEqual(['a', 'a']);
  });

  it('never lets more in than the total, whoever asks', async () => {
    const { enter, granted } = gateWith({ active: 3 });
    for (const organisation of ['a', 'b', 'c', 'd']) void enter(organisation);
    await settled();
    expect(granted).toEqual(['a', 'b', 'c']);
  });

  it('keeps an organisation at its limit while the platform has room, with others going on', async () => {
    const { gate, enter, granted } = gateWith();
    times(5, () => void enter('busy'));
    void enter('calm');
    await settled();
    expect(granted).toEqual(['busy', 'busy', 'calm']);
    // A slot of another organisation's coming free gives the busy one nothing: it is still at its limit.
    gate.leave('calm');
    await settled();
    expect(granted).toEqual(['busy', 'busy', 'calm']);
    gate.leave('busy');
    await settled();
    expect(granted).toEqual(['busy', 'busy', 'calm', 'busy']);
  });

  it('gives its own next slot to an organisation at its limit the moment one of its own ends', async () => {
    const { gate, enter, granted } = gateWith({ active: 100, perOrganisation: 1 });
    void enter('a');
    void enter('a');
    await settled();
    expect(granted).toEqual(['a']);
    gate.leave('a');
    await settled();
    expect(granted).toEqual(['a', 'a']);
  });

  it('sends a calm organisation next, past a busy one’s queue of eight', async () => {
    const { gate, enter, granted } = gateWith({ active: 2, perOrganisation: 2 });
    times(10, () => void enter('busy'));
    await settled();
    expect(granted).toEqual(['busy', 'busy']);
    void enter('calm');
    await settled();
    gate.leave('busy');
    await settled();
    expect(granted).toEqual(['busy', 'busy', 'calm']);
  });

  it('takes three organisations in turn, whatever each has queued', async () => {
    const { gate, enter, granted } = gateWith({ active: 1, perOrganisation: 1, waitMs: 100_000 });
    void enter('first');
    await settled();
    // Each at most one running, so the slot itself is what is shared.
    for (const organisation of ['a', 'a', 'a', 'b', 'b', 'b', 'c', 'c', 'c']) void enter(organisation);
    await settled();
    gate.leave('first');
    await settled();
    for (const after of ['a', 'b', 'c', 'a', 'b', 'c', 'a', 'b']) {
      gate.leave(after);
      await settled();
    }
    expect(granted).toEqual(['first', 'a', 'b', 'c', 'a', 'b', 'c', 'a', 'b', 'c']);
  });

  it('takes turns among those with room when one running slot each is not the limit', async () => {
    const { gate, enter, granted } = gateWith({ active: 2, perOrganisation: 2 });
    void enter('x');
    void enter('x');
    await settled();
    for (const organisation of ['a', 'a', 'b', 'b']) void enter(organisation);
    await settled();
    gate.leave('x');
    await settled();
    gate.leave('x');
    await settled();
    gate.leave('a');
    await settled();
    gate.leave('b');
    await settled();
    expect(granted).toEqual(['x', 'x', 'a', 'b', 'a', 'b']);
  });

  it('refuses at once only the organisation whose waiting list is full, as its own limit', async () => {
    const { enter, outcomes } = gateWith({ active: 2, perOrganisation: 1, waitingPerOrganisation: 2 });
    void enter('busy');
    await settled();
    void enter('busy');
    void enter('busy');
    await settled();
    expect(outcomes).toEqual(['busy']);
    // The list holds two; the third is turned away at once.
    void enter('busy');
    await settled();
    expect(outcomes).toEqual(['busy', new DecisionGateRefused('organisation', 0)]);
    void enter('calm');
    await settled();
    expect(outcomes.at(-1)).toBe('calm');
  });

  it('calls a full list under an organisation’s own limit the platform’s, not the organisation’s', async () => {
    const { enter, outcomes } = gateWith({ active: 1, perOrganisation: 1, waitingPerOrganisation: 1 });
    void enter('busy');
    void enter('calm');
    await settled();
    void enter('calm');
    await settled();
    expect(outcomes).toEqual(['busy', new DecisionGateRefused('platform', 0)]);
    expect(outcomes.at(-1)).toMatchObject({ reason: 'platform', waitedMs: 0 });
  });

  it('calls a wait run out at its own limit the organisation’s', async () => {
    vi.useFakeTimers();
    const { enter, outcomes } = gateWith({ active: 100, perOrganisation: 1 });
    void enter('busy');
    void enter('busy');
    await vi.advanceTimersByTimeAsync(999);
    expect(outcomes).toEqual(['busy']);
    await vi.advanceTimersByTimeAsync(1);
    expect(outcomes).toEqual(['busy', new DecisionGateRefused('organisation', 1_000)]);
  });

  it('calls a wait run out under its own limit, the platform being full, the platform’s', async () => {
    vi.useFakeTimers();
    const { enter, outcomes } = gateWith({ active: 1, perOrganisation: 1 });
    void enter('busy');
    void enter('calm');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(outcomes).toEqual(['busy', new DecisionGateRefused('platform', 1_000)]);
  });

  it('calls it the organisation’s when both are full: it hit its own limit', async () => {
    vi.useFakeTimers();
    const { enter, outcomes } = gateWith({ active: 2, perOrganisation: 1 });
    void enter('a');
    void enter('b');
    void enter('a');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(outcomes.at(-1)).toMatchObject({ reason: 'organisation' });
  });

  it('loses no slot and leaves the ring to those still waiting when a waiter’s time runs out', async () => {
    vi.useFakeTimers();
    const { gate, enter, granted, outcomes } = gateWith({ active: 1, perOrganisation: 1 });
    void enter('first');
    void enter('gone');
    await vi.advanceTimersByTimeAsync(500);
    void enter('next');
    await vi.advanceTimersByTimeAsync(500);
    expect(outcomes.at(-1)).toMatchObject({ reason: 'platform' });
    gate.leave('first');
    await vi.advanceTimersByTimeAsync(0);
    expect(granted).toEqual(['first', 'next']);
    gate.leave('next');
    await vi.advanceTimersByTimeAsync(0);
    expect(gate.organisationsInHand()).toBe(0);
    // The total is back to none: a whole limit's worth go in again.
    void enter('again');
    await vi.advanceTimersByTimeAsync(0);
    expect(granted.at(-1)).toBe('again');
  });

  it('keeps an organisation’s place in the ring when one of its waiters leaves and others stay', async () => {
    vi.useFakeTimers();
    const { gate, enter, granted } = gateWith({ active: 1, perOrganisation: 1 });
    void enter('first');
    void enter('a');
    await vi.advanceTimersByTimeAsync(500);
    void enter('a');
    void enter('b');
    await vi.advanceTimersByTimeAsync(500);
    // a's first waiter ran out; a is still ahead of b.
    gate.leave('first');
    await vi.advanceTimersByTimeAsync(0);
    expect(granted).toEqual(['first', 'a']);
  });

  it('never runs a waiter that ran out, and drops the right one from the middle of a list', async () => {
    vi.useFakeTimers();
    const { gate, enter, granted, outcomes } = gateWith({ active: 1, perOrganisation: 1, waitMs: 1_000 });
    void enter('a');
    void enter('b');
    await vi.advanceTimersByTimeAsync(600);
    void enter('b');
    await vi.advanceTimersByTimeAsync(400);
    expect(outcomes.at(-1)).toMatchObject({ reason: 'platform' });
    gate.leave('a');
    await vi.advanceTimersByTimeAsync(0);
    expect(granted).toEqual(['a', 'b']);
    gate.leave('b');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(granted).toEqual(['a', 'b']);
    expect(gate.organisationsInHand()).toBe(0);
  });

  it('holds nothing once all are given back or turned away, its own or a refused one’s', async () => {
    const { gate, enter, outcomes } = gateWith({ active: 1, perOrganisation: 1, waitingPerOrganisation: 0 });
    void enter('a');
    await settled();
    void enter('b');
    await settled();
    expect(outcomes.at(-1)).toMatchObject({ reason: 'platform' });
    expect(gate.organisationsInHand()).toBe(1);
    gate.leave('a');
    expect(gate.organisationsInHand()).toBe(0);
    // A leave no one asked for changes nothing, and never goes below none.
    gate.leave('a');
    void enter('c');
    void enter('d');
    await settled();
    expect(outcomes.at(-1)).toMatchObject({ reason: 'platform' });
  });

  it('gives no slot twice: a slot let go with no one waiting is simply free', async () => {
    const { gate, enter, granted } = gateWith({ active: 1, perOrganisation: 1 });
    void enter('a');
    await settled();
    gate.leave('a');
    void enter('b');
    void enter('c');
    await settled();
    expect(granted).toEqual(['a', 'b']);
  });

  it('says what stopped it', () => {
    expect(new DecisionGateRefused('platform', 7).message).toBe(
      "A decision was turned away after 7 ms at the gate, by the platform's limit",
    );
  });
});
