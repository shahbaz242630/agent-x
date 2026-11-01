import { afterEach, describe, expect, it, vi } from 'vitest';

import { createAgentTurns } from './agent-turns.ts';
import { createDecisionGate, DecisionGateRefused, type GateLimits } from './decision-gate.ts';
import {
  createDecisionEntry,
  type DecisionAsked,
  SUPPLIER_TURN_WAIT_MS,
  SupplierTurnExceeded,
  TURNS_A_SUPPLIER,
} from './decision-entry.ts';

const ORG = '019a0000-0000-7000-8000-00000000000a';
const OTHER_ORG = '019a0000-0000-7000-8000-00000000000b';
const SUPPLIER = '019a0000-0000-7000-8000-0000000000aa';
const OTHER_SUPPLIER = '019a0000-0000-7000-8000-0000000000bb';

const asked = (agentId: string, supplierId = SUPPLIER, orgId = ORG): DecisionAsked => ({ agentId, orgId, supplierId });

/** A piece of work that runs until it is let go, recording when it starts. */
function held(started: string[], name: string) {
  const { promise, resolve, reject } = Promise.withResolvers<string>();
  return {
    work: () => {
      started.push(name);
      return promise;
    },
    finish: () => {
      resolve(name);
    },
    fail: () => {
      reject(new Error(`${name} failed`));
    },
  };
}

/** Lets every settled promise's callbacks run. */
const settled = () => new Promise<void>((resolve) => setImmediate(resolve));

afterEach(() => {
  vi.useRealTimers();
});

describe('a decision’s way to a connection (4D2e C, PL-62)', () => {
  it('lets two of a supplier’s decisions go on, and the rest in the order they came as each ends', async () => {
    expect(TURNS_A_SUPPLIER).toBe(2);
    const entry = createDecisionEntry();
    const started: string[] = [];
    const [a, b, c, d] = ['a', 'b', 'c', 'd'].map((name) => held(started, name));
    if (a === undefined || b === undefined || c === undefined || d === undefined) throw new Error('four');
    const answers = [a, b, c, d].map(({ work }, n) => entry.run(asked(`agent-${String(n)}`), work));
    await settled();
    expect(started).toEqual(['a', 'b']);
    b.finish();
    await settled();
    expect(started).toEqual(['a', 'b', 'c']);
    a.finish();
    await settled();
    expect(started).toEqual(['a', 'b', 'c', 'd']);
    c.finish();
    d.finish();
    expect(await Promise.all(answers)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('never holds one supplier’s decisions behind another’s', async () => {
    const entry = createDecisionEntry({ perSupplier: 1 });
    const started: string[] = [];
    void entry.run(asked('agent-1'), held(started, 'one').work);
    void entry.run(asked('agent-2'), held(started, 'waits').work);
    void entry.run(asked('agent-3', OTHER_SUPPLIER), held(started, 'two').work);
    await settled();
    expect(started).toEqual(['one', 'two']);
  });

  it('never lines the same supplier ID up across two organisations: an agent can’t reach another’s line', async () => {
    const entry = createDecisionEntry({ perSupplier: 1 });
    const started: string[] = [];
    void entry.run(asked('agent-1', SUPPLIER, ORG), held(started, 'ours').work);
    void entry.run(asked('agent-2', SUPPLIER, OTHER_ORG), held(started, 'theirs').work);
    await settled();
    expect(started).toEqual(['ours', 'theirs']);
    // Two agents' turns, two suppliers' lines, two organisations at the gate.
    expect(entry.linesInHand()).toBe(6);
  });

  it('counts a supplier or organisation written in capitals as the same line', async () => {
    const entry = createDecisionEntry({ perSupplier: 1 });
    const started: string[] = [];
    const first = held(started, 'lower');
    const answer = entry.run(asked('agent-1'), first.work);
    const upper = held(started, 'upper');
    const later = entry.run(asked('agent-2', SUPPLIER.toUpperCase(), ORG.toUpperCase()), upper.work);
    await settled();
    expect(started).toEqual(['lower']);
    first.finish();
    await answer;
    await settled();
    expect(started).toEqual(['lower', 'upper']);
    upper.finish();
    await later;
    expect(entry.linesInHand()).toBe(0);
  });

  it('takes the agent’s turn first: an agent’s burst waits behind itself, never in another agent’s way on the supplier', async () => {
    const entry = createDecisionEntry({ turns: createAgentTurns({ perAgent: 1 }), perSupplier: 1 });
    const started: string[] = [];
    const a1 = held(started, 'a1');
    const answer = entry.run(asked('agent-a'), a1.work);
    void entry.run(asked('agent-a'), held(started, 'a2').work);
    void entry.run(asked('agent-b'), held(started, 'b').work);
    await settled();
    a1.finish();
    await answer;
    await settled();
    expect(started).toEqual(['a1', 'b']);
  });

  it('turns away a decision that waits its whole bound, unrun, and hands its agent’s turn on', async () => {
    vi.useFakeTimers();
    expect(SUPPLIER_TURN_WAIT_MS).toBe(3_000);
    const entry = createDecisionEntry({ turns: createAgentTurns({ perAgent: 1 }), perSupplier: 1 });
    const started: string[] = [];
    const first = held(started, 'a');
    void entry.run(asked('agent-1'), first.work);
    const late = entry.run(asked('agent-2'), held(started, 'b').work);
    const after = held(started, 'c');
    const same = entry.run(asked('agent-2', OTHER_SUPPLIER), after.work);
    const rejected = expect(late).rejects.toEqual(new SupplierTurnExceeded(SUPPLIER_TURN_WAIT_MS));
    await vi.advanceTimersByTimeAsync(SUPPLIER_TURN_WAIT_MS - 1);
    expect(started).toEqual(['a']);
    await vi.advanceTimersByTimeAsync(1);
    await rejected;
    expect(started).toEqual(['a', 'c']);
    after.finish();
    expect(await same).toBe('c');
    first.finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(entry.linesInHand()).toBe(0);
  });

  it('waits as long as it is told, when told', async () => {
    vi.useFakeTimers();
    const entry = createDecisionEntry({ perSupplier: 1, supplierWaitMs: 50 });
    void entry.run(asked('agent-1'), () => new Promise(() => undefined));
    const late = entry.run(asked('agent-2'), () => Promise.resolve('never'));
    const rejected = expect(late).rejects.toEqual(new SupplierTurnExceeded(50));
    await vi.advanceTimersByTimeAsync(50);
    await rejected;
  });

  it('hands the supplier’s turn on when a decision fails, answering that failure to its own caller alone', async () => {
    const entry = createDecisionEntry({ perSupplier: 1 });
    const started: string[] = [];
    const failing = held(started, 'a');
    const next = held(started, 'b');
    const failed = entry.run(asked('agent-1'), failing.work);
    const answer = entry.run(asked('agent-2'), next.work);
    failing.fail();
    await expect(failed).rejects.toThrow('a failed');
    await settled();
    expect(started).toEqual(['a', 'b']);
    next.finish();
    expect(await answer).toBe('b');
    expect(entry.linesInHand()).toBe(0);
  });

  it('tells the work how long each line took', async () => {
    vi.useFakeTimers();
    const entry = createDecisionEntry({ turns: createAgentTurns({ perAgent: 1 }), perSupplier: 1 });
    const started: string[] = [];
    const inTheWay = held(started, 'other agent');
    void entry.run(asked('agent-2'), inTheWay.work);
    const own = held(started, 'own earlier');
    void entry.run(asked('agent-1', OTHER_SUPPLIER), own.work);
    let waits: unknown;
    const answer = entry.run(asked('agent-1'), (waited) => {
      waits = waited;
      return Promise.resolve('done');
    });
    await vi.advanceTimersByTimeAsync(100);
    own.finish();
    await vi.advanceTimersByTimeAsync(40);
    inTheWay.finish();
    expect(await answer).toBe('done');
    expect(waits).toEqual({ turnWaitMs: 100, supplierTurnWaitMs: 40, gateWaitMs: 0 });
  });

  describe('with the fair gate', () => {
    const LIMITS: GateLimits = { active: 2, perOrganisation: 2, waitingPerOrganisation: 8, waitMs: 1_000 };

    it('takes its slot last: one waiting on a supplier’s turn holds none, so another decision has it', async () => {
      const entry = createDecisionEntry({ perSupplier: 1, gate: createDecisionGate(LIMITS) });
      const started: string[] = [];
      void entry.run(asked('agent-1'), held(started, 'a').work);
      void entry.run(asked('agent-2'), held(started, 'waits its turn').work);
      void entry.run(asked('agent-3', OTHER_SUPPLIER), held(started, 'b').work);
      await settled();
      expect(started).toEqual(['a', 'b']);
    });

    it('holds its slot and its turns the whole way through, giving all back at the end, failure too', async () => {
      const gate = createDecisionGate({ ...LIMITS, active: 1 });
      const entry = createDecisionEntry({ perSupplier: 1, gate });
      const started: string[] = [];
      const failing = held(started, 'a');
      const failed = entry.run(asked('agent-1'), failing.work);
      const next = held(started, 'b');
      const answer = entry.run(asked('agent-2', OTHER_SUPPLIER), next.work);
      await settled();
      expect(started).toEqual(['a']);
      failing.fail();
      await expect(failed).rejects.toThrow('a failed');
      await settled();
      expect(started).toEqual(['a', 'b']);
      next.finish();
      expect(await answer).toBe('b');
      expect(entry.linesInHand()).toBe(0);
    });

    it('gives back the supplier’s turn when the gate turns it away, running nothing, and holds no slot', async () => {
      vi.useFakeTimers();
      const entry = createDecisionEntry({ perSupplier: 1, gate: createDecisionGate({ ...LIMITS, active: 1 }) });
      const started: string[] = [];
      const first = held(started, 'a');
      void entry.run(asked('agent-1'), first.work);
      const late = entry.run(asked('agent-2', OTHER_SUPPLIER), held(started, 'b').work);
      const rejected = expect(late).rejects.toEqual(new DecisionGateRefused('platform', 1_000));
      await vi.advanceTimersByTimeAsync(1_000);
      await rejected;
      expect(started).toEqual(['a']);
      first.finish();
      await vi.advanceTimersByTimeAsync(0);
      expect(entry.linesInHand()).toBe(0);
    });

    it('says how long the gate took, and lines an organisation up whichever way its ID is written', async () => {
      vi.useFakeTimers();
      const entry = createDecisionEntry({ gate: createDecisionGate({ ...LIMITS, perOrganisation: 1 }) });
      const started: string[] = [];
      const first = held(started, 'a');
      const answer = entry.run(asked('agent-1', SUPPLIER, ORG), first.work);
      let waits: unknown;
      const later = entry.run(asked('agent-2', OTHER_SUPPLIER, ORG.toUpperCase()), (waited) => {
        waits = waited;
        return Promise.resolve('done');
      });
      await vi.advanceTimersByTimeAsync(70);
      first.finish();
      await answer;
      expect(await later).toBe('done');
      expect(waits).toEqual({ turnWaitMs: 0, supplierTurnWaitMs: 0, gateWaitMs: 70 });
    });
  });
});
