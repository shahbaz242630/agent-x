import { afterEach, describe, expect, it, vi } from 'vitest';

import { createAgentTurns } from './agent-turns.ts';
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
    expect(entry.linesInHand()).toBe(4);
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
    expect(waits).toEqual({ turnWaitMs: 100, supplierTurnWaitMs: 40 });
  });
});
