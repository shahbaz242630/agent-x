import { afterEach, describe, expect, it, vi } from 'vitest';

import { createAgentTurns, TURN_WAIT_MS, TURNS_AN_AGENT, TurnWaitExceeded } from './agent-turns.ts';

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

describe("an agent's turns (S160)", () => {
  it('runs two of an agent’s decisions at once, and the rest in the order they came as each ends', async () => {
    expect(TURNS_AN_AGENT).toBe(2);
    const turns = createAgentTurns();
    const started: string[] = [];
    const [a, b, c, d] = ['a', 'b', 'c', 'd'].map((name) => held(started, name));
    if (a === undefined || b === undefined || c === undefined || d === undefined) throw new Error('four');
    const answers = [a, b, c, d].map(({ work }) => turns.run('agent-1', work));
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

  it('never holds one agent’s decisions behind another’s', async () => {
    const turns = createAgentTurns({ perAgent: 1 });
    const started: string[] = [];
    const first = held(started, 'one-a');
    void turns.run('agent-1', first.work);
    void turns.run('agent-1', held(started, 'one-b').work);
    const other = held(started, 'two-a');
    const answer = turns.run('agent-2', other.work);
    await settled();
    expect(started).toEqual(['one-a', 'two-a']);
    other.finish();
    expect(await answer).toBe('two-a');
  });

  it('hands the turn on when a decision fails, and answers that failure to its own caller alone', async () => {
    const turns = createAgentTurns({ perAgent: 1 });
    const started: string[] = [];
    const failing = held(started, 'a');
    const next = held(started, 'b');
    const failed = turns.run('agent-1', failing.work);
    const answer = turns.run('agent-1', next.work);
    failing.fail();
    await expect(failed).rejects.toThrow('a failed');
    await settled();
    expect(started).toEqual(['a', 'b']);
    next.finish();
    expect(await answer).toBe('b');
  });

  it('fails a decision that waits its whole bound, unrun, and keeps the line going for those after it', async () => {
    vi.useFakeTimers();
    expect(TURN_WAIT_MS).toBe(10_000);
    const turns = createAgentTurns({ perAgent: 1 });
    const started: string[] = [];
    const first = held(started, 'a');
    void turns.run('agent-1', first.work);
    const late = turns.run('agent-1', held(started, 'b').work);
    const rejected = expect(late).rejects.toBeInstanceOf(TurnWaitExceeded);
    await vi.advanceTimersByTimeAsync(TURN_WAIT_MS - 1);
    const after = held(started, 'c');
    const answer = turns.run('agent-1', after.work);
    await vi.advanceTimersByTimeAsync(1);
    await rejected;
    await expect(late).rejects.toThrow(`waited ${String(TURN_WAIT_MS)} ms`);

    first.finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(started).toEqual(['a', 'c']);
    after.finish();
    expect(await answer).toBe('c');
  });

  it('never lets a turn’s spent wait drop another from the line', async () => {
    vi.useFakeTimers();
    const turns = createAgentTurns({ perAgent: 1 });
    const started: string[] = [];
    const [a, b, c, d] = ['a', 'b', 'c', 'd'].map((name) => held(started, name));
    if (a === undefined || b === undefined || c === undefined || d === undefined) throw new Error('four');
    void turns.run('agent-1', a.work);
    void turns.run('agent-1', b.work);
    a.finish();
    await vi.advanceTimersByTimeAsync(TURN_WAIT_MS / 2);
    // b has its turn; c and d wait, c's bound ending first.
    const answers = [c, d].map(({ work }) => turns.run('agent-1', work));
    await vi.advanceTimersByTimeAsync(TURN_WAIT_MS / 2);
    b.finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(started).toEqual(['a', 'b', 'c']);
    c.finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(started).toEqual(['a', 'b', 'c', 'd']);
    d.finish();
    expect(await Promise.all(answers)).toEqual(['c', 'd']);
  });

  it('starts afresh once an agent’s line is empty, keeping no line for it', async () => {
    const turns = createAgentTurns({ perAgent: 1 });
    expect(await turns.run('agent-1', () => Promise.resolve('first'))).toBe('first');
    await expect(turns.run('agent-2', () => Promise.reject(new Error('refused')))).rejects.toThrow('refused');
    expect(turns.agentsInHand()).toBe(0);
    const started: string[] = [];
    void turns.run('agent-1', held(started, 'again').work);
    await settled();
    expect(started).toEqual(['again']);
    expect(turns.agentsInHand()).toBe(1);
  });
});
