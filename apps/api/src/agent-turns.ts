// One agent's decisions take turns in this process (4D2d, S160 run day): at
// most a few at once hold a database connection, the rest wait here, in the
// order they came, holding none. A burst from one agent queues on its month's
// lock by design (ADR-006 §6, level 7); waiting there, each held one of the
// pool's ten connections, so every other organisation's requests waited for a
// connection behind it (S160: other organisations' p95 2 s during a 50-request
// spike, 250–290 ms either side). The lock stays the guarantee: other replicas
// and every other writer still serialise on it. This only stops one agent
// holding the pool.
//
// A wait is bounded as the pool's own is (10 s for a connection): past it the
// decision is answered busy (503 AGENT_BUSY, with Retry-After), with nothing
// made, so the agent sends it again (partner, S161).

/** Decisions of one agent at once in this process: two, so one can get its locks while another holds the month's. */
export const TURNS_AN_AGENT = 2;

/** How long a decision waits for its turn: the pool's own wait for a connection. */
export const TURN_WAIT_MS = 10_000;

/** A decision that waited its whole bound for its agent's turn: nothing of it was made. */
export class TurnWaitExceeded extends Error {
  readonly waitedMs: number;

  constructor(waitedMs: number) {
    super(`A decision waited ${String(waitedMs)} ms for its agent's turn, behind its other decisions in this process`);
    this.name = 'TurnWaitExceeded';
    this.waitedMs = waitedMs;
  }
}

import { createKeyedSlots } from '@agentx/platform/db';

export interface AgentTurns {
  /** `work` in its agent's turn: at once while fewer than the limit run, otherwise after those before it. */
  run<T>(agentId: string, work: () => Promise<T>): Promise<T>;
  /** The agents with a decision running or waiting: none once all have ended, so the memory never grows with agents seen. */
  agentsInHand(): number;
}

export function createAgentTurns({
  perAgent = TURNS_AN_AGENT,
  waitMs = TURN_WAIT_MS,
}: { readonly perAgent?: number; readonly waitMs?: number } = {}): AgentTurns {
  const turns = createKeyedSlots({ perKey: perAgent, waitMs, exceeded: () => new TurnWaitExceeded(waitMs) });
  return {
    agentsInHand: () => turns.keysInHand(),
    async run(agentId, work) {
      await turns.enter(agentId);
      try {
        return await work();
      } finally {
        turns.leave(agentId);
      }
    },
  };
}
