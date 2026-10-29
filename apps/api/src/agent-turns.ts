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
  constructor(waitedMs: number) {
    super(`A decision waited ${String(waitedMs)} ms for its agent's turn, behind its other decisions in this process`);
    this.name = 'TurnWaitExceeded';
  }
}

export interface AgentTurns {
  /** `work` in its agent's turn: at once while fewer than the limit run, otherwise after those before it. */
  run<T>(agentId: string, work: () => Promise<T>): Promise<T>;
  /** The agents with a decision running or waiting: none once all have ended, so the memory never grows with agents seen. */
  agentsInHand(): number;
}

interface Line {
  running: number;
  readonly waiting: (() => void)[];
}

export function createAgentTurns({
  perAgent = TURNS_AN_AGENT,
  waitMs = TURN_WAIT_MS,
}: { readonly perAgent?: number; readonly waitMs?: number } = {}): AgentTurns {
  // Only agents with a decision running or waiting have a line, so the map stays the size of the work in hand.
  const lines = new Map<string, Line>();

  function turnIn(line: Line): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        line.waiting.splice(line.waiting.indexOf(go), 1);
        reject(new TurnWaitExceeded(waitMs));
      }, waitMs);
      function go(): void {
        clearTimeout(timer);
        resolve();
      }
      line.waiting.push(go);
    });
  }

  /** A turn ended: handed to the next in line, or the line closed when no one waits. */
  function ended(agentId: string, line: Line): void {
    const next = line.waiting.shift();
    if (next !== undefined) {
      next();
      return;
    }
    line.running -= 1;
    if (line.running === 0) lines.delete(agentId);
  }

  return {
    agentsInHand: () => lines.size,
    async run(agentId, work) {
      let line = lines.get(agentId);
      if (line === undefined) {
        line = { running: 0, waiting: [] };
        lines.set(agentId, line);
      }
      // A turn handed on keeps its count: the one ending passes its place to the next, never freeing it first.
      if (line.running < perAgent) line.running += 1;
      else await turnIn(line);
      try {
        return await work();
      } finally {
        ended(agentId, line);
      }
    },
  };
}
