// How an agent's decision comes to a database connection in this process (4D2e
// C, PL-62): in lines, waiting in each holding no connection, the connection last.
// - Its agent's turn (agent-turns.ts): one agent's burst can't take the others'
//   places in the lines after it.
// - Its supplier's turn: decisions on one supplier take that row's lock one at a
//   time (ADR-006 §6, level 6), so past a few, each only holds a connection while
//   it waits. A wait is bounded, and answered busy with nothing made: 503
//   ORGANISATION_BUSY, with Retry-After. Keyed by the organisation as well as the
//   supplier, and the organisation comes from the agent's key, never its request:
//   whatever an agent names, it can only join its own organisation's lines. Those
//   lines slow only the organisation whose supplier it is.
// - A slot at the fair gate (decision-gate.ts), last, so none is held while waiting
//   on a turn. It lasts the whole decision, retries included; a replay's read of its
//   answer comes after it (decision-gate.ts). Those waiting in a turn behind a
//   decision held by a full platform are held by the platform too (heldByThePlatform).
// The row lock stays the guarantee: other replicas and every other writer still
// serialise on it. This only stops waiters holding the pool. Counted per process,
// so across N copies a supplier's limit is N times this.
import { createKeyedSlots } from '@agentx/platform/db';

import { type AgentTurns, createAgentTurns } from './agent-turns.ts';
import { createDecisionGate, type DecisionGate, NO_GATE_LIMITS } from './decision-gate.ts';

/** Decisions on one supplier at once in this process: one holding its lock, and the next ready as it lets go. */
export const TURNS_A_SUPPLIER = 2;

/** How long a decision waits for its supplier's turn: under the 5 s a lock's own wait may then take. */
export const SUPPLIER_TURN_WAIT_MS = 3_000;

/** A decision that waited its whole bound behind its supplier's other decisions: nothing of it was made. */
export class SupplierTurnExceeded extends Error {
  readonly waitedMs: number;

  constructor(waitedMs: number) {
    super(
      `A decision waited ${String(waitedMs)} ms for its supplier's turn, behind its other decisions in this process`,
    );
    this.name = 'SupplierTurnExceeded';
    this.waitedMs = waitedMs;
  }
}

/** Whose decision it is: the agent's key says whose the first two are, and the request names the supplier. */
export interface DecisionAsked {
  readonly agentId: string;
  readonly orgId: string;
  readonly supplierId: string;
}

/** How long a decision waited in each line, for its log line. */
export interface EntryWaits {
  readonly turnWaitMs: number;
  readonly supplierTurnWaitMs: number;
  readonly gateWaitMs: number;
}

export interface DecisionEntry {
  /** `work`, once its decision's turns have come, told how long each took. Rejects unrun, with what its wait ran out as. */
  run<T>(asked: DecisionAsked, work: (waits: EntryWaits) => Promise<T>): Promise<T>;
  /** Whether this organisation's decisions, under its own limit, are held at the gate by the whole platform being full. */
  heldByThePlatform(orgId: string): boolean;
  /** The lines with anyone in them: none once all have ended, so the memory never grows with suppliers named. */
  linesInHand(): number;
}

export function createDecisionEntry({
  turns = createAgentTurns(),
  perSupplier = TURNS_A_SUPPLIER,
  supplierWaitMs = SUPPLIER_TURN_WAIT_MS,
  gate = createDecisionGate(NO_GATE_LIMITS),
}: {
  readonly turns?: AgentTurns;
  readonly perSupplier?: number;
  readonly supplierWaitMs?: number;
  readonly gate?: DecisionGate;
} = {}): DecisionEntry {
  const suppliers = createKeyedSlots({
    perKey: perSupplier,
    waitMs: supplierWaitMs,
    exceeded: () => new SupplierTurnExceeded(supplierWaitMs),
  });
  return {
    heldByThePlatform: (orgId) => gate.heldByThePlatform(orgId.toLowerCase()),
    linesInHand: () => turns.agentsInHand() + suppliers.keysInHand() + gate.organisationsInHand(),
    run({ agentId, orgId, supplierId }, work) {
      const asked = performance.now();
      return turns.run(agentId, async () => {
        const turned = performance.now();
        // In lower case, as Postgres prints a uuid: an ID in capitals is the same supplier.
        const organisation = orgId.toLowerCase();
        const supplier = `${organisation}:${supplierId.toLowerCase()}`;
        await suppliers.enter(supplier);
        try {
          const supplierTurned = performance.now();
          await gate.enter(organisation);
          try {
            return await work({
              turnWaitMs: turned - asked,
              supplierTurnWaitMs: supplierTurned - turned,
              gateWaitMs: performance.now() - supplierTurned,
            });
          } finally {
            gate.leave(organisation);
          }
        } finally {
          suppliers.leave(supplier);
        }
      });
    },
  };
}
