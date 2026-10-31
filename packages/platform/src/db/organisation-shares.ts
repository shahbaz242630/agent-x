// Each organisation's share of the connections (4D2d, PL-63, partner S165): one
// organisation's trouble must never touch another's speed. The API's pool is
// shared, so a stuck or busy organisation could hold every connection and make
// all the others wait (the neighbours phase, S166: a calm organisation's decision
// p95 100 ms to 16 s, most of its requests failing). Past its share, only that
// organisation waits, holding no connection, and past a bound is answered busy.
// Counted per API process, so the real limit grows with replicas, as the pool does.
//
// Agents' requests alone count against it (asAgentTraffic): they are what can
// arrive by the thousand and pile up on a held row. People are held by their own
// rate limit, and background jobs walk organisations one at a time. Neither may
// queue here (the review of the first version, S166): an admin's freeze or a new
// agent's shown-once key could be told busy after it had committed, the login
// events' copy would stop for every organisation behind one busy one, and a
// bank's answer could be refused after the bank had been called.
import { AsyncLocalStorage } from 'node:async_hooks';

import { createKeyedSlots } from './keyed-slots.ts';

/** How much of the pool one organisation may hold: with one more in the same trouble, others still have the rest. */
const SHARE_OF_THE_POOL = 0.3;

/** How long a transaction waits for its organisation's share: the pool's own wait for a connection. */
const SHARE_WAIT_MS = 10_000;

/** The connections one organisation may hold of a pool of `poolMax`: at least one, or it could do nothing. */
export const organisationShareOf = (poolMax: number): number => Math.max(1, Math.floor(poolMax * SHARE_OF_THE_POOL));

/** Postgres's `lock_not_available`: a lock's wait ran out, and its transaction is rolled back. */
const LOCK_NOT_AVAILABLE = '55P03';

/** Whether a statement failed because a lock's wait ran out. */
export const isLockWaitRunOut = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === LOCK_NOT_AVAILABLE;

/** A transaction that waited its whole bound for its organisation's share: it never began, so nothing of it was made. */
export class OrganisationBusy extends Error {
  readonly waitedMs: number;

  constructor(waitedMs: number) {
    super(`A transaction waited ${String(waitedMs)} ms for its organisation's share of the connections`);
    this.name = 'OrganisationBusy';
    this.waitedMs = waitedMs;
  }
}

const agentTraffic = new AsyncLocalStorage<true>();

/** Runs `work` as an agent's request: its organisation's transactions inside count against its share. */
export const asAgentTraffic = <T>(work: () => T): T => agentTraffic.run(true, work);

/** Whether this is an agent's request, whose transactions count against its organisation's share. */
export const isAgentTraffic = (): boolean => agentTraffic.getStore() === true;

export interface OrganisationShares {
  /** Takes a place in the organisation's share, waiting its turn; rejects with OrganisationBusy past the wait. */
  enter(organisation: string): Promise<void>;
  /** Gives a place back. */
  leave(organisation: string): void;
}

export function createOrganisationShares(perOrganisation: number, waitMs = SHARE_WAIT_MS): OrganisationShares {
  return createKeyedSlots({ perKey: perOrganisation, waitMs, exceeded: () => new OrganisationBusy(waitMs) });
}
