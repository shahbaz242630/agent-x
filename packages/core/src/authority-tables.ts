// Every authority table (ADR-012 §2): a table whose fields grant, restore or
// limit authority (a status, a role, a limit, an expiry), which must equal the
// object's latest signed event. One list, kept in the product because the
// running API reads it: its live schema guard holds the app role to each
// table's narrower rights (A3f-2). CI's checks (A3c-1) and the lint rules
// (A3c-2) read this same list through tooling/authority-tables.ts, so the
// three can't drift.
//
// An entry is the module's own table description, imported from its public
// interface, never a copy: the SignedStateTable it passes to verifiedState and
// record, with the state machine that rules its status as `rules`, as
// changeStatus takes it. A new authority table goes on it in the same PR as
// its migration.
import type { SignedStateTable } from '@agentx/platform/db';

import { AGENT_KEYS, AGENTS } from './modules/agents/index.ts';
import { SOURCES } from './modules/funding-sources/index.ts';
import { FACTOR_RESETS, INVITATIONS, MEMBERSHIPS, REGISTERED_CONTACTS } from './modules/identity/index.ts';
import { MANDATE_VERSIONS, MANDATES, POLICIES, POLICY_VERSIONS } from './modules/mandates/index.ts';
import { ORGANIZATIONS } from './modules/organizations/index.ts';
import { SPEND_REQUESTS } from './modules/spend-requests/index.ts';
import { BENEFICIARY_REGISTRATIONS, SUPPLIER_VERSIONS, SUPPLIERS } from './modules/suppliers/index.ts';

/**
 * What an entry's status machine must show: its states, the one a new row
 * starts in, and every move. The shared kernel's defineStateMachine gives
 * one; this structural view fits it whatever its states and events are.
 */
export interface AuthorityStatusRules {
  readonly name: string;
  readonly states: readonly string[];
  readonly initial: string;
  readonly moves: readonly { readonly from: string; readonly to: string }[];
}

/** An authority table, with its status machine when it has a status. */
export interface AuthorityTableEntry extends SignedStateTable {
  readonly rules?: AuthorityStatusRules;
  /** Its rows are made once and never changed (a supplier's version): the made-once guard holds them (0032). */
  readonly madeOnce?: true;
  /** Its columns fixed when a row is made (a mandate's agent, time zone and window): the fixed-at-creation guard holds them (0035). */
  readonly fixedAtCreation?: readonly string[];
  /**
   * Its rows only grow (a spend request's): clearing the integrity hold checks
   * those in these statuses alone, the ones that can still act (CheckedTable).
   */
  readonly liveStatuses?: readonly string[];
  /** The checks over its status with other columns its migration writes, by name, which CI's A3c allows it alone. */
  readonly statusConditions?: readonly string[];
}

/**
 * In the global lock order (ADR-006 §6): the organisation (2), then its
 * invitations and memberships (2a, an invitation before a membership, as
 * accepting and confirming take them), then its registered contacts (2b,
 * B6-1a: an admin's membership is read before the contacts it changes), then
 * its factor resets (2c, B6-3a: a reset is confirmed by a contact read
 * first), then its agents (3) and their keys (3a, C1-1), then its mandates
 * and their versions (4, Phase 2 B1) and their policies and theirs (4,
 * after the mandates, Phase 2 C1), then its funding sources (5, D2-2),
 * then its suppliers (6), their payee registrations (6, after their supplier,
 * E2-1) and their versions (6, after the registration that gives one its
 * reference, E1-1), then its spend requests (8, Phase 2 D1). Clearing the
 * integrity hold checks every row of each in this order (verifyAll, B3+-2c; a
 * table with `liveStatuses`, its live rows), so a new table goes in at its
 * level.
 */
export const AUTHORITY_TABLES: readonly AuthorityTableEntry[] = [
  ORGANIZATIONS,
  INVITATIONS,
  MEMBERSHIPS,
  REGISTERED_CONTACTS,
  FACTOR_RESETS,
  AGENTS,
  AGENT_KEYS,
  MANDATES,
  MANDATE_VERSIONS,
  POLICIES,
  POLICY_VERSIONS,
  SOURCES,
  SUPPLIERS,
  BENEFICIARY_REGISTRATIONS,
  SUPPLIER_VERSIONS,
  SPEND_REQUESTS,
];
