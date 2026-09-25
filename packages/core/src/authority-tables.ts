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

import { INVITATIONS, MEMBERSHIPS } from './modules/identity/index.ts';
import { ORGANIZATIONS } from './modules/organizations/index.ts';

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
}

export const AUTHORITY_TABLES: readonly AuthorityTableEntry[] = [ORGANIZATIONS, MEMBERSHIPS, INVITATIONS];
