// The authority-table registry (the product's list, packages/core/src/authority-tables.ts,
// which tooling/authority-tables.ts hands to CI's checks) holds each
// module's own table description, not a copy of it, so the checks in CI are
// made against the very facts the app runs on. That only holds if a module's
// SignedStateTable and its state machine fit an AuthorityTable exactly, which
// is what this checks, on a stand-in module's table and on the real list
// (packages/testing can't import @agentx/platform or @agentx/core, so the
// checks describe what they need, as the status change does with StatusRules).
// Each `@ts-expect-error` below is itself checked: if the line compiled, the
// type check would fail on the unused directive.
import { describe, expect, it } from 'vitest';

import { defineStateMachine } from '../../packages/core/src/shared-kernel/index.ts';
import type { SignedStateTable } from '../../packages/platform/src/db/index.ts';
import type { AuthorityMachine, AuthorityTable } from '../../packages/testing/src/index.ts';
import {
  AUTHORITY_TABLES as PRODUCT_AUTHORITY_TABLES,
  type AuthorityTableEntry,
} from '../../packages/core/src/authority-tables.ts';
import { INVITATION, INVITATIONS, MEMBERSHIP, MEMBERSHIPS } from '../../packages/core/src/modules/identity/index.ts';
import { ORGANIZATION, ORGANIZATIONS } from '../../packages/core/src/modules/organizations/index.ts';
import { AUTHORITY_TABLES } from '../authority-tables.ts';
import { SCHEMA_POLICY } from '../schema-policy.ts';

const AGENT = defineStateMachine({
  name: 'agent',
  states: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
  initial: 'ACTIVE',
  events: {
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
    revoke: { from: ['ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
  },
});

/** A module's table description, as it would be written in its infrastructure. */
const AGENTS: SignedStateTable = {
  table: 'agents.agents',
  subject: 'agent',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'expires_at', type: 'timestamptz' },
  ],
};

describe('the authority-table registry takes the modules’ own descriptions', () => {
  it('a signed-state table is an authority table, with its machine when it has a status', () => {
    const withoutStatus: AuthorityTable = AGENTS;
    const withStatus: AuthorityTable = { ...AGENTS, status: AGENT };

    expect(withoutStatus.status).toBeUndefined();
    expect(withStatus.status).toBe(AGENT);
  });

  it("a state machine is a machine's rules, whatever its own states and events are", () => {
    const rules: AuthorityMachine = AGENT;

    expect(rules).toMatchObject({
      name: 'agent',
      states: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
      initial: 'ACTIVE',
      moves: [
        { from: 'ACTIVE', to: 'SUSPENDED' },
        { from: 'SUSPENDED', to: 'ACTIVE' },
        { from: 'ACTIVE', to: 'REVOKED' },
        { from: 'SUSPENDED', to: 'REVOKED' },
      ],
    });
  });

  it('and refuses a description the signed state could not read', () => {
    // @ts-expect-error -- A type the row is not read as.
    const unknownType: AuthorityTable = { ...AGENTS, fields: [{ column: 'settings', type: 'jsonb' }] };
    // @ts-expect-error -- A table records its rows as one subject type; it is not optional.
    const noSubject: AuthorityTable = { table: 'agents.agents', fields: AGENTS.fields };
    // @ts-expect-error -- A machine's moves are pairs of states, not text.
    const looseMachine: AuthorityMachine = { ...AGENT, moves: ['ACTIVE>REVOKED'] };

    expect([unknownType, noSubject, looseMachine]).toHaveLength(3);
  });

  it("fits the product's list the same way, with the machine as `rules`, as changeStatus takes it", () => {
    const entry: AuthorityTableEntry = { ...AGENTS, rules: AGENT };
    // @ts-expect-error -- The product's list names the machine `rules`, never `status`.
    const misnamed: AuthorityTableEntry = { ...AGENTS, status: AGENT };

    expect(entry.rules).toBe(AGENT);
    expect(misnamed).toBeDefined();
  });

  it("holds each module's own description, not a copy: the organisation's row (B1a), a membership (B4-1) and an invitation (B4-3a)", () => {
    const [organizations, memberships, invitations, ...others] = PRODUCT_AUTHORITY_TABLES;

    expect(organizations).toBe(ORGANIZATIONS);
    expect(memberships).toBe(MEMBERSHIPS);
    expect(invitations).toBe(INVITATIONS);
    expect(others).toEqual([]);
    // CI's view of them takes the same fields and the same machine, as `status`.
    expect(AUTHORITY_TABLES).toEqual([
      {
        table: ORGANIZATIONS.table,
        subject: ORGANIZATIONS.subject,
        fields: ORGANIZATIONS.fields,
        status: ORGANIZATION,
      },
      {
        table: MEMBERSHIPS.table,
        subject: MEMBERSHIPS.subject,
        fields: MEMBERSHIPS.fields,
        status: MEMBERSHIP,
      },
      {
        table: INVITATIONS.table,
        subject: INVITATIONS.subject,
        fields: INVITATIONS.fields,
        status: INVITATION,
      },
    ]);
    expect(AUTHORITY_TABLES[0]?.fields).toBe(ORGANIZATIONS.fields);
    expect(AUTHORITY_TABLES[0]?.status).toBe(ORGANIZATION);
    expect(AUTHORITY_TABLES[1]?.fields).toBe(MEMBERSHIPS.fields);
    expect(AUTHORITY_TABLES[1]?.status).toBe(MEMBERSHIP);
    expect(AUTHORITY_TABLES[2]?.fields).toBe(INVITATIONS.fields);
    expect(AUTHORITY_TABLES[2]?.status).toBe(INVITATION);
  });

  it('names no table the schema policy lists as a fill-in table, so each table is held to one list of columns (A5b)', () => {
    // Authority tables go by their plain name and fill-in tables by the name
    // Postgres quotes, which are the same for any name that needs no quotes;
    // a reserved word such as `user` is left to the live guard, which names
    // a table on both lists.
    const fillIn = Object.keys(SCHEMA_POLICY.fillInTables);

    expect(AUTHORITY_TABLES.map(({ table }) => table).filter((name) => fillIn.includes(name))).toEqual([]);
  });
});
