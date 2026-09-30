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
import * as agents from '../../packages/core/src/modules/agents/index.ts';
import * as fundingSources from '../../packages/core/src/modules/funding-sources/index.ts';
import * as suppliers from '../../packages/core/src/modules/suppliers/index.ts';
import {
  FACTOR_RESET,
  FACTOR_RESETS,
  INVITATION,
  INVITATIONS,
  MEMBERSHIP,
  MEMBERSHIPS,
  REGISTERED_CONTACT,
  REGISTERED_CONTACTS,
} from '../../packages/core/src/modules/identity/index.ts';
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

  it("holds each module's own description, not a copy: the organisation's row (B1a), a membership (B4-1), an invitation (B4-3a), a registered contact (B6-1a), a factor reset (B6-3a), an agent and an agent key (C1-1), a funding source (D2-2), and a supplier and a supplier version (E1-1)", () => {
    // In the lock order (ADR-006 §6): the organisation, then invitations before memberships, then contacts, then resets, then agents before their keys, then funding sources, then suppliers before their versions.
    const [
      organizations,
      invitations,
      memberships,
      contacts,
      resets,
      agentRows,
      agentKeys,
      sources,
      supplierRows,
      supplierVersions,
      ...others
    ] = PRODUCT_AUTHORITY_TABLES;

    expect(organizations).toBe(ORGANIZATIONS);
    expect(invitations).toBe(INVITATIONS);
    expect(memberships).toBe(MEMBERSHIPS);
    expect(contacts).toBe(REGISTERED_CONTACTS);
    expect(resets).toBe(FACTOR_RESETS);
    expect(agentRows).toBe(agents.AGENTS);
    expect(agentKeys).toBe(agents.AGENT_KEYS);
    expect(sources).toBe(fundingSources.SOURCES);
    expect(supplierRows).toBe(suppliers.SUPPLIERS);
    expect(supplierVersions).toBe(suppliers.SUPPLIER_VERSIONS);
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
        table: INVITATIONS.table,
        subject: INVITATIONS.subject,
        fields: INVITATIONS.fields,
        status: INVITATION,
      },
      {
        table: MEMBERSHIPS.table,
        subject: MEMBERSHIPS.subject,
        fields: MEMBERSHIPS.fields,
        status: MEMBERSHIP,
      },
      {
        table: REGISTERED_CONTACTS.table,
        subject: REGISTERED_CONTACTS.subject,
        fields: REGISTERED_CONTACTS.fields,
        status: REGISTERED_CONTACT,
      },
      {
        table: FACTOR_RESETS.table,
        subject: FACTOR_RESETS.subject,
        fields: FACTOR_RESETS.fields,
        status: FACTOR_RESET,
      },
      {
        table: agents.AGENTS.table,
        subject: agents.AGENTS.subject,
        fields: agents.AGENTS.fields,
        status: agents.AGENT,
      },
      {
        table: agents.AGENT_KEYS.table,
        subject: agents.AGENT_KEYS.subject,
        fields: agents.AGENT_KEYS.fields,
        status: agents.AGENT_KEY,
      },
      {
        table: fundingSources.SOURCES.table,
        subject: fundingSources.SOURCES.subject,
        fields: fundingSources.SOURCES.fields,
        status: fundingSources.FUNDING_SOURCE,
      },
      {
        table: suppliers.SUPPLIERS.table,
        subject: suppliers.SUPPLIERS.subject,
        fields: suppliers.SUPPLIERS.fields,
        status: suppliers.SUPPLIER,
        statusConditions: ['verified_rests_on_its_version'],
      },
      // A version is made once and never moved: no status of its own, and the made-once guard.
      {
        table: suppliers.SUPPLIER_VERSIONS.table,
        subject: suppliers.SUPPLIER_VERSIONS.subject,
        fields: suppliers.SUPPLIER_VERSIONS.fields,
        madeOnce: true,
      },
    ]);
    expect(AUTHORITY_TABLES[0]?.fields).toBe(ORGANIZATIONS.fields);
    expect(AUTHORITY_TABLES[0]?.status).toBe(ORGANIZATION);
    expect(AUTHORITY_TABLES[1]?.fields).toBe(INVITATIONS.fields);
    expect(AUTHORITY_TABLES[1]?.status).toBe(INVITATION);
    expect(AUTHORITY_TABLES[2]?.fields).toBe(MEMBERSHIPS.fields);
    expect(AUTHORITY_TABLES[2]?.status).toBe(MEMBERSHIP);
    expect(AUTHORITY_TABLES[3]?.fields).toBe(REGISTERED_CONTACTS.fields);
    expect(AUTHORITY_TABLES[3]?.status).toBe(REGISTERED_CONTACT);
    expect(AUTHORITY_TABLES[4]?.fields).toBe(FACTOR_RESETS.fields);
    expect(AUTHORITY_TABLES[4]?.status).toBe(FACTOR_RESET);
    expect(AUTHORITY_TABLES[5]?.fields).toBe(agents.AGENTS.fields);
    expect(AUTHORITY_TABLES[5]?.status).toBe(agents.AGENT);
    expect(AUTHORITY_TABLES[6]?.fields).toBe(agents.AGENT_KEYS.fields);
    expect(AUTHORITY_TABLES[6]?.status).toBe(agents.AGENT_KEY);
    expect(AUTHORITY_TABLES[7]?.fields).toBe(fundingSources.SOURCES.fields);
    expect(AUTHORITY_TABLES[7]?.status).toBe(fundingSources.FUNDING_SOURCE);
    expect(AUTHORITY_TABLES[8]?.fields).toBe(suppliers.SUPPLIERS.fields);
    expect(AUTHORITY_TABLES[8]?.status).toBe(suppliers.SUPPLIER);
    expect(AUTHORITY_TABLES[9]?.fields).toBe(suppliers.SUPPLIER_VERSIONS.fields);
    expect(AUTHORITY_TABLES[9]?.status).toBeUndefined();
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
