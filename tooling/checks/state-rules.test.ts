// A state machine the shared-kernel defines is what the status change in
// @agentx/platform/db takes (ADR-007 §1). The two packages can't import each
// other (platform never imports core), so the change describes the machine it
// needs, StatusRules, and this checks, at compile time and at run time, that
// defineStateMachine's machines are exactly that.
import { defineStateMachine } from '../../packages/core/src/shared-kernel/index.ts';
import type { StatusRules, StatusTable } from '../../packages/platform/src/db/index.ts';
import { describe, expect, it } from 'vitest';

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

describe("the shared-kernel's state machines fit the status change", () => {
  it('as its StatusRules, with the states and events they were defined with', () => {
    const rules: StatusRules<'ACTIVE' | 'SUSPENDED' | 'REVOKED', 'suspend' | 'reactivate' | 'revoke'> = AGENT;
    const table: StatusTable<'ACTIVE' | 'SUSPENDED' | 'REVOKED', 'suspend' | 'reactivate' | 'revoke'> = {
      table: 'agents.agents',
      rules: AGENT,
    };

    expect(rules.name).toBe('agent');
    expect(table.rules.transition('ACTIVE', 'suspend')).toEqual({ ok: true, from: 'ACTIVE', to: 'SUSPENDED' });
    expect(table.rules.transition('REVOKED', 'reactivate')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'REVOKED',
    });
    expect(table.rules.transition('LOST', 'revoke')).toEqual({ ok: false, problem: 'unknown_state' });
  });
});
