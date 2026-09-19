// A state machine the shared-kernel defines is what the status change in
// @agentx/platform/db takes (ADR-007 §1). The two packages can't import each
// other (platform never imports core), so the change describes the machine it
// needs, StatusRules. This checks that defineStateMachine's machines are
// exactly that: they fit where their own events are expected, and nowhere
// wider, so a misspelt or unchecked event fails the type check. Each
// `@ts-expect-error` below is itself checked: if the line compiled, the
// type check would fail on the unused directive.
import { defineStateMachine, type StateMachine } from '../../packages/core/src/shared-kernel/index.ts';
import {
  createStatusChanger,
  type StatusChanger,
  type StatusRules,
  type StatusTable,
} from '../../packages/platform/src/db/index.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { LogCapture } from '../../packages/testing/src/log-scan.ts';
import { describe, expect, it } from 'vitest';

type AgentState = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
type AgentEvent = 'suspend' | 'reactivate' | 'revoke';

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
const AGENTS: StatusTable<AgentState, AgentEvent> = { table: 'agents.agents', rules: AGENT };
const KEY = { orgId: '0199a0f0-0000-7000-8000-00000000000a', id: '0199a0f0-0000-7000-8000-00000000000b' };

describe("the shared-kernel's state machines fit the status change", () => {
  it('as its StatusRules, with the states and events they were defined with', () => {
    const rules: StatusRules<AgentState, AgentEvent> = AGENT;

    expect(rules.name).toBe('agent');
    expect(AGENTS.rules.transition('ACTIVE', 'suspend')).toEqual({ ok: true, from: 'ACTIVE', to: 'SUSPENDED' });
    expect(AGENTS.rules.transition('REVOKED', 'reactivate')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'REVOKED',
    });
    expect(AGENTS.rules.transition('LOST', 'revoke')).toEqual({ ok: false, problem: 'unknown_state' });
  });

  it('and nowhere wider: a machine with other events, or any text as an event, does not compile', () => {
    // @ts-expect-error -- A machine fits only where its own events are expected, not more.
    const wider: StatusRules<AgentState, AgentEvent | 'unlock'> = AGENT;
    // @ts-expect-error -- Nor where any text is an event.
    const anyText: StatusRules<AgentState, string> = AGENT;
    // @ts-expect-error -- The machine's own type is as strict.
    const widerMachine: StateMachine<AgentState, AgentEvent | 'unlock'> = AGENT;

    expect([wider, anyText, widerMachine]).toEqual([AGENT, AGENT, AGENT]);
  });

  it("refuses a misspelt or unchecked event at the status change's call, not at run time", () => {
    const changer = createStatusChanger({
      logger: createLogger({
        service: 'test',
        config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
        destination: new LogCapture(),
      }),
    });
    // Never run: it is here for the type check.
    const calls = (tx: Parameters<StatusChanger['change']>[0], fromRequest: string) => [
      changer.change(tx, AGENTS, KEY, 'suspend'),
      // @ts-expect-error -- A misspelt event.
      changer.change(tx, AGENTS, KEY, 'suspnd'),
      // @ts-expect-error -- Text from a request, not checked against the machine.
      changer.change(tx, AGENTS, KEY, fromRequest),
    ];

    expect(calls).toBeTypeOf('function');
  });
});
