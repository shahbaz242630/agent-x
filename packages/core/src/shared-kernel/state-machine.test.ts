import { describe, expect, it } from 'vitest';

import { defineStateMachine, type StateMachineDefinition, StateMachineInvalid } from './state-machine.ts';

// The machines of PRD §4, written as definitions: the format must be able to
// say each of them. Their modules define them for real in later phases.
const MANDATE = {
  name: 'mandate',
  states: ['DRAFT', 'PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED', 'SUPERSEDED'],
  initial: 'DRAFT',
  events: {
    submit: { from: ['DRAFT'], to: 'PENDING_ACCEPTANCE' },
    accept: { from: ['PENDING_ACCEPTANCE'], to: 'ACTIVE' },
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
    revoke: { from: ['ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
    expire: { from: ['ACTIVE', 'SUSPENDED'], to: 'EXPIRED' },
    supersede: { from: ['ACTIVE'], to: 'SUPERSEDED' },
  },
} as const;

const SPEND_REQUEST = {
  name: 'spend_request',
  states: [
    'CREATED',
    'VALIDATING',
    'DENIED',
    'APPROVAL_REQUIRED',
    'APPROVED',
    'EXPIRED',
    'CANCELLED',
    'INSTRUCTION_READY',
    'HANDED_OFF',
  ],
  initial: 'CREATED',
  events: {
    validate: { from: ['CREATED'], to: 'VALIDATING' },
    deny: { from: ['VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'], to: 'DENIED' },
    require_approval: { from: ['VALIDATING'], to: 'APPROVAL_REQUIRED' },
    approve: { from: ['VALIDATING', 'APPROVAL_REQUIRED'], to: 'APPROVED' },
    expire: { from: ['APPROVAL_REQUIRED'], to: 'EXPIRED' },
    cancel: { from: ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'], to: 'CANCELLED' },
    ready: { from: ['APPROVED'], to: 'INSTRUCTION_READY' },
    hand_off: { from: ['INSTRUCTION_READY'], to: 'HANDED_OFF' },
  },
} as const;

const TRANSACTION = {
  name: 'transaction',
  states: [
    'CREATED',
    'SUBMISSION_PENDING',
    'SUBMITTED',
    'PROCESSING',
    'SUCCEEDED',
    'FAILED',
    'CANCELLED',
    'UNKNOWN',
    'REVERSED',
  ],
  initial: 'CREATED',
  events: {
    prepare: { from: ['CREATED'], to: 'SUBMISSION_PENDING' },
    submit: { from: ['SUBMISSION_PENDING'], to: 'SUBMITTED' },
    process: { from: ['SUBMITTED'], to: 'PROCESSING' },
    succeed: { from: ['SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'SUCCEEDED' },
    fail: { from: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'FAILED' },
    cancel: { from: ['SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'CANCELLED' },
    lose_track: { from: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING'], to: 'UNKNOWN' },
    reverse: { from: ['SUCCEEDED'], to: 'REVERSED' },
  },
} as const;

const APPROVAL = {
  name: 'approval',
  states: ['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED'],
  initial: 'PENDING',
  events: {
    approve: { from: ['PENDING'], to: 'APPROVED' },
    reject: { from: ['PENDING'], to: 'REJECTED' },
    expire: { from: ['PENDING'], to: 'EXPIRED' },
    cancel: { from: ['PENDING'], to: 'CANCELLED' },
  },
} as const;

type AnyDefinition = StateMachineDefinition<string, string>;
const PRD_MACHINES: readonly (readonly [string, AnyDefinition])[] = [
  ['mandate (PRD §4.1)', MANDATE],
  ['spend request (PRD §4.2)', SPEND_REQUEST],
  ['partner execution transaction (PRD §4.3)', TRANSACTION],
  ['approval (PRD §4.4)', APPROVAL],
];

/** The problems a definition is refused for, or none. */
function problemsOf(definition: AnyDefinition): readonly string[] {
  try {
    defineStateMachine(definition);
    return [];
  } catch (error) {
    if (error instanceof StateMachineInvalid) return error.problems;
    throw error;
  }
}

describe('ADR-007 §1.1 every state machine of PRD §4 can be written as data', () => {
  it.each(PRD_MACHINES)('%s', (_name, definition) => {
    expect(problemsOf(definition)).toEqual([]);
  });
});

describe('ADR-007 §7 every invalid transition is rejected', () => {
  // Checked against the definition read independently: for every status and
  // every event, the move is allowed exactly when the event lists the status.
  it.each(PRD_MACHINES)('%s: every status against every event', (_name, definition) => {
    const machine = defineStateMachine(definition);
    let allowed = 0;
    for (const from of definition.states) {
      for (const [event, rule] of Object.entries(definition.events)) {
        const decided = machine.transition(from, event);
        if (rule.from.includes(from)) {
          allowed += 1;
          expect(decided).toEqual({ ok: true, from, to: rule.to });
        } else {
          expect(decided).toEqual({ ok: false, problem: 'not_allowed', from });
        }
      }
    }
    expect(allowed).toBeGreaterThan(0);
  });

  it('allows the moves PRD §4.1 draws for a mandate, and no other', () => {
    const mandate = defineStateMachine(MANDATE);

    expect(mandate.transition('ACTIVE', 'suspend')).toEqual({ ok: true, from: 'ACTIVE', to: 'SUSPENDED' });
    expect(mandate.transition('SUSPENDED', 'reactivate')).toEqual({ ok: true, from: 'SUSPENDED', to: 'ACTIVE' });
    expect(mandate.transition('REVOKED', 'reactivate')).toEqual({ ok: false, problem: 'not_allowed', from: 'REVOKED' });
    expect(mandate.transition('SUSPENDED', 'supersede')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'SUSPENDED',
    });
  });

  it.each(['active', 'ACTIVE ', '', 'toString', '__proto__', 'constructor', 'REVOKED\u0000'])(
    'reports a status the machine does not have as unknown: %j',
    (from) => {
      expect(defineStateMachine(MANDATE).transition(from, 'revoke')).toEqual({ ok: false, problem: 'unknown_state' });
    },
  );

  it.each(['toString', 'constructor', '__proto__', 'revoked'])(
    'throws for an event the machine does not define, which is a mistake in the calling code: %j',
    (event) => {
      const mandate = defineStateMachine<string, string>(MANDATE);

      expect(() => mandate.transition('ACTIVE', event)).toThrow(
        new RangeError('The mandate state machine has no such event'),
      );
    },
  );
});

describe('what a machine tells about itself', () => {
  const mandate = defineStateMachine(MANDATE);

  it('keeps its name, states in order, and the status every new object starts in', () => {
    expect(mandate.name).toBe('mandate');
    expect(mandate.states).toEqual(MANDATE.states);
    expect(mandate.initial).toBe('DRAFT');
  });

  it('knows its own statuses', () => {
    expect(MANDATE.states.every((state) => mandate.isState(state))).toBe(true);
    expect(mandate.isState('active')).toBe(false);
    expect(mandate.isState('toString')).toBe(false);
  });

  it('names the final statuses, which no event leaves', () => {
    expect(MANDATE.states.filter((state) => mandate.isFinal(state))).toEqual(['REVOKED', 'EXPIRED', 'SUPERSEDED']);
    const request = defineStateMachine(SPEND_REQUEST);
    expect(SPEND_REQUEST.states.filter((state) => request.isFinal(state))).toEqual([
      'DENIED',
      'EXPIRED',
      'CANCELLED',
      'HANDED_OFF',
    ]);
  });

  it("lists every move some event allows, once each: the database guard's rules", () => {
    expect(mandate.moves).toEqual([
      { from: 'DRAFT', to: 'PENDING_ACCEPTANCE' },
      { from: 'PENDING_ACCEPTANCE', to: 'ACTIVE' },
      { from: 'ACTIVE', to: 'SUSPENDED' },
      { from: 'SUSPENDED', to: 'ACTIVE' },
      { from: 'ACTIVE', to: 'REVOKED' },
      { from: 'SUSPENDED', to: 'REVOKED' },
      { from: 'ACTIVE', to: 'EXPIRED' },
      { from: 'SUSPENDED', to: 'EXPIRED' },
      { from: 'ACTIVE', to: 'SUPERSEDED' },
    ]);
  });

  it('lists a move two events make only once', () => {
    const machine = defineStateMachine({
      name: 'agent',
      states: ['ACTIVE', 'SUSPENDED'],
      initial: 'ACTIVE',
      events: {
        suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
        kill_switch: { from: ['ACTIVE'], to: 'SUSPENDED' },
        reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
      },
    });

    expect(machine.moves).toEqual([
      { from: 'ACTIVE', to: 'SUSPENDED' },
      { from: 'SUSPENDED', to: 'ACTIVE' },
    ]);
  });

  it('is frozen, all the way down', () => {
    expect(Object.isFrozen(mandate)).toBe(true);
    expect(Object.isFrozen(mandate.states)).toBe(true);
    expect(Object.isFrozen(mandate.moves)).toBe(true);
    expect(mandate.moves.every((move) => Object.isFrozen(move))).toBe(true);
  });
});

describe('the definition is read once', () => {
  it('keeps the machine as it was checked, whatever the caller changes afterwards', () => {
    const states = ['ACTIVE', 'SUSPENDED'];
    const from = ['ACTIVE'];
    const machine = defineStateMachine<string, string>({
      name: 'agent',
      states,
      initial: 'ACTIVE',
      events: { suspend: { from, to: 'SUSPENDED' }, reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' } },
    });
    states.push('REVOKED');
    from.push('SUSPENDED');

    expect(machine.states).toEqual(['ACTIVE', 'SUSPENDED']);
    expect(machine.isState('REVOKED')).toBe(false);
    expect(machine.transition('SUSPENDED', 'suspend')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'SUSPENDED',
    });
  });

  it('builds the machine from the states it checked, when a getter would give others later', () => {
    let reads = 0;
    const definition = {
      name: 'agent',
      get states(): readonly string[] {
        reads += 1;
        return reads === 1 ? ['ACTIVE', 'SUSPENDED'] : ['ACTIVE', 'SUSPENDED', 'active'];
      },
      initial: 'ACTIVE',
      events: { suspend: { from: ['ACTIVE'], to: 'SUSPENDED' }, reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' } },
    };
    const machine = defineStateMachine<string, string>(definition);

    expect(reads).toBe(1);
    expect(machine.states).toEqual(['ACTIVE', 'SUSPENDED']);
  });
});

describe('a machine written wrong is refused when it is defined', () => {
  const agent = {
    name: 'agent',
    states: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
    initial: 'ACTIVE',
    events: {
      suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
      reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
      revoke: { from: ['ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
    },
  } satisfies AnyDefinition;

  it('passes the correct one the other cases change', () => {
    expect(problemsOf(agent)).toEqual([]);
  });

  it.each(['Agent', 'agent-key', 'agent key', '', '_agent', `a${'b'.repeat(63)}`])(
    'a name written wrong: %j',
    (name) => {
      expect(problemsOf({ ...agent, name })).toEqual(['the name must be lower-case words joined by _']);
    },
  );

  it.each(['agent_key', `a${'b'.repeat(62)}`])('passes a name written right: %j', (name) => {
    expect(problemsOf({ ...agent, name })).toEqual([]);
  });

  it('a status not in capitals', () => {
    expect(
      problemsOf({
        ...agent,
        states: ['ACTIVE', 'SUSPENDED', 'Revoked'],
        events: { ...agent.events, revoke: { from: ['ACTIVE'], to: 'Revoked' } },
      }),
    ).toEqual(['state Revoked must be in capitals']);
  });

  it.each(['PENDING-ACCEPTANCE', '_ACTIVE', 'ACTIVE2', `A${'B'.repeat(63)}`])('a status written wrong: %j', (state) => {
    expect(
      problemsOf({
        ...agent,
        states: [...agent.states, state],
        events: { ...agent.events, odd: { from: ['ACTIVE'], to: state } },
      }),
    ).toEqual([`state ${state} must be in capitals`]);
  });

  it('a status listed twice', () => {
    expect(problemsOf({ ...agent, states: [...agent.states, 'SUSPENDED'] })).toEqual([
      'state SUSPENDED is listed twice',
    ]);
  });

  it('a first status that is not one of the states', () => {
    expect(problemsOf({ ...agent, initial: 'NEW' })).toEqual(['the first state NEW is not one of the states']);
  });

  it('no events', () => {
    expect(problemsOf({ ...agent, states: ['ACTIVE'], events: {} })).toEqual(['there are no events']);
  });

  it('an event name written wrong', () => {
    expect(
      problemsOf({ ...agent, events: { ...agent.events, 'Kill-switch': { from: ['ACTIVE'], to: 'SUSPENDED' } } }),
    ).toEqual(['event Kill-switch must be lower-case words joined by _']);
  });

  it('an event that happens in no state', () => {
    expect(problemsOf({ ...agent, events: { ...agent.events, revoke: { from: [], to: 'REVOKED' } } })).toEqual([
      'event revoke happens in no state',
    ]);
  });

  it('an event that lists a status twice', () => {
    expect(
      problemsOf({ ...agent, events: { ...agent.events, revoke: { from: ['ACTIVE', 'ACTIVE'], to: 'REVOKED' } } }),
    ).toEqual(['event revoke lists ACTIVE twice']);
  });

  it('an event that names a status the machine does not have, where it starts or where it leads', () => {
    expect(
      problemsOf({
        ...agent,
        events: { ...agent.events, revoke: { from: ['ACTIVE', 'LOCKED'], to: 'GONE' } },
      }),
    ).toEqual([
      'event revoke names LOCKED, which is not one of the states',
      'event revoke names GONE, which is not one of the states',
    ]);
  });

  it('an event that leads a status to itself, which would hide a repeated request as a change', () => {
    expect(
      problemsOf({
        ...agent,
        events: { ...agent.events, suspend: { from: ['ACTIVE', 'SUSPENDED'], to: 'SUSPENDED' } },
      }),
    ).toEqual(['event suspend leads from SUSPENDED to itself']);
  });

  it('a status no chain of events reaches from the first, which no row could ever get', () => {
    expect(
      problemsOf({
        ...agent,
        states: [...agent.states, 'ARCHIVED', 'PURGED'],
        events: { ...agent.events, purge: { from: ['ARCHIVED'], to: 'PURGED' } },
      }),
    ).toEqual(["state ARCHIVED can't be reached from ACTIVE", "state PURGED can't be reached from ACTIVE"]);
  });

  it('reaches a status only through a chain of several events', () => {
    const problems = problemsOf({
      name: 'chain',
      states: ['A', 'B', 'C', 'D'],
      initial: 'A',
      // Listed last to first, so reaching D takes more than one pass.
      events: {
        third: { from: ['C'], to: 'D' },
        second: { from: ['B'], to: 'C' },
        first: { from: ['A'], to: 'B' },
      },
    });

    expect(problems).toEqual([]);
  });

  it('lists every mistake at once, and leaves reachability until the rest is right', () => {
    expect(
      problemsOf({
        name: 'Agent',
        states: ['ACTIVE', 'ACTIVE', 'lost'],
        initial: 'NEW',
        events: { Go: { from: [], to: 'NOWHERE' } },
      }),
    ).toEqual([
      'the name must be lower-case words joined by _',
      'state lost must be in capitals',
      'state ACTIVE is listed twice',
      'the first state NEW is not one of the states',
      'event Go must be lower-case words joined by _',
      'event Go happens in no state',
      'event Go names NOWHERE, which is not one of the states',
    ]);
  });

  it('throws StateMachineInvalid, with the problems in its message', () => {
    expect(() => defineStateMachine({ ...agent, initial: 'NEW' })).toThrow(
      new StateMachineInvalid(['the first state NEW is not one of the states']),
    );
    expect(() => defineStateMachine({ ...agent, initial: 'NEW' })).toThrow(
      'The state machine was refused: the first state NEW is not one of the states',
    );
  });
});
