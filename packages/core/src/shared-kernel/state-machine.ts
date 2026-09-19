// State machines as data (ADR-007 §1.1): each object's statuses, the status a
// new one starts in, and the events that move it are defined once, in its
// module's domain, and every status change is decided by `transition`, a pure
// function. The database holds the same rules: a guard on each status table
// refuses a new row in any other status and any move the machine doesn't list
// (db/migrations/0004_state_rules.sql), and a change locks its row before it
// compares and sets (@agentx/platform/db, `createStatusChanger`).
//
// A machine written wrong is refused when it is defined, at start-up, not at
// the first move that meets the mistake.

/** An event's rule: the statuses it may happen in, and the one status it leads to. */
export interface EventRule<State extends string> {
  readonly from: readonly State[];
  readonly to: State;
}

export interface StateMachineDefinition<State extends string, Event extends string> {
  /** The object whose status this is: lower-case words joined by `_`, such as `mandate` or `agent_key`. */
  readonly name: string;
  /** Every status, in capitals: `ACTIVE`, `PENDING_ACCEPTANCE`. */
  readonly states: readonly State[];
  /** The status every new object starts in. */
  readonly initial: NoInfer<State>;
  /** Each event by name, in lower case (`suspend`, `revoke`), with its rule. */
  readonly events: Readonly<Record<Event, EventRule<NoInfer<State>>>>;
}

/** One allowed move, from a status to another: what the database's guard lists. */
export interface Move<State extends string> {
  readonly from: State;
  readonly to: State;
}

/**
 * What `transition` decided: the move, or why there is none. `unknown_state`
 * means the status given isn't one of the machine's, which for a status read
 * from the database means someone past the app wrote it.
 */
export type Transition<State extends string> =
  | { readonly ok: true; readonly from: State; readonly to: State }
  | { readonly ok: false; readonly problem: 'not_allowed'; readonly from: State }
  | { readonly ok: false; readonly problem: 'unknown_state' };

export interface StateMachine<State extends string, Event extends string> {
  readonly name: string;
  readonly states: readonly State[];
  readonly initial: State;
  /** Every move some event allows, once each. */
  readonly moves: readonly Move<State>[];
  isState(value: string): value is State;
  /** True for a status no event leaves, such as `REVOKED`. */
  isFinal(state: State): boolean;
  /**
   * The move `event` makes from `from`, or why it can't. `from` is any text,
   * since it is usually read back from the database. An event the machine
   * doesn't define is a mistake in the calling code, so it throws.
   */
  transition(from: string, event: Event): Transition<State>;
}

/** The definition breaks the rules below; `problems` names each mistake. */
export class StateMachineInvalid extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The state machine was refused: ${problems.join('; ')}`);
    this.name = 'StateMachineInvalid';
    this.problems = problems;
  }
}

const NAME = /^[a-z][a-z_]{0,62}$/;
const STATE = /^[A-Z][A-Z_]{0,62}$/;

function duplicates(values: readonly string[]): string[] {
  return [...new Set(values.filter((value, index) => values.indexOf(value) !== index))];
}

function stateProblems(states: readonly string[], initial: string): string[] {
  const problems = states.filter((state) => !STATE.test(state)).map((state) => `state ${state} must be in capitals`);
  problems.push(...duplicates(states).map((state) => `state ${state} is listed twice`));
  if (!states.includes(initial)) problems.push(`the first state ${initial} is not one of the states`);
  return problems;
}

function eventProblems(event: string, rule: EventRule<string>, states: readonly string[]): string[] {
  const problems: string[] = [];
  if (!NAME.test(event)) problems.push(`event ${event} must be lower-case words joined by _`);
  if (rule.from.length === 0) problems.push(`event ${event} happens in no state`);
  problems.push(...duplicates(rule.from).map((state) => `event ${event} lists ${state} twice`));
  for (const state of [...rule.from, rule.to].filter((one) => !states.includes(one))) {
    problems.push(`event ${event} names ${state}, which is not one of the states`);
  }
  if (rule.from.includes(rule.to)) problems.push(`event ${event} leads from ${rule.to} to itself`);
  return problems;
}

/** The states no chain of events reaches from the first one: a status no row could ever get. */
function unreachable(states: readonly string[], initial: string, rules: readonly EventRule<string>[]): string[] {
  const reached = new Set([initial]);
  for (let grew = true; grew;) {
    grew = false;
    for (const rule of rules) {
      if (!reached.has(rule.to) && rule.from.some((state) => reached.has(state))) {
        reached.add(rule.to);
        grew = true;
      }
    }
  }
  return states.filter((state) => !reached.has(state));
}

/** The definition, read once: the checks and the machine both use this copy. */
interface Snapshot<State extends string> {
  readonly name: string;
  readonly states: readonly State[];
  readonly initial: State;
  readonly events: readonly (readonly [string, EventRule<State>])[];
}

function snapshotOf<State extends string, Event extends string>(
  definition: StateMachineDefinition<State, Event>,
): Snapshot<State> {
  const { name, states, initial, events } = definition;
  return {
    name,
    states: [...states],
    initial,
    events: Object.entries<EventRule<State>>(events).map(([event, { from, to }]) => [event, { from, to }]),
  };
}

function definitionProblems({ name, states, initial, events }: Snapshot<string>): string[] {
  const problems: string[] = [];
  if (!NAME.test(name)) problems.push('the name must be lower-case words joined by _');
  problems.push(...stateProblems(states, initial));
  if (events.length === 0) problems.push('there are no events');
  problems.push(...events.flatMap(([event, rule]) => eventProblems(event, rule, states)));
  if (problems.length > 0) return problems;
  return unreachable(
    states,
    initial,
    events.map(([, rule]) => rule),
  ).map((state) => `state ${state} can't be reached from ${initial}`);
}

/**
 * Checks the definition and gives back its machine, frozen, or throws
 * StateMachineInvalid listing every mistake: a name or status written wrong or
 * twice, an event that happens nowhere, names an unknown status or leads a
 * status to itself, or a status no chain of events reaches from the first.
 */
export function defineStateMachine<const State extends string, const Event extends string>(
  definition: StateMachineDefinition<State, Event>,
): StateMachine<State, Event> {
  const snapshot = snapshotOf(definition);
  const problems = definitionProblems(snapshot);
  if (problems.length > 0) throw new StateMachineInvalid(problems);

  const { name, initial } = snapshot;
  const states = Object.freeze(snapshot.states);
  const known: ReadonlySet<string> = new Set(states);
  const rules = new Map(snapshot.events.map(([event, rule]) => [event, { from: new Set(rule.from), to: rule.to }]));
  const left = new Set(snapshot.events.flatMap(([, rule]) => rule.from));
  const moves = new Map<string, Move<State>>();
  for (const [, rule] of snapshot.events) {
    for (const from of rule.from) moves.set(`${from}>${rule.to}`, Object.freeze({ from, to: rule.to }));
  }

  const isState = (value: string): value is State => known.has(value);
  return Object.freeze({
    name,
    states,
    initial,
    moves: Object.freeze([...moves.values()]),
    isState,
    isFinal: (state: State) => !left.has(state),
    transition(from: string, event: Event): Transition<State> {
      const rule = rules.get(event);
      if (rule === undefined) throw new RangeError(`The ${name} state machine has no such event`);
      if (!isState(from)) return { ok: false, problem: 'unknown_state' };
      return rule.from.has(from) ? { ok: true, from, to: rule.to } : { ok: false, problem: 'not_allowed', from };
    },
  });
}
