// An organisation's audit event (ADR-011 §3, PRD §3 `AuditEvent`): who did
// what, to which object at which version, and a few facts about it. Audit
// rows are kept for years and can never be changed or deleted, so an event
// holds IDs and short facts only, never secrets, bank details or personal data
// (ADR-014 §3): the objects themselves hold those, and evidence reads them
// there.
//
// An event is checked and put into one canonical form before it is sealed,
// because its hash and MAC are computed over that form and recomputed from
// the stored row: IDs in lower case, the details' keys in order. A problem
// names the field, never its value, which could be anything a caller passed.

export type ActorType = 'user' | 'agent' | 'system';

/** Who acted: a person (their user ID), an AI agent (its ID), or the app itself (a process name such as `api`). */
export interface AuditActor {
  readonly type: ActorType;
  readonly id: string;
}

/** What the event is about: an object's type, its ID and the version the event made or saw (ADR-012 §2). */
export interface AuditSubject {
  readonly type: string;
  readonly id: string;
  readonly version: number;
}

export type AuditDetailValue = string | number | boolean | null;

/** A few facts about the event, by name: text, whole numbers, yes or no, or nothing. */
export type AuditDetails = Readonly<Record<string, AuditDetailValue>>;

export interface AuditEvent {
  readonly actor: AuditActor;
  /** Dotted lower-case words, object first: `organisation.created`, `agent_key.revoked`. */
  readonly action: string;
  readonly subject: AuditSubject;
  readonly details: AuditDetails;
}

/** The event can't be recorded as given; `problems` name each field at fault. */
export class AuditEventRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The audit event was refused: ${problems.join('; ')}`);
    this.name = 'AuditEventRefused';
    this.problems = problems;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PROCESS_NAME = /^[a-z][a-z0-9-]{0,62}$/;
const ACTION = /^[a-z][a-z_]*(?:\.[a-z][a-z_]*)+$/;
const SUBJECT_TYPE = /^[a-z][a-z_]{0,62}$/;
const DETAIL_KEY = /^[a-z][A-Za-z0-9]{0,62}$/;
// Control characters have no place in a short fact, and Postgres can't store NUL in text or JSON.
// eslint-disable-next-line no-control-regex -- Matching control characters is the point.
const CONTROL = /[\u0000-\u001f\u007f]/;

const ACTION_LENGTH = 100;
const DETAILS_COUNT = 32;
const DETAIL_TEXT_LENGTH = 1024;
const ACTOR_TYPES: ReadonlySet<string> = new Set<ActorType>(['user', 'agent', 'system']);

function actorProblems(actor: AuditActor): string[] {
  if (!ACTOR_TYPES.has(actor.type)) return ['actor.type must be user, agent or system'];
  const pattern = actor.type === 'system' ? PROCESS_NAME : UUID;
  return pattern.test(actor.id)
    ? []
    : [actor.type === 'system' ? 'actor.id must be a process name' : `actor.id must be the ${actor.type}'s UUID`];
}

function subjectProblems(subject: AuditSubject): string[] {
  const problems: string[] = [];
  if (!SUBJECT_TYPE.test(subject.type)) problems.push('subject.type must be lower-case words joined by _');
  if (!UUID.test(subject.id)) problems.push('subject.id must be a UUID');
  if (!Number.isSafeInteger(subject.version) || subject.version < 1) {
    problems.push('subject.version must be a whole number from 1');
  }
  return problems;
}

function detailValueProblem(key: string, value: unknown): string | undefined {
  if (value === null || typeof value === 'boolean') return undefined;
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) ? undefined : `details.${key} must be a whole number`;
  }
  if (typeof value !== 'string') return `details.${key} must be text, a whole number, true, false or null`;
  if (value.length > DETAIL_TEXT_LENGTH) return `details.${key} is longer than ${DETAIL_TEXT_LENGTH} characters`;
  if (!value.isWellFormed() || CONTROL.test(value)) {
    return `details.${key} holds control characters or broken Unicode`;
  }
  return undefined;
}

/** Takes what the caller passed, whatever its type claims: a caller the compiler can't see could pass anything. */
function detailsProblems(details: unknown): string[] {
  if (
    typeof details !== 'object' ||
    details === null ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(details) as object | null)
  ) {
    return ['details must be a plain object'];
  }
  const entries = Object.entries(details);
  if (entries.length > DETAILS_COUNT) return [`details has more than ${DETAILS_COUNT} entries`];
  return entries.flatMap(([key, value]) => {
    if (!DETAIL_KEY.test(key)) return ['details has a key that is not a camelCase name'];
    return detailValueProblem(key, value) ?? [];
  });
}

/**
 * The event in its canonical form, frozen, or an AuditEventRefused listing
 * every problem. `isSensitive` says which detail names hold what an audit row
 * must never keep (the logger's own list of secret and personal field names).
 */
export function checkedEvent(event: AuditEvent, isSensitive: (name: string) => boolean): AuditEvent {
  const problems = [
    ...actorProblems(event.actor),
    ...(ACTION.test(event.action) && event.action.length <= ACTION_LENGTH
      ? []
      : [`action must be dotted lower-case words, at most ${ACTION_LENGTH} characters`]),
    ...subjectProblems(event.subject),
    ...detailsProblems(event.details),
  ];
  // Checked apart from the rest, and only once every key is a plain name, so a problem can quote it.
  if (problems.length === 0) {
    for (const key of Object.keys(event.details).filter(isSensitive)) {
      problems.push(`details.${key} names a secret or personal data, which audit rows never hold (ADR-014 §3)`);
    }
  }
  if (problems.length > 0) throw new AuditEventRefused(problems);

  const lower = (id: string): string => id.toLowerCase();
  return Object.freeze({
    actor: Object.freeze({
      type: event.actor.type,
      id: event.actor.type === 'system' ? event.actor.id : lower(event.actor.id),
    }),
    action: event.action,
    subject: Object.freeze({ type: event.subject.type, id: lower(event.subject.id), version: event.subject.version }),
    details: Object.freeze(inOrder(event.details)),
  });
}

/** The details with their keys in code-unit order, whatever order they were written in. */
function inOrder(details: AuditDetails): Record<string, AuditDetailValue> {
  return Object.fromEntries(Object.entries(details).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** The details as JSON with their keys in order: the same facts always give the same text. */
export function canonicalDetails(details: AuditDetails): string {
  return JSON.stringify(inOrder(details));
}

/**
 * What the chain hashes and MACs for an event, as labelled parts. It is
 * computed from the event before it is stored and again from the stored row,
 * so both must give the same parts.
 */
export function eventContent(event: AuditEvent): readonly [string, ...string[]] {
  return [
    'actor',
    event.actor.type,
    event.actor.id,
    'action',
    event.action,
    'subject',
    event.subject.type,
    event.subject.id,
    event.subject.version.toString(),
    'details',
    canonicalDetails(event.details),
  ];
}
