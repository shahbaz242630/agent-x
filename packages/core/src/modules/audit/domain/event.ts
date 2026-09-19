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
/** Postgres's integer, the subject_version column's type. */
const MAX_VERSION = 2_147_483_647;
const ACTOR_TYPES: ReadonlySet<string> = new Set<ActorType>(['user', 'agent', 'system']);

type DetailEntry = readonly [string, unknown];

/**
 * The event's fields, each read from the caller's objects once. Every check,
 * and the event kept, use this copy: a getter can't show the check one value
 * and the record another.
 */
interface Snapshot {
  readonly actor: AuditActor;
  readonly action: string;
  readonly subject: AuditSubject;
  /** The details' entries, or nothing if the details aren't a plain object. */
  readonly details: readonly DetailEntry[] | undefined;
}

/** Takes what the caller passed, whatever its type claims: a caller the compiler can't see could pass anything. */
function plainEntries(details: unknown): readonly DetailEntry[] | undefined {
  if (
    typeof details !== 'object' ||
    details === null ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(details) as object | null)
  ) {
    return undefined;
  }
  return Object.entries(details);
}

function snapshotOf(event: AuditEvent): Snapshot {
  const { actor, action, subject, details } = event;
  return {
    actor: { type: actor.type, id: actor.id },
    action,
    subject: { type: subject.type, id: subject.id, version: subject.version },
    details: plainEntries(details),
  };
}

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
  if (!Number.isSafeInteger(subject.version) || subject.version < 1 || subject.version > MAX_VERSION) {
    problems.push(`subject.version must be a whole number from 1 to ${MAX_VERSION}`);
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

function detailsProblems(entries: readonly DetailEntry[] | undefined): string[] {
  if (entries === undefined) return ['details must be a plain object'];
  if (entries.length > DETAILS_COUNT) return [`details has more than ${DETAILS_COUNT} entries`];
  return entries.flatMap(([key, value]) => {
    if (!DETAIL_KEY.test(key)) return ['details has a key that is not a camelCase name'];
    return detailValueProblem(key, value) ?? [];
  });
}

/** Code-unit order of the keys, whatever order they were written in. */
const byKey = ([a]: DetailEntry, [b]: DetailEntry): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The event in its canonical form, frozen, or an AuditEventRefused listing
 * every problem. `isSensitive` says which details hold what an audit row must
 * never keep, by name and value (the logger's own rule for what it hides).
 */
export function checkedEvent(
  event: AuditEvent,
  isSensitive: (name: string, value: AuditDetailValue) => boolean,
): AuditEvent {
  const { actor, action, subject, details } = snapshotOf(event);
  const problems = [
    ...actorProblems(actor),
    ...(ACTION.test(action) && action.length <= ACTION_LENGTH
      ? []
      : [`action must be dotted lower-case words, at most ${ACTION_LENGTH} characters`]),
    ...subjectProblems(subject),
    ...detailsProblems(details),
  ];
  // Checked apart from the rest, and only once every key is a plain name and every value a plain fact.
  const facts = (details ?? []) as readonly (readonly [string, AuditDetailValue])[];
  if (problems.length === 0) {
    for (const [key] of facts.filter(([name, value]) => isSensitive(name, value))) {
      problems.push(`details.${key} looks like a secret or personal data, which audit rows never hold (ADR-014 §3)`);
    }
  }
  if (problems.length > 0) throw new AuditEventRefused(problems);

  const lower = (id: string): string => id.toLowerCase();
  return Object.freeze({
    actor: Object.freeze({ type: actor.type, id: actor.type === 'system' ? actor.id : lower(actor.id) }),
    action,
    subject: Object.freeze({ type: subject.type, id: lower(subject.id), version: subject.version }),
    details: Object.freeze(Object.fromEntries([...facts].sort(byKey))),
  });
}

/** The details as JSON with their keys in order: the same facts always give the same text. */
export function canonicalDetails(details: AuditDetails): string {
  return JSON.stringify(Object.fromEntries(Object.entries(details).sort(byKey)));
}

/**
 * What the chain hashes and MACs for an event, as labelled parts, with its
 * details as their JSON text. A new event's text is canonicalDetails; a stored
 * event's is the text stored, taken exactly as it is, so any change to it shows.
 */
export function eventContent(event: Omit<AuditEvent, 'details'>, detailsJson: string): readonly [string, ...string[]] {
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
    detailsJson,
  ];
}
