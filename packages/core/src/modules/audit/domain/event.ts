// An organisation's audit event (ADR-011 §3, PRD §3 `AuditEvent`): who did
// what, to which object at which version, and a few facts about it. The rules
// for the action and the details are the shared-kernel's, the same for the
// platform's own chain; this adds the actor and the subject.
//
// An event is checked and put into one canonical form before it is sealed,
// because its hash and MAC are computed over that form and recomputed from
// the stored row: IDs in lower case, the details' keys in order. A problem
// names the field, never its value, which could be anything a caller passed.
import {
  actionProblems,
  checkedDetails,
  type EventDetails,
  type EventDetailValue,
} from '../../../shared-kernel/index.ts';

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

export type AuditDetailValue = EventDetailValue;

/** A few facts about the event, by name: text, whole numbers, yes or no, or nothing. */
export type AuditDetails = EventDetails;

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
const SUBJECT_TYPE = /^[a-z][a-z_]{0,62}$/;
/** Postgres's integer, the subject_version column's type. */
const MAX_VERSION = 2_147_483_647;
const ACTOR_TYPES: ReadonlySet<string> = new Set<ActorType>(['user', 'agent', 'system']);

/**
 * The event's fields, each read from the caller's objects once. Every check,
 * and the event kept, use this copy: a getter can't show the check one value
 * and the record another. The details are read once by checkedDetails.
 */
interface Snapshot {
  readonly actor: AuditActor;
  readonly action: string;
  readonly subject: AuditSubject;
  readonly details: unknown;
}

function snapshotOf(event: AuditEvent): Snapshot {
  const { actor, action, subject, details } = event;
  return {
    actor: { type: actor.type, id: actor.id },
    action,
    subject: { type: subject.type, id: subject.id, version: subject.version },
    details,
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

/**
 * The event in its canonical form, frozen, or an AuditEventRefused listing
 * every problem. `isSensitive` says which details hold what an audit row must
 * never keep, by name and value (the logger's own rule for what it hides).
 */
export function checkedEvent(
  event: AuditEvent,
  isSensitive: (name: string, value: AuditDetailValue) => boolean,
): AuditEvent {
  const { actor, action, subject, details: given } = snapshotOf(event);
  const details = checkedDetails(given, isSensitive);
  const problems = [
    ...actorProblems(actor),
    ...actionProblems(action),
    ...subjectProblems(subject),
    ...details.problems,
  ];
  if (problems.length > 0) throw new AuditEventRefused(problems);

  const lower = (id: string): string => id.toLowerCase();
  return Object.freeze({
    actor: Object.freeze({ type: actor.type, id: actor.type === 'system' ? actor.id : lower(actor.id) }),
    action,
    subject: Object.freeze({ type: subject.type, id: lower(subject.id), version: subject.version }),
    details: details.details,
  });
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
