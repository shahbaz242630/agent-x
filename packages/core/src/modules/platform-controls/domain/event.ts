// A platform audit event (ADR-011 §3, ADR-014 §8): something the platform
// did that belongs to no organisation, on the platform's own chain. The first
// is a process starting with its config hash (ADR-012 §6, SEC-OPS-05);
// operator actions join it later, with an operator actor. The action and the
// details follow the shared-kernel's rules, the same as an organisation's.
import {
  actionProblems,
  checkedDetails,
  type EventDetails,
  type EventDetailValue,
} from '../../../shared-kernel/index.ts';

/** The app itself, by its process's name (`api`, `migrate`). */
export interface PlatformActor {
  readonly type: 'system';
  readonly id: string;
}

export interface PlatformEvent {
  readonly actor: PlatformActor;
  /** Dotted lower-case words, object first: `platform.started`. */
  readonly action: string;
  readonly details: EventDetails;
}

/** The event can't be recorded as given; `problems` name each field at fault, never a value. */
export class PlatformEventRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The platform audit event was refused: ${problems.join('; ')}`);
    this.name = 'PlatformEventRefused';
    this.problems = problems;
  }
}

const PROCESS_NAME = /^[a-z][a-z0-9-]{0,62}$/;

/**
 * The event in its canonical form, frozen, or a PlatformEventRefused listing
 * every problem. Each field is read from the caller once. `isSensitive` is the
 * logger's rule for what it hides, which audit rows never hold.
 */
export function checkedPlatformEvent(
  event: PlatformEvent,
  isSensitive: (name: string, value: EventDetailValue) => boolean,
): PlatformEvent {
  const { actor, action, details: given } = event;
  // Read as plain text: a caller the compiler can't see could pass any type.
  const type: string = actor.type;
  const { id } = actor;
  const details = checkedDetails(given, isSensitive);
  const problems = [
    ...(type === 'system' ? [] : ['actor.type must be system']),
    ...(PROCESS_NAME.test(id) ? [] : ['actor.id must be a process name']),
    ...actionProblems(action),
    ...details.problems,
  ];
  if (problems.length > 0) throw new PlatformEventRefused(problems);
  return Object.freeze({ actor: Object.freeze({ type: 'system', id }), action, details: details.details });
}

/**
 * What the chain hashes and MACs for an event, as labelled parts, with its
 * details as their JSON text: canonicalDetails for a new event, the stored
 * text exactly for a stored one.
 */
export function platformEventContent(
  event: Omit<PlatformEvent, 'details'>,
  detailsJson: string,
): readonly [string, ...string[]] {
  return ['actor', event.actor.type, event.actor.id, 'action', event.action, 'details', detailsJson];
}
