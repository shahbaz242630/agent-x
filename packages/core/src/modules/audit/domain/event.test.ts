import { describe, expect, it } from 'vitest';

import { canonicalDetails } from '../../../shared-kernel/index.ts';
import {
  type AuditDetails,
  type AuditDetailValue,
  type AuditEvent,
  AuditEventRefused,
  checkedEvent,
  eventContent,
} from './event.ts';

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const ORG = '0199a0f0-0000-7000-8000-000000000001';

const EVENT: AuditEvent = {
  actor: { type: 'user', id: USER },
  action: 'organisation.created',
  subject: { type: 'organisation', id: ORG, version: 1 },
  details: { plan: 'pilot', seats: 3 },
};

/** Nothing counts as sensitive, unless a test says otherwise. */
const nothingSensitive = (): boolean => false;

type Sensitive = (name: string, value: AuditDetailValue) => boolean;

const check = (event: AuditEvent, isSensitive: Sensitive = nothingSensitive): AuditEvent =>
  checkedEvent(event, isSensitive);

/** The problems an event is refused for, or none. */
function problemsOf(event: AuditEvent, isSensitive: Sensitive = nothingSensitive): readonly string[] {
  try {
    check(event, isSensitive);
    return [];
  } catch (error) {
    if (error instanceof AuditEventRefused) return error.problems;
    throw error;
  }
}

const withDetails = (details: unknown): AuditEvent => ({ ...EVENT, details: details as AuditDetails });

describe('an audit event in its canonical form', () => {
  it('keeps a valid event as it is, frozen', () => {
    const checked = check(EVENT);

    expect(checked).toEqual({ ...EVENT, details: { plan: 'pilot', seats: 3 } });
    expect(Object.isFrozen(checked)).toBe(true);
    expect(Object.isFrozen(checked.actor)).toBe(true);
    expect(Object.isFrozen(checked.subject)).toBe(true);
    expect(Object.isFrozen(checked.details)).toBe(true);
  });

  it('writes IDs in lower case, as Postgres returns a uuid, so the stored row hashes the same', () => {
    const checked = check({
      ...EVENT,
      actor: { type: 'agent', id: USER.toUpperCase() },
      subject: { ...EVENT.subject, id: ORG.toUpperCase() },
    });

    expect(checked.actor.id).toBe(USER);
    expect(checked.subject.id).toBe(ORG);
  });

  it("keeps a process's name as the app's own actor", () => {
    expect(check({ ...EVENT, actor: { type: 'system', id: 'anchor-check' } }).actor).toEqual({
      type: 'system',
      id: 'anchor-check',
    });
  });

  it('puts the details in key order, and keeps a version at the limit', () => {
    const checked = check({
      ...withDetails({ zeta: 1, alpha: true }),
      subject: { ...EVENT.subject, version: 2_147_483_647 },
    });

    expect(Object.keys(checked.details)).toEqual(['alpha', 'zeta']);
    expect(checked.subject.version).toBe(2_147_483_647);
  });

  it('reads each field once, so a getter cannot show the check one value and the record another', () => {
    let reads = 0;
    const details = {
      get note(): unknown {
        reads += 1;
        return reads === 1 ? 'fine' : { nested: 'changed after the check' };
      },
    };
    let actorReads = 0;
    const actor = {
      type: 'user' as const,
      get id(): string {
        actorReads += 1;
        return actorReads === 1 ? USER : 'not a uuid';
      },
    };
    const checked = check({ ...EVENT, actor, details: details as unknown as AuditDetails });

    expect(checked.details).toEqual({ note: 'fine' });
    expect(checked.actor.id).toBe(USER);
    expect([reads, actorReads]).toEqual([1, 1]);
  });
});

describe('an audit event refused', () => {
  it.each([
    ['an unknown actor type', { actor: { type: 'operator', id: USER } }, 'actor.type must be user, agent or system'],
    ['a user without a UUID', { actor: { type: 'user', id: 'alice' } }, "actor.id must be the user's UUID"],
    ['an agent without a UUID', { actor: { type: 'agent', id: '' } }, "actor.id must be the agent's UUID"],
    ['the app without a process name', { actor: { type: 'system', id: 'API' } }, 'actor.id must be a process name'],
  ])('for %s', (_case, change, problem) => {
    expect(problemsOf({ ...EVENT, ...change } as AuditEvent)).toEqual([problem]);
  });

  it('for an action or details that break the shared rules (shared-kernel/event-facts.ts)', () => {
    expect(problemsOf({ ...EVENT, action: 'created' })).toEqual([
      'action must be dotted lower-case words, at most 100 characters',
    ]);
    expect(problemsOf(withDetails(null))).toEqual(['details must be a plain object']);
    expect(problemsOf(withDetails({ contactEmail: 'x' }), (name) => name === 'contactEmail')).toEqual([
      'details.contactEmail looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
  });

  it('lists a sensitive detail beside a problem with the actor: the details are judged on their own', () => {
    const event = { ...withDetails({ contactEmail: 'x' }), actor: { type: 'user' as const, id: 'alice' } };

    expect(problemsOf(event, (name) => name === 'contactEmail')).toEqual([
      "actor.id must be the user's UUID",
      'details.contactEmail looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
  });

  it.each([
    ['a type in capitals', { type: 'Organisation' }, 'subject.type must be lower-case words joined by _'],
    ['a type with a dot', { type: 'organisation.x' }, 'subject.type must be lower-case words joined by _'],
    ['an ID that is not a UUID', { id: 'org-1' }, 'subject.id must be a UUID'],
    ['version 0', { version: 0 }, 'subject.version must be a whole number from 1 to 2147483647'],
    ['a version with a fraction', { version: 1.5 }, 'subject.version must be a whole number from 1 to 2147483647'],
    [
      'a version past safe integers',
      { version: 2 ** 53 },
      'subject.version must be a whole number from 1 to 2147483647',
    ],
    [
      'a version past Postgres integers',
      { version: 2 ** 31 },
      'subject.version must be a whole number from 1 to 2147483647',
    ],
  ])('for a subject with %s', (_case, change, problem) => {
    expect(problemsOf({ ...EVENT, subject: { ...EVENT.subject, ...change } })).toEqual([problem]);
  });

  it('lists every problem at once, and quotes none of the values', () => {
    const marker = 'planted marker words';
    const error = (() => {
      try {
        check({
          actor: { type: 'user', id: marker },
          action: marker,
          subject: { type: marker, id: marker, version: -1 },
          details: { note: `${marker}\n` },
        });
      } catch (caught) {
        return caught;
      }
      return undefined;
    })();

    expect(error).toBeInstanceOf(AuditEventRefused);
    expect((error as AuditEventRefused).problems).toHaveLength(6);
    expect((error as AuditEventRefused).message).not.toContain(marker);
  });
});

describe('what the chain seals for an event', () => {
  it('is the labelled fields, with the details as JSON in key order', () => {
    const checked = check(withDetails({ seats: 3, plan: 'pilot' }));

    expect(eventContent(checked, canonicalDetails(checked.details))).toEqual([
      'actor',
      'user',
      USER,
      'action',
      'organisation.created',
      'subject',
      'organisation',
      ORG,
      '1',
      'details',
      '{"plan":"pilot","seats":3}',
    ]);
  });
});
