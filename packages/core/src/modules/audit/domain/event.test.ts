import { describe, expect, it } from 'vitest';

import {
  type AuditDetails,
  type AuditDetailValue,
  type AuditEvent,
  AuditEventRefused,
  canonicalDetails,
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

  it('puts the details in key order, whatever order they were written in', () => {
    const checked = check(withDetails({ zeta: 1, alpha: true, mid: null }));

    expect(Object.keys(checked.details)).toEqual(['alpha', 'mid', 'zeta']);
  });

  it('accepts every kind of detail value, at the limits', () => {
    const details = {
      text: 'x'.repeat(1024),
      emoji: 'paid 💸',
      big: Number.MAX_SAFE_INTEGER,
      small: Number.MIN_SAFE_INTEGER,
      yes: true,
      no: false,
      none: null,
    };

    expect(problemsOf(withDetails(details))).toEqual([]);
    expect(problemsOf(withDetails(Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`k${i}`, i]))))).toEqual([]);
    expect(problemsOf(withDetails(Object.assign(Object.create(null) as object, { a: 1 })))).toEqual([]);
    expect(problemsOf({ ...EVENT, action: `a.${'b'.repeat(98)}` })).toEqual([]);
    expect(problemsOf({ ...EVENT, subject: { ...EVENT.subject, version: 2_147_483_647 } })).toEqual([]);
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

  it.each([
    'created',
    'Organisation.created',
    'organisation.',
    'organisation..created',
    'org-x.created',
    `a.${'b'.repeat(99)}`,
  ])('for the action %j', (action) => {
    expect(problemsOf({ ...EVENT, action })).toEqual([
      'action must be dotted lower-case words, at most 100 characters',
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

  it.each([
    ['null', null],
    ['an array', ['a']],
    ['a date', new Date(0)],
    ['a map', new Map()],
    ['text', 'plan=pilot'],
    ['missing', undefined],
  ])('for details that are %s, not a plain object', (_case, details) => {
    expect(problemsOf(withDetails(details))).toEqual(['details must be a plain object']);
  });

  it('for more than 32 details', () => {
    const details = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, i]));

    expect(problemsOf(withDetails(details))).toEqual(['details has more than 32 entries']);
  });

  it.each(['snake_case', 'Capital', '1st', '', 'with-dash', `k${'x'.repeat(63)}`])('for the detail key %j', (key) => {
    expect(problemsOf(withDetails({ [key]: 1 }))).toEqual(['details has a key that is not a camelCase name']);
  });

  it.each([
    ['a fraction', 1.5, 'details.value must be a whole number'],
    ['NaN', Number.NaN, 'details.value must be a whole number'],
    ['infinity', Number.POSITIVE_INFINITY, 'details.value must be a whole number'],
    ['a number past safe integers', 2 ** 53, 'details.value must be a whole number'],
    ['an object', { nested: 1 }, 'details.value must be text, a whole number, true, false or null'],
    ['a list', [1], 'details.value must be text, a whole number, true, false or null'],
    ['nothing at all', undefined, 'details.value must be text, a whole number, true, false or null'],
    ['a bigint', 1n, 'details.value must be text, a whole number, true, false or null'],
    ['over-long text', 'x'.repeat(1025), 'details.value is longer than 1024 characters'],
    ['a NUL', 'a\u0000b', 'details.value holds control characters or broken Unicode'],
    ['a new line', 'a\nb', 'details.value holds control characters or broken Unicode'],
    ['a DEL', 'a\u007fb', 'details.value holds control characters or broken Unicode'],
    ['half a surrogate pair', 'a\ud800b', 'details.value holds control characters or broken Unicode'],
  ])('for a detail value that is %s', (_case, value, problem) => {
    expect(problemsOf(withDetails({ value }))).toEqual([problem]);
  });

  it('asks about each detail by name and value, so a constant code can stay and anything else goes', () => {
    const asked: [string, AuditDetailValue][] = [];
    const sensitive = (name: string, value: AuditDetailValue): boolean => {
      asked.push([name, value]);
      return name === 'reasonCode' && value !== 'DUPLICATE_ORDER_REFERENCE';
    };

    expect(problemsOf(withDetails({ reasonCode: 'DUPLICATE_ORDER_REFERENCE' }), sensitive)).toEqual([]);
    expect(problemsOf(withDetails({ reasonCode: 'k3Jx9-random' }), sensitive)).toEqual([
      'details.reasonCode looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
    expect(asked).toEqual([
      ['reasonCode', 'DUPLICATE_ORDER_REFERENCE'],
      ['reasonCode', 'k3Jx9-random'],
    ]);
  });

  it('for a detail whose name marks a secret or personal data (ADR-014 §3)', () => {
    const sensitive = (name: string): boolean => ['email', 'iban'].includes(name);

    expect(problemsOf(withDetails({ email: 'a@b.example', iban: 'AE07', plan: 'x' }), sensitive)).toEqual([
      'details.email looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
      'details.iban looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
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

  it('checks detail names for secrets only once everything else passes, so a problem never quotes a strange key', () => {
    const everything = (): boolean => true;

    expect(problemsOf({ ...EVENT, action: 'bad' }, everything)).toEqual([
      'action must be dotted lower-case words, at most 100 characters',
    ]);
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

  it('gives the same details the same text in any order', () => {
    expect(canonicalDetails({ b: 2, a: 'x', c: null })).toBe(canonicalDetails({ c: null, a: 'x', b: 2 }));
    expect(canonicalDetails({ b: 2, a: 'x', c: null })).toBe('{"a":"x","b":2,"c":null}');
  });
});
