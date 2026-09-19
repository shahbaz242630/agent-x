import { describe, expect, it } from 'vitest';

import { actionProblems, canonicalDetails, checkedDetails, type EventDetailValue } from './event-facts.ts';

/** Nothing counts as sensitive, unless a test says otherwise. */
const nothingSensitive = (): boolean => false;

const problemsOf = (
  details: unknown,
  isSensitive: (name: string, value: EventDetailValue) => boolean = nothingSensitive,
): readonly string[] => checkedDetails(details, isSensitive).problems;

describe('an action', () => {
  it.each(['organisation.created', 'agent_key.revoked', 'platform.started', `a.${'b'.repeat(98)}`])(
    'passes: %s',
    (action) => {
      expect(actionProblems(action)).toEqual([]);
    },
  );

  it.each([
    'created',
    'Organisation.created',
    'organisation.',
    'organisation..created',
    'org-x.created',
    `a.${'b'.repeat(99)}`,
  ])('is refused: %j', (action) => {
    expect(actionProblems(action)).toEqual(['action must be dotted lower-case words, at most 100 characters']);
  });
});

describe('details in their canonical form', () => {
  it('come back in key order and frozen, whatever order they were written in', () => {
    const { problems, details } = checkedDetails({ zeta: 1, alpha: true, mid: null }, nothingSensitive);

    expect(problems).toEqual([]);
    expect(Object.keys(details)).toEqual(['alpha', 'mid', 'zeta']);
    expect(Object.isFrozen(details)).toBe(true);
  });

  it('accept every kind of value, at the limits', () => {
    const details = {
      text: 'x'.repeat(1024),
      emoji: 'paid 💸',
      big: Number.MAX_SAFE_INTEGER,
      small: Number.MIN_SAFE_INTEGER,
      yes: true,
      no: false,
      none: null,
    };

    expect(problemsOf(details)).toEqual([]);
    expect(problemsOf(Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`k${i}`, i])))).toEqual([]);
    expect(problemsOf(Object.assign(Object.create(null) as object, { a: 1 }))).toEqual([]);
  });

  it('are read once, so a getter cannot show the check one value and the record another', () => {
    let reads = 0;
    const details = {
      get note(): unknown {
        reads += 1;
        return reads === 1 ? 'fine' : { nested: 'changed after the check' };
      },
    };

    expect(checkedDetails(details, nothingSensitive).details).toEqual({ note: 'fine' });
    expect(reads).toBe(1);
  });

  it('give the same facts the same text in any order', () => {
    expect(canonicalDetails({ b: 2, a: 'x', c: null })).toBe(canonicalDetails({ c: null, a: 'x', b: 2 }));
    expect(canonicalDetails({ b: 2, a: 'x', c: null })).toBe('{"a":"x","b":2,"c":null}');
  });
});

describe('details refused', () => {
  it.each([
    ['null', null],
    ['an array', ['a']],
    ['a date', new Date(0)],
    ['a map', new Map()],
    ['text', 'plan=pilot'],
    ['missing', undefined],
  ])('when they are %s, not a plain object', (_case, details) => {
    expect(problemsOf(details)).toEqual(['details must be a plain object']);
  });

  it('when there are more than 32', () => {
    expect(problemsOf(Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, i])))).toEqual([
      'details has more than 32 entries',
    ]);
  });

  it.each(['snake_case', 'Capital', '1st', '', 'with-dash', `k${'x'.repeat(63)}`])('for the key %j', (key) => {
    expect(problemsOf({ [key]: 1 })).toEqual(['details has a key that is not a camelCase name']);
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
  ])('for a value that is %s', (_case, value, problem) => {
    expect(problemsOf({ value })).toEqual([problem]);
  });

  it('for a detail the logger would hide, asked by name and value, so a constant code can stay', () => {
    const asked: [string, EventDetailValue][] = [];
    const sensitive = (name: string, value: EventDetailValue): boolean => {
      asked.push([name, value]);
      return name === 'reasonCode' && value !== 'DUPLICATE_ORDER_REFERENCE';
    };

    expect(problemsOf({ reasonCode: 'DUPLICATE_ORDER_REFERENCE' }, sensitive)).toEqual([]);
    expect(problemsOf({ reasonCode: 'k3Jx9-random' }, sensitive)).toEqual([
      'details.reasonCode looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
    expect(asked).toEqual([
      ['reasonCode', 'DUPLICATE_ORDER_REFERENCE'],
      ['reasonCode', 'k3Jx9-random'],
    ]);
  });

  it('for every detail whose name marks a secret or personal data (ADR-014 §3), and gives none back', () => {
    const sensitive = (name: string): boolean => ['email', 'iban'].includes(name);
    const result = checkedDetails({ email: 'a@b.example', iban: 'AE07', plan: 'x' }, sensitive);

    expect(result.problems).toEqual([
      'details.email looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
      'details.iban looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
    expect(result.details).toEqual({});
  });

  it('asks about secrets only once the keys and values pass, so a problem never quotes a strange key', () => {
    const everything = (): boolean => true;

    expect(problemsOf({ 'Bad-Key': 1 }, everything)).toEqual(['details has a key that is not a camelCase name']);
    expect(problemsOf({ fine: 1.5 }, everything)).toEqual(['details.fine must be a whole number']);
  });
});
