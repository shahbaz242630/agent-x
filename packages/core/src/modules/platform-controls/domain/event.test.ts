import { describe, expect, it } from 'vitest';

import type { EventDetails } from '../../../shared-kernel/index.ts';
import { checkedPlatformEvent, type PlatformEvent, PlatformEventRefused, platformEventContent } from './event.ts';

const STARTED: PlatformEvent = {
  actor: { type: 'system', id: 'api' },
  action: 'platform.started',
  details: { release: 'r-1', configHash: 'sha256:abc' },
};

const nothingSensitive = (): boolean => false;

function problemsOf(
  event: PlatformEvent,
  isSensitive: (name: string) => boolean = nothingSensitive,
): readonly string[] {
  try {
    checkedPlatformEvent(event, isSensitive);
    return [];
  } catch (error) {
    if (error instanceof PlatformEventRefused) return error.problems;
    throw error;
  }
}

describe('a platform audit event in its canonical form', () => {
  it('keeps a valid event, frozen, with its details in key order', () => {
    const checked = checkedPlatformEvent(STARTED, nothingSensitive);

    expect(checked).toEqual(STARTED);
    expect(Object.keys(checked.details)).toEqual(['configHash', 'release']);
    expect(Object.isFrozen(checked)).toBe(true);
    expect(Object.isFrozen(checked.actor)).toBe(true);
    expect(Object.isFrozen(checked.details)).toBe(true);
  });

  it('reads each field once, so a getter cannot show the check one value and the record another', () => {
    let reads = 0;
    const actor = {
      type: 'system' as const,
      get id(): string {
        reads += 1;
        return reads === 1 ? 'api' : 'Not A Name';
      },
    };

    expect(checkedPlatformEvent({ ...STARTED, actor }, nothingSensitive).actor.id).toBe('api');
    expect(reads).toBe(1);
  });

  it('is sealed as its labelled fields, with the details as their JSON text', () => {
    expect(platformEventContent(STARTED, '{"configHash":"sha256:abc","release":"r-1"}')).toEqual([
      'actor',
      'system',
      'api',
      'action',
      'platform.started',
      'details',
      '{"configHash":"sha256:abc","release":"r-1"}',
    ]);
  });
});

describe('a platform audit event refused', () => {
  it.each([
    ['an actor that is not the app', { actor: { type: 'operator', id: 'api' } }, 'actor.type must be system'],
    ['an actor without a process name', { actor: { type: 'system', id: 'API' } }, 'actor.id must be a process name'],
    ['an action of one word', { action: 'started' }, 'action must be dotted lower-case words, at most 100 characters'],
    ['details that are not a plain object', { details: null }, 'details must be a plain object'],
  ])('for %s', (_case, change, problem) => {
    expect(problemsOf({ ...STARTED, ...change } as unknown as PlatformEvent)).toEqual([problem]);
  });

  it('for a detail the logger would hide, which audit rows never hold', () => {
    const details: EventDetails = { contactEmail: 'x' };

    expect(problemsOf({ ...STARTED, details }, (name) => name === 'contactEmail')).toEqual([
      'details.contactEmail looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
    ]);
  });

  it('lists every problem at once, and quotes no value', () => {
    const marker = 'planted marker words';
    const problems = problemsOf({
      actor: { type: 'system', id: marker },
      action: marker,
      details: { note: `${marker}\n` },
    });

    expect(problems).toHaveLength(3);
    expect(problems.join(' ')).not.toContain(marker);
  });
});
