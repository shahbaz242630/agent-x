import { FixedClock, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createSessions } from './sessions.ts';

const make = (idleSeconds: number, absoluteSeconds: number) => () =>
  createSessions({
    ids: new SequentialIds(),
    clock: new FixedClock(new Date('2026-09-24T09:00:00Z')),
    timeouts: { idleSeconds, absoluteSeconds },
  });

describe("the sessions' timeouts", () => {
  it('are taken as whole seconds, at least a minute, the idle one no longer than the absolute', () => {
    expect(make(60, 60)).not.toThrow();
    expect(make(1800, 43_200)).not.toThrow();
  });

  it.each([
    ['an idle timeout under a minute', 59, 3600],
    ['an absolute timeout under a minute', 60, 59],
    ['a fraction of a second', 60.5, 3600],
    ['no number', Number.NaN, 3600],
    ['an endless one', 60, Number.POSITIVE_INFINITY],
    ['a negative one', -60, 3600],
  ])('are refused with %s', (_, idle, absolute) => {
    expect(make(idle, absolute)).toThrow('session timeouts must be whole numbers of seconds, at least 60');
  });

  it('are refused with an idle timeout longer than the absolute one', () => {
    expect(make(3601, 3600)).toThrow('the idle timeout must not be longer than the absolute one');
  });
});
