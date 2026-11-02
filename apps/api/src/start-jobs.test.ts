// What holds a process with no server open, and the jobs' starting and stopping together.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { keepAlive, startJobs } from './start-jobs.ts';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('keepAlive', () => {
  it('holds a timer open that does nothing as it fires, until it is stopped', () => {
    const holding = keepAlive(1);
    expect(vi.getTimerCount()).toBe(1);

    vi.advanceTimersByTime(5);
    expect(vi.getTimerCount()).toBe(1);

    holding.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('by default waits so long it never matters, and a stop still ends it', () => {
    const holding = keepAlive();
    expect(vi.getTimerCount()).toBe(1);
    holding.stop();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('startJobs', () => {
  it('starts each in the order given, and stopping stops them all', async () => {
    const said: string[] = [];
    const job = (name: string) => ({
      name,
      start: () => {
        said.push(`${name} started`);
        return {
          stop: () => {
            said.push(`${name} stopped`);
            return Promise.resolve();
          },
        };
      },
    });

    const jobs = startJobs([job('first'), job('second')]);
    expect(said).toEqual(['first started', 'second started']);

    await jobs.stop();
    expect(said).toEqual(['first started', 'second started', 'first stopped', 'second stopped']);
  });
});
