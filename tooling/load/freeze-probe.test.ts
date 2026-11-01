import { afterEach, describe, expect, it, vi } from 'vitest';

import { withFreezeProbe } from './freeze-probe.ts';

afterEach(() => {
  vi.useRealTimers();
});

describe('the freeze asked during phase 5', () => {
  it('asks it once, when told, while the phase runs, and answers only once both are done', async () => {
    vi.useFakeTimers();
    const phase = Promise.withResolvers<string>();
    const probe = Promise.withResolvers<string>();
    const asked = vi.fn(() => probe.promise);
    let answered = false;
    const run = withFreezeProbe(1_000, asked, () => phase.promise).then((answer) => {
      answered = true;
      return answer;
    });

    await vi.advanceTimersByTimeAsync(999);
    expect(asked).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(asked).toHaveBeenCalledOnce();

    // Its answer is the report's: never lost to a phase that ended while it waited.
    phase.resolve('phase');
    await vi.advanceTimersByTimeAsync(0);
    expect(answered).toBe(false);
    probe.resolve('probed');
    expect(await run).toEqual({ ran: 'phase', probed: 'probed' });
  });

  it('asks nothing once the phase has ended first, and says none', async () => {
    vi.useFakeTimers();
    const asked = vi.fn(() => Promise.resolve('probed'));
    expect(await withFreezeProbe(1_000, asked, () => Promise.resolve('phase'))).toEqual({
      ran: 'phase',
      probed: undefined,
    });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(asked).not.toHaveBeenCalled();
  });

  it('asks nothing after a phase that throws, and passes its failure on', async () => {
    vi.useFakeTimers();
    const asked = vi.fn(() => Promise.resolve('probed'));
    await expect(withFreezeProbe(1_000, asked, () => Promise.reject(new Error('k6 stopped')))).rejects.toThrow(
      'k6 stopped',
    );
    await vi.advanceTimersByTimeAsync(5_000);
    expect(asked).not.toHaveBeenCalled();
  });
});
