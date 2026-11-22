// S210 final: the OAuth tables' alarm-only ceilings, five times each cap, counted at most once a minute, each count
// stopping one past its ceiling; an error past it, and a count that fails only a warning (SEC-OAUTH-13).
import { MOST_OPEN_FLOWS, MOST_REGISTRATIONS_A_DAY } from '@agentx/core/modules/oauth';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { CEILING_TIMES, createOauthCeilings } from './oauth-ceilings.ts';

/** The ceilings over stand-in counts, each answering what `held` says for its table and keeping what it was asked. */
function ceilingsWith(held: { registrations: () => number; flows: () => number }) {
  const clock = new FixedClock(new Date('2026-11-22T09:00:00.000Z'));
  const capture = new LogCapture();
  const asked: { table: string; now: Date; most: number }[] = [];
  const ceilings = createOauthCeilings({
    counts: {
      registrations: (now, most) => {
        asked.push({ table: 'registrations', now, most });
        return Promise.resolve(held.registrations());
      },
      flows: (now, most) => {
        asked.push({ table: 'flows', now, most });
        return Promise.resolve(held.flows());
      },
    },
    clock,
    logger: testLogger(capture),
  });
  const lines = () => capture.lines().filter((line) => line.event !== undefined);
  return { ceilings, clock, asked, lines };
}

describe('the OAuth tables’ alarm-only ceilings (S210 final)', () => {
  it('SEC-OAUTH-13 says nothing at five times the cap, and an error one past it, refusing no one', async () => {
    const registrationsCeiling = MOST_REGISTRATIONS_A_DAY * CEILING_TIMES;
    let registrations = registrationsCeiling;
    const { ceilings, clock, asked, lines } = ceilingsWith({ registrations: () => registrations, flows: () => 0 });

    await ceilings.registrations();
    expect(lines()).toEqual([]);
    // Counted no further than one past the ceiling.
    expect(asked).toEqual([{ table: 'registrations', now: clock.now(), most: registrationsCeiling + 1 }]);

    registrations += 1;
    clock.advanceBy(60_000);
    await ceilings.registrations();
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        event: 'oauth.registrations_past_ceiling',
        cap: MOST_REGISTRATIONS_A_DAY,
        ceiling: registrationsCeiling,
      }),
    ]);
  });

  it('SEC-OAUTH-13 counts each table at most once a minute, so its error comes at most once a minute', async () => {
    const { ceilings, clock, asked, lines } = ceilingsWith({
      registrations: () => 0,
      flows: () => MOST_OPEN_FLOWS * CEILING_TIMES + 1,
    });

    await ceilings.flows();
    await ceilings.flows();
    clock.advanceBy(59_999);
    await ceilings.flows();
    expect(asked).toHaveLength(1);
    expect(lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'oauth.flows_past_ceiling', cap: MOST_OPEN_FLOWS }),
    ]);
    // The other table's own minute.
    await ceilings.registrations();
    expect(asked.map((each) => each.table)).toEqual(['flows', 'registrations']);

    clock.advanceBy(1);
    await ceilings.flows();
    expect(lines().filter((line) => line.event === 'oauth.flows_past_ceiling')).toHaveLength(2);
  });

  it('never throws: a count that fails is a warning, and the next minute counts again', async () => {
    let fails = true;
    const { ceilings, clock, lines } = ceilingsWith({
      registrations: () => 0,
      flows: () => {
        if (fails) throw new Error('connection lost');
        return 0;
      },
    });

    await expect(ceilings.flows()).resolves.toBeUndefined();
    expect(lines()).toEqual([expect.objectContaining({ level: 'warn', event: 'oauth.ceiling_unread' })]);
    fails = false;
    clock.advanceBy(60_000);
    await ceilings.flows();
    expect(lines()).toHaveLength(1);
  });
});
