// Fair turns (4D2e Stage F): a lane an organisation, one item a lane a pass,
// pages only when a lane runs empty, a cursor kept between runs and wrapping,
// an organisation-wide reason ending a lane's turn; and the gate before a
// transaction, an answer ahead of a new start.
import { describe, expect, it } from 'vitest';

import { createFairLanes, createGate, isOrganisationWide, type LaneStep } from './fair-lanes.ts';

const PAGE = 2;

/** Items named `<lane><two digits>`: their order is the order they sort in. */
const itemsOf = (lane: string, count: number) =>
  Array.from({ length: count }, (_, index) => `${lane}${String(index + 1).padStart(2, '0')}`);

/** Lanes over `data`, what was read and worked noted, each item's step from `step`. */
function lanesOver(
  data: Record<string, readonly string[]>,
  {
    step = () => 'next',
    total = 1,
    limit = 1,
    prepare,
  }: {
    step?: (item: string) => LaneStep | Promise<LaneStep>;
    total?: number;
    limit?: number;
    prepare?: (lane: string) => Promise<void> | undefined;
  } = {},
) {
  const worked: string[] = [];
  const reads: [string, string | undefined][] = [];
  const thrown: unknown[] = [];
  const lanes = createFairLanes<string>({
    total,
    limitOf: () => limit,
    page: PAGE,
    idOf: (item) => item,
    read: (lane, after) => {
      reads.push([lane, after]);
      if (data[lane] === undefined) return Promise.resolve(null);
      return Promise.resolve(data[lane].filter((item) => after === undefined || item > after).slice(0, PAGE));
    },
    ...(prepare === undefined ? {} : { prepare }),
    work: async (_lane, item) => {
      worked.push(item);
      return step(item);
    },
    thrown: (_lane, error) => thrown.push(error),
  });
  return { lanes, worked, reads, thrown };
}

const never = () => false;

describe('turns in a run', () => {
  it('gives each lane one item a pass, so the big one never keeps the small one out', async () => {
    const { lanes, worked } = lanesOver({ a: itemsOf('a', 3), b: itemsOf('b', 1), c: itemsOf('c', 2) });

    const outcomes = await lanes.run(['a', 'b', 'c'], never);

    expect(worked).toEqual(['a01', 'b01', 'c01', 'a02', 'c02', 'a03']);
    expect([...outcomes.values()]).toEqual(['whole', 'whole', 'whole']);
  });

  it('reads a page only when a lane runs empty, each after the last', async () => {
    const { lanes, reads } = lanesOver({ a: itemsOf('a', 4) });

    await lanes.run(['a'], never);

    // A full page says nothing of what is behind it, so a last read finds the end.
    expect(reads).toEqual([
      ['a', undefined],
      ['a', 'a02'],
      ['a', 'a04'],
    ]);
  });

  it('holds at most the total at once, and at most the lane’s limit, the rest going as one ends', async () => {
    const release: (() => void)[] = [];
    let now = 0;
    let most = 0;
    const perLane = new Map<string, number>();
    let mostInLane = 0;
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 3), b: itemsOf('b', 3) },
      {
        total: 3,
        limit: 2,
        step: async (item): Promise<LaneStep> => {
          now += 1;
          most = Math.max(most, now);
          const lane = item.slice(0, 1);
          perLane.set(lane, (perLane.get(lane) ?? 0) + 1);
          mostInLane = Math.max(mostInLane, perLane.get(lane) ?? 0);
          await new Promise<void>((resolve) => release.push(resolve));
          now -= 1;
          perLane.set(lane, (perLane.get(lane) ?? 0) - 1);
          return 'next';
        },
      },
    );

    const running = lanes.run(['a', 'b'], never);
    await expect.poll(() => release.length).toBe(3);
    while (worked.length < 6 || release.length > 0) {
      release.shift()?.();
      await new Promise((resolve) => setImmediate(resolve));
    }
    await running;

    expect(most).toBe(3);
    expect(mostInLane).toBe(2);
    expect([...worked].sort()).toEqual([...itemsOf('a', 3), ...itemsOf('b', 3)]);
  });

  it('asks the lane’s limit each turn: one at a time where it says so now', async () => {
    let inLane = 0;
    let most = 0;
    const lanes = createFairLanes<string>({
      total: 5,
      limitOf: () => 1,
      page: PAGE,
      idOf: (item) => item,
      read: (_lane, after) => Promise.resolve(itemsOf('a', 2).filter((item) => after === undefined || item > after)),
      work: async () => {
        inLane += 1;
        most = Math.max(most, inLane);
        await new Promise((resolve) => setImmediate(resolve));
        inLane -= 1;
        return 'next';
      },
      thrown: () => undefined,
    });

    await lanes.run(['a'], never);

    expect(most).toBe(1);
  });

  it('runs nothing and says each lane was cut when the run is already stopped', async () => {
    const { lanes, worked, reads } = lanesOver({ a: itemsOf('a', 1) });

    const outcomes = await lanes.run(['a'], () => true);

    expect(worked).toEqual([]);
    expect(reads).toEqual([]);
    expect(outcomes.get('a')).toBe('cut');
  });

  it('ends with nothing to do for no lanes at all', async () => {
    const { lanes } = lanesOver({});

    expect((await lanes.run([], never)).size).toBe(0);
  });
});

describe('the cursor, kept between runs', () => {
  it('goes on where a run was cut, and wraps to the start after the end', async () => {
    let stop = false;
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 3) },
      {
        step: (item) => {
          // Cut after this item, whichever run it is in.
          stop = item === 'a01';
          return 'next';
        },
      },
    );

    expect((await lanes.run(['a'], () => stop)).get('a')).toBe('cut');
    expect(worked).toEqual(['a01']);

    stop = false;
    expect((await lanes.run(['a'], () => stop)).get('a')).toBe('whole');
    expect(worked).toEqual(['a01', 'a02', 'a03']);

    // Wrapped: back at the first, which is cut again, as the place it stopped.
    expect((await lanes.run(['a'], () => stop)).get('a')).toBe('cut');
    expect(worked).toEqual(['a01', 'a02', 'a03', 'a01']);
  });

  it('starts the next run after the last lane to have a turn, so a cut run never favours the first', async () => {
    let turns = 0;
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 1), b: itemsOf('b', 1), c: itemsOf('c', 1) },
      {
        step: () => {
          turns += 1;
          return 'next';
        },
      },
    );

    await lanes.run(['a', 'b', 'c'], () => turns >= 1);
    expect(worked).toEqual(['a01']);
    await lanes.run(['a', 'b', 'c'], () => turns >= 2);
    expect(worked).toEqual(['a01', 'b01']);
    await lanes.run(['a', 'b', 'c'], () => turns >= 3);
    expect(worked).toEqual(['a01', 'b01', 'c01']);
  });

  it('starts from the first where the last lane has left the list, and forgets a lane that has', async () => {
    let turns = 0;
    const { lanes, reads } = lanesOver(
      { a: itemsOf('a', 3), b: itemsOf('b', 1) },
      {
        step: () => {
          turns += 1;
          return 'next';
        },
      },
    );

    await lanes.run(['a'], () => turns >= 1);
    await lanes.run(['b'], never);
    reads.length = 0;
    await lanes.run(['a'], () => true);
    expect(reads).toEqual([]);
    await lanes.run(['a'], () => turns >= 3);

    // Its place was dropped while it was off the list: it starts again.
    expect(reads[0]).toEqual(['a', undefined]);
  });
});

describe('what a page read may have changed (L5)', () => {
  /** A lane whose read waits for the test: `limit` read each turn, a first item already under way when a second page is read. */
  function lanesWithSlowRead() {
    const pages: (() => void)[] = [];
    const worked: string[] = [];
    const finishing: (() => void)[] = [];
    let limit = 2;
    let endTurn = false;
    const lanes = createFairLanes<string>({
      total: 5,
      limitOf: () => limit,
      page: 1,
      idOf: (item) => item,
      read: async (_lane, after) => {
        await new Promise<void>((resolve) => pages.push(resolve));
        return after === undefined ? ['a01'] : after === 'a01' ? ['a02'] : [];
      },
      work: async (_lane, item) => {
        worked.push(item);
        await new Promise<void>((resolve) => finishing.push(resolve));
        return endTurn ? 'end_turn' : 'next';
      },
      thrown: () => undefined,
    });
    const set = (next: { limit?: number; endTurn?: boolean }) => {
      limit = next.limit ?? limit;
      endTurn = next.endTurn ?? endTurn;
    };
    return { lanes, pages, worked, finishing, set };
  }

  const ticks = async () => {
    for (let at = 0; at < 5; at += 1) await new Promise((resolve) => setImmediate(resolve));
  };

  it('takes no item past a limit that fell during the read: it waits for the one under way', async () => {
    const { lanes, pages, worked, finishing, set } = lanesWithSlowRead();
    const running = lanes.run(['a'], never);
    await ticks();
    pages.shift()?.();
    await ticks();
    expect(worked).toEqual(['a01']);

    set({ limit: 1 });
    pages.shift()?.();
    await ticks();
    expect(worked).toEqual(['a01']);

    finishing.shift()?.();
    await ticks();
    expect(worked).toEqual(['a01', 'a02']);
    finishing.shift()?.();
    await ticks();
    pages.shift()?.();
    await running;
  });

  it('takes no item from a lane closed during the read', async () => {
    const { lanes, pages, worked, finishing, set } = lanesWithSlowRead();
    const running = lanes.run(['a'], never);
    await ticks();
    pages.shift()?.();
    await ticks();

    set({ endTurn: true });
    finishing.shift()?.();
    await ticks();
    pages.shift()?.();
    const outcomes = await running;

    expect(worked).toEqual(['a01']);
    expect(outcomes.get('a')).toBe('ended');
  });
});

describe('a lane’s turn ended', () => {
  it('stops at an organisation-wide reason: nothing behind it walked, the same item tried next run', async () => {
    let frozen = true;
    const { lanes, worked, reads } = lanesOver(
      { a: itemsOf('a', 2), b: itemsOf('b', 1) },
      { step: (item) => (frozen && item.startsWith('a') ? 'end_turn' : 'next') },
    );

    const first = await lanes.run(['a', 'b'], never);
    expect(first.get('a')).toBe('ended');
    expect(first.get('b')).toBe('whole');
    expect(worked).toEqual(['a01', 'b01']);

    worked.length = 0;
    reads.length = 0;
    await lanes.run(['a', 'b'], never);
    expect(worked).toContain('a01');
    expect(worked).not.toContain('a02');
    expect(reads).toContainEqual(['a', undefined]);

    frozen = false;
    worked.length = 0;
    const third = await lanes.run(['a'], never);
    expect(third.get('a')).toBe('whole');
    expect(worked).toEqual(['a01', 'a02']);
  });

  it('starts the next run at the earliest of several that ended it at once', async () => {
    const release: (() => void)[] = [];
    let frozen = true;
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 2) },
      {
        total: 2,
        limit: 2,
        step: async () => {
          if (!frozen) return 'next';
          await new Promise<void>((resolve) => release.push(resolve));
          return 'end_turn';
        },
      },
    );

    const running = lanes.run(['a'], never);
    await expect.poll(() => release.length).toBe(2);
    // The first taken ends last, and the later one first: either order, the earliest place wins.
    release[1]?.();
    await new Promise((resolve) => setImmediate(resolve));
    release[0]?.();
    await running;

    frozen = false;
    worked.length = 0;
    await lanes.run(['a'], never);
    expect(worked).toEqual(['a01', 'a02']);
  });

  it('keeps the earliest place whichever of several ends it first', async () => {
    const release: (() => void)[] = [];
    let frozen = true;
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 2) },
      {
        total: 2,
        limit: 2,
        step: async () => {
          if (!frozen) return 'next';
          await new Promise<void>((resolve) => release.push(resolve));
          return 'end_turn';
        },
      },
    );

    const running = lanes.run(['a'], never);
    await expect.poll(() => release.length).toBe(2);
    release[0]?.();
    await new Promise((resolve) => setImmediate(resolve));
    release[1]?.();
    await running;

    frozen = false;
    worked.length = 0;
    await lanes.run(['a'], never);
    expect(worked).toEqual(['a01', 'a02']);
  });

  it('says a page that can’t be read as failed, and goes on to the other lanes', async () => {
    const { lanes, worked } = lanesOver({ b: itemsOf('b', 1) });

    const outcomes = await lanes.run(['gone', 'b'], never);

    expect(outcomes.get('gone')).toBe('failed');
    expect(outcomes.get('b')).toBe('whole');
    expect(worked).toEqual(['b01']);
  });

  it('never throws: an item that throws is said, its lane failed, past it next run', async () => {
    let bad = true;
    const { lanes, worked, thrown } = lanesOver(
      { a: itemsOf('a', 2), b: itemsOf('b', 1) },
      {
        step: (item) => {
          if (bad && item === 'a01') throw new Error('a bug');
          return 'next';
        },
      },
    );

    const outcomes = await lanes.run(['a', 'b'], never);

    expect(outcomes.get('a')).toBe('failed');
    expect(outcomes.get('b')).toBe('whole');
    expect(thrown).toHaveLength(1);
    bad = false;
    worked.length = 0;
    await lanes.run(['a'], never);
    expect(worked).toEqual(['a02']);
  });

  it('never throws: a read that throws is said, the lane stopping where it was', async () => {
    const thrown: unknown[] = [];
    let readable = false;
    const worked: string[] = [];
    const lanes = createFairLanes<string>({
      total: 1,
      limitOf: () => 1,
      page: PAGE,
      idOf: (item) => item,
      read: () => {
        if (!readable) return Promise.reject(new Error('a bug'));
        return Promise.resolve(['a01']);
      },
      work: (_lane, item) => {
        worked.push(item);
        return Promise.resolve('next');
      },
      thrown: (_lane, error) => thrown.push(error),
    });

    expect((await lanes.run(['a'], never)).get('a')).toBe('failed');
    expect(thrown).toHaveLength(1);
    readable = true;
    await lanes.run(['a'], never);
    expect(worked).toEqual(['a01']);
  });
});

describe('a lane made ready first', () => {
  it('holds no turn while it is made ready: another lane goes meanwhile, and its items after', async () => {
    const { promise: ready, resolve: readied } = Promise.withResolvers<undefined>();
    const prepared: string[] = [];
    const { lanes, worked } = lanesOver(
      { a: itemsOf('a', 1), b: itemsOf('b', 1) },
      {
        prepare: (lane) => {
          prepared.push(lane);
          return lane === 'a' ? ready.then(() => undefined) : undefined;
        },
      },
    );

    const running = lanes.run(['a', 'b'], never);
    await expect.poll(() => worked).toEqual(['b01']);
    readied(undefined);
    const outcomes = await running;

    expect(worked).toEqual(['b01', 'a01']);
    expect(prepared).toEqual(['a', 'b']);
    expect(outcomes.get('a')).toBe('whole');
  });

  it('makes nothing ready for a lane with nothing to do', async () => {
    const prepared: string[] = [];
    const { lanes } = lanesOver(
      { a: [] },
      {
        prepare: (lane) => {
          prepared.push(lane);
          return undefined;
        },
      },
    );

    await lanes.run(['a'], never);

    expect(prepared).toEqual([]);
  });

  it('says a preparation that failed, and its items still go: the item’s own check judges them', async () => {
    const { lanes, worked, thrown } = lanesOver(
      { a: itemsOf('a', 1) },
      { prepare: () => Promise.reject(new Error('a bug')) },
    );

    const outcomes = await lanes.run(['a'], never);

    expect(thrown).toHaveLength(1);
    expect(worked).toEqual(['a01']);
    expect(outcomes.get('a')).toBe('whole');
  });
});

describe('the reasons that end a lane’s turn', () => {
  it.each([
    'organization',
    'organization,agent',
    'agent,organization',
    'hold_held',
    'hold_tampered',
    'hold_bank',
    'anchor_pending',
    'pause_paused',
    'pause_unread',
  ])('%s is the whole organisation’s', (why) => {
    expect(isOrganisationWide(why)).toBe(true);
  });

  it.each(['agent', 'mandate', 'carry', 'source', 'supplier', 'payee', 'agent,mandate', ''])(
    '%s is the request’s own',
    (why) => {
      expect(isOrganisationWide(why)).toBe(false);
    },
  );
});

describe('the gate', () => {
  it('holds at most its limit, the next going as one ends, whether it succeeded or threw', async () => {
    const gate = createGate(1);
    const { promise: held, resolve: release } = Promise.withResolvers<undefined>();
    const order: string[] = [];

    const first = gate.run('a', async () => {
      await held;
      order.push('first');
      throw new Error('it failed');
    });
    const second = gate.run('a', () => {
      order.push('second');
      return Promise.resolve('second answered');
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(order).toEqual([]);

    release(undefined);
    await expect(first).rejects.toThrow('it failed');
    await expect(second).resolves.toBe('second answered');
    expect(order).toEqual(['first', 'second']);
  });

  it('lets one marked ahead go before any waiting, in the order each came', async () => {
    const gate = createGate(1);
    const { promise: held, resolve: release } = Promise.withResolvers<undefined>();
    const order: string[] = [];
    const noted = (name: string) => () => {
      order.push(name);
      return Promise.resolve();
    };

    const all = [
      gate.run('z', () => held),
      gate.run('a', noted('new a')),
      gate.run('b', noted('new b')),
      gate.run('c', noted('answer a'), true),
      gate.run('d', noted('answer b'), true),
    ];
    await new Promise((resolve) => setImmediate(resolve));
    release(undefined);
    await Promise.all(all);

    expect(order).toEqual(['answer a', 'answer b', 'new a', 'new b']);
  });

  it('lets no one past those waiting as a place comes free', async () => {
    const gate = createGate(1);
    const { promise: held, resolve: release } = Promise.withResolvers<undefined>();
    const order: string[] = [];
    const first = gate.run('a', () => held);
    const waiting = gate.run('a', () => {
      order.push('waiting');
      return Promise.resolve();
    });
    await new Promise((resolve) => setImmediate(resolve));
    release(undefined);
    await first;
    const late = gate.run('a', () => {
      order.push('late');
      return Promise.resolve();
    });
    await Promise.all([waiting, late]);

    expect(order).toEqual(['waiting', 'late']);
  });

  it('takes as many as its limit at once', async () => {
    const gate = createGate(2);
    const { promise: held, resolve: release } = Promise.withResolvers<undefined>();
    let inside = 0;
    const entered = () => {
      inside += 1;
      return held;
    };
    const all = [gate.run('a', entered), gate.run('b', entered), gate.run('c', entered)];
    await new Promise((resolve) => setImmediate(resolve));

    expect(inside).toBe(2);

    release(undefined);
    await Promise.all(all);
    expect(inside).toBe(3);
  });

  it('holds at most one of a key: the rest pass it, and it goes as its own ends', async () => {
    const gate = createGate(2);
    const { promise: stuck, resolve: unstick } = Promise.withResolvers<undefined>();
    const order: string[] = [];
    const noted = (name: string) => () => {
      order.push(name);
      return Promise.resolve();
    };

    const blocked = gate.run('x', () => stuck);
    const sameOrganisation = gate.run('x', noted('x again'));
    const answer = gate.run('x', noted('x answer'), true);
    await gate.run('y', noted('y'));
    await gate.run('y', noted('y again'), true);
    expect(order).toEqual(['y', 'y again']);

    unstick(undefined);
    await Promise.all([blocked, sameOrganisation, answer]);
    expect(order).toEqual(['y', 'y again', 'x answer', 'x again']);
  });

  it('lets a key in again after work inside it threw', async () => {
    const gate = createGate(1);

    await expect(gate.run('x', () => Promise.reject(new Error('it failed')))).rejects.toThrow('it failed');

    await expect(gate.run('x', () => Promise.resolve('in'))).resolves.toBe('in');
  });
});
