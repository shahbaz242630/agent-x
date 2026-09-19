import { describe, expect, expectTypeOf, it } from 'vitest';

import type { IdGenerator } from '../../core/src/shared-kernel/index.ts';
import { SequentialIds } from './ids.ts';

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('SequentialIds', () => {
  it("fits core's IdGenerator", () => {
    expectTypeOf<SequentialIds>().toExtend<IdGenerator>();
  });

  it('counts up from 1 in the last group', () => {
    const ids = new SequentialIds();

    expect([ids.next(), ids.next(), ids.next()]).toEqual([
      '00000000-0000-7000-8000-000000000001',
      '00000000-0000-7000-8000-000000000002',
      '00000000-0000-7000-8000-000000000003',
    ]);
  });

  it('gives the same sequence every time', () => {
    const first = new SequentialIds();
    const second = new SequentialIds();

    expect(Array.from({ length: 20 }, () => first.next())).toEqual(Array.from({ length: 20 }, () => second.next()));
  });

  it('creates valid version-7 UUIDs that sort in creation order', () => {
    const ids = new SequentialIds();
    const created = Array.from({ length: 300 }, () => ids.next());

    for (const id of created) {
      expect(id).toMatch(UUID_V7);
    }
    expect(created.toSorted()).toEqual(created);
  });

  it('starts after a given number, so two generators never overlap', () => {
    expect(new SequentialIds(0xff).next()).toBe('00000000-0000-7000-8000-000000000100');
  });

  it('stops with an error when the last group is used up', () => {
    const ids = new SequentialIds(0xffff_ffff_fffe);

    expect(ids.next()).toBe('00000000-0000-7000-8000-ffffffffffff');
    expect(() => ids.next()).toThrow('SequentialIds has no IDs left');
  });

  it.each([-1, 1.5, 0x1_0000_0000_0000, Number.NaN])('refuses the start %s', (startAfter) => {
    expect(() => new SequentialIds(startAfter)).toThrow(RangeError);
  });
});
