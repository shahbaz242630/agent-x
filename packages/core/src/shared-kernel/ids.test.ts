import { validate, version } from 'uuid';
import { describe, expect, it } from 'vitest';

import { uuidV7Ids } from './ids.ts';

describe('uuidV7Ids', () => {
  const ids = Array.from({ length: 1000 }, () => uuidV7Ids.next());

  it('creates valid version-7 UUIDs', () => {
    for (const id of ids) {
      expect(validate(id)).toBe(true);
      expect(version(id)).toBe(7);
    }
  });

  it('never repeats an ID', () => {
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('creates IDs that sort in creation order, even within one millisecond', () => {
    expect(ids.toSorted()).toEqual(ids);
  });
});
