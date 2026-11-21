import { describe, expect, it } from 'vitest';

import { UUID } from '../../../shared-kernel/index.ts';
import { namedId } from './named-id.ts';

describe('namedId', () => {
  it('names the same row the same way every time, whatever the case of its parts', () => {
    const id = namedId(['month_total', 'A1B2C3D4-0000-4000-8000-000000000001', '2026-11']);
    expect(id).toBe(namedId(['month_total', 'a1b2c3d4-0000-4000-8000-000000000001', '2026-11']));
    expect(id).toMatch(UUID);
    expect(id).toBe(id.toLowerCase());
  });

  it("is a version 8 UUID of RFC 9562's variant", () => {
    const id = namedId(['x']);
    expect(id[14]).toBe('8');
    expect(['8', '9', 'a', 'b']).toContain(id[19]);
  });

  it('names other parts, or the same text split otherwise, apart', () => {
    expect(namedId(['a', 'b'])).not.toBe(namedId(['a', 'c']));
    expect(namedId(['ab', 'c'])).not.toBe(namedId(['a', 'bc']));
    expect(namedId(['a|b'])).not.toBe(namedId(['a', 'b']));
  });
});
