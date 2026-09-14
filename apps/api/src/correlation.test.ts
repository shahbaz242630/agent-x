import { SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { correlationIdFrom } from './correlation.ts';

const NEW_ID = '00000000-0000-7000-8000-000000000001';

describe("logging standard §2: a caller's correlation ID is kept only if it's a UUID", () => {
  it.each([
    ['a UUIDv7', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b'],
    ['a UUIDv4, in capitals', '9F2C6E1A-3B4D-4E5F-8A6B-7C8D9E0F1A2B', '9f2c6e1a-3b4d-4e5f-8a6b-7c8d9e0f1a2b'],
  ])('keeps %s, in lower case', (_what, header, expected) => {
    expect(correlationIdFrom(header, new SequentialIds())).toBe(expected);
  });

  it.each([
    ['no header', undefined],
    ['an empty header', ''],
    ['text', 'request-17'],
    ['a UUID with a line break after it', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b\nX-Admin: 1'],
    ['a UUID without its dashes', '0199a1b2c3d47e5f8a6b7c8d9e0f1a2b'],
    ['a UUID in braces', '{0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b}'],
    ['a header sent twice', ['0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c']],
    ['the nil UUID, which every caller sending it would share', '00000000-0000-0000-0000-000000000000'],
    ['the max UUID, in capitals', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'],
  ])('makes a new one for %s', (_what, header) => {
    expect(correlationIdFrom(header, new SequentialIds())).toBe(NEW_ID);
  });
});
