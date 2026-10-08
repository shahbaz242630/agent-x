// The shared refinement (C3b): a body's money and domain refusals become its
// issues, each problem once; anything else is a bug, thrown, never a 400.
import { money } from '@agentx/core/shared-kernel';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { issuesOf } from './route-schemas.ts';

class Refused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super('refused');
    this.problems = problems;
  }
}

/** A schema refined by `read`, parsing anything. */
const refinedBy = (read: () => unknown) =>
  z.unknown().superRefine((_body, context) => {
    issuesOf(read, Refused, context);
  });

describe('issuesOf', () => {
  it('passes a body read without a refusal', () => {
    expect(refinedBy(() => 'fine').safeParse({}).success).toBe(true);
  });

  it('gives money that can’t be, and each problem a refusal names, as issues', () => {
    const negative = refinedBy(() => money(-1n, 'AED')).safeParse({});
    expect(negative.error?.issues.map(({ message }) => message)).toEqual(['Not money: an amount is never negative']);
    const refused = refinedBy(() => {
      throw new Refused(['one', 'two']);
    }).safeParse({});
    expect(refused.error?.issues.map(({ message }) => message)).toEqual(['one', 'two']);
  });

  it('throws anything else: a bug, never a refusal of the body', () => {
    expect(() =>
      refinedBy(() => {
        throw new TypeError('a bug');
      }).parse({}),
    ).toThrow(TypeError);
  });
});
