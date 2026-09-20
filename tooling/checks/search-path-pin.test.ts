// The search path is pinned in two packages that may not import each other,
// so this is where the two are held together (A3e-1a confirmation review).
//
// @agentx/platform pins it on every connection the product opens
// (PINNED_SEARCH_PATH). @agentx/testing pins it on the connections the schema
// checks open (CATALOGUE_OPTIONS). They must be the same: a check that read the
// catalogue through a different path from the one the app runs on could pass
// while the app was being lied to. They can't share a constant, because
// @agentx/platform depends on @agentx/testing for its own tests and the other
// way round would be a workspace cycle (removed in S28) — so tooling, which may
// import both, compares them here.
import { describe, expect, it } from 'vitest';

import { PINNED_SEARCH_PATH, PINNED_SEARCH_PATH_VALUE } from '../../packages/platform/src/db/search-path.ts';
import { CATALOGUE_OPTIONS } from '../../packages/testing/src/index.ts';

describe('the pinned search path', () => {
  it('is the same in the product and in the schema checks', () => {
    expect(CATALOGUE_OPTIONS).toBe(PINNED_SEARCH_PATH);
  });

  it('puts Postgres’s own catalogue first, so nothing planted can stand in for it', () => {
    expect(PINNED_SEARCH_PATH_VALUE.split(',')[0]).toBe('pg_catalog');
  });

  it('names pg_temp last, where it cannot shadow a type name', () => {
    // Left out, Postgres searches the session's temporary schema for relation
    // and type names *before* pg_catalog; named last, it is searched after, and
    // the creation namespace stays pg_catalog so an unqualified CREATE fails.
    const schemas = PINNED_SEARCH_PATH_VALUE.split(',');
    expect(schemas).toContain('pg_temp');
    expect(schemas.at(-1)).toBe('pg_temp');
  });
});
