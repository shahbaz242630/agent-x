// The name rule every Stage G guard shares (throwaway.ts): only a copy named
// psql-agentx-stg-g-<8 lower-case letters or digits>, never staging's own server.
import { describe, expect, it } from 'vitest';

import {
  sentinelOf,
  throwawayAnchorsContainer,
  throwawayHost,
  throwawayIdOf,
  throwawayServerOfHost,
  throwawayServerProblem,
} from './throwaway.ts';

const COPY = 'psql-agentx-stg-g-a1b2c3d4';

describe("Stage G's throwaway copy, by name", () => {
  it('takes only staging’s prefix, g-, and eight lower-case letters or digits', () => {
    expect(throwawayIdOf(COPY)).toBe('a1b2c3d4');
    expect(throwawayServerProblem(COPY)).toBeUndefined();
    for (const name of [
      'psql-agentx-stg-abc123',
      'psql-agentx-stg-drill',
      'psql-agentx-stg-g-a1b2c3d',
      'psql-agentx-stg-g-a1b2c3d4e',
      'psql-agentx-stg-g-A1B2C3D4',
      'psql-agentx-stg-g-a1b2-3d4',
      'psql-agentx-prd-g-a1b2c3d4',
      `x${COPY}`,
      `${COPY}.postgres.database.azure.com`,
      '',
    ]) {
      expect(throwawayIdOf(name)).toBeUndefined();
      expect(throwawayServerProblem(name)).toBe(
        `${name} isn't a throwaway copy's name: Stage G's database is named psql-agentx-stg-g-<8 lower-case letters or digits>.`,
      );
    }
  });

  it("never takes staging's own server: its suffix (names.bicep uniqueSuffix) is six letters or digits, no g-", () => {
    for (const suffix of ['abcdef', 'g12345', 'gggggg', '000000']) {
      expect(throwawayServerProblem(`psql-agentx-stg-${suffix}`)).toMatch(/isn't a throwaway copy's name/);
    }
  });

  it('reads the copy back from its host alone, and nothing else as one', () => {
    expect(throwawayHost(COPY)).toBe(`${COPY}.postgres.database.azure.com`);
    expect(throwawayServerOfHost(throwawayHost(COPY))).toBe(COPY);
    for (const host of [
      'psql-agentx-stg-abc123.postgres.database.azure.com',
      COPY,
      `${COPY}.postgres.database.azure.com.evil.example`,
      `${COPY}.private.postgres.database.azure.com`,
      // As long as the suffix, but not it: only the suffix itself is taken off.
      `${COPY}${'x'.repeat('.postgres.database.azure.com'.length)}`,
      '127.0.0.1',
    ]) {
      expect(throwawayServerOfHost(host)).toBeUndefined();
    }
  });

  it('names its own anchors container and a sentinel naming itself', () => {
    expect(throwawayAnchorsContainer('a1b2c3d4')).toBe('audit-anchors-g-a1b2c3d4');
    expect(sentinelOf(COPY)).toBe(`agentx-stage-g-throwaway ${COPY}`);
  });
});
