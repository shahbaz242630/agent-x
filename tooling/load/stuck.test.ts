import { describe, expect, it } from 'vitest';

import type { Database } from '../../packages/platform/src/db/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { whileStuck } from './stuck.ts';

describe('the stuck organisation', () => {
  it('is refused a phase with no stuck organisation among the run’s agents, before anything is sent', () => {
    let sent = false;
    expect(() =>
      whileStuck({} as Database<MandateWorldTables>, [{ kind: 'ample', orgId: 'o', supplierIds: ['s'] }], () => {
        sent = true;
      }),
    ).toThrow('needs the run’s stuck organisation');
    expect(sent).toBe(false);
  });
});
