import { describe, expect, it } from 'vitest';

import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import { checkedHeads, type RebaseTables } from './chain-rebase.ts';

/** A database every call to which fails, with the code given or none, as a dropped connection does. */
function failing(code?: string): Database<RebaseTables> {
  const error = Object.assign(new Error('the server holds data here'), code === undefined ? {} : { code });
  return new Proxy({} as Database<RebaseTables>, {
    // Not a thenable: an awaited stand-in would otherwise never settle.
    get: (_target, property) =>
      property === 'then'
        ? undefined
        : () => {
            throw error;
          },
  });
}

describe("AT8 a chain's checked heads", () => {
  it('says a failed read by its database code alone, never its message, and never throws', async () => {
    const heads = await checkedHeads(failing('57P01'), failing('08006'), {} as KeyProvider, { kind: 'platform' });
    // Without the copy's head, whether the live chain grows on from it is the copy's own failed read.
    expect(heads).toEqual({
      liveHead: { unreadable: '08006' },
      copyHead: { unreadable: '57P01' },
      liveFromCopy: { unreadable: '57P01' },
    });
  });

  it('says an error with no code as error', async () => {
    const heads = await checkedHeads(failing(), failing(), {} as KeyProvider, { kind: 'organisation', orgId: 'x' });
    expect(heads.liveHead).toEqual({ unreadable: 'error' });
  });
});
