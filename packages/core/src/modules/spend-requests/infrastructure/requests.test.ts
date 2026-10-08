// A spend request's table description (0039): the statuses clearing the
// integrity hold checks are exactly those a request can still move on from.
import { describe, expect, it } from 'vitest';

import { SPEND_REQUEST } from '../domain/spend-request.ts';
import { SPEND_REQUESTS } from './requests.ts';

describe('spend requests, as the signed state reads them', () => {
  it('are checked before a hold is cleared in every status with a move out, and no other', () => {
    const live = SPEND_REQUEST.states.filter((state) => SPEND_REQUEST.moves.some(({ from }) => from === state));

    expect(SPEND_REQUESTS.liveStatuses).toEqual(live);
  });
});
