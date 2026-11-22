// SEC-DB-20 TR-3: the hand-off's count of reads moved under Tx A, each organisation's in a row: said each time, and
// every fifth in a row the error; a Tx A whose reads held starts the count again. The attack that makes them is
// witness-gate.db.test.ts's.
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createReadMovedCounts } from './handoff.ts';

const ORG = '0199a0f0-0000-7000-8000-00000000a001';
const OTHER = '0199a0f0-0000-7000-8000-00000000a002';

describe('SEC-DB-20 TR-3 reads moved under Tx A, counted in a row', () => {
  it('says each, the error every fifth in a row, a run whose reads held starting again; each organisation its own', () => {
    const capture = new LogCapture();
    const log = testLogger(capture);
    const counts = createReadMovedCounts();
    const errors = () => capture.lines().filter(({ event }) => event === 'handoff.read_moved_repeatedly');
    for (let n = 0; n < 4; n += 1) counts.moved(ORG, 7n, log);
    counts.moved(OTHER, 7n, log);
    expect(errors()).toEqual([]);
    // One whose reads held: the count starts again.
    counts.held(ORG);
    for (let n = 0; n < 4; n += 1) counts.moved(ORG, 7n, log);
    expect(errors()).toEqual([]);
    counts.moved(ORG, 7n, log);
    expect(errors()).toEqual([expect.objectContaining({ level: 'error', times: 5 })]);
    for (let n = 0; n < 5; n += 1) counts.moved(ORG, 7n, log);
    expect(errors().map(({ times }) => times)).toEqual([5, 10]);
    expect(capture.lines().filter(({ event }) => event === 'handoff.read_moved')).toHaveLength(15);
  });
});
