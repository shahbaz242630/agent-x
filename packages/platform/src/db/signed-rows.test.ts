import { describe, expect, it } from 'vitest';

import { type GatheredRow, gatheredRowReads, MOST_ROWS_GATHERED, type SignedStateTable } from './signed-rows.ts';

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const ID = '0199a0f0-0000-7000-8000-000000000002';

const MANDATES = {
  table: 'probe.mandates',
  subject: 'mandate',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'current_version_id', type: 'uuid' },
  ],
} as const satisfies SignedStateTable;

const given: GatheredRow = { table: MANDATES, id: { id: ID }, lock: 'share' };

const lookedUp = (fault: { id?: string; column?: string; table?: SignedStateTable }): GatheredRow => ({
  ...given,
  id: { lookedUp: { table: MANDATES, id: ID, column: 'current_version_id', ...fault } },
});

describe('gatheredRowReads (4D2d P8): refused before any SQL is built', () => {
  it('builds one read a row, each named in order', () => {
    expect(gatheredRowReads(ORG, [given, { ...given, id: { sameAs: 0 } }])).toHaveLength(2);
  });

  it.each([
    ['an organisation not named by a UUID', 'org', [given]],
    ['no rows', ORG, []],
    ['more rows than one gather reads', ORG, Array.from({ length: MOST_ROWS_GATHERED + 1 }, () => given)],
    ['a given ID not a UUID', ORG, [{ ...given, id: { id: 'not-a-uuid' } }]],
    ['an ID from a later row', ORG, [{ ...given, id: { sameAs: 0 } }]],
    ['an ID from a row not in the list', ORG, [given, { ...given, id: { from: 5, column: 'current_version_id' } }]],
    ['an ID from a field not a uuid', ORG, [given, { ...given, id: { from: 0, column: 'status' } }]],
    ['an ID from a field the row lacks', ORG, [given, { ...given, id: { from: 0, column: 'pending_version_id' } }]],
    [
      'a row found by a column not named as ours',
      ORG,
      [{ ...given, id: { findBy: { column: 'Agent_Id; drop', value: ID, statusIn: ['ACTIVE'] } } }],
    ],
    ['a row found in no status', ORG, [{ ...given, id: { findBy: { column: 'agent_id', value: ID, statusIn: [] } } }]],
    ['a table not named as ours', ORG, [{ ...given, table: { ...MANDATES, table: 'Probe.Mandates' } }]],
    ['a looked-up row not named by a UUID', ORG, [lookedUp({ id: 'not-a-uuid' })]],
    ['an ID looked up in a field not a uuid', ORG, [lookedUp({ column: 'status' })]],
    ['an ID looked up in a field the row lacks', ORG, [lookedUp({ column: 'pending_version_id' })]],
    [
      'an ID looked up in a table not named as ours',
      ORG,
      [lookedUp({ table: { ...MANDATES, table: 'Probe.Mandates' } })],
    ],
  ] as const)('refuses %s', (_, orgId, rows) => {
    expect(() => gatheredRowReads(orgId, rows)).toThrow(RangeError);
  });

  it('looks an ID up in a uuid field of another row', () => {
    expect(gatheredRowReads(ORG, [lookedUp({}), given])).toHaveLength(2);
  });
});
