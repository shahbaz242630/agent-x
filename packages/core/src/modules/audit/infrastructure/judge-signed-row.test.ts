// PL-29 follow-up (S183): judgeSignedRow, the verifier's judgement of a row
// and its latest signed event read by the caller with no lock (a state
// recovery plan's), for the rows that aren't found: what verifiedState's own
// read in two statements makes of each. A found row is judged as
// verifiedState judges it, which signed-states.db.test.ts proves.
import type { SignedStateTable } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import { judgeSignedRow } from './signed-states.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

const THINGS = {
  table: 'probe.things',
  subject: 'thing',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;

const KEY = { orgId: '0199a0f0-0000-7000-8000-00000000e001', id: '0199a0f0-0000-7000-8000-00000000e002' };

const SIGNED = {
  kind: 'signed' as const,
  id: '0199a0f0-0000-7000-8000-00000000e003',
  seq: 4n,
  recordedAt: new Date('2026-11-10T08:00:00Z'),
  version: 1,
  seal: { fingerprint: Buffer.alloc(32), keyVersion: 1 },
};

describe('PL-29 follow-up: judgeSignedRow, a row read with no lock', () => {
  it('reads a row and a log that both have nothing as missing', () => {
    expect(judgeSignedRow(keys, THINGS, KEY, { outcome: 'missing' }, { kind: 'none' })).toEqual({
      outcome: 'missing',
    });
  });

  it('reads a missing row whose log is broken as the log tampered with', () => {
    expect(judgeSignedRow(keys, THINGS, KEY, { outcome: 'missing' }, { kind: 'broken', seq: 3n })).toEqual({
      outcome: 'tampered',
      sign: 'log',
    });
  });

  it('reads a missing row whose log signed it as deleted', () => {
    expect(judgeSignedRow(keys, THINGS, KEY, { outcome: 'missing' }, SIGNED)).toEqual({
      outcome: 'tampered',
      sign: 'deleted',
    });
  });

  it('reads an unreadable row as the row tampered with, whatever the log holds', () => {
    for (const latest of [{ kind: 'none' as const }, SIGNED]) {
      expect(judgeSignedRow(keys, THINGS, KEY, { outcome: 'unreadable' }, latest)).toEqual({
        outcome: 'tampered',
        sign: 'row',
      });
    }
  });

  it('reads a found row against a seal it does not match as the seal', () => {
    const row = { outcome: 'found' as const, version: 1, eventId: SIGNED.id, fields: [['label', 'x']] as const };
    expect(judgeSignedRow(keys, THINGS, KEY, row, SIGNED)).toEqual({ outcome: 'tampered', sign: 'seal' });
  });
});
