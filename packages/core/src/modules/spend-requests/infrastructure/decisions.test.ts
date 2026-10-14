// A spend request read back through its signed state (D4): its record from
// the verified fields, and a throw for a field that isn't one of its own,
// which the table's checks and the seal make a bug. The database test
// (apps/api spend-request-decisions.db.test.ts) reads real ones.
import { describe, expect, it } from 'vitest';

import type { SignedStates } from '../../audit/index.ts';
import { decidedAgainst, requestOf } from './decisions.ts';

const KEY = { orgId: '0199a0f0-0000-7000-8000-000000000001', id: '0199A0F0-0000-7000-8000-0000000000D4' };

const FIELDS: Readonly<Record<string, string | null>> = {
  agent_id: '0199a0f0-0000-7000-8000-000000000002',
  mandate_id: null,
  supplier_id: '0199a0f0-0000-7000-8000-000000000003',
  funding_source_id: '0199a0f0-0000-7000-8000-000000000004',
  amount_minor: '150000',
  currency: 'AED',
  purpose: 'Printer paper',
  order_reference: 'INV-1001',
  decision: 'DENY',
  reason_codes: 'MANDATE_NOT_IN_FORCE SUPPLIER_NOT_VERIFIED',
  status: 'DENIED',
};

/** Signed states whose read gives these fields, verified. */
const reading = (fields: Readonly<Record<string, string | null>>) =>
  ({
    verifiedState: () =>
      Promise.resolve({ outcome: 'verified', version: 2, eventId: 'e', fields: new Map(Object.entries(fields)) }),
  }) as unknown as SignedStates;

// The read never touches the transaction itself: the signed states do.
const read = (states: SignedStates) => requestOf({} as never, states, KEY);

describe('a spend request read through its signed state', () => {
  it('gives its record from the verified fields', async () => {
    expect(await read(reading(FIELDS))).toMatchObject({
      outcome: 'found',
      request: {
        id: KEY.id.toLowerCase(),
        mandateId: null,
        amount: { minor: 150_000n, currency: 'AED' },
        purpose: 'Printer paper',
        decision: 'DENY',
        reasons: ['MANDATE_NOT_IN_FORCE', 'SUPPLIER_NOT_VERIFIED'],
        status: 'DENIED',
      },
    });
    expect(await read(reading({ ...FIELDS, decision: 'ALLOW', reason_codes: null }))).toMatchObject({
      request: { reasons: [] },
    });
  });

  it('passes a read that found none, or found tampering, on as it is', async () => {
    const answering = (answer: object) => ({ verifiedState: () => Promise.resolve(answer) }) as unknown as SignedStates;

    expect(await read(answering({ outcome: 'missing' }))).toEqual({ outcome: 'missing' });
    expect(await read(answering({ outcome: 'tampered', sign: 'seal' }))).toEqual({ outcome: 'tampered', sign: 'seal' });
  });

  it('throws for a field that isn’t one of its own: a bug, never a request', async () => {
    for (const bad of [
      { agent_id: null },
      { amount_minor: '-1' },
      { decision: 'MAYBE' },
      { status: 'PAID' },
      { purpose: null },
      { order_reference: null },
    ]) {
      await expect(read(reading({ ...FIELDS, ...bad }))).rejects.toThrow("a field that isn't one of its own");
    }
    await expect(read(reading({ ...FIELDS, reason_codes: 'NOT_A_REASON' }))).rejects.toThrow("a reason that isn't one");
  });
});

describe('decidedAgainst', () => {
  const stateOf = (fields: Readonly<Record<string, string | null>>) => ({
    outcome: 'verified' as const,
    version: 1,
    eventId: '0199a0f0-0000-7000-8000-0000000000e1',
    recordedAt: new Date(0),
    fields: new Map(Object.entries(fields)),
  });

  it('names the key, mandate version and supplier version it was decided against, null for none', () => {
    expect(decidedAgainst(stateOf({ agent_key_id: 'k', mandate_version_id: null, supplier_version_id: 's' }))).toEqual({
      agentKeyId: 'k',
      mandateVersionId: null,
      supplierVersionId: 's',
    });
  });

  it('throws for one that names no agent key, which 0039 makes a bug', () => {
    expect(() => decidedAgainst(stateOf({ supplier_version_id: 's' }))).toThrow('names no agent key');
  });
});
