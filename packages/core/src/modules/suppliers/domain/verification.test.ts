// What verifying a supplier rests on, its people aside (ADR-012 §1; SEC-PAY-03,
// SEC-PAY-07; E3-2a): its state, its cooling-off, the partner's name check,
// the call-back's phone and note.
import { describe, expect, it } from 'vitest';

import {
  CALL_BACK_UNCHANGED_DAYS,
  CALL_NOTE_MOST,
  callNote,
  type VerificationFacts,
  verificationProblem,
} from './verification.ts';

const DAY = 86_400_000;
const NOW = new Date('2026-10-20T12:00:00.000Z');
const daysAgo = (days: number): Date => new Date(NOW.getTime() - days * DAY);

/** A supplier ready to verify: added 60 days ago, its phone since then, a payee matched, cooled off an hour ago. */
const READY: VerificationFacts = {
  supplier: { status: 'UNVERIFIED', pendingVersionId: null, coolingOffUntil: new Date(NOW.getTime() - 3_600_000) },
  current: { phoneSince: daysAgo(60), beneficiaryRef: 'BEN-1' },
  nameCheck: 'match',
  firstEnteredAt: daysAgo(60),
  note: null,
};

const problem = (change: Partial<VerificationFacts>, now = NOW) => verificationProblem({ ...READY, ...change }, now);

describe('verifying a supplier, its people aside (E3-2a)', () => {
  it('uses ADR-012 §1’s 30 days for the phone, and bounds a note at 500 characters', () => {
    expect([CALL_BACK_UNCHANGED_DAYS, CALL_NOTE_MOST]).toEqual([30, 500]);
  });

  it('lets an unverified supplier with a matched payee, cooled off, be verified', () => {
    expect(problem({})).toBeUndefined();
  });

  it('refuses a supplier verified or suspended', () => {
    for (const status of ['VERIFIED', 'SUSPENDED'] as const) {
      expect(problem({ supplier: { ...READY.supplier, status } })).toBe('SUPPLIER_NOT_UNVERIFIED');
    }
  });

  it('refuses one with a change waiting, and one with no payee yet', () => {
    expect(problem({ supplier: { ...READY.supplier, pendingVersionId: 'v-2' } })).toBe('SUPPLIER_CHANGE_WAITING');
    expect(problem({ current: { ...READY.current, beneficiaryRef: null } })).toBe('SUPPLIER_NO_PAYEE');
  });

  it('refuses one still cooling off, up to the very moment it ends, and one with no cooling-off at all', () => {
    const ends = new Date(NOW.getTime() + 1);
    expect(problem({ supplier: { ...READY.supplier, coolingOffUntil: ends } })).toBe('SUPPLIER_COOLING_OFF');
    expect(problem({ supplier: { ...READY.supplier, coolingOffUntil: NOW } })).toBeUndefined();
    expect(problem({ supplier: { ...READY.supplier, coolingOffUntil: null } })).toBe('SUPPLIER_COOLING_OFF');
  });

  it('refuses a "no match" name check, whatever the note', () => {
    expect(problem({ nameCheck: 'no_match', note: 'Called them, it is fine' })).toBe('SUPPLIER_NAME_MISMATCH');
  });

  it('needs a written note for any name check short of a match (partner, S69, S74)', () => {
    for (const nameCheck of ['partial', 'unavailable', null] as const) {
      expect(problem({ nameCheck })).toBe('SUPPLIER_CALL_NOTE_NEEDED');
      expect(problem({ nameCheck, note: 'Spoke to Sara in accounts; trading name differs' })).toBeUndefined();
    }
  });

  it('takes a phone the supplier has had since it was added: from its independent source', () => {
    const added = daysAgo(2);
    expect(problem({ firstEnteredAt: added, current: { ...READY.current, phoneSince: added } })).toBeUndefined();
  });

  it('refuses a phone changed since it was added, until it has been the supplier’s 30 days', () => {
    const changed = { firstEnteredAt: daysAgo(90), current: { ...READY.current, phoneSince: daysAgo(29) } };
    expect(problem(changed)).toBe('SUPPLIER_PHONE_TOO_NEW');
    const thirty = { ...changed, current: { ...changed.current, phoneSince: daysAgo(30) } };
    expect(problem(thirty)).toBeUndefined();
    expect(problem(thirty, new Date(NOW.getTime() - 1))).toBe('SUPPLIER_PHONE_TOO_NEW');
  });

  it('checks in the order a member would fix them', () => {
    const everything: Partial<VerificationFacts> = {
      supplier: { status: 'UNVERIFIED', pendingVersionId: null, coolingOffUntil: null },
      current: { phoneSince: daysAgo(1), beneficiaryRef: 'BEN-1' },
      nameCheck: 'no_match',
      firstEnteredAt: daysAgo(90),
    };
    expect(problem(everything)).toBe('SUPPLIER_COOLING_OFF');
    expect(problem({ ...everything, supplier: READY.supplier })).toBe('SUPPLIER_NAME_MISMATCH');
    expect(problem({ ...everything, supplier: READY.supplier, nameCheck: 'match' })).toBe('SUPPLIER_PHONE_TOO_NEW');
  });
});

describe('a call-back note', () => {
  it('is kept composed (NFC)', () => {
    expect(callNote('Café owner confirmed')).toEqual({ note: 'Café owner confirmed', problems: [] });
  });

  it('is 1 to 500 readable characters, with no controls or outer spaces, its problems naming the note', () => {
    expect(callNote('x'.repeat(500)).problems).toEqual([]);
    expect(callNote('x'.repeat(501)).problems).toEqual(['the note is 1 to 500 characters']);
    expect(callNote('').problems).toContain('the note is 1 to 500 characters');
    expect(callNote('line one\nline two').problems).toEqual([
      'the note holds a control, format, invisible or unassigned character',
    ]);
    expect(callNote(' spaced').problems).toEqual(['the note starts or ends with a space']);
  });
});
