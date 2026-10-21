// Phase 4 B2 (PRD §6, §11; ADR-007 §8–§11; rail map §3–§4; partner decision
// 5): the fake partner's payments. The contract Agent X relies on: an intent
// accepted or refused with proof that nothing was made; the same instruction
// ID again inside the 24-hour window answering as the first (one payment);
// an answer that never comes back (RailUnavailable) after the payment was
// made, found by the lookup by key; a lookup that finds nothing proving
// nothing; only the organisation's own payments; and the rail's five statuses
// moving on, the amount's fils choosing each outcome.
import { FixedClock, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { type ApprovedPaymentIntent, paymentStateOf } from '../domain/payments.ts';
import { RailUnavailable } from '../domain/rail.ts';
import { FAKE_REJECT_CODES, scriptOf } from './fake-payments.ts';
import { createFakeRail, USUAL_CONTROLS } from './fake-rail.ts';

const ORG = '00000000-0000-7000-8000-00000000aaaa';
const OTHER_ORG = '00000000-0000-7000-8000-00000000bbbb';
const LINK = '00000000-0000-7000-8000-00000000cccc';
const INSTRUCTION = '00000000-0000-7000-8000-0000000000d1';
const START = new Date('2026-10-01T08:00:00Z');
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';

/** A fake partner with a source linked for ORG, its consent in use: the rail, its bank, the clock and the consent's ID. */
async function linked() {
  const clock = new FixedClock(START);
  const rail = createFakeRail({ clock, ids: new SequentialIds() });
  const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
  const consentId = await rail.bank.approve(ORG, session.sessionRef, ACCOUNT);
  return { clock, rail, consentId };
}

/** An intent of AED 1,000 (100,000 fils, which succeeds) unless the test says otherwise. */
const intentOf = (consentId: string, overrides: Partial<ApprovedPaymentIntent> = {}): ApprovedPaymentIntent => ({
  organizationId: ORG,
  instructionId: INSTRUCTION,
  accountConsentId: consentId,
  beneficiaryRef: 'fake-payee-1',
  amountMinor: 100_000n,
  currency: 'AED',
  paymentReference: 'INV-1001',
  ...overrides,
});

describe('the amount’s fils choose the outcome (decision 5)', () => {
  it.each([
    [100_001n, 'declined'],
    [100_002n, 'lost'],
    [100_003n, 'duplicate'],
    [100_004n, 'unknown'],
    [100_000n, 'succeeds'],
    [100_005n, 'succeeds'],
    [100_099n, 'succeeds'],
  ])('%s fils: %s', (amount, script) => {
    expect(scriptOf(amount)).toBe(script);
  });
});

describe('a payment that succeeds', () => {
  it('is accepted Pending, then settled at the debtor, then credited: SUCCEEDED only then (STA-1)', async () => {
    const { clock, rail, consentId } = await linked();

    const submitted = await rail.submitApprovedIntent(intentOf(consentId));
    if (submitted.kind !== 'accepted') throw new Error(`not accepted: ${submitted.kind}`);
    expect(submitted.execution).toMatchObject({
      organizationId: ORG,
      instructionId: INSTRUCTION,
      providerStatus: 'Pending',
      rejectCode: null,
      noDebitProven: false,
      amountMinor: 100_000n,
      currency: 'AED',
      statusChangedAt: START,
    });
    expect(paymentStateOf(submitted.execution)).toBe('PROCESSING');

    const states = [];
    for (const minutes of [1, 2, 60]) {
      clock.advanceBy(START.getTime() + minutes * MINUTE - clock.now().getTime());
      const found = await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION });
      if (found.kind !== 'found') throw new Error('not found');
      states.push([found.execution.providerStatus, paymentStateOf(found.execution)]);
      expect(found.execution.paymentInstructionRef).toBe(submitted.execution.paymentInstructionRef);
    }
    expect(states).toEqual([
      ['AcceptedSettlementCompleted', 'PROCESSING'],
      ['AcceptedCreditSettlementCompleted', 'SUCCEEDED'],
      ['AcceptedCreditSettlementCompleted', 'SUCCEEDED'],
    ]);
  });

  it('answers the same instruction ID again within 24 hours as the first did, whatever the body: one payment', async () => {
    const { clock, rail, consentId } = await linked();
    const first = await rail.submitApprovedIntent(intentOf(consentId));
    clock.advanceBy(START.getTime() + DAY - MINUTE - clock.now().getTime());

    const again = await rail.submitApprovedIntent(intentOf(consentId, { amountMinor: 999_900n }));

    if (first.kind !== 'accepted' || again.kind !== 'accepted') throw new Error('not accepted');
    expect(again.execution.paymentInstructionRef).toBe(first.execution.paymentInstructionRef);
    expect(again.execution.amountMinor).toBe(100_000n);
  });

  it('makes a second payment for the same key past the window, as the rail does: why Agent X never resends', async () => {
    const { clock, rail, consentId } = await linked();
    const first = await rail.submitApprovedIntent(intentOf(consentId));
    clock.advanceBy(START.getTime() + DAY - clock.now().getTime());

    const again = await rail.submitApprovedIntent(intentOf(consentId));
    const found = await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION });

    if (first.kind !== 'accepted' || again.kind !== 'accepted' || found.kind !== 'found') throw new Error('not made');
    expect(again.execution.paymentInstructionRef).not.toBe(first.execution.paymentInstructionRef);
    // The lookup by key gives the newest.
    expect(found.execution.paymentInstructionRef).toBe(again.execution.paymentInstructionRef);
  });
});

describe('a payment refused, lost, duplicated or unknown', () => {
  it('refuses `.01` with a code proving nothing was made: no payment to look up (FAILED)', async () => {
    const { rail, consentId } = await linked();

    expect(await rail.submitApprovedIntent(intentOf(consentId, { amountMinor: 100_001n }))).toEqual({
      kind: 'refused',
      code: FAKE_REJECT_CODES.declined,
    });
    expect(await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION })).toEqual({ kind: 'not_found' });
  });

  it.each([
    ['.02, the answer lost (a timeout)', 100_002n],
    ['.03, the rail’s 409 for a key it is already working on (a duplicate)', 100_003n],
  ])('makes the payment for %s, then fails as no answer: the lookup by key finds it', async (_, amountMinor) => {
    const { rail, consentId } = await linked();

    await expect(rail.submitApprovedIntent(intentOf(consentId, { amountMinor }))).rejects.toBeInstanceOf(
      RailUnavailable,
    );
    const found = await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION });
    expect(found).toMatchObject({ kind: 'found', execution: { providerStatus: 'Pending', amountMinor } });
    // Asked again within the window, it answers this time, the same payment.
    const again = await rail.submitApprovedIntent(intentOf(consentId, { amountMinor }));
    expect(again).toMatchObject({
      kind: 'accepted',
      execution: { paymentInstructionRef: expect.any(String) as string },
    });
  });

  it('rejects `.04` after the account was debited, with no proof the money stayed: UNKNOWN, never FAILED', async () => {
    const { clock, rail, consentId } = await linked();
    await rail.submitApprovedIntent(intentOf(consentId, { amountMinor: 100_004n }));
    clock.advanceBy(START.getTime() + 2 * MINUTE - clock.now().getTime());

    const found = await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION });

    if (found.kind !== 'found') throw new Error('not found');
    expect(found.execution).toMatchObject({
      providerStatus: 'Rejected',
      rejectCode: FAKE_REJECT_CODES.afterDebit,
      noDebitProven: false,
    });
    expect(paymentStateOf(found.execution)).toBe('UNKNOWN');
  });
});

describe('what the rail refuses before making anything', () => {
  it('refuses a consent not the organisation’s, not in use, in another currency or below the amount', async () => {
    const { rail, consentId } = await linked();
    const refusedFor = (intent: ApprovedPaymentIntent) =>
      rail.submitApprovedIntent(intent).then((result) => (result.kind === 'refused' ? result.code : result.kind));

    expect(await refusedFor(intentOf('fake-consent-none'))).toBe(FAKE_REJECT_CODES.consent);
    expect(await refusedFor(intentOf(consentId, { organizationId: OTHER_ORG }))).toBe(FAKE_REJECT_CODES.consent);
    expect(await refusedFor(intentOf(consentId, { currency: 'USD' }))).toBe(FAKE_REJECT_CODES.consent);
    expect(await refusedFor(intentOf(consentId, { amountMinor: USUAL_CONTROLS.maxPaymentMinor + 100n }))).toBe(
      FAKE_REJECT_CODES.overLimit,
    );
    await rail.bank.changeConsent(ORG, consentId, 'Suspended');
    expect(await refusedFor(intentOf(consentId))).toBe(FAKE_REJECT_CODES.consent);
  });

  it('refuses an instruction ID the rail can’t take as its key, before anything', async () => {
    const { rail, consentId } = await linked();
    await expect(rail.submitApprovedIntent(intentOf(consentId, { instructionId: 'has a space' }))).rejects.toThrow(
      RangeError,
    );
    await expect(rail.submitApprovedIntent(intentOf(consentId, { instructionId: 'x'.repeat(41) }))).rejects.toThrow(
      RangeError,
    );
  });

  it('makes nothing while the partner is down, and shows another organisation none of ORG’s payments', async () => {
    const { rail, consentId } = await linked();
    rail.bank.goDown();
    await expect(rail.submitApprovedIntent(intentOf(consentId))).rejects.toBeInstanceOf(RailUnavailable);
    rail.bank.comeBack();
    expect(await rail.getExecution({ organizationId: ORG, instructionId: INSTRUCTION })).toEqual({ kind: 'not_found' });

    await rail.submitApprovedIntent(intentOf(consentId));
    expect(await rail.getExecution({ organizationId: OTHER_ORG, instructionId: INSTRUCTION })).toEqual({
      kind: 'not_found',
    });
  });
});
