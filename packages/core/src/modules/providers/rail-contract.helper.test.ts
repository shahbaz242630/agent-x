// The rail adapter contract (Phase 4 B2's promise, gate H6): what Agent X
// relies on from any partner, asked through the port alone, so the fake now
// and a real partner's adapter later (Phase 5, its sandbox) pass the same
// tests. Each adapter's own test file calls `railContract` with how to set it
// up; what only a fake can do (choose an outcome, lose an answer) stays in
// that adapter's own tests.
//
// - An intent accepted is answered about that intent alone; the same
//   instruction ID again answers as the first, one payment (the rail's
//   idempotency key); a refusal carries its reject code, the proof nothing was
//   made (ADR-007 §9, §11).
// - The lookup by key finds the payment, only for its own organisation; one
//   never given is not found, which proves nothing.
// - A payee registered again under the same ID answers as the first (BEN-6).
// - A message is verified over its raw body, or refused, never thrown for.
import { describe, expect, it } from 'vitest';

import { type ApprovedPaymentIntent, paymentStateOf } from './domain/payments.ts';
import type { EventHeaders } from './domain/events.ts';
import type { FinancialRailAdapter, PayeeDetails } from './domain/rail.ts';

/** An adapter set up for the contract: an organisation with a consent and a payee it can pay. */
export interface RailUnderContract {
  readonly rail: FinancialRailAdapter;
  readonly organizationId: string;
  /** Another organisation of the partner's, holding none of the first's payments. */
  readonly otherOrganizationId: string;
  /** The organisation's consent a payment may be made under. */
  readonly accountConsentId: string;
  /** The partner's reference of a payee registered for the organisation. */
  readonly beneficiaryRef: string;
  /** Amounts in minor units the partner answers as named: one it accepts, one it refuses. */
  readonly amounts: { readonly accepted: bigint; readonly refused: bigint };
  /** A payee's details a pass-through registration may carry. */
  readonly payee: PayeeDetails;
  /** A new UUID: our instruction and registration IDs. */
  readonly newId: () => string;
  /** A message the partner signed now, naming the consent; left out where a test can't make one. */
  readonly signedMessage?: () => Promise<{ readonly body: Uint8Array; readonly headers: EventHeaders }>;
}

/** The contract's tests, for the adapter `setUp` makes afresh for each. */
export function railContract(name: string, setUp: () => Promise<RailUnderContract>): void {
  /** An intent of `amount` under the organisation's consent, to its payee, by a new instruction ID. */
  const intentOf = (under: RailUnderContract, amountMinor: bigint): ApprovedPaymentIntent => ({
    organizationId: under.organizationId,
    instructionId: under.newId(),
    accountConsentId: under.accountConsentId,
    beneficiaryRef: under.beneficiaryRef,
    amountMinor,
    currency: 'AED',
    paymentReference: 'INV-CONTRACT-1',
  });

  describe(`the rail adapter contract: ${name} (B2, gate H6)`, () => {
    it('says what it can do: its payee routes and whether its payee identity is stable', async () => {
      const { rail } = await setUp();
      const can = await rail.capabilities();

      expect(can.beneficiaryRoutes.length).toBeGreaterThan(0);
      for (const route of can.beneficiaryRoutes) expect(['hosted', 'pass_through']).toContain(route);
      expect(typeof can.stablePayeeIdentity).toBe('boolean');
    });

    it('accepts an intent and answers about that intent alone', async () => {
      const under = await setUp();
      const intent = intentOf(under, under.amounts.accepted);

      const answer = await under.rail.submitApprovedIntent(intent);

      if (answer.kind !== 'accepted') throw new Error(`not accepted: ${answer.kind}`);
      expect(answer.execution).toMatchObject({
        organizationId: intent.organizationId,
        instructionId: intent.instructionId,
        amountMinor: intent.amountMinor,
        currency: intent.currency,
      });
      expect(answer.execution.paymentInstructionRef).not.toBe('');
      expect(['PROCESSING', 'SUCCEEDED', 'FAILED', 'UNKNOWN']).toContain(paymentStateOf(answer.execution));
    });

    it('answers the same instruction ID again as the first: one payment, found by the lookup by key', async () => {
      const under = await setUp();
      const intent = intentOf(under, under.amounts.accepted);

      const first = await under.rail.submitApprovedIntent(intent);
      const again = await under.rail.submitApprovedIntent(intent);
      const found = await under.rail.getExecution({
        organizationId: intent.organizationId,
        instructionId: intent.instructionId,
      });

      if (first.kind !== 'accepted' || again.kind !== 'accepted') throw new Error('not accepted twice');
      expect(again.execution.paymentInstructionRef).toBe(first.execution.paymentInstructionRef);
      if (found.kind !== 'found') throw new Error('not found by its key');
      expect(found.execution).toMatchObject({
        instructionId: intent.instructionId,
        paymentInstructionRef: first.execution.paymentInstructionRef,
        amountMinor: intent.amountMinor,
      });
    });

    it('refuses with a reject code, its proof nothing was made, and again the same', async () => {
      const under = await setUp();
      const intent = intentOf(under, under.amounts.refused);

      const first = await under.rail.submitApprovedIntent(intent);
      const again = await under.rail.submitApprovedIntent(intent);

      if (first.kind !== 'refused') throw new Error(`not refused: ${first.kind}`);
      expect(first.code).not.toBe('');
      expect(again).toEqual(first);
    });

    it('finds nothing for an instruction it was never given, and nothing of one organisation’s for another', async () => {
      const under = await setUp();
      const intent = intentOf(under, under.amounts.accepted);
      await under.rail.submitApprovedIntent(intent);

      expect(
        await under.rail.getExecution({ organizationId: under.organizationId, instructionId: under.newId() }),
      ).toEqual({ kind: 'not_found' });
      expect(
        await under.rail.getExecution({
          organizationId: under.otherOrganizationId,
          instructionId: intent.instructionId,
        }),
      ).toEqual({ kind: 'not_found' });
    });

    it('answers a payee registered again under the same ID as the first, whatever details come with it', async () => {
      const under = await setUp();
      const { beneficiaryRoutes } = await under.rail.capabilities();
      const registrationId = under.newId();
      const registration = beneficiaryRoutes.includes('pass_through')
        ? ({ route: 'pass_through', organizationId: under.organizationId, registrationId, payee: under.payee } as const)
        : ({ route: 'hosted', organizationId: under.organizationId, registrationId } as const);

      const first = await under.rail.registerBeneficiary(registration);
      const again = await under.rail.registerBeneficiary(
        registration.route === 'pass_through'
          ? { ...registration, payee: { ...under.payee, name: `${under.payee.name} Again` } }
          : registration,
      );

      expect(again).toEqual(first);
      expect(await under.rail.getBeneficiaryState({ organizationId: under.organizationId, registrationId })).toEqual(
        first,
      );
    });

    it('refuses a message it can’t verify, never throwing, whatever it holds', async () => {
      const { rail } = await setUp();
      const bodies = [Buffer.from(''), Buffer.from('not json'), Buffer.from('{"Meta":{}}'), Buffer.from([0xff, 0x00])];
      const headers: EventHeaders[] = [{}, { 'content-type': 'application/json', 'x-signature': 'v1=0' }];

      for (const body of bodies) {
        for (const each of headers) expect((await rail.verifyEvent(body, each)).kind).toBe('refused');
      }
    });

    it('verifies a message the partner signed, naming the consent, with a key to tell a replay', async (context) => {
      const under = await setUp();
      if (under.signedMessage === undefined) {
        context.skip();
        return;
      }
      const { body, headers } = await under.signedMessage();

      const check = await under.rail.verifyEvent(body, headers);

      if (check.kind !== 'verified') throw new Error(`refused: ${check.reason}`);
      expect(check.event.partner).toBe(under.rail.identity.partner);
      expect(check.event.dedupeKey).not.toBe('');
      expect(check.event.reference).toEqual({ kind: 'consent', consentId: under.accountConsentId });
      expect(await under.rail.verifyEvent(body, headers)).toEqual(check);
    });
  });
}
