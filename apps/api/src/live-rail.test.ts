import type {
  ApprovedPaymentIntent,
  BeneficiaryOutcome,
  BeneficiaryRef,
  BeneficiaryRegistration,
  EventCheck,
  EventHeaders,
  ExecutionLookup,
  FinancialRailAdapter,
  LinkContext,
  LinkOutcome,
  PartnerExecutionRef,
  PartnerLinkSession,
  RailCapabilities,
  SourceLookup,
  SourceRef,
  SubmissionResult,
} from '@agentx/core/modules/providers';
import { recordedStartWith } from '@agentx/platform/config';
import { LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { liveOnly, NotStartedLive } from './live-rail.ts';

const GATE_REF = `LMG-v1-sha256:${'ab'.repeat(32)}`;
const INTENT = { instructionId: 'i-1' } as unknown as ApprovedPaymentIntent;

/**
 * A live adapter stand-in written as a class, as a real adapter may be: every
 * method keeps what it was asked in a private field, so it works only when
 * called on the adapter itself. Each answers with its name and what it was given.
 */
class LiveRail implements FinancialRailAdapter {
  readonly identity = { partner: 'bank', legalEntityId: 'le-1', licenceRef: 'lic-1' };
  readonly authoriseOrigin = 'https://pay.bank.example';
  readonly formOrigin = 'https://forms.bank.example';
  readonly #asked: string[] = [];

  get asked(): readonly string[] {
    return [...this.#asked];
  }

  capabilities(): Promise<RailCapabilities> {
    return this.#answer('capabilities');
  }
  startSourceLink(input: LinkContext): Promise<PartnerLinkSession> {
    return this.#answer('startSourceLink', input);
  }
  confirmSourceLink(input: LinkContext): Promise<LinkOutcome> {
    return this.#answer('confirmSourceLink', input);
  }
  getSourceState(ref: SourceRef): Promise<SourceLookup> {
    return this.#answer('getSourceState', ref);
  }
  registerBeneficiary(input: BeneficiaryRegistration): Promise<BeneficiaryOutcome> {
    return this.#answer('registerBeneficiary', input);
  }
  getBeneficiaryState(ref: BeneficiaryRef): Promise<BeneficiaryOutcome> {
    return this.#answer('getBeneficiaryState', ref);
  }
  submitApprovedIntent(intent: ApprovedPaymentIntent): Promise<SubmissionResult> {
    return this.#answer('submitApprovedIntent', intent);
  }
  getExecution(ref: PartnerExecutionRef): Promise<ExecutionLookup> {
    return this.#answer('getExecution', ref);
  }
  verifyEvent(body: Uint8Array, headers: EventHeaders): Promise<EventCheck> {
    return this.#answer('verifyEvent', body, headers);
  }

  #answer<T>(name: string, ...given: unknown[]): Promise<T> {
    this.#asked.push(name);
    return Promise.resolve({ name, given } as T);
  }
}

afterEach(() => {
  recordedStartWith(undefined);
});

describe('SEC-OPS-07 the live adapter refuses to move money unless this process started live (ADR-014 §4, PM3)', () => {
  it.each([
    ['no start recorded', undefined],
    ['a fake start', { mode: 'fake' } as const],
    ['a sandbox start', { mode: 'sandbox' } as const],
  ])('refuses a payment after %s, says so, and never asks the partner', async (_, partner) => {
    recordedStartWith(partner);
    const capture = new LogCapture();
    const rail = new LiveRail();

    await expect(liveOnly(rail, testLogger(capture)).submitApprovedIntent(INTENT)).rejects.toThrow(NotStartedLive);
    expect(rail.asked).toEqual([]);
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'partner.live_refused', partner: 'bank' }),
    ]);
  });

  it('hands the payment over once the live start is recorded, and asks again on every payment', async () => {
    const capture = new LogCapture();
    const rail = new LiveRail();
    const guarded = liveOnly(rail, testLogger(capture));

    recordedStartWith({ mode: 'live', gateRef: GATE_REF });
    await expect(guarded.submitApprovedIntent(INTENT)).resolves.toEqual({
      name: 'submitApprovedIntent',
      given: [INTENT],
    });

    recordedStartWith({ mode: 'fake' });
    await expect(guarded.submitApprovedIntent(INTENT)).rejects.toThrow(NotStartedLive);
    expect(rail.asked).toEqual(['submitApprovedIntent']);
    expect(capture.lines().map((line) => line.event)).toEqual(['partner.live_refused']);
  });

  it('hands every other part to a class adapter itself, whatever the start: only a payment moves money', async () => {
    const rail = new LiveRail();
    const guarded = liveOnly(rail, testLogger());
    // Stand-ins: the adapter only hands them back.
    const link = { linkId: 'l-1' } as never;
    const ref = { ref: 'r-1' } as never;
    const body = new Uint8Array([1]);
    const headers = { h: 'v' } as never;

    expect([guarded.identity, guarded.authoriseOrigin, guarded.formOrigin]).toEqual([
      rail.identity,
      rail.authoriseOrigin,
      rail.formOrigin,
    ]);
    const answers = await Promise.all([
      guarded.capabilities(),
      guarded.startSourceLink(link),
      guarded.confirmSourceLink(link),
      guarded.getSourceState(ref),
      guarded.registerBeneficiary(link),
      guarded.getBeneficiaryState(ref),
      guarded.getExecution(ref),
      guarded.verifyEvent(body, headers),
    ]);
    expect(answers).toEqual([
      { name: 'capabilities', given: [] },
      { name: 'startSourceLink', given: [link] },
      { name: 'confirmSourceLink', given: [link] },
      { name: 'getSourceState', given: [ref] },
      { name: 'registerBeneficiary', given: [link] },
      { name: 'getBeneficiaryState', given: [ref] },
      { name: 'getExecution', given: [ref] },
      { name: 'verifyEvent', given: [body, headers] },
    ]);
    await expect(guarded.submitApprovedIntent(INTENT)).rejects.toThrow(NotStartedLive);
    expect(rail.asked).not.toContain('submitApprovedIntent');
  });

  it('names what was refused, for the hand-off’s own error line', () => {
    const error = new NotStartedLive();
    expect(error.name).toBe('NotStartedLive');
    expect(error.message).toBe(
      "the live partner's adapter refused a payment: this process's start wasn't recorded live",
    );
  });
});
