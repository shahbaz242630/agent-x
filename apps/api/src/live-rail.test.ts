import type { ApprovedPaymentIntent, FinancialRailAdapter, SubmissionResult } from '@agentx/core/modules/providers';
import { recordedStartWith } from '@agentx/platform/config';
import { LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { liveOnly, NotStartedLive } from './live-rail.ts';

const GATE_REF = `LMG-v1-sha256:${'ab'.repeat(32)}`;
/** What the partner answers a payment it took: these tests only see whether it was asked. */
const ACCEPTED = { kind: 'accepted' } as unknown as SubmissionResult;
const INTENT = { instructionId: 'i-1' } as unknown as ApprovedPaymentIntent;

/** A live adapter stand-in: its identity, a payment it takes, and a read that moves no money. */
function liveRail() {
  const submitApprovedIntent = vi.fn((_intent: ApprovedPaymentIntent) => Promise.resolve(ACCEPTED));
  const getExecution = vi.fn(() => Promise.resolve({ kind: 'not_found' }));
  const rail = {
    identity: { partner: 'bank', legalEntityId: 'le-1', licenceRef: 'lic-1' },
    authoriseOrigin: 'https://pay.bank.example',
    submitApprovedIntent,
    getExecution,
  } as unknown as FinancialRailAdapter;
  return { rail, submitApprovedIntent, getExecution };
}

afterEach(() => {
  recordedStartWith({ mode: 'fake' });
});

describe('SEC-OPS-07 the live adapter refuses to move money unless this process started live (ADR-014 §4, PM3)', () => {
  it.each([
    ['no start recorded yet', undefined],
    ['a fake start', { mode: 'fake' } as const],
    ['a sandbox start', { mode: 'sandbox' } as const],
  ])('refuses a payment after %s, says so, and never asks the partner', async (_, partner) => {
    if (partner !== undefined) recordedStartWith(partner);
    const capture = new LogCapture();
    const { rail, submitApprovedIntent } = liveRail();

    await expect(liveOnly(rail, testLogger(capture)).submitApprovedIntent(INTENT)).rejects.toThrow(NotStartedLive);
    expect(submitApprovedIntent).not.toHaveBeenCalled();
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'partner.live_refused', partner: 'bank' }),
    ]);
  });

  it('hands the payment over once the live start is recorded, and asks again on every payment', async () => {
    const capture = new LogCapture();
    const { rail, submitApprovedIntent } = liveRail();
    const guarded = liveOnly(rail, testLogger(capture));

    recordedStartWith({ mode: 'live', gateRef: GATE_REF });
    await expect(guarded.submitApprovedIntent(INTENT)).resolves.toBe(ACCEPTED);
    expect(submitApprovedIntent).toHaveBeenCalledWith(INTENT);

    recordedStartWith({ mode: 'fake' });
    await expect(guarded.submitApprovedIntent(INTENT)).rejects.toThrow(NotStartedLive);
    expect(submitApprovedIntent).toHaveBeenCalledTimes(1);
    expect(capture.lines().map((line) => line.event)).toEqual(['partner.live_refused']);
  });

  it('keeps the rest of the adapter as it is: only a payment moves money', async () => {
    recordedStartWith({ mode: 'fake' });
    const { rail, getExecution } = liveRail();
    const guarded = liveOnly(rail, testLogger());

    expect(guarded.identity).toBe(rail.identity);
    expect(guarded.authoriseOrigin).toBe(rail.authoriseOrigin);
    await guarded.getExecution({ instructionId: 'i-1' } as never);
    expect(getExecution).toHaveBeenCalledTimes(1);
  });

  it('names what was refused, for the hand-off’s own error line', () => {
    const error = new NotStartedLive();
    expect(error.name).toBe('NotStartedLive');
    expect(error.message).toBe(
      "the live partner's adapter refused a payment: this process's start wasn't recorded live",
    );
  });
});
