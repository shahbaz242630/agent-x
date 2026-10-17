// Phase 3 E7c (the partner's S119 rule): a consent's lapse recorded once,
// naming the choice in force, read from the log; a log that can't be believed
// records nothing.
import type { AuditTransaction, SignedStates, VerifiedState } from '@agentx/core/modules/audit';
import type { SourceRecord } from '@agentx/core/modules/funding-sources';
import type { FundingSourceState } from '@agentx/core/modules/providers';
import { describe, expect, it } from 'vitest';

import { consentExpiryDetails } from './consent-expiry-choice.ts';
import { CONSENT_LAPSED, lapseAnswered, lapsedBy, lapseRecorded } from './consent-lapses.ts';

const TX = {} as AuditTransaction;
const FOUND = { source: { id: 'source' }, state: {} as VerifiedState };
const CONSENT = { id: 'consent-1', expiresAt: new Date('2026-10-16T10:00:00Z') };

type History = Awaited<ReturnType<SignedStates['historyOf']>>;

/** A history holding `details` as its newest event, or none. */
const history = (details?: Readonly<Record<string, unknown>>): History =>
  ({ outcome: 'read', events: details === undefined ? [] : [{ event: { details } }] }) as unknown as History;

/** Signed states whose lapses and choices are as given, recording into `recorded`. */
const statesWith = (lapses: History, choice: History = history()) => {
  const recorded: unknown[] = [];
  const states = {
    historyOf: (_tx: unknown, _org: string, find: { readonly actions: readonly string[] }) =>
      Promise.resolve(find.actions.includes(CONSENT_LAPSED) ? lapses : choice),
    record: (...args: unknown[]) => {
      recorded.push(args[5]);
      return Promise.resolve();
    },
  } as unknown as SignedStates;
  return { states, recorded };
};

describe('a consent’s lapse (E7c)', () => {
  it('records it as the API’s, naming the consent, its end and the choice in force', async () => {
    const { states, recorded } = statesWith(history(), history(consentExpiryDetails('pause')));

    expect(await lapseRecorded(TX, states, FOUND, 'org', CONSENT)).toBe(true);
    expect(recorded).toEqual([
      {
        actor: { type: 'system', id: 'api' },
        action: CONSENT_LAPSED,
        details: {
          consentId: 'consent-1',
          consentExpiresAt: '2026-10-16T10:00:00.000Z',
          pendingRequests: 'pause',
          chosen: true,
        },
      },
    ]);
  });

  it('names a cancel not chosen for a source with no choice (linked before E7)', async () => {
    const { states, recorded } = statesWith(history({ consentId: 'consent-0' }));

    expect(await lapseRecorded(TX, states, FOUND, 'org', CONSENT)).toBe(true);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ details: { pendingRequests: 'cancel', chosen: false } });
  });

  it('records nothing for a consent whose lapse is logged already', async () => {
    const { states, recorded } = statesWith(history({ consentId: 'consent-1' }));

    expect(await lapseRecorded(TX, states, FOUND, 'org', CONSENT)).toBe(false);
    expect(recorded).toEqual([]);
  });

  it('throws for a history that can’t be believed, recording nothing', async () => {
    const { states, recorded } = statesWith({ outcome: 'tampered', sign: 'log' } as unknown as History);

    await expect(lapseRecorded(TX, states, FOUND, 'org', CONSENT)).rejects.toThrow(/can't be believed/);
    expect(recorded).toEqual([]);
  });

  it('is due only for a source not ended whose consent has run out', () => {
    const now = new Date('2026-10-16T12:00:00Z');
    const source = (status: SourceRecord['status'], consentExpiresAt: Date) =>
      ({ status, accountConsentId: 'consent-1', consentExpiresAt }) as SourceRecord;

    expect(lapsedBy(source('ACTIVE', CONSENT.expiresAt), now)).toEqual(CONSENT);
    expect(lapsedBy(source('SUSPENDED', now), now)).toEqual({ id: 'consent-1', expiresAt: now });
    expect(lapsedBy(source('ENDED', CONSENT.expiresAt), now)).toBeUndefined();
    expect(lapsedBy(source('ACTIVE', new Date(now.getTime() + 1)), now)).toBeUndefined();
  });

  it('a refresh meets the consent a newer answer says ran out, none for one ended early, else the one held', () => {
    const now = new Date('2026-10-16T12:00:00Z');
    const before = new Date('2026-10-16T09:00:00Z');
    const held = {
      status: 'ACTIVE',
      accountConsentId: 'consent-1',
      consentExpiresAt: CONSENT.expiresAt,
      partnerChangedAt: before,
    } as SourceRecord;
    const answer = (change: Partial<FundingSourceState>) =>
      ({
        availability: 'UNAVAILABLE',
        accountConsentId: 'consent-1',
        consentExpiresAt: CONSENT.expiresAt,
        statusChangedAt: CONSENT.expiresAt,
        ...change,
      }) as FundingSourceState;
    const early = new Date('2026-10-16T09:30:00Z');

    // Ran out, by the answer's own times: the answer's consent.
    expect(lapseAnswered(held, answer({ accountConsentId: 'consent-2' }), now)).toMatchObject({ id: 'consent-2' });
    // Revoked before its end: no lapse, though its end has passed by now.
    expect(lapseAnswered(held, answer({ statusChangedAt: early }), now)).toBeUndefined();
    // Another consent's early end, a stale answer, one still available, or none: the one held, past its end.
    expect(lapseAnswered(held, answer({ statusChangedAt: early, accountConsentId: 'consent-2' }), now)).toEqual(
      CONSENT,
    );
    expect(lapseAnswered(held, answer({ statusChangedAt: new Date('2026-10-16T08:00:00Z') }), now)).toEqual(CONSENT);
    expect(lapseAnswered(held, answer({ availability: 'ACTIVE' }), now)).toEqual(CONSENT);
    expect(lapseAnswered(held, undefined, now)).toEqual(CONSENT);
  });
});
