// PRD §6, §2.3, rail map §2 (D1-1): the fake partner's source links. The
// contract Agent X relies on (a link answered server to server, only to the
// organisation that started it; a source's state by its reference, only to
// its organisation; renewal; a partner that doesn't answer; no account number
// in any answer), and the UAE rail's consent lifecycle the fake mirrors.
import { FixedClock, findLeaks, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { AccountNumberLeak } from '../domain/account-numbers.ts';
import { type FundingSourceState, type LinkOutcome, RailUnavailable, type SourceLookup } from '../domain/rail.ts';
import { createFakeRail, type FakeRailOptions, USUAL_CONTROLS } from './fake-rail.ts';
import { type RailAccount, SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

const ORG = '00000000-0000-7000-8000-00000000aaaa';
const OTHER_ORG = '00000000-0000-7000-8000-00000000bbbb';
const LINK = '00000000-0000-7000-8000-00000000cccc';
const START = new Date('2026-10-01T08:00:00Z');
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));

function setUp(options: Partial<FakeRailOptions> = {}) {
  const clock = new FixedClock(START);
  const rail = createFakeRail({ clock, ids: new SequentialIds(), ...options });
  return { clock, rail, bank: rail.bank };
}

/** A link started and approved at the bank with `accountId`; the source as the partner confirms it. */
async function linked(accountId = ACCOUNT, organizationId = ORG, linkId = LINK) {
  const setup = setUp();
  const session = await setup.rail.startSourceLink({ organizationId, linkId });
  const consentId = setup.bank.approve(session.sessionRef, accountId);
  const outcome = await setup.rail.confirmSourceLink({ organizationId, linkId });
  return { ...setup, session, consentId, source: sourceOf(outcome) };
}

function sourceOf(outcome: LinkOutcome | SourceLookup): FundingSourceState {
  if (outcome.kind !== 'linked' && outcome.kind !== 'found') throw new Error(`No source: ${outcome.kind}`);
  return outcome.source;
}

const text = (value: unknown): string =>
  JSON.stringify(value, (_, each: unknown) => (typeof each === 'bigint' ? each.toString() : each));

describe('starting a link (D1-1)', () => {
  it('gives the partner’s session and where the person approves it, for 15 minutes', async () => {
    const { rail } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    expect(session).toEqual({
      linkId: LINK,
      sessionRef: 'fake-link-00000000-0000-7000-8000-000000000001',
      authoriseUrl: 'https://bank.fake-partner.invalid/authorise/fake-link-00000000-0000-7000-8000-000000000001',
      expiresAt: new Date(START.getTime() + 15 * MINUTE),
    });
  });

  it('answers the same link ID again with the same session: the ID is the partner’s idempotency key', async () => {
    const { rail } = setUp();
    const first = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    expect(await rail.startSourceLink({ organizationId: ORG, linkId: LINK })).toEqual(first);
    const theirs = await rail.startSourceLink({ organizationId: OTHER_ORG, linkId: LINK });
    expect(theirs.sessionRef).not.toBe(first.sessionRef);
  });

  it.each(['', 'a'.repeat(41), 'two words', 'tab\there'])(
    'refuses the link ID %j, as the rail refuses the key',
    async (linkId) => {
      const { rail } = setUp();
      await expect(rail.startSourceLink({ organizationId: ORG, linkId })).rejects.toThrow(RangeError);
    },
  );

  it('takes a link ID of 40 characters', async () => {
    const { rail } = setUp();
    await expect(rail.startSourceLink({ organizationId: ORG, linkId: 'a'.repeat(40) })).resolves.toBeDefined();
  });
});

describe('confirming a link, server to server (D1-1)', () => {
  it('waits while the business hasn’t finished at its bank', async () => {
    const { rail } = setUp();
    await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).toEqual({ kind: 'waiting' });
  });

  it('gives the source once the business approves, with the bank’s controls and a year’s consent', async () => {
    const { source, consentId } = await linked();
    expect(source).toEqual({
      organizationId: ORG,
      externalRef: 'fake-source-00000000-0000-7000-8000-000000000002',
      accountConsentId: consentId,
      replacesConsentId: null,
      availability: 'ACTIVE',
      consentStatus: 'Authorized',
      statusChangedAt: START,
      consentExpiresAt: new Date(START.getTime() + 365 * DAY),
      controls: USUAL_CONTROLS,
      summary: { holderName: 'Jasmine AI FZ-LLC', accountType: 'sme', currency: 'AED', hint: 'AE…6026' },
    });
    expect(consentId).toBe('fake-consent-00000000-0000-7000-8000-000000000003');
  });

  it('answers the same again when asked again', async () => {
    const { rail, source } = await linked();
    expect(sourceOf(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK }))).toEqual(source);
  });

  it('keeps the controls the business approved', async () => {
    const { rail, bank } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    const controls = { ...USUAL_CONTROLS, period: 'week' as const, maxPaymentMinor: 100_000n };
    bank.approve(session.sessionRef, ACCOUNT, { controls });
    expect(sourceOf(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).controls).toEqual(controls);
  });

  it('is linked but pending while the bank waits for another authoriser', async () => {
    const { rail, bank } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    const consentId = bank.approve(session.sessionRef, ACCOUNT, { awaitingOtherAuthorisers: true });
    const pending = sourceOf(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK }));
    expect(pending).toMatchObject({ availability: 'PENDING', consentStatus: 'AwaitingAuthorization' });
    bank.changeConsent(consentId, 'Authorized');
    const active = sourceOf(await rail.getSourceState({ organizationId: ORG, externalRef: pending.externalRef }));
    expect(active).toMatchObject({ availability: 'ACTIVE', consentStatus: 'Authorized' });
  });

  it('is refused when the business turns it down at its bank', async () => {
    const { rail, bank } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    bank.reject(session.sessionRef);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).toEqual({
      kind: 'refused',
      reason: 'rejected',
    });
    expect(() => bank.approve(session.sessionRef, ACCOUNT)).toThrow('No link waiting');
  });

  it('is refused once 15 minutes pass unapproved, and can’t be approved after', async () => {
    const { rail, bank, clock } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    clock.advanceBy(15 * MINUTE - 1);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).toEqual({ kind: 'waiting' });
    clock.advanceBy(1);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).toEqual({
      kind: 'refused',
      reason: 'expired',
    });
    expect(() => bank.approve(session.sessionRef, ACCOUNT)).toThrow('No link waiting');
  });

  it('answers another organisation’s link as it answers none (SEC-PTR-08)', async () => {
    const { rail } = await linked();
    const unknown = { kind: 'refused', reason: 'unknown' };
    expect(await rail.confirmSourceLink({ organizationId: OTHER_ORG, linkId: LINK })).toEqual(unknown);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: 'never-started' })).toEqual(unknown);
  });

  it('can’t approve with an account the bank doesn’t hold, or an unknown session', async () => {
    const { rail, bank } = setUp();
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    expect(() => bank.approve(session.sessionRef, 'someone-else-acct-01')).toThrow('no such account');
    expect(() => bank.approve('fake-link-unknown', ACCOUNT)).toThrow('No link waiting');
  });
});

describe('a source’s state (D1-1)', () => {
  it('is found only for the organisation that linked it; another’s answers as none does', async () => {
    const { rail, source } = await linked();
    expect(sourceOf(await rail.getSourceState({ organizationId: ORG, externalRef: source.externalRef }))).toEqual(
      source,
    );
    const notFound = { kind: 'not_found' };
    expect(await rail.getSourceState({ organizationId: OTHER_ORG, externalRef: source.externalRef })).toEqual(notFound);
    expect(await rail.getSourceState({ organizationId: ORG, externalRef: 'fake-source-unknown' })).toEqual(notFound);
  });

  it('pauses while suspended and comes back', async () => {
    const { rail, bank, clock, source, consentId } = await linked();
    const ref = { organizationId: ORG, externalRef: source.externalRef };
    clock.advanceBy(DAY);
    bank.changeConsent(consentId, 'Suspended');
    expect(sourceOf(await rail.getSourceState(ref))).toMatchObject({
      availability: 'SUSPENDED',
      consentStatus: 'Suspended',
      statusChangedAt: new Date(START.getTime() + DAY),
    });
    bank.changeConsent(consentId, 'Authorized');
    expect(sourceOf(await rail.getSourceState(ref)).availability).toBe('ACTIVE');
  });

  it.each(['Revoked', 'Consumed'] as const)('is unavailable for good once %s', async (status) => {
    const { rail, bank, source, consentId } = await linked();
    bank.changeConsent(consentId, status);
    const ref = { organizationId: ORG, externalRef: source.externalRef };
    expect(sourceOf(await rail.getSourceState(ref))).toMatchObject({
      availability: 'UNAVAILABLE',
      consentStatus: status,
    });
    expect(() => {
      bank.changeConsent(consentId, 'Authorized');
    }).toThrow(`from ${status} to Authorized`);
  });

  it('expires at the consent’s expiry, dated then, and stays expired', async () => {
    const { rail, bank, clock, source, consentId } = await linked();
    const ref = { organizationId: ORG, externalRef: source.externalRef };
    clock.advanceBy(365 * DAY - 1);
    expect(sourceOf(await rail.getSourceState(ref)).availability).toBe('ACTIVE');
    clock.advanceBy(1 + DAY);
    expect(sourceOf(await rail.getSourceState(ref))).toMatchObject({
      availability: 'UNAVAILABLE',
      consentStatus: 'Expired',
      statusChangedAt: source.consentExpiresAt,
    });
    expect(() => {
      bank.changeConsent(consentId, 'Suspended');
    }).toThrow('from Expired to Suspended');
  });

  it('keeps its reference through a renewal, with the new consent naming the one it replaced', async () => {
    const { rail, bank, clock, source, consentId } = await linked();
    const ref = { organizationId: ORG, externalRef: source.externalRef };
    clock.advanceBy(400 * DAY);
    const controls = { ...USUAL_CONTROLS, maxPeriodPayments: 10 };
    const renewedId = bank.renew(source.externalRef, controls);
    expect(sourceOf(await rail.getSourceState(ref))).toMatchObject({
      externalRef: source.externalRef,
      accountConsentId: renewedId,
      replacesConsentId: consentId,
      availability: 'ACTIVE',
      consentExpiresAt: new Date(START.getTime() + 765 * DAY),
      controls,
    });
    expect(renewedId).not.toBe(consentId);
    expect(() => {
      bank.changeConsent(consentId, 'Revoked');
    }).toThrow('No source holds that consent');
    expect(() => bank.renew('fake-source-unknown')).toThrow('No such source');
  });

  it('keeps the old controls through a renewal unless new ones are approved', async () => {
    const { rail, bank, source } = await linked();
    bank.renew(source.externalRef);
    const renewed = sourceOf(await rail.getSourceState({ organizationId: ORG, externalRef: source.externalRef }));
    expect(renewed.controls).toEqual(USUAL_CONTROLS);
  });

  it('hands out copies: changing an answer changes nothing at the partner', async () => {
    const { rail, source } = await linked();
    source.consentExpiresAt.setTime(0);
    source.statusChangedAt.setTime(0);
    const again = sourceOf(await rail.getSourceState({ organizationId: ORG, externalRef: source.externalRef }));
    expect(again.consentExpiresAt).toEqual(new Date(START.getTime() + 365 * DAY));
    expect(again.statusChangedAt).toEqual(START);
  });
});

describe('no account number in any answer (ADR-014 §3, PRD §6)', () => {
  it.each(SANDBOX_ACCOUNTS.map((account) => account.AccountId))(
    '%s: every answer hints at the IBAN, never holds it',
    async (accountId) => {
      const { rail, source } = await linked(accountId);
      const answers = [
        source,
        await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK }),
        await rail.getSourceState({ organizationId: ORG, externalRef: source.externalRef }),
      ];
      const written = text(answers);
      expect(findLeaks(written, IBANS)).toEqual([]);
      expect(source.summary.hint).toMatch(/^AE…\d{4}$/);
    },
  );

  it('refuses to answer when the partner’s account data would carry the number through', async () => {
    const [first] = SANDBOX_ACCOUNTS;
    if (first === undefined) throw new Error('No sandbox accounts');
    const [iban] = first.AccountIdentifiers;
    const careless: RailAccount = { ...first, AccountHolderName: `Jasmine AI FZ-LLC ${iban?.Identification ?? ''}` };
    const { rail, bank } = setUp({ accounts: [careless] });
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    bank.approve(session.sessionRef, careless.AccountId);
    await expect(rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).rejects.toThrow(AccountNumberLeak);
  });

  it('offers only accounts with an IBAN', async () => {
    const [first] = SANDBOX_ACCOUNTS;
    if (first === undefined) throw new Error('No sandbox accounts');
    const numbered: RailAccount = {
      ...first,
      AccountIdentifiers: [{ SchemeName: 'AccountNumber', Identification: '1234' }],
    };
    const { rail, bank } = setUp({ accounts: [numbered] });
    const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK });
    bank.approve(session.sessionRef, numbered.AccountId);
    await expect(rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).rejects.toThrow(
      'only accounts with an IBAN',
    );
  });

  it('shows a USD account as USD: whether it can pay in AED is Agent X’s check, not the partner’s', async () => {
    const { source } = await linked('sme-rak-trading-emirati-acct-02');
    expect(source.summary).toMatchObject({ currency: 'USD', accountType: 'sme' });
    const { source: corporate } = await linked('corporate-treasury-listed-acct-04');
    expect(corporate.summary.accountType).toBe('corporate');
  });
});

describe('a partner that doesn’t answer (D1-1)', () => {
  it('fails every call with RailUnavailable until it comes back, having changed nothing', async () => {
    const { rail, bank, source } = await linked();
    const ref = { organizationId: ORG, externalRef: source.externalRef };
    bank.goDown();
    await expect(rail.startSourceLink({ organizationId: ORG, linkId: 'another' })).rejects.toThrow(RailUnavailable);
    await expect(rail.confirmSourceLink({ organizationId: ORG, linkId: LINK })).rejects.toThrow(RailUnavailable);
    await expect(rail.getSourceState(ref)).rejects.toThrow(RailUnavailable);
    bank.comeBack();
    expect(sourceOf(await rail.getSourceState(ref))).toEqual(source);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: 'another' })).toEqual({
      kind: 'refused',
      reason: 'unknown',
    });
  });

  it('says nothing of what it was asked', () => {
    expect(new RailUnavailable().message).toBe('The payment partner did not answer');
  });
});
