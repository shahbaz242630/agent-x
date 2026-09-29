// The fake payment partner (ADR-004 §8: every adapter has a fake), shaped on
// the UAE Open Finance rail (rail map §2, §3): a link is a payment consent the
// business approves at its bank, with the bank's controls and an expiry; a
// renewal is a new consent linked to the old (`BaseConsentId`); a consent may
// be suspended and come back, or end revoked, expired or consumed. Its bank
// offers the sandbox's synthetic business accounts, and its answers pass the
// same account-number check a real adapter's must.
//
// `bank` plays everything that happens outside Agent X: the business at its
// bank, the partner changing a consent, the partner going down. Tests use it,
// and the Phase 1 demo on staging stands in for the partner with it.
import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { accountHint, withoutAccountNumbers } from '../domain/account-numbers.ts';
import {
  type ConsentControls,
  type FinancialRailAdapter,
  type FundingSourceState,
  type LinkContext,
  type LinkOutcome,
  type PartnerLinkSession,
  RailUnavailable,
  type SourceLookup,
  type SourceRef,
  type SourceSummary,
} from '../domain/rail.ts';
import { availabilityOf, type ConsentStatus, consentMayMove } from '../domain/uae-consent.ts';
import { type RailAccount, SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

/** The rail's idempotency key: at most 40 characters, no spaces (rail map §3, `x-idempotency-key`). */
const LINK_ID = /^[^\s]{1,40}$/;
const MINUTE_MS = 60_000;
const DAY_MS = 24 * 60 * MINUTE_MS;

/** The controls a business approves unless a test says otherwise: AED 50,000 a payment, AED 200,000 and 100 payments a month. */
export const USUAL_CONTROLS: ConsentControls = {
  currency: 'AED',
  period: 'month',
  maxPaymentMinor: 5_000_000n,
  maxPeriodMinor: 20_000_000n,
  maxPeriodPayments: 100,
};

export interface FakeRailOptions {
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly accounts?: readonly RailAccount[];
  /** How long a person has to approve a link at their bank. */
  readonly linkMinutes?: number;
  /** How long an approved consent lasts. */
  readonly consentDays?: number;
}

export interface ApproveOptions {
  readonly controls?: ConsentControls;
  /** The business's bank needs another authoriser (rail map §2 step 3): the consent waits for them. */
  readonly awaitingOtherAuthorisers?: boolean;
}

/** What happens outside Agent X, at the business's bank and the partner. */
export interface FakeBank {
  /** The business approves the link at its bank with one of its accounts; gives the consent's ID. */
  approve(sessionRef: string, accountId: string, options?: ApproveOptions): string;
  /** The business turns the link down at its bank. */
  reject(sessionRef: string): void;
  /** The partner or the bank moves a source's current consent, as the rail allows. */
  changeConsent(consentId: string, to: ConsentStatus): void;
  /** The business renews: a new consent, linked to the old one, for the same source; gives its ID. */
  renew(externalRef: string, controls?: ConsentControls): string;
  /** Every call to the partner fails, as if it didn't answer, until it comes back. */
  goDown(): void;
  comeBack(): void;
}

export interface FakeRail extends FinancialRailAdapter {
  readonly bank: FakeBank;
}

interface Session {
  readonly organizationId: string;
  readonly linkId: string;
  readonly sessionRef: string;
  readonly expiresAt: Date;
  outcome: 'open' | 'rejected' | { readonly externalRef: string };
}

interface Source {
  readonly organizationId: string;
  readonly externalRef: string;
  readonly account: RailAccount;
  consentId: string;
  replacesConsentId: string | null;
  status: ConsentStatus;
  statusChangedAt: Date;
  expiresAt: Date;
  controls: ConsentControls;
}

const ACCOUNT_TYPES = { Retail: 'retail', SME: 'sme', Corporate: 'corporate' } as const;

/** The account's IBAN: the sandbox's accounts all have one, and a summary hints at nothing else. */
function ibanOf(account: RailAccount): string {
  const iban = account.AccountIdentifiers.find((identifier) => identifier.SchemeName === 'IBAN');
  if (iban === undefined) throw new Error('The fake bank offers only accounts with an IBAN');
  return iban.Identification;
}

function summaryOf(account: RailAccount): SourceSummary {
  return {
    holderName: account.AccountHolderName,
    accountType: ACCOUNT_TYPES[account.AccountType],
    currency: account.Currency,
    hint: accountHint(ibanOf(account)),
  };
}

export function createFakeRail(options: FakeRailOptions): FakeRail {
  const { clock, ids, accounts = SANDBOX_ACCOUNTS, linkMinutes = 15, consentDays = 365 } = options;
  const sessions = new Map<string, Session>();
  const sources = new Map<string, Source>();
  let down = false;

  const sessionFor = ({ organizationId, linkId }: LinkContext): Session | undefined =>
    [...sessions.values()].find((each) => each.organizationId === organizationId && each.linkId === linkId);
  const openSession = (sessionRef: string): Session => {
    const session = sessions.get(sessionRef);
    if (session?.outcome !== 'open' || clock.now() >= session.expiresAt) {
      throw new Error('No link waiting at the bank under that session');
    }
    return session;
  };
  const sourceByConsent = (consentId: string): Source => {
    const source = [...sources.values()].find((each) => each.consentId === consentId);
    if (source === undefined) throw new Error('No source holds that consent now');
    return source;
  };

  /** A consent past its expiry is expired, when it was still pending or in use (the rail's lifecycle). */
  const brought = (source: Source): Source => {
    if (clock.now() >= source.expiresAt && consentMayMove(source.status, 'Expired')) {
      source.status = 'Expired';
      source.statusChangedAt = source.expiresAt;
    }
    return source;
  };

  const stateOf = (source: Source): FundingSourceState =>
    withoutAccountNumbers(
      {
        organizationId: source.organizationId,
        externalRef: source.externalRef,
        accountConsentId: source.consentId,
        replacesConsentId: source.replacesConsentId,
        availability: availabilityOf(source.status),
        consentStatus: source.status,
        statusChangedAt: new Date(source.statusChangedAt),
        consentExpiresAt: new Date(source.expiresAt),
        controls: { ...source.controls },
        summary: summaryOf(source.account),
      },
      source.account.AccountIdentifiers.map((identifier) => identifier.Identification),
    );

  const newConsent = (
    source: Omit<Source, 'consentId' | 'status' | 'statusChangedAt' | 'expiresAt'>,
    status: ConsentStatus,
  ) => {
    const now = clock.now();
    return {
      ...source,
      consentId: `fake-consent-${ids.next()}`,
      status,
      statusChangedAt: now,
      expiresAt: new Date(now.getTime() + consentDays * DAY_MS),
    };
  };

  const bank: FakeBank = {
    approve(sessionRef, accountId, { controls = USUAL_CONTROLS, awaitingOtherAuthorisers = false } = {}) {
      const session = openSession(sessionRef);
      const account = accounts.find((each) => each.AccountId === accountId);
      if (account === undefined) throw new Error('The bank has no such account');
      const externalRef = `fake-source-${ids.next()}`;
      const source = newConsent(
        {
          organizationId: session.organizationId,
          externalRef,
          account,
          replacesConsentId: null,
          controls: { ...controls },
        },
        awaitingOtherAuthorisers ? 'AwaitingAuthorization' : 'Authorized',
      );
      sources.set(externalRef, source);
      session.outcome = { externalRef };
      return source.consentId;
    },
    reject(sessionRef) {
      openSession(sessionRef).outcome = 'rejected';
    },
    changeConsent(consentId, to) {
      const source = brought(sourceByConsent(consentId));
      if (!consentMayMove(source.status, to))
        throw new Error(`The rail doesn't move a consent from ${source.status} to ${to}`);
      source.status = to;
      source.statusChangedAt = clock.now();
    },
    renew(externalRef, controls) {
      const old = sources.get(externalRef);
      if (old === undefined) throw new Error('No such source');
      const renewed = newConsent(
        {
          organizationId: old.organizationId,
          externalRef,
          account: old.account,
          replacesConsentId: old.consentId,
          controls: { ...(controls ?? old.controls) },
        },
        'Authorized',
      );
      sources.set(externalRef, renewed);
      return renewed.consentId;
    },
    goDown() {
      down = true;
    },
    comeBack() {
      down = false;
    },
  };

  /** Every call answers later, as a partner's would; while the partner is down it fails, whatever it asked. */
  const answer = <T>(work: () => T): Promise<T> =>
    Promise.resolve().then(() => {
      if (down) throw new RailUnavailable();
      return work();
    });

  const started = (input: LinkContext): Session => {
    const sessionRef = `fake-link-${ids.next()}`;
    const session: Session = {
      organizationId: input.organizationId,
      linkId: input.linkId,
      sessionRef,
      expiresAt: new Date(clock.now().getTime() + linkMinutes * MINUTE_MS),
      outcome: 'open',
    };
    sessions.set(sessionRef, session);
    return session;
  };

  const outcomeOf = (session: Session | undefined): LinkOutcome => {
    if (session === undefined) return { kind: 'refused', reason: 'unknown' };
    const { outcome } = session;
    if (outcome === 'rejected') return { kind: 'refused', reason: 'rejected' };
    if (outcome === 'open')
      return clock.now() >= session.expiresAt ? { kind: 'refused', reason: 'expired' } : { kind: 'waiting' };
    const source = sources.get(outcome.externalRef);
    if (source === undefined) throw new Error('A linked session names a source the partner lost');
    return { kind: 'linked', source: stateOf(brought(source)) };
  };

  return {
    bank,

    startSourceLink: (input: LinkContext): Promise<PartnerLinkSession> =>
      answer(() => {
        if (!LINK_ID.test(input.linkId)) throw new RangeError('A link ID is 1 to 40 characters, with no spaces');
        const session = sessionFor(input) ?? started(input);
        return {
          linkId: session.linkId,
          sessionRef: session.sessionRef,
          authoriseUrl: `https://bank.fake-partner.invalid/authorise/${session.sessionRef}`,
          expiresAt: new Date(session.expiresAt),
        };
      }),

    confirmSourceLink: (input: LinkContext): Promise<LinkOutcome> => answer(() => outcomeOf(sessionFor(input))),

    getSourceState: ({ organizationId, externalRef }: SourceRef): Promise<SourceLookup> =>
      answer(() => {
        const source = sources.get(externalRef);
        if (source?.organizationId !== organizationId) return { kind: 'not_found' };
        return { kind: 'found', source: stateOf(brought(source)) };
      }),
  };
}
