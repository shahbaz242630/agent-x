// The fake payment partner (ADR-004 §8: every adapter has a fake), shaped on
// the UAE Open Finance rail (rail map §2, §3): a link is a payment consent the
// business approves at its bank, with the bank's controls and an expiry; a
// renewal is a new consent linked to the old (`BaseConsentId`); a consent may
// be suspended and come back, or end revoked, expired or consumed. Its bank
// offers the sandbox's synthetic business accounts, and its answers pass the
// same account-number check a real adapter's must. Its payees are in
// fake-payees.ts.
//
// `bank` plays everything that happens outside Agent X: the business at its
// bank, a person at the partner's payee form, the partner changing a consent,
// the partner going down or its answer being lost. Tests use it, and the
// Phase 1 demo on staging stands in for the partner with it.
//
// It keeps its records where `records` says (D2-1): in memory for the unit
// tests, in the database on staging, so a link or payee outlives a restart
// and the API and the bank's steps see the same partner. Everything the
// partner holds is one organisation's, so every call and every bank step
// names the organisation it acts for. The partner going down or losing an
// answer (`goDown`, `loseNextAnswer`) is not a record: it holds only for the
// fake it is set on, in that process, as the unit tests use it.
import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { accountHint, withoutAccountNumbers } from '../domain/account-numbers.ts';
import {
  BENEFICIARY_ROUTES,
  type BeneficiaryRoute,
  type ConsentControls,
  type FinancialRailAdapter,
  type FundingSourceState,
  type LinkContext,
  type LinkOutcome,
  type PartnerLinkSession,
  type PayeeDetails,
  RailUnavailable,
  type SourceLookup,
  type SourceSummary,
} from '../domain/rail.ts';
import { availabilityOf, type ConsentStatus, consentMayMove } from '../domain/uae-consent.ts';
import { createFakePayees } from './fake-payees.ts';
import {
  createMemoryRecords,
  type FakePartnerStore,
  type FakeRecord,
  type FakeRecords,
  type SourceBody,
} from './fake-records.ts';
import { type RailAccount, SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

/** The rail's idempotency key, which our link and registration IDs are: at most 40 characters, no spaces (rail map §3, `x-idempotency-key`). */
const PARTNER_KEY = /^[^\s]{1,40}$/;
const MINUTE_MS = 60_000;
const DAY_MS = 24 * 60 * MINUTE_MS;
const AUTHORISE_BASE = 'https://bank.fake-partner.invalid/authorise/';

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
  /** Where the partner keeps its records: in memory unless given (the database's on staging). */
  readonly records?: FakePartnerStore;
  readonly accounts?: readonly RailAccount[];
  /** How long a person has to approve a link at their bank. */
  readonly linkMinutes?: number;
  /** How long an approved consent lasts. */
  readonly consentDays?: number;
  /** How a supplier's details may reach this partner: both, unless a test mirrors a partner with one. */
  readonly beneficiaryRoutes?: readonly BeneficiaryRoute[];
  /** Whether this partner gives the same payee identity for the same account (BEN-2). */
  readonly stablePayeeIdentity?: boolean;
  /** How long a person has to fill in the hosted payee form. */
  readonly formMinutes?: number;
}

export interface ApproveOptions {
  readonly controls?: ConsentControls;
  /** The business's bank needs another authoriser (rail map §2 step 3): the consent waits for them. */
  readonly awaitingOtherAuthorisers?: boolean;
}

/** What happens outside Agent X, at the business's bank and the partner, each for the organisation named. */
export interface FakeBank {
  /** The business approves the link at its bank with one of its accounts; gives the consent's ID. */
  approve(organizationId: string, sessionRef: string, accountId: string, options?: ApproveOptions): Promise<string>;
  /** The business turns the link down at its bank. */
  reject(organizationId: string, sessionRef: string): Promise<void>;
  /** The partner or the bank moves a source's current consent, as the rail allows. */
  changeConsent(organizationId: string, consentId: string, to: ConsentStatus): Promise<void>;
  /** The business renews: a new consent, linked to the old one, for the same source; gives its ID. */
  renew(organizationId: string, externalRef: string, controls?: ConsentControls): Promise<string>;
  /** A person fills in the partner's hosted payee form, opened at `formUrl`; the form refuses details it can't take. */
  fillForm(organizationId: string, formUrl: string, payee: PayeeDetails): Promise<void>;
  /** Every call to this fake fails, as if the partner didn't answer, until it comes back: this process's fake alone. */
  goDown(): void;
  comeBack(): void;
  /** The next call to this fake is done at the partner, but its answer is lost: the caller sees RailUnavailable. */
  loseNextAnswer(): void;
}

export interface FakeRail extends FinancialRailAdapter {
  readonly bank: FakeBank;
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

const controlsOf = ({ maxPaymentMinor, maxPeriodMinor, ...rest }: SourceBody['controls']): ConsentControls => ({
  ...rest,
  maxPaymentMinor: BigInt(maxPaymentMinor),
  maxPeriodMinor: BigInt(maxPeriodMinor),
});

const controlsBody = ({ maxPaymentMinor, maxPeriodMinor, ...rest }: ConsentControls): SourceBody['controls'] => ({
  ...rest,
  maxPaymentMinor: maxPaymentMinor.toString(),
  maxPeriodMinor: maxPeriodMinor.toString(),
});

export function createFakeRail(options: FakeRailOptions): FakeRail {
  const {
    clock,
    ids,
    records = createMemoryRecords(),
    accounts = SANDBOX_ACCOUNTS,
    linkMinutes = 15,
    consentDays = 365,
    beneficiaryRoutes = BENEFICIARY_ROUTES,
    stablePayeeIdentity = true,
    formMinutes = 30,
  } = options;
  const payees = createFakePayees({
    clock,
    ids,
    accounts,
    routes: beneficiaryRoutes,
    stablePayeeIdentity,
    formMinutes,
  });
  let down = false;
  let loseAnswer = false;

  const accountOf = (accountId: string): RailAccount => {
    const account = accounts.find((each) => each.AccountId === accountId);
    if (account === undefined) throw new Error('The bank has no such account');
    return account;
  };

  const openSession = async (held: FakeRecords, sessionRef: string): Promise<FakeRecord<'link'>> => {
    const session = await held.byAlias('link', sessionRef);
    if (session?.body.outcome !== 'open' || clock.now() >= new Date(session.body.expiresAt)) {
      throw new Error('No link waiting at the bank under that session');
    }
    return session;
  };

  /** A consent past its expiry is expired, when it was still pending or in use (the rail's lifecycle). */
  const brought = (body: SourceBody): SourceBody =>
    clock.now() >= new Date(body.expiresAt) && consentMayMove(body.status, 'Expired')
      ? { ...body, status: 'Expired', statusChangedAt: body.expiresAt }
      : body;

  const stateOf = (organizationId: string, source: FakeRecord<'source'>): FundingSourceState => {
    const body = brought(source.body);
    const account = accountOf(body.accountId);
    return withoutAccountNumbers(
      {
        organizationId,
        externalRef: source.ref,
        accountConsentId: source.alias,
        replacesConsentId: body.replacesConsentId,
        availability: availabilityOf(body.status),
        consentStatus: body.status,
        statusChangedAt: new Date(body.statusChangedAt),
        consentExpiresAt: new Date(body.expiresAt),
        controls: controlsOf(body.controls),
        summary: summaryOf(account),
      },
      account.AccountIdentifiers.map((identifier) => identifier.Identification),
    );
  };

  /** A new consent for a source, from now: its ID and its body. */
  const newConsent = (
    accountId: string,
    replacesConsentId: string | null,
    controls: ConsentControls,
    status: ConsentStatus,
  ): { consentId: string; body: SourceBody } => {
    const now = clock.now();
    return {
      consentId: `fake-consent-${ids.next()}`,
      body: {
        accountId,
        replacesConsentId,
        status,
        statusChangedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + consentDays * DAY_MS).toISOString(),
        controls: controlsBody(controls),
      },
    };
  };

  const bank: FakeBank = {
    approve: (organizationId, sessionRef, accountId, approval = {}) =>
      records.within(organizationId, async (held) => {
        const { controls = USUAL_CONTROLS, awaitingOtherAuthorisers = false } = approval;
        const session = await openSession(held, sessionRef);
        accountOf(accountId);
        const externalRef = `fake-source-${ids.next()}`;
        const { consentId, body } = newConsent(
          accountId,
          null,
          controls,
          awaitingOtherAuthorisers ? 'AwaitingAuthorization' : 'Authorized',
        );
        await held.add('source', { ref: externalRef, alias: consentId, body });
        await held.update('link', { ...session, body: { ...session.body, outcome: { externalRef } } });
        return consentId;
      }),
    reject: (organizationId, sessionRef) =>
      records.within(organizationId, async (held) => {
        const session = await openSession(held, sessionRef);
        await held.update('link', { ...session, body: { ...session.body, outcome: 'rejected' } });
      }),
    changeConsent: (organizationId, consentId, to) =>
      records.within(organizationId, async (held) => {
        const source = await held.byAlias('source', consentId);
        if (source === undefined) throw new Error('No source holds that consent now');
        const body = brought(source.body);
        if (!consentMayMove(body.status, to))
          throw new Error(`The rail doesn't move a consent from ${body.status} to ${to}`);
        await held.update('source', {
          ...source,
          body: { ...body, status: to, statusChangedAt: clock.now().toISOString() },
        });
      }),
    renew: (organizationId, externalRef, controls) =>
      records.within(organizationId, async (held) => {
        const old = await held.get('source', externalRef);
        if (old === undefined) throw new Error('No such source');
        const renewed = newConsent(
          old.body.accountId,
          old.alias,
          controls ?? controlsOf(old.body.controls),
          'Authorized',
        );
        await held.update('source', { ref: externalRef, alias: renewed.consentId, body: renewed.body });
        return renewed.consentId;
      }),
    fillForm: (organizationId, formUrl, payee) =>
      records.within(organizationId, (held) => payees.fillForm(held, formUrl, payee)),
    goDown() {
      down = true;
    },
    comeBack() {
      down = false;
    },
    loseNextAnswer() {
      loseAnswer = true;
    },
  };

  /**
   * Every call answers later, as a partner's would. While the partner is down
   * it fails, having done nothing; a lost answer fails after the work is done.
   */
  const answer = async <T>(work: () => Promise<T>): Promise<T> => {
    await Promise.resolve();
    if (down) throw new RailUnavailable();
    const answered = await work();
    if (loseAnswer) {
      loseAnswer = false;
      throw new RailUnavailable();
    }
    return answered;
  };

  const partnerKey = (id: string): void => {
    if (!PARTNER_KEY.test(id)) throw new RangeError('A link or registration ID is 1 to 40 characters, with no spaces');
  };

  const sessionOf = (session: FakeRecord<'link'>): PartnerLinkSession => ({
    linkId: session.ref,
    sessionRef: session.alias,
    authoriseUrl: `${AUTHORISE_BASE}${session.alias}`,
    expiresAt: new Date(session.body.expiresAt),
  });

  const outcomeOf = async (held: FakeRecords, session: FakeRecord<'link'> | undefined): Promise<LinkOutcome> => {
    if (session === undefined) return { kind: 'refused', reason: 'unknown' };
    const { outcome, expiresAt } = session.body;
    if (outcome === 'rejected') return { kind: 'refused', reason: 'rejected' };
    if (outcome === 'open')
      return clock.now() >= new Date(expiresAt) ? { kind: 'refused', reason: 'expired' } : { kind: 'waiting' };
    const source = await held.get('source', outcome.externalRef);
    if (source === undefined) throw new Error('A linked session names a source the partner lost');
    return { kind: 'linked', source: stateOf(held.organizationId, source) };
  };

  return {
    bank,

    capabilities: () =>
      answer(() => Promise.resolve({ beneficiaryRoutes: [...beneficiaryRoutes], stablePayeeIdentity })),

    startSourceLink: ({ organizationId, linkId }: LinkContext): Promise<PartnerLinkSession> =>
      answer(() => {
        partnerKey(linkId);
        return records.within(organizationId, async (held) => {
          const known = await held.get('link', linkId);
          if (known !== undefined) return sessionOf(known);
          const session: FakeRecord<'link'> = {
            ref: linkId,
            alias: `fake-link-${ids.next()}`,
            body: {
              expiresAt: new Date(clock.now().getTime() + linkMinutes * MINUTE_MS).toISOString(),
              outcome: 'open',
            },
          };
          // Adds nothing when another call with the same ID started it at
          // once: its session, read back, is the session.
          await held.add('link', session);
          return sessionOf((await held.get('link', linkId)) ?? session);
        });
      }),

    confirmSourceLink: ({ organizationId, linkId }: LinkContext): Promise<LinkOutcome> =>
      answer(() => records.within(organizationId, async (held) => outcomeOf(held, await held.get('link', linkId)))),

    getSourceState: ({ organizationId, externalRef }): Promise<SourceLookup> =>
      answer(() =>
        records.within(organizationId, async (held): Promise<SourceLookup> => {
          const source = await held.get('source', externalRef);
          return source === undefined
            ? { kind: 'not_found' }
            : { kind: 'found', source: stateOf(organizationId, source) };
        }),
      ),

    registerBeneficiary: (input) =>
      answer(() => {
        partnerKey(input.registrationId);
        return records.within(input.organizationId, (held) => payees.register(held, input));
      }),

    getBeneficiaryState: (ref) => answer(() => records.within(ref.organizationId, (held) => payees.stateOf(held, ref))),
  };
}
