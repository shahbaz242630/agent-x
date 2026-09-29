// The fake partner's payees (ADR-014 §3; rail map §1.1, §3): the rail has no
// payee register, so a partner keeps its own and issues opaque references.
// This one registers a supplier by either route, checks the name against the
// account's holder at the fake bank (Confirmation of Payee: a match, partly,
// none, or the bank can't say), masks both, and gives the same payee
// identity for the same account within an organisation, or none, as the
// partner being mirrored would (BEN-2).
import { type Clock, type IdGenerator, visibleName } from '../../../shared-kernel/index.ts';
import { accountHint, isUaeIban, withoutAccountNumbers } from '../domain/account-numbers.ts';
import type {
  BeneficiaryOutcome,
  BeneficiaryRef,
  BeneficiaryRegistration,
  BeneficiaryRoute,
  BeneficiaryState,
  PayeeDetails,
  PayeeNameCheck,
} from '../domain/rail.ts';
import type { RailAccount } from './sandbox-accounts.ts';

const MINUTE_MS = 60_000;
/** The longest payee name the fake takes: the rail's creditor name. */
const MAX_NAME = 140;
const FORM_BASE = 'https://payees.fake-partner.invalid/form/';

export interface FakePayeesOptions {
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly accounts: readonly RailAccount[];
  readonly routes: readonly BeneficiaryRoute[];
  readonly stablePayeeIdentity: boolean;
  readonly formMinutes: number;
}

interface Registration {
  readonly organizationId: string;
  readonly registrationId: string;
  /** Set until a hosted form is filled in; null for a pass-through. */
  readonly form: { readonly formRef: string; readonly expiresAt: Date } | null;
  outcome: 'waiting' | 'invalid_details' | { readonly beneficiary: BeneficiaryState; readonly iban: string };
}

/** The payees' part of the fake partner: the adapter's two calls, and the person filling in the hosted form. */
export interface FakePayees {
  register(input: BeneficiaryRegistration): BeneficiaryOutcome;
  stateOf(ref: BeneficiaryRef): BeneficiaryOutcome;
  fillForm(formUrl: string, payee: PayeeDetails): void;
}

const compact = (text: string): string => text.replaceAll(' ', '').toUpperCase();

/** A name as a bank compares it: composed, in capitals, letters and digits in words. */
const comparable = (name: string): string =>
  name
    .normalize('NFKC')
    .toUpperCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();

const CHARACTERS = new Intl.Segmenter('en', { granularity: 'grapheme' });

/** The holder's name as a bank shows it masked: each word's first character, then a star for each of the rest. */
const masked = (name: string): string =>
  name
    .split(' ')
    .map((word) => Array.from(CHARACTERS.segment(word), ({ segment }, index) => (index === 0 ? segment : '*')).join(''))
    .join(' ');

export function createFakePayees(options: FakePayeesOptions): FakePayees {
  const { clock, ids, accounts, routes, stablePayeeIdentity, formMinutes } = options;
  const registrations = new Map<string, Registration>();
  const identities = new Map<string, string>();

  const key = (organizationId: string, registrationId: string): string => `${organizationId} ${registrationId}`;

  /** The holder of an account at the fake bank, if it holds one with this IBAN. */
  const holderOf = (iban: string): string | undefined =>
    accounts.find((account) =>
      account.AccountIdentifiers.some((identifier) => compact(identifier.Identification) === compact(iban)),
    )?.AccountHolderName;

  const nameCheck = (name: string, holder: string | undefined): PayeeNameCheck => {
    if (holder === undefined) return 'unavailable';
    const [typed, held] = [comparable(name), comparable(holder)];
    if (typed === held) return 'match';
    return typed.split(' ')[0] === held.split(' ')[0] ? 'partial' : 'no_match';
  };

  /** The partner's identity for the account within the organisation: the same for the same account, another organisation's never. */
  const identityOf = (organizationId: string, iban: string): string | null => {
    if (!stablePayeeIdentity) return null;
    const account = `${organizationId} ${compact(iban)}`;
    const known = identities.get(account) ?? `fake-payee-${ids.next()}`;
    identities.set(account, known);
    return known;
  };

  /** The payee registered, or `invalid_details` for an account the rail can't pay or a name no one could read. */
  const registered = (registration: Registration, payee: PayeeDetails): Registration['outcome'] => {
    if (!isUaeIban(payee.iban) || visibleName(payee.name, MAX_NAME).problems.length > 0) return 'invalid_details';
    const holder = holderOf(payee.iban);
    const beneficiary: BeneficiaryState = {
      organizationId: registration.organizationId,
      registrationId: registration.registrationId,
      beneficiaryRef: `fake-beneficiary-${ids.next()}`,
      payeeIdentity: identityOf(registration.organizationId, payee.iban),
      nameCheck: nameCheck(payee.name, holder),
      maskedName: holder === undefined ? null : masked(holder),
      hint: accountHint(payee.iban),
      registeredAt: clock.now(),
    };
    return { beneficiary, iban: payee.iban };
  };

  const outcomeOf = (registration: Registration | undefined): BeneficiaryOutcome => {
    if (registration === undefined) return { kind: 'refused', reason: 'unknown' };
    const { outcome, form } = registration;
    if (outcome === 'invalid_details') return { kind: 'refused', reason: 'invalid_details' };
    if (outcome !== 'waiting') {
      const { beneficiary, iban } = outcome;
      return withoutAccountNumbers(
        { kind: 'registered', beneficiary: { ...beneficiary, registeredAt: new Date(beneficiary.registeredAt) } },
        [iban],
      );
    }
    if (form === null) throw new Error('A pass-through registration is never left waiting');
    if (clock.now() >= form.expiresAt) return { kind: 'refused', reason: 'expired' };
    return { kind: 'waiting', formUrl: `${FORM_BASE}${form.formRef}`, expiresAt: new Date(form.expiresAt) };
  };

  return {
    register(input) {
      if (!routes.includes(input.route)) throw new RangeError(`This partner has no ${input.route} route`);
      const known = registrations.get(key(input.organizationId, input.registrationId));
      if (known !== undefined) return outcomeOf(known);
      const registration: Registration = {
        organizationId: input.organizationId,
        registrationId: input.registrationId,
        form:
          input.route === 'hosted'
            ? {
                formRef: `fake-form-${ids.next()}`,
                expiresAt: new Date(clock.now().getTime() + formMinutes * MINUTE_MS),
              }
            : null,
        outcome: 'waiting',
      };
      if (input.route === 'pass_through') registration.outcome = registered(registration, input.payee);
      registrations.set(key(input.organizationId, input.registrationId), registration);
      return outcomeOf(registration);
    },

    stateOf: ({ organizationId, registrationId }) => outcomeOf(registrations.get(key(organizationId, registrationId))),

    fillForm(formUrl, payee) {
      const registration = [...registrations.values()].find(
        ({ form }) => form !== null && `${FORM_BASE}${form.formRef}` === formUrl,
      );
      if (registration?.outcome !== 'waiting' || registration.form === null) throw new Error('No form open there');
      if (clock.now() >= registration.form.expiresAt) throw new Error('No form open there');
      const outcome = registered(registration, payee);
      if (outcome === 'invalid_details') throw new Error('The form refuses those details: fix them and send again');
      registration.outcome = outcome;
    },
  };
}
