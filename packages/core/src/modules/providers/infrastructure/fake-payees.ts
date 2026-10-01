// The fake partner's payees (ADR-014 §3; rail map §1.1, §3): the rail has no
// payee register, so a partner keeps its own and issues opaque references.
// This one registers a supplier by either route, checks the name against the
// account's holder at the fake bank (Confirmation of Payee: a match, partly,
// none, or the bank can't say), masks both, and gives the same payee
// identity for the same account within an organisation, or none, as the
// partner being mirrored would (BEN-2). Its records hold the masked parts
// alone (D2-1): the identity is derived from the account each time, so the
// account is never kept to find it again.
import { createHash } from 'node:crypto';

import { type Clock, type IdGenerator, visibleName } from '../../../shared-kernel/index.ts';
import { accountHint, isUaeIban, withoutAccountNumbers } from '../domain/account-numbers.ts';
import type {
  BeneficiaryOutcome,
  BeneficiaryRef,
  BeneficiaryRegistration,
  BeneficiaryRoute,
  PayeeDetails,
  PayeeNameCheck,
} from '../domain/rail.ts';
import type { BeneficiaryBody, FakeRecord, FakeRecords, RegistrationBody } from './fake-records.ts';
import type { RailAccount } from './sandbox-accounts.ts';

const MINUTE_MS = 60_000;
/** The longest payee name the fake takes: the rail's creditor name. */
const MAX_NAME = 140;
/** The fake partner's payee form: its own origin, which every `formUrl` it gives is on. */
export const FORM_ORIGIN = 'https://payees.fake-partner.invalid';
const FORM_BASE = `${FORM_ORIGIN}/form/`;

/** Why the fake bank or the partner's form refused a step asked of it: nothing was changed. */
export type FakeBankRefusal = 'no_link_waiting' | 'no_such_account' | 'no_form_open' | 'details_refused';

/** A step the fake bank or the partner's form refused, as the staging demo's routes answer it (D2-3c, E2-2a). */
export class FakeBankRefused extends Error {
  readonly reason: FakeBankRefusal;

  constructor(reason: FakeBankRefusal, message: string) {
    super(message);
    this.name = 'FakeBankRefused';
    this.reason = reason;
  }
}

export interface FakePayeesOptions {
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly accounts: readonly RailAccount[];
  readonly routes: readonly BeneficiaryRoute[];
  readonly stablePayeeIdentity: boolean;
  readonly formMinutes: number;
}

/** The payees' part of the fake partner, each on one organisation's records: the adapter's two calls, and the person filling in the hosted form. */
export interface FakePayees {
  register(records: FakeRecords, input: BeneficiaryRegistration): Promise<BeneficiaryOutcome>;
  stateOf(records: FakeRecords, ref: BeneficiaryRef): Promise<BeneficiaryOutcome>;
  fillForm(records: FakeRecords, formUrl: string, payee: PayeeDetails): Promise<void>;
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

  /**
   * The partner's identity for the account within the organisation: the same
   * for the same account, another organisation's never. Its digest is written
   * in letters alone (a to p for each hex digit): in hex, one in about a
   * hundred read as an IBAN with valid check digits, and the answer was
   * refused as an account number (E2-2b).
   */
  const identityOf = (organizationId: string, iban: string): string | null => {
    if (!stablePayeeIdentity) return null;
    const digest = createHash('sha256')
      .update(`fake-payee ${organizationId} ${compact(iban)}`)
      .digest('hex');
    const letters = digest
      .slice(0, 32)
      .replaceAll(/[\da-f]/g, (digit) => String.fromCodePoint(0x61 + Number.parseInt(digit, 16)));
    return `fake-payee-${letters}`;
  };

  /** The payee registered, or `invalid_details` for an account the rail can't pay or a name no one could read. */
  const registered = (organizationId: string, payee: PayeeDetails): RegistrationBody['outcome'] => {
    if (!isUaeIban(payee.iban) || visibleName(payee.name, MAX_NAME).problems.length > 0) return 'invalid_details';
    const holder = holderOf(payee.iban);
    const beneficiary: BeneficiaryBody = {
      beneficiaryRef: `fake-beneficiary-${ids.next()}`,
      payeeIdentity: identityOf(organizationId, payee.iban),
      nameCheck: nameCheck(payee.name, holder),
      maskedName: holder === undefined ? null : masked(holder),
      hint: accountHint(payee.iban),
      registeredAt: clock.now().toISOString(),
    };
    return { beneficiary };
  };

  const outcomeOf = (
    organizationId: string,
    registration: FakeRecord<'registration'> | undefined,
  ): BeneficiaryOutcome => {
    if (registration === undefined) return { kind: 'refused', reason: 'unknown' };
    const { outcome, form } = registration.body;
    if (outcome === 'invalid_details') return { kind: 'refused', reason: 'invalid_details' };
    if (outcome !== 'waiting') {
      // Built from masked parts alone (the hint, the masked holder), so the
      // IBAN check is the last line here: no part of the number is named.
      const { beneficiary } = outcome;
      return withoutAccountNumbers(
        {
          kind: 'registered',
          beneficiary: {
            organizationId,
            registrationId: registration.ref,
            ...beneficiary,
            registeredAt: new Date(beneficiary.registeredAt),
          },
        },
        [],
      );
    }
    if (form === null) throw new Error('A pass-through registration is never left waiting');
    const expiresAt = new Date(form.expiresAt);
    if (clock.now() >= expiresAt) return { kind: 'refused', reason: 'expired' };
    return { kind: 'waiting', formUrl: `${FORM_BASE}${form.formRef}`, expiresAt };
  };

  const stateOf = async (records: FakeRecords, { registrationId }: BeneficiaryRef): Promise<BeneficiaryOutcome> =>
    outcomeOf(records.organizationId, await records.get('registration', registrationId));

  return {
    async register(records, input) {
      const known = await records.get('registration', input.registrationId);
      if (known !== undefined) return outcomeOf(records.organizationId, known);
      if (!routes.includes(input.route)) throw new RangeError(`This partner has no ${input.route} route`);
      const form =
        input.route === 'hosted'
          ? {
              formRef: `fake-form-${ids.next()}`,
              expiresAt: new Date(clock.now().getTime() + formMinutes * MINUTE_MS).toISOString(),
            }
          : null;
      const registration: FakeRecord<'registration'> = {
        ref: input.registrationId,
        alias: form?.formRef ?? null,
        body: {
          form,
          outcome: input.route === 'pass_through' ? registered(records.organizationId, input.payee) : 'waiting',
        },
      };
      // Another call with the same ID registered it first: its answer is the answer.
      if (!(await records.add('registration', registration))) return stateOf(records, input);
      return outcomeOf(records.organizationId, registration);
    },

    stateOf,

    async fillForm(records, formUrl, payee) {
      const formRef = formUrl.startsWith(FORM_BASE) ? formUrl.slice(FORM_BASE.length) : '';
      const registration = await records.byAlias('registration', formRef);
      const form = registration?.body.outcome === 'waiting' ? registration.body.form : null;
      if (registration === undefined || form === null || clock.now() >= new Date(form.expiresAt)) {
        throw new FakeBankRefused('no_form_open', 'No form open there');
      }
      const outcome = registered(records.organizationId, payee);
      if (outcome === 'invalid_details') {
        throw new FakeBankRefused('details_refused', 'The form refuses those details: fix them and send again');
      }
      await records.update('registration', { ...registration, body: { form, outcome } });
    },
  };
}
