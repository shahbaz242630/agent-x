// ADR-014 §3, PRD §6, BEN-1 to BEN-6 (D1-2): the fake partner's payees. The
// contract Agent X relies on (both routes; our registration ID as the
// partner's idempotency key; the outcome read server to server by that ID,
// only for its organisation; a lost answer recovered by asking, never by
// registering again; no account number in any answer), and the rail's name
// check the fake mirrors.
import { FixedClock, findLeaks, SENSITIVE_SAMPLES, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import {
  type BeneficiaryOutcome,
  type BeneficiaryState,
  isPartnerPage,
  type PayeeDetails,
  RailUnavailable,
} from '../domain/rail.ts';
import { createFakeRail, type FakeRailOptions } from './fake-rail.ts';
import { SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

const ORG = '00000000-0000-7000-8000-00000000aaaa';
const OTHER_ORG = '00000000-0000-7000-8000-00000000bbbb';
const REGISTRATION = '00000000-0000-7000-8000-00000000dddd';
const START = new Date('2026-10-01T08:00:00Z');
const MINUTE = 60_000;
const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));
const [JASMINE = ''] = IBANS;
const MERIDIAN = IBANS[3] ?? '';

/** A UAE IBAN with valid check digits around any 19 digits (ISO 13616: A is 10, E is 14). */
function uaeIban(digits: string): string {
  const check = 98n - (BigInt(`${digits}101400`) % 97n);
  return `AE${String(check).padStart(2, '0')}${digits}`;
}

function setUp(options: Partial<FakeRailOptions> = {}) {
  const clock = new FixedClock(START);
  const rail = createFakeRail({ clock, ids: new SequentialIds(), ...options });
  return { clock, rail, bank: rail.bank };
}

const passThrough = (payee: PayeeDetails, organizationId = ORG, registrationId = REGISTRATION) =>
  ({ route: 'pass_through', organizationId, registrationId, payee }) as const;

const jasmine: PayeeDetails = { name: 'Jasmine AI FZ-LLC', iban: JASMINE };

function beneficiaryOf(outcome: BeneficiaryOutcome): BeneficiaryState {
  if (outcome.kind !== 'registered') throw new Error(`Not registered: ${outcome.kind}`);
  return outcome.beneficiary;
}

function formUrlOf(outcome: BeneficiaryOutcome): string {
  if (outcome.kind !== 'waiting') throw new Error(`Not waiting: ${outcome.kind}`);
  return outcome.formUrl;
}

describe('what the partner offers (D1-2)', () => {
  it('says both routes and a stable payee identity, unless it mirrors a partner with less', async () => {
    expect(await setUp().rail.capabilities()).toEqual({
      beneficiaryRoutes: ['hosted', 'pass_through'],
      stablePayeeIdentity: true,
    });
    const hostedOnly = setUp({ beneficiaryRoutes: ['hosted'], stablePayeeIdentity: false }).rail;
    expect(await hostedOnly.capabilities()).toEqual({ beneficiaryRoutes: ['hosted'], stablePayeeIdentity: false });
  });

  it('refuses a route it doesn’t offer: a caller reads the capabilities first', async () => {
    const { rail } = setUp({ beneficiaryRoutes: ['hosted'] });
    await expect(rail.registerBeneficiary(passThrough(jasmine))).rejects.toThrow('no pass_through route');
  });

  it('hands out a copy of its routes', async () => {
    const { rail } = setUp();
    const first = await rail.capabilities();
    (first.beneficiaryRoutes as string[]).pop();
    expect((await rail.capabilities()).beneficiaryRoutes).toEqual(['hosted', 'pass_through']);
  });
});

describe('a pass-through registration (D1-2)', () => {
  it('registers the payee at once, with the name check, the masked holder and a hint', async () => {
    const { rail } = setUp();
    expect(beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine)))).toEqual({
      organizationId: ORG,
      registrationId: REGISTRATION,
      beneficiaryRef: 'fake-beneficiary-00000000-0000-7000-8000-000000000001',
      payeeIdentity: expect.stringMatching(/^fake-payee-[a-p]{32}$/) as string,
      nameCheck: 'match',
      maskedName: 'J****** A* F*****',
      hint: `AE…${JASMINE.slice(-4)}`,
      registeredAt: START,
    });
  });

  it.each([
    ['jasmine ai fz llc', 'match'],
    ['JASMINE AI, FZ-LLC.', 'match'],
    ['Jasmine Trading', 'partial'],
    ['Falcon Pearl General Trading LLC', 'no_match'],
  ] as const)('checks the name %j against the holder: %s', async (name, nameCheck) => {
    const { rail } = setUp();
    const beneficiary = beneficiaryOf(await rail.registerBeneficiary(passThrough({ name, iban: JASMINE })));
    expect(beneficiary).toMatchObject({ nameCheck, maskedName: 'J****** A* F*****' });
  });

  it('says the check was unavailable for an account the bank can’t answer for, with no masked name', async () => {
    const { rail } = setUp();
    const elsewhere = uaeIban('1234567890123456789');
    const beneficiary = beneficiaryOf(
      await rail.registerBeneficiary(passThrough({ name: 'A Supplier', iban: elsewhere })),
    );
    expect(beneficiary).toMatchObject({
      nameCheck: 'unavailable',
      maskedName: null,
      hint: `AE…${elsewhere.slice(-4)}`,
    });
  });

  it('takes the IBAN in groups or lower case', async () => {
    const { rail } = setUp();
    const grouped = JASMINE.toLowerCase().replace(/(.{4})/g, '$1 ');
    const beneficiary = beneficiaryOf(await rail.registerBeneficiary(passThrough({ ...jasmine, iban: grouped })));
    expect(beneficiary).toMatchObject({ nameCheck: 'match', hint: `AE…${JASMINE.slice(-4)}` });
  });

  it.each([
    ['another country’s IBAN', { name: 'A Supplier', iban: SENSITIVE_SAMPLES.lowercaseIban }],
    ['bad check digits', { name: 'A Supplier', iban: `AE00${JASMINE.slice(4)}` }],
    ['a short number', { name: 'A Supplier', iban: JASMINE.slice(0, 22) }],
    ['no name', { name: ' ', iban: JASMINE }],
    ['a name no one can read', { name: String.fromCharCode(0x200b), iban: JASMINE }],
    ['a name too long', { name: 'a'.repeat(141), iban: JASMINE }],
  ])('refuses %s, and answers the same when that ID comes again', async (_, payee) => {
    const { rail } = setUp();
    const refused = { kind: 'refused', reason: 'invalid_details' };
    expect(await rail.registerBeneficiary(passThrough(payee))).toEqual(refused);
    expect(await rail.registerBeneficiary(passThrough(jasmine))).toEqual(refused);
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION })).toEqual(refused);
  });

  it('takes a name of 140 characters', async () => {
    const { rail } = setUp();
    const outcome = await rail.registerBeneficiary(passThrough({ name: 'a'.repeat(140), iban: JASMINE }));
    expect(beneficiaryOf(outcome).nameCheck).toBe('no_match');
  });
});

describe('our registration ID, the partner’s idempotency key (BEN-6)', () => {
  it('answers the same registration again with the first answer, whatever details come with it', async () => {
    const { rail } = setUp();
    const first = await rail.registerBeneficiary(passThrough(jasmine));
    const again = await rail.registerBeneficiary(passThrough({ name: 'Meridian Auto Spares LLC', iban: MERIDIAN }));
    expect(again).toEqual(first);
  });

  it('answers the first answer even when the same ID comes again by a route it doesn’t offer', async () => {
    const { rail } = setUp({ beneficiaryRoutes: ['pass_through'] });
    const first = await rail.registerBeneficiary(passThrough(jasmine));
    const hosted = { route: 'hosted', organizationId: ORG, registrationId: REGISTRATION } as const;
    expect(await rail.registerBeneficiary(hosted)).toEqual(first);
  });

  it('keeps each organisation’s registrations apart, even under the same ID', async () => {
    const { rail } = setUp();
    const ours = beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine)));
    const theirs = beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine, OTHER_ORG)));
    expect(theirs.beneficiaryRef).not.toBe(ours.beneficiaryRef);
    expect(theirs.organizationId).toBe(OTHER_ORG);
  });

  it.each(['', 'a'.repeat(41), 'two words'])(
    'refuses the registration ID %j, as the rail refuses the key',
    async (id) => {
      const { rail } = setUp();
      await expect(rail.registerBeneficiary(passThrough(jasmine, ORG, id))).rejects.toThrow(RangeError);
    },
  );

  it('recovers a lost answer by asking with the ID: the payee was registered once', async () => {
    const { rail, bank } = setUp();
    bank.loseNextAnswer();
    await expect(rail.registerBeneficiary(passThrough(jasmine))).rejects.toThrow(RailUnavailable);
    const found = beneficiaryOf(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION }));
    expect(beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine)))).toEqual(found);
  });

  it('registers nothing while the partner is down', async () => {
    const { rail, bank } = setUp();
    bank.goDown();
    await expect(rail.registerBeneficiary(passThrough(jasmine))).rejects.toThrow(RailUnavailable);
    await expect(rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION })).rejects.toThrow(
      RailUnavailable,
    );
    bank.comeBack();
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION })).toEqual({
      kind: 'refused',
      reason: 'unknown',
    });
  });
});

describe('a registration’s state, server to server (SEC-PAY-08, BEN-4)', () => {
  it('is read only by the organisation that started it; another’s answers as none does', async () => {
    const { rail } = setUp();
    const registered = await rail.registerBeneficiary(passThrough(jasmine));
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION })).toEqual(registered);
    const unknown = { kind: 'refused', reason: 'unknown' };
    expect(await rail.getBeneficiaryState({ organizationId: OTHER_ORG, registrationId: REGISTRATION })).toEqual(
      unknown,
    );
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: 'never-started' })).toEqual(unknown);
  });

  it('hands out copies: changing an answer changes nothing at the partner', async () => {
    const { rail } = setUp();
    beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine))).registeredAt.setTime(0);
    const again = beneficiaryOf(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION }));
    expect(again.registeredAt).toEqual(START);
  });
});

describe('the payee identity (ADR-014 §3 source (a), BEN-2)', () => {
  it('is the same for the same account in an organisation, each registration its own reference', async () => {
    const { rail } = setUp();
    const first = beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine, ORG, 'reg-1')));
    const grouped = { ...jasmine, iban: JASMINE.replace(/(.{4})/g, '$1 ') };
    const second = beneficiaryOf(await rail.registerBeneficiary(passThrough(grouped, ORG, 'reg-2')));
    const other = beneficiaryOf(
      await rail.registerBeneficiary(passThrough({ ...jasmine, iban: MERIDIAN }, ORG, 'reg-3')),
    );
    expect(second.payeeIdentity).toBe(first.payeeIdentity);
    expect(second.beneficiaryRef).not.toBe(first.beneficiaryRef);
    expect(other.payeeIdentity).not.toBe(first.payeeIdentity);
  });

  it('is never another organisation’s', async () => {
    const { rail } = setUp();
    const ours = beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine, ORG, 'reg-1')));
    const theirs = beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine, OTHER_ORG, 'reg-1')));
    expect(theirs.payeeIdentity).not.toBe(ours.payeeIdentity);
  });

  it('is never refused as an account number, for any organisation and account (E2-2b: in hex, about one in a hundred was)', async () => {
    const { rail } = setUp();
    const organisations = Array.from(
      { length: 200 },
      (_, index) => `00000000-0000-7000-8000-${index.toString(16).padStart(12, '0')}`,
    );
    for (const organizationId of organisations) {
      for (const [index, iban] of IBANS.filter((each) => each.startsWith('AE')).entries()) {
        const outcome = await rail.registerBeneficiary(
          passThrough({ ...jasmine, iban }, organizationId, `reg-${String(index)}`),
        );
        expect(beneficiaryOf(outcome).payeeIdentity).toMatch(/^fake-payee-[a-p]{32}$/);
      }
    }
  });

  it('is null from a partner that gives none', async () => {
    const { rail } = setUp({ stablePayeeIdentity: false });
    expect(beneficiaryOf(await rail.registerBeneficiary(passThrough(jasmine))).payeeIdentity).toBeNull();
  });
});

describe('a hosted-form registration (D1-2)', () => {
  const hosted = { route: 'hosted', organizationId: ORG, registrationId: REGISTRATION } as const;
  const ref = { organizationId: ORG, registrationId: REGISTRATION };

  it('waits for the form for 30 minutes, then registers what the person entered there', async () => {
    const { rail, bank } = setUp();
    const waiting = {
      kind: 'waiting',
      formUrl: 'https://payees.fake-partner.invalid/form/fake-form-00000000-0000-7000-8000-000000000001',
      expiresAt: new Date(START.getTime() + 30 * MINUTE),
    };
    expect(await rail.registerBeneficiary(hosted)).toEqual(waiting);
    expect(await rail.getBeneficiaryState(ref)).toEqual(waiting);
    expect(await rail.registerBeneficiary(hosted)).toEqual(waiting);
    await bank.fillForm(ORG, waiting.formUrl, jasmine);
    const beneficiary = beneficiaryOf(await rail.getBeneficiaryState(ref));
    expect(beneficiary).toMatchObject({
      registrationId: REGISTRATION,
      nameCheck: 'match',
      hint: `AE…${JASMINE.slice(-4)}`,
    });
    await expect(bank.fillForm(ORG, waiting.formUrl, jasmine)).rejects.toMatchObject({
      name: 'FakeBankRefused',
      reason: 'no_form_open',
    });
    // A page a person may be sent to: the partner's own form origin, over HTTPS (E2-2a).
    expect(isPartnerPage(waiting.formUrl, rail.formOrigin)).toBe(true);
    expect(isPartnerPage(waiting.formUrl, rail.authoriseOrigin)).toBe(false);
  });

  it('keeps the form open when it refuses details, until they are right', async () => {
    const { rail, bank } = setUp();
    const formUrl = formUrlOf(await rail.registerBeneficiary(hosted));
    await expect(
      bank.fillForm(ORG, formUrl, { name: 'A Supplier', iban: SENSITIVE_SAMPLES.lowercaseIban }),
    ).rejects.toMatchObject({ name: 'FakeBankRefused', reason: 'details_refused' });
    expect((await rail.getBeneficiaryState(ref)).kind).toBe('waiting');
    await bank.fillForm(ORG, formUrl, jasmine);
    expect((await rail.getBeneficiaryState(ref)).kind).toBe('registered');
  });

  it('is refused once 30 minutes pass unfilled, and the form closes', async () => {
    const { rail, bank, clock } = setUp();
    const formUrl = formUrlOf(await rail.registerBeneficiary(hosted));
    clock.advanceBy(30 * MINUTE - 1);
    expect((await rail.getBeneficiaryState(ref)).kind).toBe('waiting');
    clock.advanceBy(1);
    expect(await rail.getBeneficiaryState(ref)).toEqual({ kind: 'refused', reason: 'expired' });
    await expect(bank.fillForm(ORG, formUrl, jasmine)).rejects.toThrow('No form open there');
  });

  it('opens no form at an address the partner didn’t give', async () => {
    const { bank } = setUp();
    await expect(
      bank.fillForm(ORG, 'https://payees.fake-partner.invalid/form/fake-form-unknown', jasmine),
    ).rejects.toThrow('No form open there');
  });

  it('answers another organisation as none, before and after the form', async () => {
    const { rail, bank } = setUp();
    const formUrl = formUrlOf(await rail.registerBeneficiary(hosted));
    const unknown = { kind: 'refused', reason: 'unknown' };
    expect(await rail.getBeneficiaryState({ ...ref, organizationId: OTHER_ORG })).toEqual(unknown);
    await bank.fillForm(ORG, formUrl, jasmine);
    expect(await rail.getBeneficiaryState({ ...ref, organizationId: OTHER_ORG })).toEqual(unknown);
  });
});

describe('no account number in any answer (ADR-014 §3, SEC-PAY-05)', () => {
  it.each(IBANS)('%s: registered by either route, every answer hints at it, never holds it', async (iban) => {
    const { rail, bank } = setUp();
    const payee = { name: 'Someone Trading LLC', iban };
    const answers: unknown[] = [await rail.registerBeneficiary(passThrough(payee, ORG, 'reg-1'))];
    const hosted = { route: 'hosted', organizationId: ORG, registrationId: 'reg-2' } as const;
    const formUrl = formUrlOf(await rail.registerBeneficiary(hosted));
    await bank.fillForm(ORG, formUrl, payee);
    answers.push(
      await rail.getBeneficiaryState({ organizationId: ORG, registrationId: 'reg-1' }),
      await rail.getBeneficiaryState({ organizationId: ORG, registrationId: 'reg-2' }),
    );
    expect(findLeaks(JSON.stringify(answers), [iban])).toEqual([]);
  });
});
