// The fake partner held to the rail adapter contract (gate H6; Rule Book §6:
// the fake and every real adapter pass the same contract tests). The fake's
// own tests (fake-payments, fake-payees, fake-events) cover what only it does:
// the amount's fils choosing an outcome, an answer lost, the clock moving it on.
import { FixedClock, SequentialIds } from '@agentx/testing';

import { railContract } from '../rail-contract.helper.test.ts';
import { createFakeRail } from './fake-rail.ts';
import { SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

const ORG = '00000000-0000-7000-8000-00000000aaaa';
const OTHER_ORG = '00000000-0000-7000-8000-00000000bbbb';
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const [PAYEE_IBAN = ''] = SANDBOX_ACCOUNTS.flatMap((account) =>
  account.AccountIdentifiers.map((each) => each.Identification),
);
const PAYEE = { name: 'Jasmine AI FZ-LLC', iban: PAYEE_IBAN };

railContract('the fake partner', async () => {
  const ids = new SequentialIds();
  const rail = createFakeRail({ clock: new FixedClock(new Date('2026-10-01T08:00:00Z')), ids });
  const session = await rail.startSourceLink({ organizationId: ORG, linkId: ids.next() });
  const accountConsentId = await rail.bank.approve(ORG, session.sessionRef, ACCOUNT);
  const registered = await rail.registerBeneficiary({
    route: 'pass_through',
    organizationId: ORG,
    registrationId: ids.next(),
    payee: PAYEE,
  });
  if (registered.kind !== 'registered') throw new Error(`the fake's payee not registered: ${registered.kind}`);
  return {
    rail,
    organizationId: ORG,
    otherOrganizationId: OTHER_ORG,
    accountConsentId,
    beneficiaryRef: registered.beneficiary.beneficiaryRef,
    // The fake's outcome is the amount's fils (decision 5): .00 succeeds, .01 is declined.
    amounts: { accepted: 100_000n, refused: 100_001n },
    payee: PAYEE,
    newId: () => ids.next(),
    signedMessage: () => rail.bank.signEvent({ eventType: 'payment.status', consentId: accountConsentId }),
  };
});
