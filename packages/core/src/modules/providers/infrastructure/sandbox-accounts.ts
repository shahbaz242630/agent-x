// Business accounts the fake partner offers at its pretend bank, in the UAE
// standard's account-data shape (v2.1 `AEAccountArrayId`; rail map §2's
// safe summary). Synthetic: copied from the OpenFinance-OS Data Sandbox's
// published fixtures (github.com/openfinance-os/data-sandbox; data CC0,
// fixtures v1 0.0.1, spec v2.1-errata2), `bundles/<persona>/median/seed-<n>/
// accounts.json` for the three personas below, retrieved 29 Sep 2026. Only
// the fields an adapter reads are kept. The IBANs are the sandbox's own,
// with valid check digits, and belong to no one.

/** One account as the rail's account data gives it: the IBAN in full, which an adapter never passes on. */
export interface RailAccount {
  readonly AccountId: string;
  readonly Status: string;
  readonly Currency: string;
  readonly AccountType: 'Retail' | 'SME' | 'Corporate';
  readonly AccountHolderName: string;
  readonly AccountIdentifiers: readonly { readonly SchemeName: string; readonly Identification: string }[];
}

/** One business's accounts at the bank: each its ID's ending, currency and IBAN. */
const business = (
  persona: string,
  AccountHolderName: string,
  AccountType: RailAccount['AccountType'],
  accounts: readonly (readonly [number, string, string])[],
): RailAccount[] =>
  accounts.map(([number, Currency, iban]) => ({
    AccountId: `${persona}-acct-0${String(number)}`,
    Status: 'Active',
    Currency,
    AccountType,
    AccountHolderName,
    AccountIdentifiers: [{ SchemeName: 'IBAN', Identification: iban }],
  }));

export const SANDBOX_ACCOUNTS: readonly RailAccount[] = [
  // sme_rak_trading_emirati, seed 4106
  ...business('sme-rak-trading-emirati', 'Jasmine AI FZ-LLC', 'SME', [
    [1, 'AED', 'AE129991676394720046026'],
    [2, 'USD', 'AE666103443463767477727'],
    [3, 'AED', 'AE523706630924601511273'],
  ]),
  // sme_trading_business, seed 4821
  ...business('sme-trading-business', 'Meridian Auto Spares LLC', 'SME', [
    [1, 'AED', 'AE487503558275153799998'],
    [2, 'AED', 'AE707506160602680028496'],
  ]),
  // corporate_treasury_listed, seed 7142
  ...business('corporate-treasury-listed', 'Glide Logistics Group PJSC', 'Corporate', [
    [1, 'AED', 'AE377909049986523395591'],
    [2, 'USD', 'AE217500095569014017955'],
    [3, 'AED', 'AE842509793599069593272'],
    [4, 'AED', 'AE619300855079374610850'],
  ]),
];
