// Money (ADR-006 §1–2; PRD §3.1): integer minor units with an explicit ISO
// currency, never a float. A `bigint` so the compiler refuses to mix it with a
// `number`; every sum and comparison goes through here, and refuses two
// currencies. Which currencies are accepted is the deployment's choice (the
// `allowed_currencies` table, MVP AED), not this module's: it checks the
// code's shape only.

/** An ISO 4217 alphabetic code: three capital letters. */
const CURRENCY = /^[A-Z]{3}$/;

/** An amount: whole minor units (fils for AED) of one currency. Never negative. */
export interface Money {
  readonly minor: bigint;
  readonly currency: string;
}

/** An amount or a currency that can't be one, or two currencies mixed: the message never says the amount. */
export class MoneyRefused extends Error {
  constructor(problem: string) {
    super(`Not money: ${problem}`);
    this.name = 'MoneyRefused';
  }
}

/** An amount of `minor` units of `currency`; MoneyRefused for a negative amount or a code that isn't one. */
export function money(minor: bigint, currency: string): Money {
  if (!CURRENCY.test(currency)) throw new MoneyRefused('the currency is not an ISO 4217 code');
  if (minor < 0n) throw new MoneyRefused('an amount is never negative');
  return Object.freeze({ minor, currency });
}

/**
 * An amount as JSON gives it (ADR-006 §1: `amount_minor` an integer, checked
 * as a safe integer at the edge, then a `bigint`): a whole number from 1 up to
 * Number.MAX_SAFE_INTEGER, as JSON.parse rounds anything past 2^53.
 */
export function moneyFromJson(value: unknown, currency: string): Money {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new MoneyRefused('the amount is not a whole number of minor units from 1 to 2^53 − 1');
  }
  return money(BigInt(value), currency);
}

/** The currency both share; MoneyRefused when they differ (ADR-006 §2: never converted). */
function sameCurrency(a: Money, b: Money): string {
  if (a.currency !== b.currency) throw new MoneyRefused('two currencies are never mixed');
  return a.currency;
}

/** The sum of two amounts of one currency. */
export function plus(a: Money, b: Money): Money {
  return money(a.minor + b.minor, sameCurrency(a, b));
}

/** The sum of every amount, `zero` of `currency` when there are none; every one in that currency. */
export function total(amounts: readonly Money[], currency: string): Money {
  return amounts.reduce(plus, money(0n, currency));
}

/** -1, 0 or 1 as `a` is less than, equal to or more than `b`, of one currency. */
export function compare(a: Money, b: Money): -1 | 0 | 1 {
  sameCurrency(a, b);
  if (a.minor === b.minor) return 0;
  return a.minor < b.minor ? -1 : 1;
}

/** Whether `amount` is no more than `limit`, of one currency: how every limit is checked. */
export const withinLimit = (amount: Money, limit: Money): boolean => compare(amount, limit) <= 0;
