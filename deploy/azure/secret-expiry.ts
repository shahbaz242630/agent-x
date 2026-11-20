/**
 * Each vault secret's expiry date (PL-25), read from secret-expiry.json, the one place the schedule is written:
 * secrets.bicep compiles the same file. A secret a run writes gets `exp` at the first day of that run's month plus its
 * period; deploy.ts reads every date back after a secrets run and holds each secret the run wrote to it.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

interface ExpiryFile {
  readonly secrets: Readonly<Record<string, string>>;
  readonly keys: string;
  readonly keysNever: readonly string[];
  readonly publicHalves: string;
}

const EXPIRY_FILE = path.join(import.meta.dirname, 'secret-expiry.json');

export const readExpiry = (): ExpiryFile => JSON.parse(readFileSync(EXPIRY_FILE, 'utf8')) as ExpiryFile;

/** The periods the schedule uses: whole years (Secrets-Register.md's intervals are 12 months or 2 years). */
const YEARS = /^P([1-9])Y$/;

/** An app key's family: `key-audit-mac-v2` is `key-audit-mac`. */
const familyOf = (key: string): string => key.replace(/-v\d+$/, '');

/**
 * A secret's period as the schedule gives it: "" for none, undefined for a secret it doesn't name (a job's held
 * request, written per run: never held to a date).
 */
export function periodOf(name: string, schedule: ExpiryFile = readExpiry()): string | undefined {
  if (Object.hasOwn(schedule.secrets, name)) return schedule.secrets[name];
  if (/^key-.+-v\d+$/.test(name)) return schedule.keysNever.includes(familyOf(name)) ? '' : schedule.keys;
  if (/^public-.+-v\d+$/.test(name)) return schedule.publicHalves;
  return undefined;
}

/** The `exp` (seconds since 1970, UTC) a secret written at `at` gets for a period: the first of that month, plus it. */
export function expiryFor(period: string, at: Date): number {
  const years = YEARS.exec(period)?.[1];
  if (years === undefined)
    throw new Error(`secret-expiry.json gives ${JSON.stringify(period)}, not a whole number of years`);
  return Date.UTC(at.getUTCFullYear() + Number(years), at.getUTCMonth(), 1) / 1000;
}

/** A secret as the vault lists it after a run, with its current version and expiry (never its value). */
export interface Dated {
  readonly name: string;
  readonly version: string;
  /** `attributes.exp`, when the vault holds one. */
  readonly expires?: number;
}

const dayOf = (seconds: number): string => new Date(seconds * 1000).toISOString().slice(0, 10);

/**
 * Every secret this run wrote (a new version, or new) whose expiry isn't the schedule's, in plain words: one missing,
 * one nobody scheduled, or another date. A run that crosses a month's end may have written either month's date, so
 * both count. A secret the run didn't write keeps the date it had, and isn't held to one here.
 */
export function expiryProblems(
  before: readonly Pick<Dated, 'name' | 'version'>[],
  after: readonly Dated[],
  started: Date,
  ended: Date,
  schedule: ExpiryFile = readExpiry(),
): string[] {
  return after.flatMap((secret) => {
    const was = before.find((each) => each.name === secret.name);
    const period = periodOf(secret.name, schedule);
    if (was?.version === secret.version || period === undefined) return [];
    if (period === '') {
      return secret.expires === undefined
        ? []
        : [
            `${secret.name} was written with an expiry date (${dayOf(secret.expires)}) the schedule doesn't give it: secret-expiry.json and secrets.bicep disagree, so fix them in a reviewed PR`,
          ];
    }
    const due = [expiryFor(period, started), expiryFor(period, ended)];
    if (secret.expires !== undefined && due.includes(secret.expires)) return [];
    const said = secret.expires === undefined ? 'none' : dayOf(secret.expires);
    return [
      `${secret.name} was written with expiry date ${said}, not ${dayOf(due[1] ?? 0)} as the schedule says: secrets.bicep didn't set it, so the vault won't say when it is due. Run the same secrets command again; if it stays, fix secrets.bicep in a reviewed PR`,
    ];
  });
}

/** Each secret's expiry date for the run's closing list: the date, or that it has none yet. */
export const expiryLine = (secret: Dated): string =>
  `  ${secret.name}: ${secret.expires === undefined ? 'no expiry date' : 'expires ' + dayOf(secret.expires)}`;
