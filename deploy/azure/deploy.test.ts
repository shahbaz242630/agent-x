// SEC-OPS-11: the deploy tool (G3a). Nothing here reaches Azure: the terminal
// and the Azure CLI are stand-ins that record what the tool asked and sent, so
// the safety properties can be read off them — a secret travels only in the
// child process's environment, is never said, and nothing is sent before the
// operator has confirmed the subscription, the rules have passed and Azure's
// what-if has been answered.
import { createPublicKey, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { BICEP_VERSION } from '../../tooling/bicep/bicep.ts';
import { newPassword } from '../compose/prepare.ts';
import { APP_KEYS } from './app-keys.ts';
import {
  ACTION_GROUP,
  APP_KEYS_VARIABLE,
  APP_VARIABLES,
  APPS_ENVIRONMENT,
  askPassword,
  type Az,
  azInvocation,
  type AzResult,
  Cancelled,
  CERTIFICATE_VARIABLES,
  deploy,
  deploymentName,
  describePlan,
  type DnsLookup,
  keyProblems,
  doorRecords,
  HiddenLine,
  type Images,
  main,
  type Makers,
  parseArguments,
  issuedMissing,
  issuedProblems,
  passwordProblems,
  peopleAskedFor,
  policyCheck,
  realDns,
  realImages,
  RESOURCE_GROUP,
  secretValues,
  shapedForPolicy,
  type Steps,
  type Terminal,
  USAGE,
  UsageError,
  VAULT_SECRETS,
} from './deploy.ts';
import type { Checkout } from './git.ts';
import { policyProblems } from './policy.ts';
import { environmentSnapshot, inCopy, type Snapshot } from './snapshot.ts';

const AZURE_DIR = import.meta.dirname;
const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000a';
/** A commit and an image digest in the shapes GitHub and ghcr.io give them, made up. */
const COMMIT = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;

/** What an operator would paste: assembled when the tests run, all four kinds, never written down. */
const aPaste = (): string => ['Str0ng', 'Enough', '#', randomBytes(8).toString('hex')].join('');

const all = { kind: 'all' } as const;
const keysOnly = { kind: 'keys' } as const;
const rotating = (...names: string[]) => ({ kind: 'rotate', names: new Set(names) }) as const;

/** Makers that are quick and tell their outputs apart. */
function quickMakers(): Makers {
  let calls = 0;
  return {
    random: (bytes) => {
      calls += 1;
      return Buffer.alloc(bytes, calls);
    },
    keyPair: () => ({ publicPem: 'PUBLIC-HALF-PEM', privatePem: 'PRIVATE-HALF-PEM' }),
  };
}

const variableOf = (name: string): string => VAULT_SECRETS[name]?.variable ?? `unknown ${name}`;

/** The two people's secrets, in the order peopleAskedFor gives them. */
const PEOPLE = ['db-admin-password', 'zitadel-admin-password'] as const;

/**
 * What the operator pasted for each person, by the secret's name. Built from
 * the list rather than written as a map, since a secret's name beside a
 * value is the shape GitGuardian reads as a password (PRs #27 and #28).
 */
const pasted = (...values: readonly string[]): Record<string, string> =>
  Object.fromEntries(values.map((value, index) => [PEOPLE[index] ?? `extra ${String(index)}`, value]));

/** A PEM block's first line, assembled so no scanner reads the test as holding a key. */
const pemHeader = (...label: readonly string[]): string => ['-----BEGIN', ...label].join(' ') + '-----\n';

describe('parseArguments', () => {
  it('reads the ways the tool is run', () => {
    expect(parseArguments(['foundation'])).toEqual({ command: 'foundation' });
    expect(parseArguments(['alerts'])).toEqual({ command: 'alerts' });
    expect(parseArguments(['dns'])).toEqual({ command: 'dns' });
    expect(parseArguments(['certificates'])).toEqual({ command: 'certificates' });
    expect(parseArguments(['secrets', '--all'])).toEqual({ command: 'secrets', plan: all });
    expect(parseArguments(['secrets', '--keys'])).toEqual({ command: 'secrets', plan: keysOnly });
    expect(parseArguments(['apps'])).toEqual({ command: 'apps', commit: undefined, keepRunning: false });
    expect(parseArguments(['apps', '--commit', COMMIT])).toEqual({
      command: 'apps',
      commit: COMMIT,
      keepRunning: false,
    });
    expect(parseArguments(['secrets', '--rotate', 'db-app-password', 'db-owner-password'])).toEqual({
      command: 'secrets',
      plan: rotating('db-app-password', 'db-owner-password'),
    });
  });

  it("reads apps' two options in either order", () => {
    expect(parseArguments(['apps', '--keep-running'])).toEqual({
      command: 'apps',
      commit: undefined,
      keepRunning: true,
    });
    for (const argv of [
      ['apps', '--keep-running', '--commit', COMMIT],
      ['apps', '--commit', COMMIT, '--keep-running'],
    ]) {
      expect(parseArguments(argv)).toEqual({ command: 'apps', commit: COMMIT, keepRunning: true });
    }
  });

  it('rotates the login key pair as one thing, whichever half is named', () => {
    for (const half of ['login-client-private-key', 'login-client-public-key']) {
      expect(parseArguments(['secrets', '--rotate', half])).toEqual({
        command: 'secrets',
        plan: rotating(half, 'login-client-private-key', 'login-client-public-key'),
      });
    }
  });

  it('refuses anything else, saying why', () => {
    for (const [argv, reason] of [
      [[], /not nothing/],
      [['deploy'], /say foundation, secrets, apps, alerts, dns or certificates, not deploy/],
      [['apps', '--commit'], /apps takes --keep-running, and --commit with one full 40-hex commit/],
      [['apps', '--commit', 'baca38b'], /one full 40-hex commit/],
      [['apps', '--commit', COMMIT.toUpperCase()], /one full 40-hex commit/],
      [['apps', '--commit', COMMIT, 'extra'], /apps takes --keep-running/],
      [['apps', 'latest'], /apps takes --keep-running/],
      [['apps', '--commit', '--keep-running', COMMIT], /each at most once/],
      [['apps', '--commit', COMMIT, '--commit', COMMIT], /each at most once/],
      [['apps', '--keep-running', '--keep-running'], /each at most once/],
      [['apps', '--keep'], /each at most once/],
      [['foundation', '--all'], /foundation takes no options/],
      [['alerts', '--fix'], /alerts takes no options, not --fix/],
      [['dns', 'app.example.invalid'], /dns takes no options, not app.example.invalid/],
      [['certificates', '--keep-running'], /certificates takes no options, not --keep-running/],
      [['secrets'], /needs --all \(the first run\), --rotate <names> or --keys/],
      [['secrets', '--all', 'db-app-password'], /--all takes no names/],
      [['secrets', '--keys', 'key-audit-mac-v1'], /--keys takes no names/],
      // What a key sealed or signed needs it as it was: a key gets a new version instead.
      [
        ['secrets', '--rotate', 'key-audit-mac-v1'],
        /key-audit-mac-v1 is never written again: .* a new version in app-keys.json, then secrets --keys/,
      ],
      [['secrets', '--rotate'], /at least one secret name/],
      [['secrets', '--rotate', 'db-typo-password'], /isn't a secret the vault holds/],
      // Zitadel can't read what it encrypted with another master key.
      [['secrets', '--rotate', 'zitadel-masterkey'], /never rotated/],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(UsageError);
      expect(() => parseArguments(argv)).toThrow(reason);
    }
  });
});

describe('the secrets a run writes', () => {
  it('asks people only for their own secrets, and only when the run writes them', () => {
    expect(peopleAskedFor(all)).toEqual([...PEOPLE]);
    expect(peopleAskedFor(rotating('db-app-password'))).toEqual([]);
    expect(peopleAskedFor(rotating('zitadel-admin-password'))).toEqual(['zitadel-admin-password']);
  });

  it('writes all nine on a first run: the pasted two as pasted, the logins fresh and distinct, the pair together', () => {
    const adminPaste = aPaste();
    const zitadelPaste = aPaste();
    const values = secretValues(all, pasted(adminPaste, zitadelPaste), quickMakers());
    expect(Object.keys(values).sort()).toEqual(
      [...Object.values(VAULT_SECRETS).map((s) => s.variable), APP_KEYS_VARIABLE].sort(),
    );
    expect(values[variableOf('db-admin-password')]).toBe(adminPaste);
    expect(values[variableOf('zitadel-admin-password')]).toBe(zitadelPaste);
    const logins = ['db-owner-password', 'db-app-password', 'db-backup-password', 'db-zitadel-password'].map(
      (name) => values[variableOf(name)] ?? '',
    );
    expect(new Set(logins).size).toBe(4);
    for (const login of logins) expect(login).toMatch(/^[0-9a-f]{32}aZ9!$/);
    expect(values[variableOf('zitadel-masterkey')]).toMatch(/^[0-9a-f]{32}$/);
    expect(values[variableOf('login-client-private-key')]).toBe('PRIVATE-HALF-PEM');
    expect(values[variableOf('login-client-public-key')]).toBe('PUBLIC-HALF-PEM');
  });

  it("makes every one of the app's keys fresh on every run, 32 bytes each as base64url, each its own", () => {
    for (const plan of [all, rotating('db-app-password'), keysOnly]) {
      const keys = JSON.parse(
        secretValues(plan, pasted(aPaste(), aPaste()), quickMakers())[APP_KEYS_VARIABLE] ?? '{}',
      ) as Record<string, string>;
      expect(Object.keys(keys)).toEqual([...APP_KEYS]);
      for (const key of Object.values(keys)) expect(Buffer.from(key, 'base64url')).toHaveLength(32);
      expect(new Set(Object.values(keys)).size).toBe(APP_KEYS.length);
    }
  });

  it('writes nothing but the keys and the master key on a keys run, and asks nobody', () => {
    const values = secretValues(keysOnly, {}, quickMakers());
    const written = Object.entries(values)
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable);
    expect(written.sort()).toEqual([APP_KEYS_VARIABLE, variableOf('zitadel-masterkey')].sort());
    expect(peopleAskedFor(keysOnly)).toEqual([]);
  });

  it('makes a real key pair whose halves belong together, in the forms Zitadel reads', () => {
    const values = secretValues(all, pasted(aPaste(), aPaste()));
    const privateHalf = values[variableOf('login-client-private-key')] ?? '';
    const publicHalf = values[variableOf('login-client-public-key')] ?? '';
    expect(privateHalf.startsWith(pemHeader('PRIVATE', 'KEY'))).toBe(true);
    expect(publicHalf.startsWith(pemHeader('PUBLIC', 'KEY'))).toBe(true);
    expect(createPublicKey(privateHalf).export({ type: 'spki', format: 'pem' })).toBe(publicHalf);
    expect(newPassword()).not.toBe(values[variableOf('db-app-password')]);
  });

  it('on a rotation, writes the named secrets and a fresh master key, and leaves every other one empty', () => {
    const values = secretValues(rotating('db-app-password'), {}, quickMakers());
    const written = Object.entries(values)
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable);
    expect(written.sort()).toEqual(
      [variableOf('db-app-password'), variableOf('zitadel-masterkey'), APP_KEYS_VARIABLE].sort(),
    );
    const pair = secretValues(rotating('login-client-private-key', 'login-client-public-key'), {}, quickMakers());
    expect(pair[variableOf('login-client-private-key')]).toBe('PRIVATE-HALF-PEM');
    expect(pair[variableOf('login-client-public-key')]).toBe('PUBLIC-HALF-PEM');
    expect(pair[variableOf('db-admin-password')]).toBe('');
  });

  it("refuses to write a person's secret nobody gave", () => {
    expect(() => secretValues(all, pasted(aPaste()), quickMakers())).toThrow(
      /zitadel-admin-password was to be written but nobody gave it/,
    );
  });

  it('describes a run by names alone', () => {
    expect(describePlan(rotating('db-app-password'))).toEqual([
      '  db-admin-password: kept as the vault has it',
      '  db-owner-password: kept as the vault has it',
      '  db-app-password: written, made fresh by this run',
      '  db-backup-password: kept as the vault has it',
      '  db-zitadel-password: kept as the vault has it',
      '  zitadel-admin-password: kept as the vault has it',
      '  login-client-private-key: kept as the vault has it',
      '  login-client-public-key: kept as the vault has it',
      '  zitadel-masterkey: written only if the vault has none yet',
      '  api-oidc-client-secret: kept as the vault has it',
      ...APP_KEYS.map((key) => `  ${key}: written only if the vault has none yet`),
    ]);
    expect(describePlan(all)).toContain('  zitadel-admin-password: written, from what you paste');
    // Zitadel gives the API's secret once the API is registered with it: a first run can't have it, so only its name writes it (B2-6).
    expect(describePlan(all)).toContain('  api-oidc-client-secret: kept as the vault has it');
    expect(describePlan(rotating('api-oidc-client-secret'))).toContain(
      '  api-oidc-client-secret: written, from what you paste',
    );
    expect(describePlan(keysOnly).filter((line) => line.includes(': written,'))).toEqual([]);
  });
});

describe('issuedProblems', () => {
  /** What Zitadel shows, in its shape: 64 letters and digits, no symbol. Built here, so no scanner takes it for one. */
  const zitadels = 'aB3d'.repeat(16);

  it('takes a secret as the service showed it, with no symbol, which a password would need', () => {
    expect(issuedProblems(zitadels)).toEqual([]);
    expect(passwordProblems(zitadels)).toContain('it has no a symbol');
  });

  it.each([
    ['too short to be one', 'abc123', /shorter than 16/],
    ['a space a paste added', ` ${zitadels}`, /starts or ends with a space/],
    ['a space inside', `${zitadels.slice(0, 20)} ${zitadels.slice(20)}`, /not plain visible ASCII/],
    ['a character outside plain ASCII', `${zitadels}é`, /not plain visible ASCII/],
    ['more than the API takes', 'a'.repeat(2049), /longer than the 2048/],
  ])('refuses %s, never repeating the value', (_what, value, problem) => {
    const problems = issuedProblems(value);
    expect(problems).toContainEqual(expect.stringMatching(problem));
    expect(problems.join(' ')).not.toContain(value.trim());
  });
});

describe('passwordProblems', () => {
  it("accepts what a password manager's generator makes, and says what is missing otherwise, never the value", () => {
    expect(passwordProblems(aPaste())).toEqual([]);
    const cases: readonly (readonly [string, RegExp])[] = [
      ['Sh0rt#', /shorter than 16/],
      ['Aa1#'.repeat(33), /longer than the 128/],
      [` ${aPaste()}`, /starts or ends with a space/],
      [`${aPaste()} `, /starts or ends with a space/],
      ['NOLOWERCASE1234#', /no a lower-case letter/],
      ['nouppercase1234#', /no an upper-case letter/],
      ['NoDigitsAtAllHere#', /no a digit/],
      ['NoSymbolsAtAll1234', /no a symbol/],
    ];
    for (const [value, problem] of cases) {
      const problems = passwordProblems(value);
      expect(problems.join('; ')).toMatch(problem);
      expect(problems.join('; ')).not.toContain(value.trim());
    }
  });
});

describe('HiddenLine', () => {
  const typed = (...chunks: string[]): { state: string; value: string } => {
    const line = new HiddenLine();
    let state = 'more';
    for (const chunk of chunks) {
      state = line.feed(chunk);
      if (state !== 'more') break;
    }
    return { state, value: line.value };
  };

  it('ends on Enter, however the terminal sends it, and ignores what follows in the same paste', () => {
    expect(typed('a', 'b', 'c', '\r')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('abc\n')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('abc\r\n')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('abc\rmore')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('ab', 'c')).toEqual({ state: 'more', value: 'abc' });
  });

  it('takes back a character on either backspace, cancels on Ctrl+C, and drops other control characters', () => {
    expect(typed('abx\u007fc\r')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('abx\bc\r')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('\u007f\u007fa\r')).toEqual({ state: 'done', value: 'a' });
    expect(typed('abc\u0003')).toEqual({ state: 'cancelled', value: 'abc' });
    expect(typed('a\tb\u001bc\r')).toEqual({ state: 'done', value: 'abc' });
    expect(typed('a é ✓\r')).toEqual({ state: 'done', value: 'a é ✓' });
  });

  it("drops the markers a terminal wraps a bracketed paste in, keeping what's inside", () => {
    expect(typed('\u001b[200~pasted\u001b[201~\r')).toEqual({ state: 'done', value: 'pasted' });
  });
});

describe('askPassword', () => {
  it('asks twice, retries a mismatch or a weak paste, and never says either value', async () => {
    const good = aPaste();
    const other = aPaste();
    const terminal = new ScriptedTerminal([], ['weak', other, good, good, good]);
    await expect(askPassword(terminal, 'the test login')).resolves.toBe(good);
    expect(terminal.hiddenQuestions).toEqual([
      'Paste the test login (nothing will show): ',
      'Paste the test login (nothing will show): ',
      'Paste it again: ',
      'Paste the test login (nothing will show): ',
      'Paste it again: ',
    ]);
    expect(terminal.said.some((line) => line.includes("won't do: it is shorter than 16"))).toBe(true);
    expect(terminal.said).toContain('The two pastes differ. Try again.');
    terminal.neverSaid([good, other]);
  });

  it('gives up after three tries', async () => {
    const terminal = new ScriptedTerminal([], ['weak', 'weak', 'weak']);
    await expect(askPassword(terminal, 'the test login')).rejects.toThrow(/No usable the test login after 3 tries/);
  });
});

describe('azInvocation', () => {
  it('elsewhere: runs az, with the pinned Bicep first on the PATH and the CLI told to use it', () => {
    const invocation = azInvocation(
      'linux',
      { PATH: '/usr/bin:/bin', HOME: '/home/op', UNSET: undefined },
      '/repo/.tools/bicep/bicep',
    );
    expect(invocation.command).toBe('az');
    expect(invocation.prefix).toEqual([]);
    expect(invocation.env).toEqual({
      PATH: '/repo/.tools/bicep:/usr/bin:/bin',
      HOME: '/home/op',
      AZURE_BICEP_USE_BINARY_FROM_PATH: 'true',
      AZURE_BICEP_CHECK_VERSION: 'false',
      AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no',
    });
  });

  it("on Windows: runs the CLI's own Python, keeps the one Path variable Windows has, and needs both files", () => {
    const cli = String.raw`C:\Program Files\Microsoft SDKs\Azure\CLI2`;
    const present = new Set([String.raw`${cli}\wbin\az.cmd`, String.raw`${cli}\python.exe`]);
    const invocation = azInvocation(
      'win32',
      { Path: String.raw`C:\Windows;${cli}\wbin` },
      String.raw`C:\repo\.tools\bicep\0.47.16\bicep.exe`,
      (file) => present.has(file),
    );
    expect(invocation.command).toBe(String.raw`${cli}\python.exe`);
    expect(invocation.prefix).toEqual(['-IBm', 'azure.cli']);
    expect(invocation.env.Path).toBe(String.raw`C:\repo\.tools\bicep\0.47.16;C:\Windows;${cli}\wbin`);
    expect(Object.keys(invocation.env).filter((name) => name.toUpperCase() === 'PATH')).toEqual(['Path']);
    expect(invocation.env.AZ_INSTALLER).toBe('MSI');
    expect(() => azInvocation('win32', { Path: String.raw`C:\Windows` }, 'C:\\bicep.exe', () => false)).toThrow(
      /Azure CLI is not on the PATH/,
    );
    expect(() =>
      azInvocation('win32', { Path: String.raw`${cli}\wbin` }, 'C:\\bicep.exe', (file) => file.endsWith('az.cmd')),
    ).toThrow(/own Python isn't at/);
  });
});

describe('deploymentName', () => {
  it('names what is deployed and when, within the 64 characters and the characters Azure allows', () => {
    const name = deploymentName('foundation', new Date('2026-09-16T16:42:15.123Z'));
    expect(name).toBe('agentx-staging-foundation-20260916T164215Z');
    expect(name.length).toBeLessThanOrEqual(64);
    expect(name).toMatch(/^[-\w.()]+$/);
  });
});

/** A terminal that answers from a script and records everything asked and said. */
class ScriptedTerminal implements Terminal {
  readonly said: string[] = [];
  readonly questions: string[] = [];
  readonly hiddenQuestions: string[] = [];
  readonly #answers: string[];
  readonly #hidden: string[];

  constructor(answers: readonly string[], hidden: readonly string[]) {
    this.#answers = [...answers];
    this.#hidden = [...hidden];
  }

  say(line: string): void {
    this.said.push(line);
  }

  ask(question: string): Promise<string> {
    this.questions.push(question);
    const answer = this.#answers.shift();
    return answer === undefined
      ? Promise.reject(new Error(`unexpected question: ${question}`))
      : Promise.resolve(answer);
  }

  askHidden(question: string): Promise<string> {
    this.hiddenQuestions.push(question);
    const answer = this.#hidden.shift();
    return answer === undefined
      ? Promise.reject(new Error(`unexpected hidden question: ${question}`))
      : Promise.resolve(answer);
  }

  /** Nothing the tool said or asked holds any of these. */
  neverSaid(values: readonly string[]): void {
    const everything = [...this.said, ...this.questions, ...this.hiddenQuestions].join('\n');
    for (const value of values.filter((each) => each !== '')) expect(everything).not.toContain(value);
  }
}

interface Call {
  readonly args: readonly string[];
  /** Only for the deployment itself: what went into its environment. */
  readonly values?: Readonly<Record<string, string>>;
}

/** A secret in the vault: its name, or its name and current version. */
type Held = string | { readonly name: string; readonly version: string };

/** How the vault lists a secret: its name and its current version's URL, never its value. */
const listed = (held: Held) => {
  const { name, version } = typeof held === 'string' ? { name: held, version: '1' } : held;
  return { name, properties: { secretUriWithVersion: `https://kv.example.invalid/secrets/${name}/${version}` } };
};

interface AzAnswers {
  /** What `az bicep version` prints. */
  readonly bicep?: string;
  /** The key vaults the resource group holds. */
  readonly vaults?: readonly string[];
  /**
   * The secrets the vault holds before the deployment, and after it: a name,
   * or a name and its current version (by default `1`, the same before and after).
   */
  readonly before?: readonly Held[];
  readonly after?: readonly Held[];
  /**
   * How Azure pages the vault's list: three a page, as on the first real run
   * (S19), each page linking to the next, and an empty page last. `emptyFirst`
   * puts an empty page before the rest; `nextLink` replaces every link; a list
   * that never ends keeps linking to its first page.
   */
  readonly pages?: { readonly emptyFirst?: boolean; readonly nextLink?: string; readonly endless?: boolean };
  /** The status the deployment command ends with: 0, or what a failure returns. */
  readonly status?: number;
  /**
   * How Azure says the deployment ended, read back afterwards. Declined: none
   * exists, as when the operator answers no — the CLI still ends with 0.
   */
  readonly ended?: string;
  /**
   * The alert group's email receivers, one list per reading, the last one
   * repeated; by default one address, switched on and confirmed.
   */
  readonly receivers?: readonly (readonly Receiver[])[];
  /** The alert group's own switch, as Azure answers it; on by default, left out when undefined. */
  readonly groupEnabled?: unknown;
  /** The environment as Azure answers it; by default with its address and verification code. */
  readonly environment?: unknown;
  /** Each app's name and replica minimum; by default all three kept running. */
  readonly apps?: readonly { readonly name: string; readonly fewest?: unknown }[];
  /** The environment's certificates after the deployment. */
  readonly certificates?: readonly unknown[];
  /**
   * How the migration job takes a record (T1b): kept (the default); no job yet
   * (a first deploy); the write refused; or kept by the write but missing
   * from the read back.
   */
  readonly record?: 'kept' | 'no job' | 'refused' | 'lost';
}

/** The migration job, which holds the records, as `az tag` names it. */
const RECORDS_JOB_ID = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/jobs/job-agentx-stg-migrate`;

/** The tag commands a recorded deploy runs, with the record it writes, by their first three words. */
const RECORDING = ['tag update --resource-id', 'tag list --resource-id'] as const;

const ENVIRONMENT_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/managedEnvironments/cae-agentx-staging`;
/** A made-up address from the documentation range, and a made-up code of the shape Azure gives. */
const ENVIRONMENT_IP = '192.0.2.10';
const VERIFICATION = 'AB'.repeat(32);
const ENVIRONMENT_DNS_PROPERTIES = {
  staticIp: ENVIRONMENT_IP,
  customDomainConfiguration: { customDomainVerificationId: VERIFICATION },
};
const KEPT_RUNNING = ['ca-agentx-stg-zitadel', 'ca-agentx-stg-api', 'ca-agentx-stg-login'].map((name) => ({
  name,
  fewest: 1,
}));

const APP_HOST = 'app.example.invalid';
const AUTH_HOST = 'auth.example.invalid';

/** A DNS that answers from a table, as the operator's resolver would, recording what it was asked. */
class TableDns implements DnsLookup {
  readonly asked: string[] = [];
  readonly #a: Readonly<Record<string, readonly string[]>>;
  readonly #txt: Readonly<Record<string, readonly string[]>>;

  constructor(a: Readonly<Record<string, readonly string[]>>, txt: Readonly<Record<string, readonly string[]>>) {
    this.#a = a;
    this.#txt = txt;
  }

  addresses(host: string): Promise<readonly string[]> {
    this.asked.push(`A ${host}`);
    return Promise.resolve(this.#a[host] ?? []);
  }

  texts(host: string): Promise<readonly string[]> {
    this.asked.push(`TXT ${host}`);
    return Promise.resolve(this.#txt[host] ?? []);
  }
}

/** Every record both doors need, in place. */
const readyDns = (): TableDns =>
  new TableDns(
    { [APP_HOST]: [ENVIRONMENT_IP], [AUTH_HOST]: [ENVIRONMENT_IP] },
    { [`asuid.${APP_HOST}`]: [VERIFICATION], [`asuid.${AUTH_HOST}`]: ['other-text', VERIFICATION] },
  );

/** As Azure answers; a field left undefined is one Azure didn't send. */
interface Receiver {
  readonly emailAddress?: string;
  readonly status?: string | undefined;
  readonly verificationStatus?: string | undefined;
}

const CONFIRMED: Receiver = { emailAddress: 'ops@example.invalid', status: 'Enabled', verificationStatus: 'Verified' };
const PENDING: Receiver = { ...CONFIRMED, verificationStatus: 'VerificationPending' };

const ACTION_GROUP_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.Insights/actionGroups/ag-agentx-stg?api-version=2026-03-01-preview`;

/** An Azure CLI that answers from the options and records every call. */
class RecordingAz implements Az {
  readonly calls: Call[] = [];
  readonly options: AzAnswers;
  /** The migration job's tags, as Azure holds them after each write. */
  readonly tags: Record<string, string | undefined> = { environment: 'staging', product: 'agent-x' };
  #deployed = false;
  #readings = 0;

  constructor(options: AzAnswers = {}) {
    this.options = options;
  }

  interactive(args: readonly string[], values: Readonly<Record<string, string>>): number | null {
    this.calls.push({ args, values });
    this.#deployed = true;
    return this.options.status ?? 0;
  }

  run(args: readonly string[]): AzResult {
    this.calls.push({ args });
    const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    switch (args.slice(0, 2).join(' ')) {
      case 'account show':
        return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
      case 'bicep version':
        return {
          status: 0,
          stdout: this.options.bicep ?? `Bicep CLI version ${BICEP_VERSION} (3f73e1a234)\n`,
          stderr: '',
        };
      case 'deployment sub':
      case 'deployment group': {
        const ended = this.options.ended ?? 'Succeeded';
        if (ended === 'Declined') {
          return {
            status: 3,
            stdout: '',
            stderr: "ERROR: (DeploymentNotFound) Deployment 'x' could not be found.\nCode: DeploymentNotFound\n",
          };
        }
        return json({ state: ended, outputs: { databaseHost: { type: 'String', value: 'db.example.invalid' } } });
      }
      case 'keyvault list':
        return json(this.options.vaults ?? ['kv-agentx-stg-abcdef']);
      case 'containerapp list':
        if (args.some((arg) => arg.includes('fewest'))) return json(this.options.apps ?? KEPT_RUNNING);
        return json([{ name: 'ca-agentx-stg-api', state: 'Succeeded' }]);
      case 'containerapp job':
        return json([{ name: 'job-agentx-stg-db-setup', state: 'Succeeded' }]);
      case 'tag update': {
        const record = this.options.record ?? 'kept';
        if (record === 'no job') {
          return {
            status: 3,
            stdout: '',
            stderr: `ERROR: (ResourceNotFound) The Resource 'Microsoft.App/jobs/job-agentx-stg-migrate' under resource group 'rg-agentx-staging' was not found.\nCode: ResourceNotFound\n`,
          };
        }
        if (record === 'refused') {
          return { status: 1, stdout: '', stderr: 'ERROR: (AuthorizationFailed) The client may not write tags.\n' };
        }
        const [name, value] = (args[args.indexOf('--tags') + 1] ?? '').split('=');
        if (record === 'kept' && name !== undefined) this.tags[name] = value;
        return json({ properties: { tags: this.tags } });
      }
      case 'tag list':
        return json({ properties: { tags: this.tags } });
      case 'rest --method': {
        const url = args[args.indexOf('--url') + 1] ?? '';
        if (url === `${ENVIRONMENT_URL}?api-version=2026-01-01`) {
          return json(this.options.environment ?? { properties: ENVIRONMENT_DNS_PROPERTIES });
        }
        if (url === `${ENVIRONMENT_URL}/managedCertificates?api-version=2026-01-01`) {
          return json({ value: this.options.certificates ?? [] });
        }
        if (url.includes('/actionGroups/')) {
          if (url !== ACTION_GROUP_URL) throw new Error(`unexpected action group read ${url}`);
          const readings = this.options.receivers ?? [[CONFIRMED]];
          const reading = readings[Math.min(this.#readings, readings.length - 1)];
          this.#readings += 1;
          const enabled = 'groupEnabled' in this.options ? this.options.groupEnabled : true;
          return json({ name: 'ag-agentx-stg', properties: { enabled, emailReceivers: reading } });
        }
        // Unless a test says otherwise, the vault holds the API's client secret, which apps needs (B2-6).
        const names = (this.#deployed ? this.options.after : this.options.before) ?? ['api-oidc-client-secret'];
        const pages = this.options.pages ?? {};
        const token = /[?&]\$skiptoken=(\d+|first)$/.exec(url)?.[1];
        const link = (next: string) => pages.nextLink ?? `${url.replace(/&\$skiptoken=.*$/, '')}&$skiptoken=${next}`;
        if (token === undefined && pages.emptyFirst === true) return json({ value: [], nextLink: link('0') });
        const from = token === undefined || token === 'first' ? 0 : Number(token);
        const page = names.slice(from, from + 3).map(listed);
        if (pages.endless === true) return json({ value: page, nextLink: link('first') });
        return json(from + 3 <= names.length ? { value: page, nextLink: link(String(from + 3)) } : { value: page });
      }
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  /** The commands, by their first two words, in the order they ran. */
  get sequence(): string[] {
    return this.calls.map((call) => call.args.slice(0, 3).join(' '));
  }

  get deployment(): Call | undefined {
    return this.calls.find((call) => call.values !== undefined);
  }
}

interface Scenario {
  readonly answers?: readonly string[];
  readonly hidden?: readonly string[];
  readonly az?: RecordingAz;
  readonly problems?: readonly string[];
  readonly rangesCurrent?: boolean;
  readonly images?: Images;
  readonly dns?: DnsLookup;
  /** The folder the run is in: at COMMIT with nothing changed unless given, and no way to read it for null. */
  readonly checkout?: Checkout | null;
}

/** One run of the tool, with everything it touched. */
async function run(argv: readonly string[], scenario: Scenario = {}) {
  const terminal = new ScriptedTerminal(scenario.answers ?? [], scenario.hidden ?? []);
  const az = scenario.az ?? new RecordingAz();
  const checked: Readonly<Record<string, string>>[] = [];
  const steps: Steps = {
    terminal,
    az,
    policy: (values) => {
      checked.push(values);
      return [...(scenario.problems ?? [])];
    },
    rangesCurrent: () => scenario.rangesCurrent ?? true,
    now: () => new Date('2026-09-16T16:42:15Z'),
    makers: quickMakers(),
    ...(scenario.images === undefined ? {} : { images: scenario.images }),
    ...(scenario.dns === undefined ? {} : { dns: scenario.dns }),
    ...(scenario.checkout === null ? {} : { checkout: () => scenario.checkout ?? { head: COMMIT, clean: true } }),
  };
  const outcome = await deploy(parseArguments(argv), steps).then(
    (status) => ({ status, error: undefined }),
    (error: unknown) => ({ status: undefined, error }),
  );
  return { ...outcome, terminal, az, checked };
}

describe('deploy foundation', () => {
  it('confirms the subscription and the compiler, checks the rules, then deploys with the secret in the environment alone', async () => {
    const admin = aPaste();
    const done = await run(['foundation'], { answers: ['y', 'ops@example.invalid'], hidden: [admin, admin] });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'bicep version',
      'deployment sub create',
      'deployment sub show',
      ...RECORDING,
      'rest --method get',
    ]);
    // The commit it sent, recorded on the migration job once Azure said it succeeded, and read back.
    expect(done.az.calls.find((call) => call.args[1] === 'update')?.args).toEqual([
      'tag',
      'update',
      '--resource-id',
      RECORDS_JOB_ID,
      '--operation',
      'Merge',
      '--tags',
      `agentx-deployed-foundation=${COMMIT}`,
      '--output',
      'json',
    ]);
    expect(done.az.tags['agentx-deployed-foundation']).toBe(COMMIT);
    expect(done.terminal.said).toContain(
      `Recorded on job-agentx-stg-migrate: foundation sent ${COMMIT}. CI's release takes it for what foundation reads.`,
    );
    const deployment = done.az.deployment;
    expect(deployment?.args).toEqual([
      'deployment',
      'sub',
      'create',
      '--subscription',
      SUBSCRIPTION,
      '--location',
      'uaenorth',
      '--name',
      'agentx-staging-foundation-20260916T164215Z',
      '--parameters',
      'staging.bicepparam',
      '--confirm-with-what-if',
    ]);
    expect(deployment?.values).toEqual({
      AGENTX_AZURE_ALERT_EMAIL: 'ops@example.invalid',
      AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD: admin,
    });
    // The rules saw the run's values; the real check shapes them before any snapshot (shapedForPolicy).
    expect(done.checked).toEqual([deployment?.values]);
    for (const call of done.az.calls) expect(call.args.join(' ')).not.toContain(admin);
    done.terminal.neverSaid([admin]);
    expect(done.terminal.said).toContain('  databaseHost: db.example.invalid');
    expect(done.terminal.said.at(-1)).toBe('Alert email: confirmed, so every alert reaches it.');
    expect(done.terminal.questions).toHaveLength(2);
  });

  it('waits for a new alert address to be confirmed, since Azure sends it nothing until then', async () => {
    const admin = aPaste();
    const done = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid', ''],
      hidden: [admin, admin],
      az: new RecordingAz({ receivers: [[PENDING], [CONFIRMED]] }),
    });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.terminal.said).toContain(
      "No alert email reaches:\n  ops@example.invalid: it isn't confirmed (VerificationPending)",
    );
    expect(done.terminal.said.join('\n')).toMatch(/one-time code, valid for 30 minutes.*Action groups, ag-agentx-stg/s);
    expect(done.terminal.questions.at(-1)).toBe('Press Enter once the address is confirmed, or type skip: ');
    expect(done.terminal.said.at(-1)).toBe('Alert email: confirmed, so every alert reaches it.');
    expect(done.az.sequence.filter((call) => call === 'rest --method get')).toHaveLength(2);
  });

  it('ends with failure, the deployment kept, when the address is still unconfirmed or the operator skips', async () => {
    const admin = aPaste();
    const unconfirmed = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid', '', '', ''],
      hidden: [admin, admin],
      az: new RecordingAz({ receivers: [[PENDING]] }),
    });
    expect(unconfirmed.error).toBeUndefined();
    expect(unconfirmed.status).toBe(1);
    expect(unconfirmed.az.sequence.filter((call) => call === 'rest --method get')).toHaveLength(4);
    expect(unconfirmed.terminal.said.at(-1)).toBe(
      'The foundation is deployed, but no alert email can reach you yet. Once the address is confirmed, run node deploy/azure/deploy.ts alerts to check.',
    );
    // The instructions are given once, not on every reading.
    expect(unconfirmed.terminal.said.filter((line) => line.includes('one-time code'))).toHaveLength(1);
    const skipped = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid', 'SKIP'],
      hidden: [admin, admin],
      az: new RecordingAz({ receivers: [[PENDING], [CONFIRMED]] }),
    });
    expect(skipped.status).toBe(1);
    expect(skipped.az.sequence.filter((call) => call === 'rest --method get')).toHaveLength(1);
  });

  it('stops before asking for anything when the operator declines the subscription', async () => {
    const done = await run(['foundation'], { answers: ['n'] });
    expect(done.error).toBeInstanceOf(Cancelled);
    expect(done.az.sequence).toEqual(['account show --output']);
    expect(done.terminal.hiddenQuestions).toEqual([]);
  });

  it('stops before asking for anything when the CLI would compile with another Bicep, or GitHub has moved', async () => {
    const otherBicep = await run(['foundation'], {
      answers: ['y'],
      az: new RecordingAz({ bicep: 'Bicep CLI version 0.99.0 (abc)\n' }),
    });
    expect(otherBicep.error).toMatchObject({
      message: expect.stringMatching(/isn't using the pinned Bicep/) as unknown,
    });
    expect(otherBicep.terminal.hiddenQuestions).toEqual([]);
    const moved = await run(['foundation'], { answers: ['y'], rangesCurrent: false });
    expect(moved.error).toMatchObject({
      message: expect.stringMatching(/published addresses have changed/) as unknown,
    });
    expect(moved.terminal.hiddenQuestions).toEqual([]);
    expect(moved.az.deployment).toBeUndefined();
  });

  it('sends nothing when the address is no address, or the rules refuse the deployment', async () => {
    const noAddress = await run(['foundation'], { answers: ['y', 'not an address'] });
    expect(noAddress.error).toMatchObject({ message: expect.stringMatching(/isn't an email address/) as unknown });
    expect(noAddress.az.deployment).toBeUndefined();
    const admin = aPaste();
    const refused = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid'],
      hidden: [admin, admin],
      problems: ['vnet [apps-egress] a door nothing needs'],
    });
    expect(refused.error).toMatchObject({ message: expect.stringMatching(/breaks the project's rules/) as unknown });
    expect(refused.az.deployment).toBeUndefined();
  });

  it('reports failure, and reads nothing back, when the what-if is declined or the deployment fails', async () => {
    const admin = aPaste();
    const done = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid'],
      hidden: [admin, admin],
      az: new RecordingAz({ status: 1 }),
    });
    expect(done.status).toBe(1);
    expect(done.az.sequence).not.toContain('deployment sub show');
  });
});

describe('alerts', () => {
  it('reads the alert group without asking to deploy or for any secret, and sends nothing', async () => {
    const done = await run(['alerts']);
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual(['account show --output', 'rest --method get']);
    expect(done.az.deployment).toBeUndefined();
    expect(done.terminal.questions).toEqual([]);
    expect(done.terminal.hiddenQuestions).toEqual([]);
    expect(done.terminal.said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      'Reading ag-agentx-stg in rg-agentx-staging; nothing is changed.',
      'Alert email: confirmed, so every alert reaches it.',
    ]);
  });

  it('names each address that gets nothing, and why, leaving out the ones that are fine', async () => {
    const other = { ...CONFIRMED, emailAddress: 'second@example.invalid' };
    const done = await run(['alerts'], {
      answers: ['skip'],
      az: new RecordingAz({
        receivers: [
          [
            CONFIRMED,
            { ...other, status: 'Disabled' },
            { ...other, emailAddress: 'third@example.invalid', verificationStatus: undefined },
            { ...other, emailAddress: 'fourth@example.invalid', status: undefined },
          ],
        ],
      }),
    });
    expect(done.status).toBe(1);
    expect(done.terminal.said).toContain(
      [
        'No alert email reaches:',
        '  second@example.invalid: Azure has it switched off (Disabled)',
        "  third@example.invalid: it isn't confirmed (Azure did not say)",
        '  fourth@example.invalid: Azure has it switched off (no status)',
      ].join('\n'),
    );
    expect(done.terminal.said.at(-1)).toBe('Until that changes, no alert email reaches you.');
  });

  it('counts an address switched off as unreached even when it is confirmed', async () => {
    const done = await run(['alerts'], {
      answers: ['skip'],
      az: new RecordingAz({ receivers: [[{ ...CONFIRMED, status: 'Disabled' }]] }),
    });
    expect(done.status).toBe(1);
  });

  it('counts every address unreached when the group itself is off, or Azure does not say it is on', async () => {
    for (const groupEnabled of [false, undefined, 'true']) {
      const done = await run(['alerts'], { answers: ['skip'], az: new RecordingAz({ groupEnabled }) });
      expect({ groupEnabled, status: done.status }).toEqual({ groupEnabled, status: 1 });
      expect(done.terminal.said).toContain(
        'No alert email reaches:\n  every address: ag-agentx-stg itself is switched off',
      );
    }
  });

  it('refuses a group with no email address', async () => {
    const done = await run(['alerts'], { az: new RecordingAz({ receivers: [[]] }) });
    expect(done.error).toMatchObject({ message: 'ag-agentx-stg has no email address, so no alert is emailed.' });
  });
});

describe("what a secrets run did to the app's keys", () => {
  const vault = (versions: Readonly<Record<string, string>>) =>
    Object.entries(versions).map(([name, version]) => ({ name, version }));
  const every = (version: string) => Object.fromEntries(APP_KEYS.map((key) => [key, version]));

  it('accepts every key there, each the version it was, or new', () => {
    expect(keyProblems(vault(every('v1')), vault(every('v1')))).toEqual([]);
    expect(keyProblems([], vault(every('v1')))).toEqual([]);
    // Another secret written again is no key's business.
    const other = 'zitadel-masterkey';
    expect(keyProblems(vault({ [other]: 'v1' }), vault({ ...every('v1'), [other]: 'v2' }))).toEqual([]);
  });

  it('names each key missing, and each written again', () => {
    const { 'key-audit-anchor-v1': _gone, ...rest } = every('v1');
    expect(keyProblems([], vault(rest))).toEqual([
      "key-audit-anchor-v1 isn't in the vault, so the API won't start: run secrets --keys again",
    ]);
    expect(keyProblems(vault(every('v1')), vault({ ...every('v1'), 'key-payee-index-v1': 'v2' }))).toEqual([
      'key-payee-index-v1 was written again, so what it sealed may not open and what it signed may not check: stop, and follow Azure.md, "A key written again"',
    ]);
  });
});

describe('deploy secrets', () => {
  /** What a first --all writes: every secret but the one Zitadel issues, which only its name writes (B2-6). */
  const nine = Object.keys(VAULT_SECRETS).filter((name) => VAULT_SECRETS[name]?.source !== 'issued');
  /** Every secret a deployment leaves: the nine and the app's keys. */
  const everything = [...nine, ...APP_KEYS];

  it('on a first run, asks for both pastes, writes every secret, and lists the vault afterwards', async () => {
    const admin = aPaste();
    const zitadel = aPaste();
    const done = await run(['secrets', '--all'], {
      answers: ['y'],
      hidden: [admin, admin, zitadel, zitadel],
      az: new RecordingAz({ before: [], after: everything }),
    });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'bicep version',
      'keyvault list --subscription',
      'rest --method get',
      'deployment group create',
      'deployment group show',
      // Fifteen secrets, three a page, and the empty page Azure ends with.
      ...Array<string>(6).fill('rest --method get'),
      ...RECORDING,
    ]);
    expect(done.az.tags['agentx-deployed-secrets']).toBe(COMMIT);
    const deployment = done.az.deployment;
    expect(deployment?.args).toContain('staging.secrets.bicepparam');
    expect(deployment?.args).toContain(RESOURCE_GROUP);
    const values = deployment?.values ?? {};
    // All but the API's client secret, which Zitadel issues later and only its name writes.
    expect(
      Object.entries(values)
        .filter(([, value]) => value === '')
        .map(([name]) => name),
    ).toEqual(['AGENTX_AZURE_API_OIDC_CLIENT_SECRET']);
    expect(values.AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD).toBe(admin);
    expect(values.AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD).toBe(zitadel);
    for (const call of done.az.calls) {
      for (const value of Object.values(values).filter((given) => given !== '')) {
        expect(call.args.join(' ')).not.toContain(value);
      }
    }
    done.terminal.neverSaid(Object.values(values));
    expect(done.terminal.said.slice(-17, -2)).toEqual([...everything].sort().map((name) => `  ${name}`));
    expect(done.terminal.said.slice(-2)).toEqual([
      "The app's 6 keys are there, and none that was there before was written again.",
      `Recorded on job-agentx-stg-migrate: secrets sent ${COMMIT}. CI's release takes it for what secrets reads.`,
    ]);
  });

  it('on a vault that already has secrets, --all goes on only when the operator types the words', async () => {
    const declined = await run(['secrets', '--all'], {
      answers: ['y', 'yes'],
      az: new RecordingAz({ before: nine }),
    });
    expect(declined.error).toBeInstanceOf(Cancelled);
    expect(declined.terminal.hiddenQuestions).toEqual([]);
    expect(declined.az.deployment).toBeUndefined();
    const admin = aPaste();
    const zitadel = aPaste();
    const agreed = await run(['secrets', '--all'], {
      answers: ['y', 'rotate everything'],
      hidden: [admin, admin, zitadel, zitadel],
      az: new RecordingAz({ before: nine, after: everything }),
    });
    expect(agreed.status).toBe(0);
  });

  it('reads every page of the vault, so a first page that happens to be empty still counts as secrets held', async () => {
    const declined = await run(['secrets', '--all'], {
      answers: ['y', 'yes'],
      az: new RecordingAz({ before: nine, pages: { emptyFirst: true } }),
    });
    expect(declined.error).toBeInstanceOf(Cancelled);
    expect(declined.terminal.said).toContainEqual(expect.stringMatching(/^The vault already holds 9 secrets\./));
    expect(declined.az.deployment).toBeUndefined();
  });

  it('refuses a vault list that leads outside Azure Resource Manager, or never ends, before deploying', async () => {
    const elsewhere = 'https://example.invalid/secrets?$skiptoken=3';
    const outside = await run(['secrets', '--all'], {
      answers: ['y'],
      az: new RecordingAz({ before: nine, pages: { nextLink: elsewhere } }),
    });
    expect(outside.error).toMatchObject({
      message: expect.stringMatching(/outside Azure Resource Manager/) as unknown,
    });
    expect(outside.az.calls.map((call) => call.args.join(' '))).not.toContainEqual(expect.stringContaining(elsewhere));
    expect(outside.az.deployment).toBeUndefined();
    const endless = await run(['secrets', '--all'], {
      answers: ['y'],
      az: new RecordingAz({ before: nine, pages: { endless: true } }),
    });
    expect(endless.error).toMatchObject({ message: expect.stringMatching(/went past 100 pages/) as unknown });
    expect(endless.az.sequence.filter((command) => command === 'rest --method get')).toHaveLength(100);
    expect(endless.az.deployment).toBeUndefined();
  });

  it("on a rotation of the API's client secret, takes Zitadel's as pasted, twice, and writes it alone (B2-6)", async () => {
    const issued = 'aB3d'.repeat(16);
    const done = await run(['secrets', '--rotate', 'api-oidc-client-secret'], {
      answers: ['y'],
      hidden: [issued, issued],
      az: new RecordingAz({ before: everything, after: [...everything, 'api-oidc-client-secret'] }),
    });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.terminal.hiddenQuestions).toEqual([
      "Paste the API's client secret, as Zitadel showed it (nothing will show): ",
      'Paste it again: ',
    ]);
    const values = done.az.deployment?.values ?? {};
    expect(values.AGENTX_AZURE_API_OIDC_CLIENT_SECRET).toBe(issued);
    expect(
      Object.entries(values)
        .filter(([, value]) => value !== '')
        .map(([variable]) => variable)
        .sort(),
    ).toEqual(['AGENTX_AZURE_API_OIDC_CLIENT_SECRET', 'AGENTX_AZURE_APP_KEYS', 'AGENTX_AZURE_ZITADEL_MASTERKEY']);
    expect(done.terminal.said.join('\n')).not.toContain(issued);
    expect(done.terminal.said.join('\n')).not.toMatch(/set-up job/);
  });

  it('on a rotation, asks for nothing, writes the named login and the master key, and says to run the set-up job', async () => {
    const done = await run(['secrets', '--rotate', 'db-app-password'], {
      answers: ['y'],
      az: new RecordingAz({ before: everything, after: everything }),
    });
    expect(done.status).toBe(0);
    expect(done.terminal.hiddenQuestions).toEqual([]);
    const written = Object.entries(done.az.deployment?.values ?? {})
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable)
      .sort();
    expect(written).toEqual([
      'AGENTX_AZURE_APP_KEYS',
      'AGENTX_AZURE_DB_APP_PASSWORD',
      'AGENTX_AZURE_ZITADEL_MASTERKEY',
    ]);
    expect(done.terminal.said.at(-1)).toMatch(/start the set-up job now/);
  });

  it('on a keys run, asks for nothing, writes only the keys and the master key, and checks every key is there', async () => {
    const done = await run(['secrets', '--keys'], {
      answers: ['y'],
      az: new RecordingAz({ before: nine, after: everything }),
    });
    expect(done.status).toBe(0);
    expect(done.terminal.hiddenQuestions).toEqual([]);
    expect(done.terminal.said).not.toContainEqual(expect.stringMatching(/already holds/));
    const written = Object.entries(done.az.deployment?.values ?? {})
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable)
      .sort();
    expect(written).toEqual(['AGENTX_AZURE_APP_KEYS', 'AGENTX_AZURE_ZITADEL_MASTERKEY']);
    done.terminal.neverSaid(Object.values(done.az.deployment?.values ?? {}).filter((value) => value !== ''));
    expect(done.terminal.said.at(-2)).toBe(
      "The app's 6 keys are there, and none that was there before was written again.",
    );
    expect(done.az.tags['agentx-deployed-secrets']).toBe(COMMIT);
  });

  it('ends red when a key the vault held was written again, naming it and never a value', async () => {
    const done = await run(['secrets', '--keys'], {
      answers: ['y'],
      az: new RecordingAz({
        before: everything,
        after: everything.map((name) => (name === 'key-audit-mac-v1' ? { name, version: '2' } : name)),
      }),
    });
    expect(done.status).toBe(1);
    expect(done.terminal.said.at(-1)).toBe(
      'key-audit-mac-v1 was written again, so what it sealed may not open and what it signed may not check: stop, and follow Azure.md, "A key written again"',
    );
  });

  it('ends red when a key is missing after the run, since the API would refuse to start', async () => {
    const done = await run(['secrets', '--keys'], {
      answers: ['y'],
      az: new RecordingAz({ before: nine, after: everything.filter((name) => name !== 'key-audit-anchor-v1') }),
    });
    expect(done.status).toBe(1);
    expect(done.terminal.said.at(-1)).toBe(
      "key-audit-anchor-v1 isn't in the vault, so the API won't start: run secrets --keys again",
    );
  });

  it('refuses before asking anything when the foundation has no vault', async () => {
    const done = await run(['secrets', '--all'], { answers: ['y'], az: new RecordingAz({ vaults: [] }) });
    expect(done.error).toMatchObject({ message: expect.stringMatching(/deploy the foundation first/) as unknown });
    expect(done.terminal.hiddenQuestions).toEqual([]);
  });
});

/** An image source that answers from the options and records what it was asked. */
function recordingImages(
  options: { readonly commit?: string; readonly digest?: string; readonly refuse?: boolean } = {},
): Images & { readonly asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    latestCommit: () => {
      asked.push('latest');
      return Promise.resolve(options.commit ?? COMMIT);
    },
    digestOf: (commit) => {
      asked.push(`digest ${commit}`);
      return Promise.resolve(options.digest ?? DIGEST);
    },
    verify: (image, commit) => {
      asked.push(`verify ${image} ${commit}`);
      return options.refuse === true
        ? { verified: false, reason: 'SIGNATURE_REFUSED', detail: 'not signed by CI on main' }
        : { verified: true };
    },
  };
}

/** The API's client ID in Zitadel, as its app's page shows one. */
const CLIENT_ID = '338719472394810051';

describe('deploy apps', () => {
  const answers = ['y', 'Auth.Example.invalid', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID];

  it("sends nothing, and asks nothing past the subscription, while the vault lacks the API's client secret (B2-6)", async () => {
    const images = recordingImages();
    const done = await run(['apps'], { answers, images, az: new RecordingAz({ before: ['db-app-password'] }) });
    expect(done.error).toMatchObject({
      message: expect.stringMatching(
        /^The vault doesn't hold api-oidc-client-secret yet, .*secrets --rotate api-oidc-client-secret .*Nothing was deployed\.$/,
      ) as unknown,
    });
    expect(done.az.deployment).toBeUndefined();
    expect(images.asked).toEqual([]);
    // Only which subscription, before the vault is read.
    expect(done.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
  });

  it('names only the issued secrets a vault lacks', () => {
    expect(issuedMissing([])).toEqual(['api-oidc-client-secret']);
    expect(issuedMissing(['db-app-password', 'api-oidc-client-secret'])).toEqual([]);
  });

  it("deploys main's newest image only once it is verified, by digest, with the hosts as typed", async () => {
    const images = recordingImages();
    const done = await run(['apps'], { answers, images });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(images.asked).toEqual([
      'latest',
      `digest ${COMMIT}`,
      `verify ghcr.io/shahbaz242630/agent-x@${DIGEST} ${COMMIT}`,
    ]);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'bicep version',
      // The vault holds the API's client secret, which the API reads (B2-6).
      'keyvault list --subscription',
      'rest --method get',
      'deployment group create',
      'deployment group show',
      'containerapp list --subscription',
      'containerapp job list',
    ]);
    const deployment = done.az.deployment;
    expect(deployment?.args).toContain('staging.apps.bicepparam');
    expect(deployment?.args).toContain('--confirm-with-what-if');
    expect(deployment?.values).toEqual({
      AGENTX_AZURE_APP_IMAGE_DIGEST: DIGEST,
      AGENTX_AZURE_RELEASE: COMMIT,
      AGENTX_AZURE_AUTH_HOST: 'auth.example.invalid',
      AGENTX_AZURE_APP_HOST: 'app.example.invalid',
      AGENTX_AZURE_ZITADEL_ADMIN_EMAIL: 'admin@example.invalid',
      AGENTX_AZURE_API_OIDC_CLIENT_ID: CLIENT_ID,
      AGENTX_AZURE_APP_MIN_REPLICAS: '0',
    });
    expect(done.checked).toEqual([deployment?.values]);
    expect(done.terminal.said).toContain('Each app will scale to zero while nothing uses it.');
    expect(done.terminal.said.join('\n')).not.toContain('--keep-running');
    expect(done.terminal.said).toContain('  ca-agentx-stg-api: Succeeded');
    expect(done.terminal.said).toContain('  job-agentx-stg-db-setup: Succeeded');
    // The doors are deployed with the apps, but serve nothing until DNS points at them.
    expect(done.terminal.said.slice(-2)[0]).toBe(
      "A public door answers once its host's DNS records point at the environment (G3b).",
    );
    // Which jobs come next depends on the deploy, so the tool says when each is needed.
    expect(done.terminal.said.slice(-1)[0]).toMatch(
      /^On a first deploy, run the four jobs next, in order \(deploy\/azure\/jobs\.ts\)\. Later, run migrate when a release adds a migration, and zitadel-setup when Zitadel moves to a new version\.$/,
    );
  });

  it('keeps one replica of each app running when asked, and says so before and after', async () => {
    const done = await run(['apps', '--keep-running'], { answers, images: recordingImages() });
    expect(done.status).toBe(0);
    const values = done.az.deployment?.values;
    expect(values?.AGENTX_AZURE_APP_MIN_REPLICAS).toBe('1');
    expect(done.checked).toEqual([values]);
    const said = done.terminal.said;
    const before = said.indexOf(
      'Each app will keep one replica running, billed, until apps runs again without --keep-running.',
    );
    const after = said.indexOf(
      'Each app now keeps one replica running, billed: run apps without --keep-running to stop it.',
    );
    expect(before).toBeGreaterThan(-1);
    expect(before).toBeLessThan(said.findIndex((line) => line.startsWith("Azure's what-if follows")));
    expect(after).toBe(said.length - 1);
    expect(said).not.toContain('Each app will scale to zero while nothing uses it.');
  });

  it('says nothing about a running replica when a kept-running deployment fails', async () => {
    const done = await run(['apps', '--keep-running'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ status: 1 }),
    });
    expect(done.status).toBe(1);
    expect(done.terminal.said.join('\n')).not.toContain('now keeps one replica');
  });

  it('deploys the commit it is given, without asking GitHub for the newest', async () => {
    const other = 'c'.repeat(40);
    const images = recordingImages();
    const done = await run(['apps', '--commit', other], { answers, images, checkout: { head: other, clean: true } });
    expect(done.status).toBe(0);
    expect(images.asked[0]).toBe(`digest ${other}`);
    expect(done.az.deployment?.values?.AGENTX_AZURE_RELEASE).toBe(other);
  });

  it("sends nothing unless this folder is exactly the commit the apps are stamped with, since CI's release reads the stamp", async () => {
    const other = 'c'.repeat(40);
    for (const [checkout, where] of [
      [{ head: other, clean: true }, other],
      [{ head: COMMIT, clean: false }, `${COMMIT} with changes not committed`],
      [{ head: other, clean: false }, `${other} with changes not committed`],
    ] as const) {
      const images = recordingImages();
      const done = await run(['apps'], { answers, images, checkout });
      expect(done.error).toMatchObject({
        message: `This folder is at ${where}, but the image is for ${COMMIT}. apps sends this folder's Bicep and stamps the apps with ${COMMIT}, so the two must be the same commit, with nothing changed (git switch main, then git pull). Nothing was deployed.`,
      });
      // Nothing asked past the subscription, and the image not even looked up.
      expect(done.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
      expect(images.asked).toEqual(['latest']);
      expect(done.az.deployment).toBeUndefined();
    }
    const done = await run(['apps'], { answers, images: recordingImages(), checkout: null });
    expect(done.error).toMatchObject({ message: 'No way to read this folder was given.' });
    expect(done.az.deployment).toBeUndefined();
  });

  it('asks nothing and sends nothing when the image is refused, or the registry or GitHub answer nonsense', async () => {
    for (const [images, reason] of [
      [
        recordingImages({ refuse: true }),
        /refused \(SIGNATURE_REFUSED\), so nothing was deployed:\nnot signed by CI on main/,
      ],
      [recordingImages({ digest: 'sha256:short' }), /isn't one/],
      [recordingImages({ digest: '' }), /isn't one/],
      [recordingImages({ commit: 'main' }), /main's newest commit, which isn't one/],
    ] as const) {
      const done = await run(['apps'], { answers: ['y'], images });
      expect(done.error).toMatchObject({ message: expect.stringMatching(reason) as unknown });
      expect(done.az.deployment).toBeUndefined();
      expect(done.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
    }
  });

  it('sends nothing for a host that is no host, the same host twice, or an address that is no address', async () => {
    for (const [typed, reason] of [
      [['y', 'auth example', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID], /isn't a host name/],
      [['y', 'localhost', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID], /isn't a host name/],
      [['y', '-auth.example.invalid', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID], /isn't a host name/],
      [
        ['y', 'https://auth.example.invalid', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID],
        /isn't a host name/,
      ],
      [
        ['y', 'auth.example.invalid', 'AUTH.example.invalid', 'admin@example.invalid', CLIENT_ID],
        /two hosts must differ/,
      ],
      [['y', 'auth.example.invalid', 'app.example.invalid', 'admin'], /isn't an email address/],
      [['y', 'auth.example.invalid', 'app.example.invalid', 'admin@example.invalid', 'two words'], /isn't a client ID/],
      [['y', 'auth.example.invalid', 'app.example.invalid', 'admin@example.invalid', ''], /isn't a client ID/],
    ] as const) {
      const done = await run(['apps'], { answers: typed, images: recordingImages() });
      expect(done.error).toMatchObject({ message: expect.stringMatching(reason) as unknown });
      expect(done.az.deployment).toBeUndefined();
    }
  });

  it('reports failure, and lists nothing, when the what-if is declined', async () => {
    const done = await run(['apps'], { answers, images: recordingImages(), az: new RecordingAz({ status: 1 }) });
    expect(done.status).toBe(1);
    expect(done.az.sequence).not.toContain('containerapp list --subscription');
  });

  it('refuses to run without a way to find the image', async () => {
    const done = await run(['apps'], { answers });
    expect(done.error).toMatchObject({ message: 'No way to find the image was given.' });
    expect(done.az.calls).toEqual([]);
  });
});

describe('the records a door needs', () => {
  const environment = { ip: ENVIRONMENT_IP, verification: VERIFICATION };

  it('asks for an A record and an asuid TXT record per host, in the order given', async () => {
    const dns = readyDns();
    const records = await doorRecords(dns, [APP_HOST, AUTH_HOST], environment);
    expect(records.map((record) => [record.type, record.name, record.value, record.ready])).toEqual([
      ['A', APP_HOST, ENVIRONMENT_IP, true],
      ['TXT', `asuid.${APP_HOST}`, VERIFICATION, true],
      ['A', AUTH_HOST, ENVIRONMENT_IP, true],
      ['TXT', `asuid.${AUTH_HOST}`, VERIFICATION, true],
    ]);
    expect(dns.asked).toEqual([`A ${APP_HOST}`, `TXT asuid.${APP_HOST}`, `A ${AUTH_HOST}`, `TXT asuid.${AUTH_HOST}`]);
  });

  it('counts an A record ready only when the environment is the one address, and a TXT only when it holds the code', async () => {
    for (const [addresses, ready] of [
      [[], false],
      [['192.0.2.99'], false],
      [[ENVIRONMENT_IP, '192.0.2.99'], false],
      [[ENVIRONMENT_IP], true],
    ] as const) {
      const [record] = await doorRecords(new TableDns({ [APP_HOST]: addresses }, {}), [APP_HOST], environment);
      expect({ addresses, ready: record?.ready, answers: record?.answers }).toEqual({
        addresses,
        ready,
        answers: addresses,
      });
    }
    for (const [texts, ready] of [
      [[], false],
      [['something else'], false],
      [[VERIFICATION.toLowerCase()], false],
      [[`${VERIFICATION} `], false],
      [['something else', VERIFICATION], true],
    ] as const) {
      const [, record] = await doorRecords(new TableDns({}, { [`asuid.${APP_HOST}`]: texts }), [APP_HOST], environment);
      expect({ texts, ready: record?.ready }).toEqual({ texts, ready });
    }
  });
});

describe('realDns', () => {
  const failing = (code: string) => () => Promise.reject(Object.assign(new Error(`queryA ${code} host`), { code }));

  it('joins a TXT record’s strings and treats a missing name or record as none', async () => {
    const dns = realDns({
      resolve4: (host: string) => Promise.resolve(host === 'one.example.invalid' ? ['192.0.2.1'] : []),
      resolveTxt: () => Promise.resolve([['AB', 'CD'], ['EF']]),
    } as unknown as Parameters<typeof realDns>[0]);
    expect(await dns.addresses('one.example.invalid')).toEqual(['192.0.2.1']);
    expect(await dns.texts('asuid.one.example.invalid')).toEqual(['ABCD', 'EF']);
    for (const code of ['ENOTFOUND', 'ENODATA']) {
      const none = realDns({ resolve4: failing(code), resolveTxt: failing(code) });
      expect(await none.addresses('gone.example.invalid')).toEqual([]);
      expect(await none.texts('gone.example.invalid')).toEqual([]);
    }
  });

  it('fails, naming the host, when the lookup itself fails', async () => {
    const broken = realDns({ resolve4: failing('ETIMEOUT'), resolveTxt: failing('ESERVFAIL') });
    await expect(broken.addresses('slow.example.invalid')).rejects.toThrow(
      'Looking up slow.example.invalid failed: Error: queryA ETIMEOUT host',
    );
    await expect(broken.texts('asuid.slow.example.invalid')).rejects.toThrow(
      'Looking up asuid.slow.example.invalid failed: Error: queryA ESERVFAIL host',
    );
  });
});

describe('dns', () => {
  const hosts = ['Auth.Example.invalid', APP_HOST];

  it('says each record is in place, changing nothing, and ends 0', async () => {
    const dns = readyDns();
    const done = await run(['dns'], { answers: hosts, dns });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual(['account show --output', `rest --method get`]);
    expect(done.az.deployment).toBeUndefined();
    expect(done.terminal.questions).toEqual(['Host for sign-in (Zitadel): ', 'Host for the app (the API): ']);
    expect(done.terminal.said.slice(-5)).toEqual([
      `  A    ${APP_HOST}  ${ENVIRONMENT_IP}  (in place)`,
      `  TXT  asuid.${APP_HOST}  ${VERIFICATION}  (in place)`,
      `  A    ${AUTH_HOST}  ${ENVIRONMENT_IP}  (in place)`,
      `  TXT  asuid.${AUTH_HOST}  ${VERIFICATION}  (in place)`,
      'Every record is in place.',
    ]);
  });

  it('marks a record missing or wrong, and ends 1', async () => {
    const dns = new TableDns(
      { [APP_HOST]: ['192.0.2.99', ENVIRONMENT_IP] },
      { [`asuid.${AUTH_HOST}`]: [VERIFICATION] },
    );
    const done = await run(['dns'], { answers: hosts, dns });
    expect(done.status).toBe(1);
    expect(done.terminal.said.slice(-5)).toEqual([
      `  A    ${APP_HOST}  ${ENVIRONMENT_IP}  (WRONG: it answers 192.0.2.99, ${ENVIRONMENT_IP})`,
      `  TXT  asuid.${APP_HOST}  ${VERIFICATION}  (MISSING)`,
      `  A    ${AUTH_HOST}  ${ENVIRONMENT_IP}  (MISSING)`,
      `  TXT  asuid.${AUTH_HOST}  ${VERIFICATION}  (in place)`,
      'Add or fix the records marked above. A new record can take a few minutes to show.',
    ]);
  });

  it('refuses an environment Azure gives no address or code for, and hosts that are no hosts', async () => {
    for (const environment of [
      {},
      { properties: { ...ENVIRONMENT_DNS_PROPERTIES, staticIp: '' } },
      { properties: { ...ENVIRONMENT_DNS_PROPERTIES, staticIp: '192.0.2.256' } },
      { properties: { ...ENVIRONMENT_DNS_PROPERTIES, customDomainConfiguration: {} } },
      {
        properties: {
          ...ENVIRONMENT_DNS_PROPERTIES,
          customDomainConfiguration: { customDomainVerificationId: 'ab'.repeat(32) },
        },
      },
    ]) {
      const done = await run(['dns'], { answers: hosts, dns: readyDns(), az: new RecordingAz({ environment }) });
      expect(done.error).toMatchObject({
        message:
          'Azure gave no public address and verification code for cae-agentx-staging: deploy the foundation first.',
      });
    }
    const same = await run(['dns'], { answers: [APP_HOST, APP_HOST], dns: readyDns() });
    expect(same.error).toMatchObject({ message: 'The two hosts must differ: nothing was deployed.' });
    const none = await run(['dns'], { answers: hosts });
    expect(none.error).toMatchObject({ message: 'No way to look up DNS was given.' });
    expect(none.az.calls).toEqual([]);
  });
});

describe('what a hand deploy records (T1b)', () => {
  const admin = aPaste();
  /** Each recorded deploy, with what its run is told; each succeeds by default. */
  const deploys = (): readonly { deployment: string; argv: readonly string[]; told: Scenario }[] => [
    {
      deployment: 'foundation',
      argv: ['foundation'],
      told: { answers: ['y', 'ops@example.invalid'], hidden: [admin, admin] },
    },
    { deployment: 'secrets', argv: ['secrets', '--keys'], told: { answers: ['y'] } },
    {
      deployment: 'certificates',
      argv: ['certificates'],
      told: { answers: ['y', AUTH_HOST, APP_HOST], dns: readyDns() },
    },
  ];
  const keys = [...Object.keys(VAULT_SECRETS), ...APP_KEYS];
  /** Staging answering as the options say, with the vault's keys sound. */
  const staging = (options: AzAnswers = {}): RecordingAz => new RecordingAz({ before: keys, after: keys, ...options });

  it('refuses, before asking anything, to send from a folder with changes or none to read', async () => {
    for (const { deployment, argv, told } of deploys()) {
      const dirty = await run(argv, { ...told, checkout: { head: COMMIT, clean: false } });
      expect(dirty.error).toMatchObject({
        message: `This folder is at ${COMMIT} with changes not committed. ${deployment} records the commit it sends, and CI's release takes the record as what Azure was built from, so the Bicep sent must be a commit's with nothing changed (git switch main, then git pull). Nothing was deployed.`,
      });
      expect(dirty.az.calls).toEqual([]);
      expect(dirty.terminal.questions).toEqual([]);
      const unread = await run(argv, { ...told, checkout: null });
      expect(unread.error).toMatchObject({ message: 'No way to read this folder was given.' });
      expect(unread.az.calls).toEqual([]);
    }
  });

  it('records the commit a clean folder is at, whatever commit that is, and nothing else', async () => {
    const other = 'c'.repeat(40);
    for (const { deployment, argv, told } of deploys()) {
      const az = staging();
      const done = await run(argv, { ...told, az, checkout: { head: other, clean: true } });
      expect(done.status).toBe(0);
      // Its own record, beside the job's own tags as they were.
      expect(az.tags).toEqual({ environment: 'staging', product: 'agent-x', [`agentx-deployed-${deployment}`]: other });
    }
  });

  it('records nothing when the deployment failed or was declined', async () => {
    for (const options of [{ ended: 'Failed' }, { ended: 'Declined' }, { status: 1 }]) {
      for (const { argv, told } of deploys()) {
        const done = await run(argv, { ...told, az: staging(options) });
        expect(done.status).toBe(1);
        expect(done.az.sequence).not.toContain('tag update --resource-id');
      }
    }
  });

  it('records nothing, and ends as it would, before the first apps run makes the migration job', async () => {
    for (const { argv, told } of deploys()) {
      const done = await run(argv, { ...told, az: staging({ record: 'no job' }) });
      expect(done.status).toBe(0);
      expect(done.az.sequence).not.toContain('tag list --resource-id');
      expect(done.terminal.said).toContain(
        'No job-agentx-stg-migrate yet (apps creates it), so nothing was recorded: the first apps run stamps what staging runs.',
      );
    }
  });

  it('ends red, the deployment kept, when the record is refused or does not read back', async () => {
    for (const { deployment, argv, told } of deploys()) {
      const refused = await run(argv, { ...told, az: staging({ record: 'refused' }) });
      expect(refused.status).toBe(1);
      expect(refused.terminal.said).toContain(
        `Deployed, but not recorded (az tag update --resource-id ${RECORDS_JOB_ID} --operation Merge --tags agentx-deployed-${deployment}=${COMMIT} failed:\nERROR: (AuthorizationFailed) The client may not write tags.): CI's release stays red on what ${deployment} reads until apps runs.`,
      );
      const lost = await run(argv, { ...told, az: staging({ record: 'lost' }) });
      expect(lost.status).toBe(1);
      expect(lost.terminal.said).toContain(
        `Deployed, but not recorded (agentx-deployed-${deployment} reads back as nothing): CI's release stays red on what ${deployment} reads until apps runs.`,
      );
    }
  });

  it("records nothing for secrets whose keys aren't sound", async () => {
    const missing = await run(['secrets', '--keys'], {
      answers: ['y'],
      az: new RecordingAz({ before: keys, after: keys.filter((name) => name !== 'key-audit-mac-v1') }),
    });
    expect(missing.status).toBe(1);
    expect(missing.az.sequence).not.toContain('tag update --resource-id');
  });
});

describe('deploy certificates', () => {
  const answers = ['y', AUTH_HOST, APP_HOST];
  const certificates = [
    { name: 'mc-agentx-stg-app', properties: { subjectName: APP_HOST, provisioningState: 'Succeeded' } },
    { name: 'mc-agentx-stg-auth', properties: { subjectName: AUTH_HOST, provisioningState: 'Pending' } },
  ];

  it('checks the records and the running apps, then deploys with the two hosts alone and lists how each certificate stands', async () => {
    const done = await run(['certificates'], {
      answers,
      dns: readyDns(),
      az: new RecordingAz({ certificates }),
    });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'bicep version',
      'rest --method get',
      'containerapp list --subscription',
      'deployment group create',
      'deployment group show',
      'rest --method get',
      ...RECORDING,
    ]);
    expect(done.az.tags['agentx-deployed-certificates']).toBe(COMMIT);
    const deployment = done.az.deployment;
    expect(deployment?.args).toContain('staging.certificates.bicepparam');
    expect(deployment?.args).toContain('--confirm-with-what-if');
    expect(deployment?.args[deployment.args.indexOf('--name') + 1]).toBe(
      'agentx-staging-certificates-20260916T164215Z',
    );
    expect(deployment?.values).toEqual({ AGENTX_AZURE_AUTH_HOST: AUTH_HOST, AGENTX_AZURE_APP_HOST: APP_HOST });
    expect(done.checked).toEqual([deployment?.values]);
    expect(done.terminal.said.slice(-5)).toEqual([
      'Deployed. The certificates, and how Azure left each:',
      `  mc-agentx-stg-app: ${APP_HOST}, Succeeded`,
      `  mc-agentx-stg-auth: ${AUTH_HOST}, Pending`,
      `Recorded on job-agentx-stg-migrate: certificates sent ${COMMIT}. CI's release takes it for what certificates reads.`,
      'A door answers over https once its certificate has succeeded. Then run apps without --keep-running to stop the billing.',
    ]);
  });

  it('deploys nothing while a record is missing or an app keeps no replica, and checks no rules first', async () => {
    const missing = await run(['certificates'], {
      answers,
      dns: new TableDns({ [APP_HOST]: [ENVIRONMENT_IP], [AUTH_HOST]: [ENVIRONMENT_IP] }, {}),
    });
    expect(missing.error).toMatchObject({
      message:
        'Every record above must be in place first (node deploy/azure/deploy.ts dns says when): nothing was deployed.',
    });
    expect(missing.terminal.said).toContain(`  TXT  asuid.${APP_HOST}  ${VERIFICATION}  (MISSING)`);
    for (const apps of [
      [
        { name: 'ca-agentx-stg-api', fewest: 1 },
        { name: 'ca-agentx-stg-login', fewest: 0 },
        { name: 'ca-agentx-stg-zitadel', fewest: 0 },
      ],
      [
        { name: 'ca-agentx-stg-api' },
        { name: 'ca-agentx-stg-login', fewest: 1 },
        { name: 'ca-agentx-stg-zitadel', fewest: '1' },
      ],
    ]) {
      const idle = await run(['certificates'], { answers, dns: readyDns(), az: new RecordingAz({ apps }) });
      const named = apps.filter((app) => app.fewest !== 1).map((app) => app.name);
      expect(idle.error).toMatchObject({
        message: `A certificate is issued only while its app runs, and ${named.join(', ')} keep no replica running: run apps --keep-running first. Nothing was deployed.`,
      });
      expect(idle.az.deployment).toBeUndefined();
      expect(idle.checked).toEqual([]);
    }
    const noApps = await run(['certificates'], { answers, dns: readyDns(), az: new RecordingAz({ apps: [] }) });
    expect(noApps.error).toMatchObject({ message: 'rg-agentx-staging holds no apps: deploy them first.' });
    // An answer that isn't a list is no apps either.
    const notAList = await run(['certificates'], {
      answers,
      dns: readyDns(),
      az: new RecordingAz({ apps: { value: KEPT_RUNNING } as unknown as [] }),
    });
    expect(notAList.error).toMatchObject({ message: 'rg-agentx-staging holds no apps: deploy them first.' });
    for (const done of [missing, noApps, notAList]) {
      expect(done.az.deployment).toBeUndefined();
      expect(done.checked).toEqual([]);
    }
  });

  it('lists nothing when the what-if is declined or the deployment fails, and asks nothing without DNS', async () => {
    for (const az of [
      new RecordingAz({ status: 1 }),
      new RecordingAz({ ended: 'Declined' }),
      new RecordingAz({ ended: 'Failed' }),
    ]) {
      const done = await run(['certificates'], { answers, dns: readyDns(), az });
      expect(done.status).toBe(1);
      expect(done.az.sequence.at(-1)).not.toBe('rest --method get');
      expect(done.terminal.said.join('\n')).not.toContain('The certificates, and how Azure left each');
    }
    const none = await run(['certificates'], { answers });
    expect(none.error).toMatchObject({ message: 'No way to look up DNS was given.' });
    expect(none.terminal.questions).toEqual([]);
  });
});

describe('realImages', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** A fetch that answers each address from the table and records what was asked. */
  function stubFetch(table: Readonly<Record<string, Response>>): { url: string; init?: RequestInit }[] {
    const calls: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal('fetch', (url: string, init?: RequestInit) => {
      calls.push({ url, ...(init === undefined ? {} : { init }) });
      const key = Object.keys(table).find((prefix) => url.startsWith(prefix));
      return Promise.resolve(
        key === undefined
          ? new Response(null, { status: 404 })
          : (table[key]?.clone() ?? new Response(null, { status: 500 })),
      );
    });
    return calls;
  }

  it("asks GitHub for main's newest commit and ghcr.io for its image's digest, with a pull token and no credential of ours", async () => {
    const calls = stubFetch({
      'https://api.github.com/repos/shahbaz242630/agent-x/commits/main': Response.json({ sha: COMMIT }),
      'https://ghcr.io/token?scope=repository:shahbaz242630/agent-x:pull&service=ghcr.io': Response.json({
        token: 'pull-only',
      }),
      [`https://ghcr.io/v2/shahbaz242630/agent-x/manifests/${COMMIT}`]: new Response(null, {
        status: 200,
        headers: { 'docker-content-digest': DIGEST },
      }),
    });
    const images = realImages(() => 'unused');
    await expect(images.latestCommit()).resolves.toBe(COMMIT);
    await expect(images.digestOf(COMMIT)).resolves.toBe(DIGEST);
    const manifest = calls.at(-1);
    expect(manifest?.init?.method).toBe('HEAD');
    const headers = new Headers(manifest?.init?.headers);
    expect(headers.get('authorization')).toBe('Bearer pull-only');
    expect(headers.get('accept')).toContain('application/vnd.oci.image.index.v1+json');
    expect(headers.get('accept')).toContain('application/vnd.docker.distribution.manifest.v2+json');
    for (const call of calls) expect(call.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("says CI hasn't published an image the registry doesn't have, and fails on any other refusal", async () => {
    stubFetch({
      'https://ghcr.io/token': Response.json({ token: 'pull-only' }),
      'https://api.github.com/': new Response(null, { status: 403 }),
    });
    const images = realImages(() => 'unused');
    await expect(images.digestOf(COMMIT)).rejects.toThrow(
      `ghcr.io has no image for ${COMMIT} (404): has CI published it on main yet?`,
    );
    await expect(images.latestCommit()).rejects.toThrow(/answered 403/);
  });

  it('checks the image with the installed cosign, and refuses before running anything when cosign is missing', () => {
    const images = realImages(() => {
      throw new Error("cosign 3.1.3 isn't installed");
    });
    expect(() => images.verify(`ghcr.io/shahbaz242630/agent-x@${DIGEST}`, COMMIT)).toThrow(
      "cosign 3.1.3 isn't installed",
    );
  });
});

describe('a deployment the operator declines, or that ends otherwise', () => {
  const admin = aPaste();
  const zitadel = aPaste();
  const commands: readonly (readonly [string, readonly string[], Scenario])[] = [
    ['foundation', ['foundation'], { answers: ['y', 'ops@example.invalid'], hidden: [admin, admin] }],
    ['secrets', ['secrets', '--all'], { answers: ['y'], hidden: [admin, admin, zitadel, zitadel] }],
    [
      'apps',
      ['apps'],
      {
        answers: ['y', 'auth.example.invalid', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID],
        images: recordingImages(),
      },
    ],
  ];

  it('says nothing was deployed when the what-if is answered no, though the CLI ends with 0, and reads nothing more', async () => {
    for (const [command, argv, scenario] of commands) {
      // A first secrets run finds the vault empty; apps finds the API's client secret there.
      const vault = command === 'secrets' ? { before: [] } : {};
      const done = await run(argv, { ...scenario, az: new RecordingAz({ ended: 'Declined', ...vault }) });
      expect({ command, status: done.status, error: done.error }).toEqual({ command, status: 1, error: undefined });
      expect(done.terminal.said.at(-1)).toBe('You answered no at the what-if: nothing was deployed.');
      const afterShow = done.az.sequence.slice(done.az.sequence.findIndex((call) => call.endsWith(' show')) + 1);
      expect({ command, afterShow }).toEqual({ command, afterShow: [] });
    }
  });

  it('reports any other end, and reads nothing more', async () => {
    for (const [command, argv, scenario] of commands) {
      const vault = command === 'secrets' ? { before: [] } : {};
      const done = await run(argv, { ...scenario, az: new RecordingAz({ ended: 'Canceled', ...vault }) });
      expect({ command, status: done.status }).toEqual({ command, status: 1 });
      expect(done.terminal.said.at(-1)).toMatch(
        /^The deployment agentx-staging-\w+-20260916T164215Z ended Canceled: nothing more was done\.$/,
      );
    }
  });
});

describe('main', () => {
  it('prints the usage for arguments it cannot read, and refuses to run anywhere but a terminal', async () => {
    const said: string[] = [];
    await expect(main(['deploy'], true, (line) => said.push(line))).resolves.toBe(2);
    expect(said.join('\n')).toContain(USAGE);
    said.length = 0;
    await expect(main(['foundation'], false, (line) => said.push(line))).resolves.toBe(1);
    expect(said.join('\n')).toMatch(/Run this in your own terminal window/);
  });
});

describe('the tool and the deployment agree', () => {
  let snapshot: Snapshot;
  let privateHalf: string;

  beforeAll(() => {
    // A real key pair, made for this test and thrown away: its halves are PEM
    // text over several lines, which must reach Bicep through the environment.
    const values = secretValues(all, pasted(aPaste(), aPaste()));
    privateHalf = values.AGENTX_AZURE_LOGIN_CLIENT_PRIVATE_KEY ?? '';
    snapshot = inCopy((dir) => environmentSnapshot(dir, 'staging', values)).together;
  });

  it('names every secret the deployment creates, by the variable its parameters file reads', () => {
    const created = snapshot.predictedResources
      .filter((resource) => resource.type === 'Microsoft.KeyVault/vaults/secrets')
      .map((resource) => resource.name.split('/').at(-1));
    expect(created.sort()).toEqual([...Object.keys(VAULT_SECRETS), ...APP_KEYS].sort());
    const paramsText = readFileSync(path.join(AZURE_DIR, 'staging.secrets.bicepparam'), 'utf8');
    const read = [...paramsText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(read.sort()).toEqual(
      [...Object.values(VAULT_SECRETS).map((secret) => secret.variable), APP_KEYS_VARIABLE].sort(),
    );
    const appsText = readFileSync(path.join(AZURE_DIR, 'staging.apps.bicepparam'), 'utf8');
    const appsRead = [...appsText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(appsRead.sort()).toEqual(Object.values(APP_VARIABLES).sort());
    const foundationText = readFileSync(path.join(AZURE_DIR, 'staging.bicepparam'), 'utf8');
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD')");
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')");
  });

  it('reads the certificates’ hosts from the apps’ variables, and finds the environment the foundation creates', () => {
    const certificatesText = readFileSync(path.join(AZURE_DIR, 'staging.certificates.bicepparam'), 'utf8');
    const read = [...certificatesText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(read.sort()).toEqual(Object.values(CERTIFICATE_VARIABLES).sort());
    const environments = snapshot.predictedResources.filter(
      (resource) => resource.type === 'Microsoft.App/managedEnvironments',
    );
    expect(environments.map((environment) => environment.name)).toEqual([APPS_ENVIRONMENT]);
  });

  it('deploys into the resource group the foundation creates', () => {
    const groups = snapshot.predictedResources.filter(
      (resource) => resource.type === 'Microsoft.Resources/resourceGroups',
    );
    expect(groups.map((group) => group.name)).toEqual([RESOURCE_GROUP]);
  });

  it('reads the alert group the foundation creates', () => {
    const actionGroups = snapshot.predictedResources.filter(
      (resource) => resource.type === 'Microsoft.Insights/actionGroups',
    );
    expect(actionGroups.map((group) => group.name)).toEqual([ACTION_GROUP]);
    expect(ACTION_GROUP_URL).toContain(`/resourceGroups/${RESOURCE_GROUP}/`);
    expect(ACTION_GROUP_URL).toContain(`/actionGroups/${ACTION_GROUP}?`);
  });

  it('compiles with a multi-line key in the environment, and the snapshot never holds it', () => {
    expect(privateHalf.split('\n').length).toBeGreaterThan(10);
    expect(snapshot.diagnostics ?? []).toEqual([]);
    const body = privateHalf.split('\n')[5] ?? '';
    expect(body.length).toBeGreaterThan(40);
    expect(JSON.stringify(snapshot)).not.toContain(body);
  });

  it('checks a first run by the same rules CI runs, with stand-ins of the same shape in place of every secret', () => {
    const values = secretValues(all, pasted(aPaste(), aPaste()));
    const shaped = shapedForPolicy({ ...values, AGENTX_AZURE_ALERT_EMAIL: 'ops@example.invalid' }, randomBytes);
    // A first run leaves the API's client secret empty (Zitadel issues it later), and an empty value stays empty.
    for (const [variable, value] of Object.entries(values).filter(
      ([name, given]) => name !== APP_KEYS_VARIABLE && given !== '',
    )) {
      expect(shaped[variable]).not.toBe(value);
      expect(shaped[variable]?.length).toBe(variable === 'AGENTX_AZURE_ZITADEL_MASTERKEY' ? 32 : 48);
    }
    // The keys stay one JSON value with a key each, every one of them a stand-in.
    const given = JSON.parse(values[APP_KEYS_VARIABLE] ?? '{}') as Record<string, string>;
    const standIns = JSON.parse(shaped[APP_KEYS_VARIABLE] ?? '{}') as Record<string, string>;
    expect(Object.keys(standIns)).toEqual([...APP_KEYS]);
    for (const key of APP_KEYS) expect(standIns[key]).not.toBe(given[key]);
    expect(shaped.AGENTX_AZURE_ALERT_EMAIL).toBe('ops@example.invalid');
    const rotation = shapedForPolicy(secretValues(rotating('db-app-password'), {}, quickMakers()), randomBytes);
    expect(
      Object.entries(rotation)
        .filter(([, value]) => value !== '')
        .map(([variable]) => variable)
        .sort(),
    ).toEqual(['AGENTX_AZURE_APP_KEYS', 'AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY']);
    // The apps' values too, which are no secrets and pass through as given.
    const appValues = {
      [APP_VARIABLES.digest]: DIGEST,
      [APP_VARIABLES.release]: COMMIT,
      [APP_VARIABLES.authHost]: 'auth.example.invalid',
      [APP_VARIABLES.appHost]: 'app.example.invalid',
      [APP_VARIABLES.adminEmail]: 'admin@example.invalid',
      [APP_VARIABLES.apiClientId]: CLIENT_ID,
      [APP_VARIABLES.minReplicas]: '0',
    };
    expect(shapedForPolicy(appValues, randomBytes)).toEqual(appValues);
    expect(policyCheck({ ...values, ...appValues })).toEqual([]);
  });

  it('runs each app at the replica count the tool sets, 0 or 1, both within the rules', () => {
    const appsWith = (count: string) =>
      inCopy((dir) => {
        const { together } = environmentSnapshot(dir, 'staging', { [APP_VARIABLES.minReplicas]: count });
        const apps = together.predictedResources.filter((resource) => resource.type === 'Microsoft.App/containerApps');
        const fewest = (app: (typeof apps)[number]) =>
          (app.properties as { template?: { scale?: { minReplicas?: unknown } } } | undefined)?.template?.scale
            ?.minReplicas;
        return {
          fewest: apps.map((app) => fewest(app)),
          problems: policyProblems(together, { region: 'uaenorth', environment: 'staging' }),
        };
      });
    expect(appsWith('0')).toEqual({ fewest: [0, 0, 0], problems: [] });
    expect(appsWith('1')).toEqual({ fewest: [1, 1, 1], problems: [] });
    // Anything but a number stops the deployment before Azure sees it.
    expect(() => appsWith('one')).toThrow(/Failed to evaluate parameter "appMinReplicas"/);
  });
});
