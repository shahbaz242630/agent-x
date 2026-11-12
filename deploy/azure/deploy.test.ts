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
import { IMAGE_REPOSITORY, LOAD_SIGNER } from '../image/verify.ts';
import { APP_KEYS, PUBLIC_HALVES } from './app-keys.ts';

/** The app's keys and the operator's key's public half (PL-57), each created once. */
const CREATED_ONCE: readonly string[] = [...APP_KEYS, ...PUBLIC_HALVES.values()];
import {
  ACTION_GROUP,
  ALERTING,
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
  isOwnServer,
  HiddenLine,
  type Images,
  LOAD_VARIABLES,
  main,
  type Makers,
  type Migrations,
  DEAD_MAN_RULE,
  parseArguments,
  issuedMissing,
  COPIED_SECRETS,
  secretsRunFor,
  issuedProblems,
  passwordProblems,
  peopleAskedFor,
  type PlannedAlert,
  plannedAlerts,
  policyCheck,
  realDns,
  realImages,
  RESOURCE_GROUP,
  retriedWhileOffline,
  secretValues,
  servedServerOf,
  shapedForPolicy,
  type Steps,
  type Terminal,
  USAGE,
  UsageError,
  VAULT_SECRETS,
} from './deploy.ts';
import type { Checkout } from './git.ts';
import type { MigrationState } from './migration-state.ts';
import { policyProblems } from './policy.ts';
import { type EnvironmentSnapshot, environmentSnapshot, inCopy, type Snapshot } from './snapshot.ts';

const AZURE_DIR = import.meta.dirname;
const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000a';
/** A commit and an image digest in the shapes GitHub and ghcr.io give them, made up. */
const COMMIT = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;
/** The load test's image for the same commit (D2c). */
const LOAD_DIGEST = `sha256:${'c'.repeat(64)}`;

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

describe('the entry (S187)', () => {
  it('starts main without a top-level await, so apps can load migration-state.ts and release.ts, which import it', () => {
    // A top-level await held this module loading until main ended, and main's own dynamic import of a module importing
    // this one waited for it: Node exited "unsettled" before apps sent anything (the partner's first apps after #614).
    const source = readFileSync(path.join(AZURE_DIR, 'deploy.ts'), 'utf8');
    expect(source).not.toMatch(/^if \(import\.meta\.main\).*\bawait\b/m);
    expect(source).toMatch(/^ {2}void main\(process\.argv\.slice\(2\)\)\.then\(/m);
  });
});

describe('parseArguments', () => {
  it('reads the ways the tool is run', () => {
    expect(parseArguments(['foundation'])).toEqual({ command: 'foundation', loadSize: false, alwaysOn: false });
    expect(parseArguments(['foundation', '--load-size'])).toEqual({
      command: 'foundation',
      loadSize: true,
      alwaysOn: false,
    });
    expect(parseArguments(['foundation', '--always-on'])).toEqual({
      command: 'foundation',
      loadSize: false,
      alwaysOn: true,
    });
    expect(parseArguments(['foundation', '--always-on', '--load-size'])).toEqual({
      command: 'foundation',
      loadSize: true,
      alwaysOn: true,
    });
    expect(parseArguments(['alerts'])).toEqual({ command: 'alerts' });
    expect(parseArguments(['dns'])).toEqual({ command: 'dns' });
    expect(parseArguments(['certificates'])).toEqual({ command: 'certificates' });
    expect(parseArguments(['secrets', '--all'])).toEqual({ command: 'secrets', plan: all });
    expect(parseArguments(['secrets', '--keys'])).toEqual({ command: 'secrets', plan: keysOnly });
    expect(parseArguments(['apps'])).toEqual({
      command: 'apps',
      commit: undefined,
      keepRunning: false,
      loadRun: false,
    });
    expect(parseArguments(['apps', '--commit', COMMIT])).toEqual({
      command: 'apps',
      commit: COMMIT,
      keepRunning: false,
      loadRun: false,
    });
    expect(parseArguments(['secrets', '--rotate', 'db-app-password', 'db-owner-password'])).toEqual({
      command: 'secrets',
      plan: rotating('db-app-password', 'db-owner-password'),
    });
  });

  it("reads apps' three options in any order", () => {
    expect(parseArguments(['apps', '--keep-running'])).toEqual({
      command: 'apps',
      commit: undefined,
      keepRunning: true,
      loadRun: false,
    });
    expect(parseArguments(['apps', '--load-run'])).toEqual({
      command: 'apps',
      commit: undefined,
      keepRunning: false,
      loadRun: true,
    });
    for (const argv of [
      ['apps', '--keep-running', '--commit', COMMIT],
      ['apps', '--commit', COMMIT, '--keep-running'],
    ]) {
      expect(parseArguments(argv)).toEqual({ command: 'apps', commit: COMMIT, keepRunning: true, loadRun: false });
    }
    for (const argv of [
      ['apps', '--load-run', '--keep-running', '--commit', COMMIT],
      ['apps', '--commit', COMMIT, '--load-run', '--keep-running'],
    ]) {
      expect(parseArguments(argv)).toEqual({ command: 'apps', commit: COMMIT, keepRunning: true, loadRun: true });
    }
    for (const argv of [
      ['apps', '--load-run', '--load-database', 'psql-agentx-stg-g-a1b2c3d4'],
      ['apps', '--load-database', 'psql-agentx-stg-g-a1b2c3d4', '--load-run'],
    ]) {
      expect(parseArguments(argv)).toEqual({
        command: 'apps',
        commit: undefined,
        keepRunning: false,
        loadRun: true,
        loadDatabase: 'psql-agentx-stg-g-a1b2c3d4',
      });
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
      [
        ['apps', '--commit'],
        /apps takes --keep-running, --load-run, --load-database with the throwaway copy, --commit with one full 40-hex commit, --api-stopped, --migrate-first and --back-to-generation <n>/,
      ],
      // Stage G's copy (4D2e): its name alone, never staging's own server, and only in a load run.
      [['apps', '--load-run', '--load-database'], /--load-database with the throwaway copy/],
      [['apps', '--load-run', '--load-database', '--keep-running'], /--load-database with the throwaway copy/],
      [
        ['apps', '--load-run', '--load-database', 'psql-agentx-stg-abcdef'],
        /psql-agentx-stg-abcdef isn't a throwaway copy's name: Stage G's database is named psql-agentx-stg-g-<8 lower-case letters or digits>\./,
      ],
      [['apps', '--load-run', '--load-database', 'psql-agentx-stg-drill'], /isn't a throwaway copy's name/],
      [['apps', '--load-run', '--load-database', 'psql-agentx-stg-g-ABCDEFGH'], /isn't a throwaway copy's name/],
      [
        ['apps', '--load-database', 'psql-agentx-stg-g-a1b2c3d4'],
        /--load-database is Stage G's load run alone: give --load-run with it/,
      ],
      [
        [
          'apps',
          '--load-run',
          '--load-database',
          'psql-agentx-stg-g-a1b2c3d4',
          '--load-database',
          'psql-agentx-stg-g-a1b2c3d4',
        ],
        /each at most once/,
      ],
      [['apps', '--load-run', '--load-run'], /each at most once/],
      [['apps', '--load-size'], /each at most once/],
      [['apps', '--commit', 'baca38b'], /one full 40-hex commit/],
      [['apps', '--commit', COMMIT.toUpperCase()], /one full 40-hex commit/],
      [['apps', '--commit', COMMIT, 'extra'], /apps takes --keep-running/],
      [['apps', 'latest'], /apps takes --keep-running/],
      [['apps', '--commit', '--keep-running', COMMIT], /each at most once/],
      [['apps', '--commit', COMMIT, '--commit', COMMIT], /each at most once/],
      [['apps', '--keep-running', '--keep-running'], /each at most once/],
      [['apps', '--keep'], /each at most once/],
      [['foundation', '--all'], /foundation takes only --load-size/],
      [['foundation', '--load-size', '--load-size'], /foundation takes only --load-size/],
      [['foundation', '--load-size=yes'], /foundation takes only --load-size/],
      [['foundation', '--always-on', '--always-on'], /foundation takes only --load-size/],
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
      // With each operator-only key's public half beside it (PL-57), 32 bytes as well.
      expect(Object.keys(keys).toSorted()).toEqual([...CREATED_ONCE].toSorted());
      for (const key of Object.values(keys)) expect(Buffer.from(key, 'base64url')).toHaveLength(32);
      expect(new Set(Object.values(keys)).size).toBe(CREATED_ONCE.length);
    }
  });

  it('writes nothing but the keys and the master key on a keys run, and asks nobody', () => {
    const values = secretValues(keysOnly, {}, quickMakers());
    const written = Object.entries(values)
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable);
    expect(written.toSorted()).toEqual([APP_KEYS_VARIABLE, variableOf('zitadel-masterkey')].toSorted());
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
    expect(written.toSorted()).toEqual(
      [variableOf('db-app-password'), variableOf('zitadel-masterkey'), APP_KEYS_VARIABLE].toSorted(),
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
      '  db-operator-password: kept as the vault has it',
      '  db-zitadel-password: kept as the vault has it',
      '  zitadel-admin-password: kept as the vault has it',
      '  login-client-private-key: kept as the vault has it',
      '  login-client-public-key: kept as the vault has it',
      '  zitadel-masterkey: written only if the vault has none yet',
      '  api-oidc-client-secret: kept as the vault has it',
      '  zitadel-directory-token: kept as the vault has it',
      '  zitadel-reset-token: kept as the vault has it',
      // B5-3: copied from the email service on every run, whatever the run writes.
      '  acs-access-key: copied from its Azure service, as every run does',
      ...CREATED_ONCE.map((key) => `  ${key}: written only if the vault has none yet`),
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

describe('retriedWhileOffline', () => {
  const offline: AzResult = {
    status: 1,
    stdout: '',
    stderr: "NameResolutionError: Failed to resolve 'login.microsoftonline.com' ([Errno 11001] getaddrinfo failed)",
  };
  const ok: AzResult = { status: 0, stdout: '{}', stderr: '' };
  const scripted = (results: AzResult[]) => {
    const calls: (readonly string[])[] = [];
    const waits: number[] = [];
    const notes: string[] = [];
    const run = retriedWhileOffline(
      (args) => {
        calls.push(args);
        return results.shift() ?? ok;
      },
      (ms) => waits.push(ms),
      (line) => notes.push(line),
      3,
    );
    return { run, calls, waits, notes };
  };

  it('runs the same command again, 30 s apart, while the address cannot be looked up, then gives its answer', () => {
    const { run, calls, waits, notes } = scripted([offline, offline, ok]);
    expect(run(['rest', '--method', 'get'])).toEqual(ok);
    expect(calls).toEqual([
      ['rest', '--method', 'get'],
      ['rest', '--method', 'get'],
      ['rest', '--method', 'get'],
    ]);
    expect(waits).toEqual([30_000, 30_000]);
    expect(notes).toEqual([
      "Couldn't reach Azure: this computer's internet is down. Trying again in 30 s (1 of 2).",
      "Couldn't reach Azure: this computer's internet is down. Trying again in 30 s (2 of 2).",
    ]);
  });

  it('stops after the tries it was given and returns the last failure; reads (show, list) are repeated too', () => {
    const { run, calls } = scripted([offline, offline, offline, ok]);
    expect(run(['containerapp', 'job', 'show'])).toEqual(offline);
    expect(calls).toHaveLength(3);
    const listed = scripted([offline, ok]);
    expect(listed.run(['containerapp', 'revision', 'list'])).toEqual(ok);
    expect(listed.calls).toHaveLength(2);
  });

  it('never repeats a long-running write: Azure may have taken it before the drop', () => {
    const { run, calls, waits } = scripted([offline, ok]);
    expect(run(['postgres', 'flexible-server', 'restart'])).toEqual(offline);
    expect(calls).toHaveLength(1);
    expect(waits).toEqual([]);
  });

  it("never repeats Azure's own answer, even one that says it failed to resolve something", () => {
    const kql: AzResult = {
      status: 1,
      stdout: '',
      stderr: 'Bad Request({"error":{"message":"\'where\' operator: Failed to resolve table or column expression"}})',
    };
    const refused: AzResult = { status: 1, stdout: '', stderr: 'ConnectionResetError: connection aborted' };
    for (const failure of [kql, refused]) {
      const { run, calls, waits } = scripted([failure, ok]);
      expect(run(['rest', '--method', 'post'])).toEqual(failure);
      expect(calls).toHaveLength(1);
      expect(waits).toEqual([]);
    }
  });

  it('runs a success once, even with a warning on stderr', () => {
    const { run, calls } = scripted([{ ...ok, stderr: offline.stderr }]);
    expect(run(['rest'])).toEqual({ ...ok, stderr: offline.stderr });
    expect(calls).toHaveLength(1);
  });

  it('by default tries 21 times: 10 minutes at 30 s', () => {
    let calls = 0;
    const run = retriedWhileOffline(
      () => {
        calls += 1;
        return offline;
      },
      () => undefined,
      () => undefined,
    );
    run(['rest']);
    expect(calls).toBe(21);
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
type Held = string | { readonly name: string; readonly version: string; readonly disabled?: boolean };

/** How the vault lists a secret: its name and its current version's URL, never its value. */
const listed = (held: Held) => {
  const { name, version, disabled } = typeof held === 'string' ? { name: held, version: '1', disabled: false } : held;
  return {
    name,
    properties: {
      secretUriWithVersion: `https://kv.example.invalid/secrets/${name}/${version}`,
      attributes: { enabled: disabled !== true },
    },
  };
};

interface AzAnswers {
  /** The log alerts the resource group holds (none by default), no group yet (a first deploy), or a list that fails. */
  readonly alerts?: readonly unknown[] | 'no group' | 'unreadable';
  /** Whether Azure refuses to delete an alert: every one, or every one after the first. */
  readonly deleteRefused?: boolean | 'after one';
  /** Whether the alerts on the jobs stopping are on, or a read that fails. */
  readonly deadMen?: boolean | 'unreadable';
  /** The database's connection limit: applied, waiting on a restart that takes, one that doesn't, one Azure refuses, or no read at all. */
  readonly limit?: 'applied' | 'waiting' | 'stays' | 'refused' | 'unreadable';
  /** What the server list answers: the servers (by default one, named), or a failure. */
  readonly servers?: readonly unknown[] | 'unreadable' | Readonly<Record<string, never>>;
  /** The server's max_connections as Azure shows it: by default the load size's 120. */
  readonly connectionLimit?: string;
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
  /** The jobs Azure lists after an apps deploy, by name (default the set-up job alone). */
  readonly jobs?: readonly string[];
  /** The apps Azure lists after an apps deploy, by name (default the API alone). */
  readonly listedApps?: readonly string[];
  /** Whether Azure refuses to remove an app. */
  readonly removeRefused?: boolean;
  /** How many reads of a removed app still find it (default one); Infinity for one that never goes. */
  readonly removalReads?: number;
  /** The API's running state, one a read, the last repeated (default Stopped); and whether Azure refuses its stop. */
  readonly apiStates?: readonly string[];
  /**
   * The API's newest revision, one a read of the app, the last repeated (AZ7): by default named, the ready one,
   * provisioned, running and active, with the image the deployment sent.
   */
  readonly revisions?: readonly RevisionRead[];
  readonly stopRefused?: boolean;
  /** The jobs app's identity: there (default), missing, or unreadable. */
  readonly jobsIdentity?: 'there' | 'missing' | 'unreadable';
  /** The environment's certificates after the deployment. */
  readonly certificates?: readonly unknown[];
  /**
   * How the migration job takes a record (T1b): kept (the default); no job yet
   * (a first deploy); the write refused; or kept by the write but missing
   * from the read back.
   */
  readonly record?: 'kept' | 'no job' | 'refused' | 'lost';
}

/** How Azure has the API's newest revision at one read: a field left out is the default's. */
interface RevisionRead {
  readonly name?: string;
  readonly ready?: boolean;
  readonly image?: string;
  readonly provisioning?: string;
  readonly running?: string;
  readonly active?: boolean;
  /** The revision's own read fails. */
  readonly unreadable?: boolean;
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

/** The resource group's log alerts, as the tool lists them (at the API the Bicep writes them with). */
const ALERTS_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.Insights/scheduledQueryRules?api-version=2026-03-01`;

/** Staging's server at generation 0, under the suffix of the vault the fake lists (`kv-agentx-stg-abcdef`). */
const OWN_SERVER = 'psql-agentx-stg-abcdef';

/** An az call that succeeded, answering with the value as JSON. */
const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/** An Azure CLI that answers from the options and records every call. */
class RecordingAz implements Az {
  readonly calls: Call[] = [];
  readonly options: AzAnswers;
  /** The migration job's tags, as Azure holds them after each write. */
  readonly tags: Record<string, string | undefined> = { environment: 'staging', product: 'agent-x' };
  #deployed = false;
  #readings = 0;
  #limitApplied = false;
  #appReads = 0;
  #apiReads = 0;
  #revisionReads = 0;
  #revision: RevisionRead = {};

  constructor(options: AzAnswers = {}) {
    this.options = options;
  }

  /** The database's connection limit: waiting on a restart until one takes, as `limit` says. */
  #database(args: readonly string[]): AzResult {
    const limit = this.options.limit ?? 'applied';
    if (args[2] === 'list') {
      const { servers } = this.options;
      return servers === 'unreadable'
        ? { status: 1, stdout: '', stderr: 'ERROR: ResourceGroupNotFound' }
        : json(servers ?? [{ name: OWN_SERVER }]);
    }
    if (limit === 'unreadable') return { status: 1, stdout: '', stderr: 'ERROR: Bad Gateway' };
    if (args[2] === 'restart') {
      if (limit === 'refused') return { status: 1, stdout: '', stderr: 'ERROR: Conflict' };
      if (limit === 'waiting') this.#limitApplied = true;
      return json({});
    }
    const waiting = limit !== 'applied' && !this.#limitApplied;
    return json({ value: this.options.connectionLimit ?? '120', isConfigPendingRestart: limit === 'stays' || waiting });
  }

  interactive(args: readonly string[], values: Readonly<Record<string, string>>): number | null {
    this.calls.push({ args, values });
    this.#deployed = true;
    return this.options.status ?? 0;
  }

  run(args: readonly string[]): AzResult {
    this.calls.push({ args });
    switch (args.slice(0, 2).join(' ')) {
      case 'account show':
        return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
      case 'postgres flexible-server':
        return this.#database(args);
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
      case 'resource delete': {
        const { deleteRefused } = this.options;
        const earlier = this.calls.filter((call) => call.args.slice(0, 2).join(' ') === 'resource delete').length;
        return deleteRefused === true || (deleteRefused === 'after one' && earlier > 1)
          ? { status: 1, stdout: '', stderr: 'ERROR: (AuthorizationFailed) The client may not delete alerts.\n' }
          : { status: 0, stdout: '', stderr: '' };
      }
      case 'resource show': {
        const { deadMen } = this.options;
        return deadMen === 'unreadable'
          ? { status: 3, stdout: '', stderr: 'ERROR: (ResourceNotFound) not found' }
          : json(deadMen ?? false);
      }
      case 'keyvault list':
        return json(this.options.vaults ?? ['kv-agentx-stg-abcdef']);
      case 'containerapp list':
        if (args.some((arg) => arg.includes('fewest'))) return json(this.options.apps ?? KEPT_RUNNING);
        return json((this.options.listedApps ?? ['ca-agentx-stg-api']).map((name) => ({ name, state: 'Succeeded' })));
      case 'containerapp job':
        return json((this.options.jobs ?? ['job-agentx-stg-db-setup']).map((name) => ({ name, state: 'Succeeded' })));
      case 'tag update':
        return this.#tagUpdate(args);
      case 'tag list':
        return json({ properties: { tags: this.tags } });
      case 'identity show':
        return this.#jobsIdentity();
      case 'rest --method':
        return this.#restCall(args);
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  /** The jobs app's identity, as the options say Azure has it (4D2e D13). */
  #jobsIdentity(): AzResult {
    const identity = this.options.jobsIdentity ?? 'there';
    if (identity === 'there') return json({ name: 'id-agentx-stg-jobs' });
    return {
      status: 3,
      stdout: '',
      stderr: identity === 'missing' ? 'ERROR: (ResourceNotFound) The Resource was not found.' : 'ERROR: Bad Gateway',
    };
  }

  /** A Resource Manager call: the jobs app's removal and its reads back (4D2e D13), or a read (`#rest`). */
  #restCall(args: readonly string[]): AzResult {
    const url = args[args.indexOf('--url') + 1] ?? '';
    if (url.includes('/containerApps/ca-agentx-stg-api')) return this.#api(args[2], url);
    if (args[2] === 'get' && url.includes('/containerApps/')) {
      this.#appReads += 1;
      return this.#appReads <= (this.options.removalReads ?? 1)
        ? json({ name: 'ca-agentx-stg-jobs' })
        : { status: 3, stdout: '', stderr: 'ERROR: (ResourceNotFound) The Resource was not found.' };
    }
    if (args[2] === 'delete') {
      return this.options.removeRefused === true
        ? { status: 1, stdout: '', stderr: 'ERROR: Forbidden({"error":{"code":"AuthorizationFailed"}})' }
        : { status: 0, stdout: '', stderr: '' };
    }
    return this.#rest(url);
  }

  /** The API app (AZ25 `--api-stopped`): a stop, or a read of its running state, one answer a read, the last repeated. */
  #api(method: string | undefined, url: string): AzResult {
    if (method === 'post') {
      if (!url.includes('/stop?')) throw new Error(`unexpected API action ${url}`);
      return this.options.stopRefused === true
        ? { status: 1, stdout: '', stderr: 'ERROR: (AuthorizationFailed) may not stop' }
        : json({});
    }
    if (url.includes('/revisions/')) return this.#revisionOf(url);
    const states = this.options.apiStates ?? ['Stopped'];
    const state = states[Math.min(this.#apiReads, states.length - 1)];
    this.#apiReads += 1;
    const revisions = this.options.revisions ?? [{}];
    this.#revision = revisions[Math.min(this.#revisionReads, revisions.length - 1)] ?? {};
    this.#revisionReads += 1;
    const name = this.#revision.name ?? 'ca-agentx-stg-api--new0001';
    return json({
      name: 'ca-agentx-stg-api',
      properties: {
        runningStatus: state,
        latestRevisionName: name,
        latestReadyRevisionName: this.#revision.ready === false ? 'ca-agentx-stg-api--old0001' : name,
      },
    });
  }

  /** A read of the revision the last read of the app named, as the options have it. */
  #revisionOf(url: string): AzResult {
    const { name = 'ca-agentx-stg-api--new0001', unreadable, image, provisioning, running, active } = this.#revision;
    if (!url.includes(`/revisions/${name}?`)) throw new Error(`unexpected revision read ${url}`);
    if (unreadable === true) return { status: 1, stdout: '', stderr: 'ERROR: Bad Gateway' };
    const digest = this.deployment?.values?.AGENTX_AZURE_APP_IMAGE_DIGEST ?? '';
    return json({
      name,
      properties: {
        provisioningState: provisioning ?? 'Provisioned',
        runningState: running ?? 'Running',
        active: active ?? true,
        template: { containers: [{ name: 'api', image: image ?? `${IMAGE_REPOSITORY}@${digest}` }] },
      },
    });
  }

  /** A write of the migration job's tags, as the options say Azure takes it. */
  #tagUpdate(args: readonly string[]): AzResult {
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

  /** A Resource Manager read: the environment, its certificates, the action group, or a page of the vault's secrets. */
  #rest(url: string): AzResult {
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
    if (url.includes('/scheduledQueryRules?')) return this.#alerts(url);
    return this.#vaultPage(url);
  }

  /** The resource group's log alerts, as the options say Azure lists them. */
  #alerts(url: string): AzResult {
    if (url !== ALERTS_URL) throw new Error(`unexpected alert read ${url}`);
    const { alerts } = this.options;
    if (alerts === 'no group') {
      return {
        status: 1,
        stdout: '',
        stderr: `ERROR: Not Found({"error":{"code":"ResourceGroupNotFound","message":"Resource group 'rg-agentx-staging' could not be found."}})\n`,
      };
    }
    if (alerts === 'unreadable') return { status: 1, stdout: '', stderr: 'ERROR: Bad Gateway\n' };
    return json({ value: alerts ?? [], nextLink: null });
  }

  /** A page of the vault's secrets, as the options say the vault pages them. */
  #vaultPage(url: string): AzResult {
    // Unless a test says otherwise, the vault holds what apps needs: the API's client secret (B2-6), its
    // directory token and the email key (B5-3), its reset token (B6-3c).
    const names = (this.#deployed ? this.options.after : this.options.before) ?? [
      'api-oidc-client-secret',
      'zitadel-directory-token',
      'zitadel-reset-token',
      'acs-access-key',
    ];
    const pages = this.options.pages ?? {};
    const token = /[?&]\$skiptoken=(\d+|first)$/.exec(url)?.[1];
    const link = (next: string) => pages.nextLink ?? `${url.replace(/&\$skiptoken=.*$/, '')}&$skiptoken=${next}`;
    if (token === undefined && pages.emptyFirst === true) return json({ value: [], nextLink: link('0') });
    const from = token === undefined || token === 'first' ? 0 : Number(token);
    const page = names.slice(from, from + 3).map(listed);
    if (pages.endless === true) return json({ value: page, nextLink: link('first') });
    return json(from + 3 <= names.length ? { value: page, nextLink: link(String(from + 3)) } : { value: page });
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
  /** The log alerts the deployment would create: none unless given. */
  readonly planned?: readonly PlannedAlert[];
  /** The database server's generation the foundation names (AZ25): database-generation.json's unless given. */
  readonly generation?: number;
  /** The database's migrations (AZ6): holding every one the image brings unless given, and no way to read them for null. */
  readonly migrations?: RecordingMigrations | null;
}

/** A stand-in for the migrations' reading and running (AZ6), answering as told and recording what it was asked. */
class RecordingMigrations implements Migrations {
  readonly asked: string[] = [];
  readonly #state: MigrationState;
  readonly #runFails: boolean;

  constructor(
    state: MigrationState = { kind: 'holds', run: 'job-agentx-stg-migrate-old1x', ran: COMMIT },
    runFails = false,
  ) {
    this.#state = state;
    this.#runFails = runFails;
  }

  state(subscription: string, host: string, commit: string): Promise<MigrationState> {
    this.asked.push(`state ${subscription} ${host} ${commit}`);
    return Promise.resolve(this.#state);
  }

  runFirst(subscription: string, commit: string, digest: string): Promise<void> {
    this.asked.push(`run first ${subscription} ${commit} ${digest}`);
    return this.#runFails
      ? Promise.reject(new Error('job-agentx-stg-migrate-new0x ended Failed, so nothing was deployed.'))
      : Promise.resolve();
  }
}

/** One run of the tool, with everything it touched. */
async function run(argv: readonly string[], scenario: Scenario = {}) {
  const terminal = new ScriptedTerminal(scenario.answers ?? [], scenario.hidden ?? []);
  const az = scenario.az ?? new RecordingAz();
  const checked: Readonly<Record<string, string>>[] = [];
  const planned: { part: string; subscription: string; values: Readonly<Record<string, string>> }[] = [];
  const steps: Steps = {
    terminal,
    az,
    policy: (values) => {
      checked.push(values);
      return [...(scenario.problems ?? [])];
    },
    alerts: (part, subscription, values) => {
      planned.push({ part, subscription, values });
      return scenario.planned ?? [];
    },
    rangesCurrent: () => scenario.rangesCurrent ?? true,
    now: () => new Date('2026-09-16T16:42:15Z'),
    sleep: () => Promise.resolve(),
    makers: quickMakers(),
    ...(scenario.images === undefined ? {} : { images: scenario.images }),
    ...(scenario.dns === undefined ? {} : { dns: scenario.dns }),
    ...(scenario.checkout === null ? {} : { checkout: () => scenario.checkout ?? { head: COMMIT, clean: true } }),
    ...(scenario.generation === undefined ? {} : { generation: scenario.generation }),
    ...(scenario.migrations === null ? {} : { migrations: scenario.migrations ?? new RecordingMigrations() }),
  };
  const outcome = await deploy(parseArguments(argv), steps).then(
    (status) => ({ status, error: undefined }),
    (error: unknown) => ({ status: undefined, error }),
  );
  return { ...outcome, terminal, az, checked, planned };
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
      'keyvault list --subscription',
      'postgres flexible-server list',
      'resource show --subscription',
      'deployment sub create',
      'deployment sub show',
      ...RECORDING,
      'postgres flexible-server parameter',
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
      AGENTX_AZURE_DATABASE_DISK_GB: '32',
      AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD: admin,
      // Always sent: a load size left in the operator's shell never reaches Azure.
      AGENTX_AZURE_DATABASE_SIZE: 'normal',
      AGENTX_AZURE_ALWAYS_ON: 'false',
    });
    expect(done.terminal.said).toContain(
      'The database stays at (or goes back to) its normal size, B1ms; a change of size restarts it for a few minutes.',
    );
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

  describe('the alerts on the jobs stopping, which a partner must not have to remember (4D2e D)', () => {
    const TAIL =
      'Staging sleeps, so they email you every 10 minutes unless apps runs with --keep-running. When that ends, run foundation without --always-on.';

    it.each([
      [['foundation'], false, 'false', 'The alerts on the jobs stopping are off now, and stay off: staging sleeps.'],
      [
        ['foundation'],
        true,
        'false',
        'The alerts on the jobs stopping are on now, and this run turns them off: staging sleeps.',
      ],
      [['foundation'], 'unreadable', 'false', 'This run leaves the alerts on the jobs stopping off: staging sleeps.'],
      [
        ['foundation', '--always-on'],
        false,
        'true',
        `The alerts on the jobs stopping are off now, and this run turns them on. ${TAIL}`,
      ],
      [['foundation', '--always-on'], true, 'true', `The alerts on the jobs stopping are on now, and stay on. ${TAIL}`],
      [['foundation', '--always-on'], 'unreadable', 'true', `This run turns them on. ${TAIL}`],
    ] as const)('%j, with them %j: sends %j and says it', async (argv, deadMen, sent, said) => {
      const admin = aPaste();
      const done = await run(argv, {
        answers: ['y', 'ops@example.invalid'],
        hidden: [admin, admin],
        az: new RecordingAz({ deadMen }),
      });
      expect(done.status).toBe(0);
      expect(done.az.deployment?.values).toMatchObject({ AGENTX_AZURE_ALWAYS_ON: sent });
      expect(done.terminal.said).toContain(said);
      const asked = done.az.calls.find((call) => call.args[0] === 'resource');
      expect(asked?.args).toEqual(
        expect.arrayContaining([
          '--resource-group',
          'rg-agentx-staging',
          '--resource-type',
          'Microsoft.Insights/scheduledQueryRules',
          '--name',
          DEAD_MAN_RULE,
          '--query',
          'properties.enabled',
        ]),
      );
    });
  });

  it('sizes the database for the load run with --load-size, and says what it costs and how to size it back (D2c)', async () => {
    const admin = aPaste();
    const done = await run(['foundation', '--load-size'], {
      answers: ['y', 'ops@example.invalid'],
      hidden: [admin, admin],
    });
    expect(done.status).toBe(0);
    expect(done.az.deployment?.values).toMatchObject({ AGENTX_AZURE_DATABASE_SIZE: 'load' });
    expect(done.checked).toEqual([done.az.deployment?.values]);
    expect(done.terminal.said).toContain(
      "The database goes to the load run's size, D2ads_v5 (about $0.22 an hour, $5.20 a day): it restarts for a few minutes, and the run's measurements (Query Store) switch on. Run foundation again without --load-size the same day to size it back and switch them off.",
    );
  });

  it.each([
    ['a server autogrow has grown', [{ name: OWN_SERVER, storage: { storageSizeGb: 64 } }], '64'],
    ['a server at the least', [{ name: OWN_SERVER, storage: { storageSizeGb: 32 } }], '32'],
    ['a list that says nothing of it', [{ name: OWN_SERVER }], '32'],
    ['a size that is no number', [{ name: OWN_SERVER, storage: { storageSizeGb: '64' } }], '32'],
    // Stage G's copy or the drill's beside it (4D2e): staging's own server's disk, wherever the list puts it.
    [
      "staging's own server after a copy's",
      [
        { name: 'psql-agentx-stg-g-a1b2c3d4', storage: { storageSizeGb: 256 } },
        { name: 'psql-agentx-stg-drill', storage: { storageSizeGb: 128 } },
        { name: 'psql-agentx-stg-abcdef', storage: { storageSizeGb: 64 } },
      ],
      '64',
    ],
  ] as const)(
    'sends the disk as the server has it, never a shrink Azure would refuse: %s (S168)',
    async (_, servers, disk) => {
      const admin = aPaste();
      const done = await run(['foundation'], {
        answers: ['y', 'ops@example.invalid'],
        hidden: [admin, admin],
        az: new RecordingAz({ servers }),
      });
      expect(done.status).toBe(0);
      expect(done.az.deployment?.values).toMatchObject({ AGENTX_AZURE_DATABASE_DISK_GB: disk });
      const asked = done.az.calls.find((call) => call.args[2] === 'list');
      expect(asked?.args).toEqual(expect.arrayContaining(['--resource-group', 'rg-agentx-staging']));
    },
  );

  describe("the database server's generation: never a new, empty server in the live one's place (AZ25)", () => {
    const disk = (gb: number) => ({ storage: { storageSizeGb: gb } });
    const foundation = (generation: number, options: AzAnswers, flags: readonly string[] = []) => {
      const admin = aPaste();
      return run(['foundation', ...flags], {
        answers: ['y', 'ops@example.invalid'],
        hidden: [admin, admin],
        az: new RecordingAz(options),
        generation,
      });
    };
    /** Nothing deleted, restarted or written but the deployment itself and its record: the old server stays as it was. */
    const touchedNoServer = (az: RecordingAz) => {
      for (const call of az.calls) expect(call.args).not.toContain('delete');
      expect(az.calls.filter((call) => call.args[0] === 'postgres').map((call) => call.args[2])).not.toContain(
        'update',
      );
    };
    const refused = async (generation: number, options: AzAnswers, why: RegExp) => {
      const done = await foundation(generation, options);
      expect(done.error).toMatchObject({ message: expect.stringMatching(why) as unknown });
      expect((done.error as Error).message).toMatch(/Nothing was deployed\.$/);
      // Refused on reads alone, before any question past the subscription or any password.
      expect(done.az.deployment).toBeUndefined();
      expect(done.terminal.hiddenQuestions).toEqual([]);
      expect(done.terminal.questions).toHaveLength(1);
      expect(done.az.sequence).toEqual([
        'account show --output',
        'bicep version',
        'keyvault list --subscription',
        'postgres flexible-server list',
      ]);
      touchedNoServer(done.az);
    };

    it('refuses a generation raised before its server was restored, naming the server to restore', async () => {
      await refused(
        1,
        { servers: [{ name: OWN_SERVER }] },
        /generation 1, psql-agentx-stg-abcdef-r1, and the newest server there is generation 0: it names a server that is not there yet\. .*az postgres flexible-server restore --name psql-agentx-stg-abcdef-r1/,
      );
    });

    it('refuses a generation going back to a server no longer there, or skipping ahead', async () => {
      await refused(
        0,
        { servers: [{ name: `${OWN_SERVER}-r1` }] },
        /goes back to a generation whose server is no longer there/,
      );
      await refused(
        1,
        { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r2` }] },
        /goes back to a generation whose server is no longer there/,
      );
      await refused(
        3,
        { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }] },
        /skips ahead \(the next generation is 2\)/,
      );
    });

    it("refuses a lost live server beside a drill's, a -before or a Stage G copy: the data is somewhere", async () => {
      for (const copy of ['psql-agentx-stg-drill', 'psql-agentx-stg-before', 'psql-agentx-stg-g-a1b2c3d4']) {
        await refused(
          0,
          { servers: [{ name: copy }] },
          new RegExp(`^The live database server is missing: .*\\(only ${copy}\\)\\. Check whether it was lost`),
        );
      }
    });

    it('refuses any later generation when the vault or the servers cannot be read, never guessing', async () => {
      await refused(1, { vaults: [] }, /holds no key vault, so no foundation has run here, but .* generation 1/);
      await refused(1, { vaults: ['kv-agentx-stg-abcdef', 'kv-agentx-stg-other1'] }, /couldn't be read/);
      await refused(1, { servers: 'unreadable' }, /couldn't be read/);
      // A list Azure answers with something other than a list reads as unread, never as no servers.
      await refused(1, { servers: {} }, /the key vault or the servers couldn't be read/);
      await refused(0, { servers: {} }, /couldn't be read, so there's no telling the live server is there/);
    });

    it('deploys a restored generation, its disk read from it, and leaves the earlier one as it was', async () => {
      const done = await foundation(1, {
        servers: [
          { name: OWN_SERVER, ...disk(128) },
          { name: 'psql-agentx-stg-drill', ...disk(256) },
          { name: `${OWN_SERVER}-r1`, ...disk(64) },
        ],
      });
      expect(done.error).toBeUndefined();
      expect(done.status).toBe(0);
      expect(done.az.deployment?.values).toMatchObject({ AGENTX_AZURE_DATABASE_DISK_GB: '64' });
      expect(done.terminal.said).toContain(
        'The database server is psql-agentx-stg-abcdef-r1 (generation 1), which is there. Kept as they are, with their restore points, never changed or deleted by this deployment: psql-agentx-stg-abcdef.',
      );
      touchedNoServer(done.az);
    });

    it('refuses going back while a newer server is there: two live databases', async () => {
      await refused(
        0,
        { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }] },
        /a newer server of the environment's is there \(psql-agentx-stg-abcdef-r1\): going back would leave two live databases.*run foundation --back-to-generation 0\./,
      );
      // The flag names the very generation the file does, or it is refused too.
      const wrong = await foundation(0, { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }] }, [
        '--back-to-generation',
        '1',
      ]);
      expect(wrong.error).toMatchObject({
        message: expect.stringMatching(/^--back-to-generation 1 doesn't match database-generation\.json/) as unknown,
      });
      expect(wrong.az.deployment).toBeUndefined();
    });

    it('goes back with --back-to-generation naming it, or past a skipped one, only while that server is there', async () => {
      const back = await foundation(0, { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }] }, [
        '--back-to-generation',
        '0',
      ]);
      expect(back.status).toBe(0);
      expect(back.terminal.said).toContain(
        'The database server is psql-agentx-stg-abcdef (generation 0), which is there. Kept as they are, with their restore points, never changed or deleted by this deployment: psql-agentx-stg-abcdef-r1.',
      );
      const skipped = await foundation(2, { servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r2` }] });
      expect(skipped.status).toBe(0);
      touchedNoServer(back.az);
      touchedNoServer(skipped.az);
    });

    it('makes the first server on its own only where no foundation ran: no key vault yet', async () => {
      for (const servers of [[], 'unreadable'] as const) {
        const first = await foundation(0, { vaults: [], servers });
        expect(first.status).toBe(0);
        expect(first.terminal.said).toContain(
          'No key vault yet, so no foundation has run here: the deployment makes the first database server, generation 0.',
        );
      }
    });

    it('refuses a live server missing where a foundation ran, or a list it cannot read, unless --first-server', async () => {
      await refused(
        0,
        { servers: [] },
        /^The live database server is missing: the key vault shows a foundation ran here before.*\(no server at all\)\. Check whether it was lost or deleted and restore it first \(playbook L\), then run foundation again; only for a server that was never made, in a group holding no server at all, run foundation --first-server/,
      );
      await refused(0, { servers: 'unreadable' }, /no telling the live server is there/);
      const made = await foundation(0, { servers: [] }, ['--first-server']);
      expect(made.status).toBe(0);
      expect(made.terminal.said).toContain(
        '--first-server: the deployment makes psql-agentx-stg-abcdef, new and empty, though the key vault shows a foundation ran here before.',
      );
      const unread = await foundation(0, { servers: 'unreadable' }, ['--first-server']);
      expect((unread.error as Error).message).toMatch(
        /--first-server goes only once the key vault and the servers are both read/,
      );
      expect(unread.az.deployment).toBeUndefined();
      // An empty group alone: any server listed, a copy's or any other, refuses --first-server, vault or none.
      for (const copy of ['psql-agentx-stg-before', 'psql-agentx-stg-drill', 'psql-agentx-stg-g-a1b2c3d4']) {
        const beside = await foundation(0, { servers: [{ name: copy }] }, ['--first-server']);
        expect((beside.error as Error).message).toMatch(/--first-server is for an empty group alone/);
        expect(beside.az.deployment).toBeUndefined();
        const noVault = await foundation(0, { vaults: [], servers: [{ name: copy }] }, ['--first-server']);
        expect((noVault.error as Error).message).toMatch(/^The group holds no key vault.*and the group holds /);
        expect(noVault.az.deployment).toBeUndefined();
      }
      // Never a later generation, which only a restore makes.
      await refused(1, { servers: [] }, /names a server that is not there yet/);
      const later = await foundation(1, { servers: [{ name: OWN_SERVER }] }, ['--first-server']);
      expect(later.az.deployment).toBeUndefined();
    });

    it('takes --first-server on foundation alone, and --back-to-generation only with a generation', () => {
      expect(parseArguments(['foundation', '--first-server', '--load-size'])).toEqual({
        command: 'foundation',
        loadSize: true,
        alwaysOn: false,
        server: { firstServer: true },
      });
      expect(parseArguments(['secrets', '--back-to-generation', '0', '--keys'])).toEqual({
        command: 'secrets',
        plan: { kind: 'keys' },
        server: { backTo: 0 },
      });
      expect(parseArguments(['apps', '--back-to-generation', '12'])).toMatchObject({ server: { backTo: 12 } });
      expect(() => parseArguments(['apps', '--first-server'])).toThrow(UsageError);
      expect(() => parseArguments(['foundation', '--first-server', '--first-server'])).toThrow(UsageError);
      for (const value of [undefined, 'x', '-1', '100', '01']) {
        expect(() =>
          parseArguments(['foundation', '--back-to-generation', ...(value === undefined ? [] : [value])]),
        ).toThrow('--back-to-generation takes the generation database-generation.json names');
      }
    });

    it('names generation 0 for staging today, so the next foundation changes no name', async () => {
      const admin = aPaste();
      const done = await run(['foundation'], { answers: ['y', 'ops@example.invalid'], hidden: [admin, admin] });
      expect(done.status).toBe(0);
      expect(done.terminal.said).toContain(
        'The database server is psql-agentx-stg-abcdef (generation 0), which is there.',
      );
    });
  });

  it('restarts the database when its connection limit is waiting on one, and only then, naming the server (S167)', async () => {
    const admin = aPaste();
    const foundation = (limit: NonNullable<AzAnswers['limit']>) =>
      run(['foundation', '--load-size'], {
        answers: ['y', 'ops@example.invalid'],
        hidden: [admin, admin],
        az: new RecordingAz({ limit }),
      });
    const restarted = await foundation('waiting');
    expect(restarted.status).toBe(0);
    const restart = restarted.az.calls.find((call) => call.args[2] === 'restart');
    expect(restart?.args).toEqual([
      'postgres',
      'flexible-server',
      'restart',
      '--subscription',
      SUBSCRIPTION,
      '--resource-group',
      RESOURCE_GROUP,
      '--name',
      'db',
    ]);
    const read = restarted.az.calls.find((call) => call.args[2] === 'parameter');
    expect(read?.args).toEqual(expect.arrayContaining(['--server-name', 'db', '--name', 'max_connections']));
    expect(restarted.terminal.said).toContain(
      "The database's new connection limit needs a restart, so it restarts now, for a few minutes...",
    );
    const applied = await foundation('applied');
    expect(applied.status).toBe(0);
    expect(applied.az.calls.some((call) => call.args[2] === 'restart')).toBe(false);
  });

  it("fails, naming the very command to run, when the database's connection limit can't be said to have taken effect (S167)", async () => {
    for (const limit of ['stays', 'refused', 'unreadable'] as const) {
      for (const [argv, said] of [
        [
          ['foundation', '--load-size'],
          "The database's connection limit may not have taken effect, so a load run would be refused connections as on run day 5. Run node deploy/azure/deploy.ts foundation --load-size again; if this repeats, restart db in the Azure portal.",
        ],
        [
          ['foundation'],
          "The database's connection limit may not have taken effect, so the small server may still hold the load run's limit. Run node deploy/azure/deploy.ts foundation again; if this repeats, restart db in the Azure portal.",
        ],
      ] as const) {
        const admin = aPaste();
        const done = await run([...argv], {
          answers: ['y', 'ops@example.invalid'],
          hidden: [admin, admin],
          az: new RecordingAz({ limit }),
        });
        expect(done.error).toBeUndefined();
        expect(done.status).toBe(1);
        expect(done.terminal.said).toContain(said);
        // The deployment did happen: its record is left, and the alert address still checked.
        expect(done.az.calls.some((call) => call.args[1] === 'update')).toBe(true);
        expect(done.terminal.said).toContain('Alert email: confirmed, so every alert reaches it.');
      }
    }
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
  const every = (version: string) => Object.fromEntries(CREATED_ONCE.map((key) => [key, version]));

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
  /** What a first --all writes: every secret but the ones Zitadel issues, which only their names write (B2-6, B5-3). */
  const nine = Object.keys(VAULT_SECRETS).filter((name) => VAULT_SECRETS[name]?.source !== 'issued');
  /** Every secret a deployment leaves: the nine, the email key it copies (B5-3) and the app's keys. */
  const everything = [...nine, ...COPIED_SECRETS, ...CREATED_ONCE];

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
      // The database server's generation checked first (AZ25): the vault's suffix, then the servers.
      'keyvault list --subscription',
      'postgres flexible-server list',
      'keyvault list --subscription',
      'rest --method get',
      'deployment group create',
      'deployment group show',
      // Twenty-two secrets, three a page: the last one part full.
      ...Array<string>(8).fill('rest --method get'),
      ...RECORDING,
    ]);
    expect(done.az.tags['agentx-deployed-secrets']).toBe(COMMIT);
    const deployment = done.az.deployment;
    expect(deployment?.args).toEqual([
      'deployment',
      'group',
      'create',
      '--subscription',
      SUBSCRIPTION,
      '--resource-group',
      RESOURCE_GROUP,
      '--name',
      expect.stringMatching(/^agentx-staging-secrets-\d{8}T\d{6}Z$/),
      '--parameters',
      'staging.secrets.bicepparam',
      '--confirm-with-what-if',
    ]);
    const values = deployment?.values ?? {};
    // All but the three Zitadel issues later, which only their names write.
    expect(
      Object.entries(values)
        .filter(([, value]) => value === '')
        .map(([name]) => name),
    ).toEqual([
      'AGENTX_AZURE_API_OIDC_CLIENT_SECRET',
      'AGENTX_AZURE_ZITADEL_DIRECTORY_TOKEN',
      'AGENTX_AZURE_ZITADEL_RESET_TOKEN',
    ]);
    expect(values.AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD).toBe(admin);
    expect(values.AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD).toBe(zitadel);
    for (const call of done.az.calls) {
      for (const value of Object.values(values).filter((given) => given !== '')) {
        expect(call.args.join(' ')).not.toContain(value);
      }
    }
    done.terminal.neverSaid(Object.values(values));
    expect(done.terminal.said.slice(-(everything.length + 2), -2)).toEqual(
      [...everything].sort().map((name) => `  ${name}`),
    );
    expect(done.terminal.said.slice(-2)).toEqual([
      `The app's ${String(CREATED_ONCE.length)} keys and public halves are there, and none that was there before was written again.`,
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
    expect(declined.terminal.said).toContainEqual(expect.stringMatching(/^The vault already holds 10 secrets\./));
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
      `The app's ${String(CREATED_ONCE.length)} keys and public halves are there, and none that was there before was written again.`,
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
  options: {
    readonly commit?: string;
    readonly digest?: string;
    readonly refuse?: boolean;
    readonly refuseLoad?: boolean;
    readonly noLoadImage?: boolean;
  } = {},
): Images & { readonly asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    latestCommit: () => {
      asked.push('latest');
      return Promise.resolve(options.commit ?? COMMIT);
    },
    digestOf: (commit, signer) => {
      const load = signer?.repository === LOAD_SIGNER.repository;
      asked.push(load ? `load digest ${commit}` : `digest ${commit}`);
      if (load && options.noLoadImage === true) {
        return Promise.reject(new Error(`ghcr.io has no image for ${commit} (404)`));
      }
      return Promise.resolve(load ? LOAD_DIGEST : (options.digest ?? DIGEST));
    },
    verify: (image, commit, signer) => {
      const by = signer === undefined ? '' : ` by ${signer.workflow}`;
      asked.push(`verify ${image} ${commit}${by}`);
      const refused = signer === LOAD_SIGNER ? options.refuseLoad : options.refuse;
      return refused === true
        ? { verified: false, reason: 'SIGNATURE_REFUSED', detail: 'not signed by CI on main' }
        : { verified: true };
    },
  };
}

/** The API's client ID in Zitadel, as its app's page shows one. */
const CLIENT_ID = '338719472394810051';

describe('deploy apps', () => {
  const answers = ['y', 'Auth.Example.invalid', 'app.example.invalid', 'admin@example.invalid', CLIENT_ID];

  describe("secrets and apps follow the database server's generation, never lead it (AZ25)", () => {
    const part = (command: 'secrets' | 'apps', generation: number, options: AzAnswers, flags: string[] = []) =>
      command === 'apps'
        ? run(['apps', ...flags], { answers, images: recordingImages(), az: new RecordingAz(options), generation })
        : run(['secrets', '--keys', ...flags], { answers: ['y'], az: new RecordingAz(options), generation });

    describe('apps --api-stopped: no hand-off from a restored server before its pause (AZ25, playbook L)', () => {
      const stopped = (options: AzAnswers = {}) =>
        run(['apps', '--api-stopped'], { answers, images: recordingImages(), az: new RecordingAz(options) });
      const apiCalls = (az: RecordingAz) =>
        az.calls
          .filter((call) => (call.args[call.args.indexOf('--url') + 1] ?? '').includes('ca-agentx-stg-api'))
          .map(
            (call) => `${String(call.args[2])} ${call.args.some((arg) => arg.includes('/stop?')) ? 'stop' : 'read'}`,
          );

      it('stops the API before sending, sends, stops it again and reads it stopped, saying the pause comes next', async () => {
        const done = await stopped();
        expect(done.error).toBeUndefined();
        expect(done.status).toBe(0);
        expect(apiCalls(done.az)).toEqual(['post stop', 'get read', 'post stop', 'get read']);
        const sequence = done.az.sequence;
        expect(sequence.indexOf('rest --method post')).toBeLessThan(sequence.indexOf('deployment group create'));
        expect(sequence.lastIndexOf('rest --method post')).toBeGreaterThan(sequence.indexOf('deployment group show'));
        expect(done.terminal.said).toContainEqual(
          expect.stringMatching(/^Deployed, and ca-agentx-stg-api is still stopped\. Set the hand-off pause/),
        );
        for (const call of done.az.calls) expect(call.args).not.toContain('start');
      });

      it("sends nothing, stopping nothing, beside a load run's jobs app", async () => {
        const beside = await stopped({ listedApps: ['ca-agentx-stg-api', 'ca-agentx-stg-jobs'] });
        expect((beside.error as Error).message).toMatch(
          /^ca-agentx-stg-jobs, a load run's jobs app, is there: it runs the hand-offs too.*Remove it first.*Nothing was deployed\.$/,
        );
        expect(beside.az.deployment).toBeUndefined();
        expect(apiCalls(beside.az)).toEqual([]);
      });

      it('sends nothing when the API cannot be confirmed stopped first', async () => {
        for (const options of [{ stopRefused: true }, { apiStates: ['Running'] }, { apiStates: [''] }]) {
          const done = await stopped(options);
          expect((done.error as Error).message).toMatch(
            /^ca-agentx-stg-api couldn't be confirmed stopped before the deployment.*Nothing was deployed\.$/,
          );
          expect(done.az.deployment).toBeUndefined();
        }
      });

      it('never reports done when the API reads running after the deployment', async () => {
        const done = await stopped({ apiStates: ['Stopped', 'Running'] });
        expect(done.az.deployment).toBeDefined();
        expect(done.status).toBe(1);
        expect(done.terminal.said).toContainEqual(
          expect.stringMatching(/^Deployed, but ca-agentx-stg-api couldn't be confirmed stopped/),
        );
      });

      it('is never taken with --keep-running or --load-run, and leaves plain apps as it was', async () => {
        expect(() => parseArguments(['apps', '--api-stopped', '--keep-running'])).toThrow(UsageError);
        expect(() => parseArguments(['apps', '--load-run', '--api-stopped'])).toThrow(UsageError);
        expect(() => parseArguments(['apps', '--api-stopped', '--api-stopped'])).toThrow(UsageError);
        expect(parseArguments(['apps', '--api-stopped'])).toMatchObject({ apiStopped: true });
        expect(parseArguments(['apps'])).not.toHaveProperty('apiStopped');
        const plain = await run(['apps'], { answers, images: recordingImages() });
        // Never stopped: read only to wait for its new revision to be the ready one (AZ7), the app and then the revision.
        expect(apiCalls(plain.az)).toEqual(['get read', 'get read']);
      });
    });

    it('secrets and apps go back to an older generation beside a newer one only with --back-to-generation', async () => {
      const both = {
        servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }],
        after: [...COPIED_SECRETS, ...CREATED_ONCE],
      };
      for (const command of ['secrets', 'apps'] as const) {
        const refusedBack = await part(command, 0, both);
        expect((refusedBack.error as Error).message).toMatch(
          new RegExp(`two live databases.*run ${command} --back-to-generation 0\\.`),
        );
        expect(refusedBack.az.deployment).toBeUndefined();
        const back = await part(command, 0, both, ['--back-to-generation', '0']);
        expect(back.status).toBe(0);
        for (const call of back.az.calls) expect(call.args).not.toContain('delete');
      }
    });
    const refusals: readonly [number, AzAnswers, RegExp][] = [
      [1, { servers: [{ name: OWN_SERVER }] }, /it names a server that is not there yet/],
      [0, { servers: [{ name: `${OWN_SERVER}-r1` }] }, /goes back to a generation whose server is no longer there/],
      [
        0,
        { servers: [{ name: 'psql-agentx-stg-before' }] },
        /server of the environment's own \(only psql-agentx-stg-before\)/,
      ],
      [
        1,
        { vaults: ['kv-agentx-stg-abcdef', 'kv-agentx-stg-other1'] },
        /the key vault or the servers couldn't be read/,
      ],
      [0, { servers: [] }, /^The live database server is missing/],
      [0, { servers: {} }, /no telling the live server is there/],
      [1, { servers: 'unreadable' }, /the key vault or the servers couldn't be read/],
    ];

    for (const command of ['secrets', 'apps'] as const) {
      it(`${command} refuses a generation whose server isn't there, naming the restore, then foundation, then ${command}`, async () => {
        for (const [generation, options, why] of refusals) {
          const done = await part(command, generation, options);
          expect(done.error).toMatchObject({ message: expect.stringMatching(why) as unknown });
          const message = (done.error as Error).message;
          expect(message).toMatch(new RegExp(`then run foundation, then ${command} again.* Nothing was deployed\\.$`));
          expect(message).toMatch(/[Rr]estore it/);
          expect(done.az.deployment).toBeUndefined();
          expect(done.az.sequence).toEqual([
            'account show --output',
            'bicep version',
            'keyvault list --subscription',
            'postgres flexible-server list',
          ]);
          expect(done.terminal.hiddenQuestions).toEqual([]);
          for (const call of done.az.calls) expect(call.args).not.toContain('delete');
        }
      });

      it(`${command} goes ahead once the generation's server is there, keeping the earlier one`, async () => {
        const done = await part(command, 1, {
          servers: [{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }],
          // A keys run ends green only with every key there afterwards.
          after: [...COPIED_SECRETS, ...CREATED_ONCE],
        });
        expect(done.error).toBeUndefined();
        expect(done.status).toBe(0);
        expect(done.az.deployment).toBeDefined();
        expect(done.terminal.said).toContain(
          'The database server is psql-agentx-stg-abcdef-r1 (generation 1), which is there. Kept as they are, with their restore points, never changed or deleted by this deployment: psql-agentx-stg-abcdef.',
        );
        for (const call of done.az.calls) expect(call.args).not.toContain('delete');
      });
    }
  });

  it("sends nothing, and asks nothing past the subscription, while the vault lacks the API's client secret (B2-6)", async () => {
    const images = recordingImages();
    const done = await run(['apps'], { answers, images, az: new RecordingAz({ before: ['db-app-password'] }) });
    expect(done.error).toMatchObject({
      message: expect.stringMatching(
        /^The vault doesn't hold api-oidc-client-secret, zitadel-directory-token, zitadel-reset-token, acs-access-key yet, or holds it disabled, .*secrets --rotate api-oidc-client-secret zitadel-directory-token zitadel-reset-token .*that run copies the email key too.*Nothing was deployed\.$/,
      ) as unknown,
    });
    expect(done.az.deployment).toBeUndefined();
    expect(images.asked).toEqual([]);
    // Only which subscription, before the vault is read.
    expect(done.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
  });

  it('counts a disabled client secret as missing: the API could no more read it', async () => {
    const done = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ before: [{ name: 'api-oidc-client-secret', version: '1', disabled: true }] }),
    });
    expect(done.error).toMatchObject({ message: expect.stringMatching(/or holds it disabled/) as unknown });
    expect(done.az.deployment).toBeUndefined();
  });

  it('names only the issued and copied secrets a vault lacks, and the secrets run that writes them', () => {
    expect(issuedMissing([])).toEqual([
      'api-oidc-client-secret',
      'zitadel-directory-token',
      'zitadel-reset-token',
      'acs-access-key',
    ]);
    const held = [
      'db-app-password',
      'api-oidc-client-secret',
      'zitadel-directory-token',
      'zitadel-reset-token',
      'acs-access-key',
    ];
    // B6-3c: the reset token alone, as staging lacks it until the partner's run.
    expect(issuedMissing(held.filter((name) => name !== 'zitadel-reset-token'))).toEqual(['zitadel-reset-token']);
    expect(secretsRunFor(['zitadel-reset-token'])).toBe('secrets --rotate zitadel-reset-token');
    expect(issuedMissing(held)).toEqual([]);
    expect(issuedMissing(held.filter((name) => name !== 'zitadel-directory-token'))).toEqual([
      'zitadel-directory-token',
    ]);
    expect(issuedMissing(held.filter((name) => name !== 'acs-access-key'))).toEqual(['acs-access-key']);
    expect(secretsRunFor(['zitadel-directory-token', 'acs-access-key'])).toBe(
      'secrets --rotate zitadel-directory-token',
    );
    // The email key alone: any secrets run copies it, so the one that writes nothing else.
    expect(secretsRunFor(['acs-access-key'])).toBe('secrets --keys');
  });

  describe("waits for the API's revision of the new image to be the ready one before saying done (AZ7)", () => {
    const apps = (az: RecordingAz) => run(['apps'], { answers, images: recordingImages(), az });
    /** The reads of the API the wait made, app and revision alike. */
    const apiReads = (az: RecordingAz): number =>
      az.calls.filter((call) => call.args.some((arg) => arg.includes('/containerApps/ca-agentx-stg-api'))).length;

    it('reads again while the revision starts, and goes on once it is ready', async () => {
      const az = new RecordingAz({
        revisions: [
          { name: 'ca-agentx-stg-api--old0001', image: `${IMAGE_REPOSITORY}@sha256:${'e'.repeat(64)}` },
          { ready: false, provisioning: 'Provisioning', running: 'Activating', active: false },
          { ready: false, unreadable: true },
          {},
        ],
      });
      const done = await apps(az);
      expect(done.status).toBe(0);
      expect(apiReads(az)).toBe(8);
      expect(done.terminal.said).toContain(
        "ca-agentx-stg-api's revision ca-agentx-stg-api--new0001 runs the new image and is the ready one.",
      );
    });

    it('stops at once on a revision that failed to start, saying how a fresh one is made', async () => {
      for (const failed of [{ provisioning: 'Failed' }, { running: 'Failed' }, { running: 'ActivationFailed' }]) {
        const az = new RecordingAz({
          revisions: [{ ready: false, ...failed }],
          listedApps: ['ca-agentx-stg-api', 'ca-agentx-stg-jobs'],
        });
        const done = await apps(az);
        expect(done.status).toBe(1);
        expect(apiReads(az)).toBe(2);
        const said = done.terminal.said.at(-1) ?? '';
        expect(said).toMatch(
          /^Deployed, but ca-agentx-stg-api's revision of the new image failed to start \(ca-agentx-stg-api--new0001: /,
        );
        expect(said).toContain('then apps --keep-running, which makes a fresh revision, then apps.');
        // A load run's jobs app stays until the API serves: it still holds the jobs meanwhile.
        expect(az.calls.some((call) => call.args.includes('delete'))).toBe(false);
      }
    });

    it('gives up after ten minutes, saying what it last read and what to look at', async () => {
      const cases: [RevisionRead, string][] = [
        [{ ready: false }, '(ca-agentx-stg-api--new0001: Provisioned, Running, active, not the ready one)'],
        [
          { provisioning: '', running: '', active: false },
          '(ca-agentx-stg-api--new0001: no provisioning state, no running state, not active, the ready one)',
        ],
        [{ image: 'ghcr.io/example/other@sha256:1' }, '(Azure named no revision of the new image)'],
        [{ name: 'not-the-api' }, '(Azure named no revision of the new image)'],
      ];
      for (const [revision, last] of cases) {
        const az = new RecordingAz({ revisions: [revision] });
        const done = await apps(az);
        expect(done.status).toBe(1);
        expect(apiReads(az)).toBe(revision.name === undefined ? 80 : 40);
        const said = done.terminal.said.at(-1) ?? '';
        expect(said).toMatch(
          /^Deployed, but ca-agentx-stg-api's revision of the new image wasn't the ready one 10 minutes later \(/,
        );
        expect(said).toContain(last);
      }
    });

    it("takes an answer Azure doesn't give as no revision yet, never as one", async () => {
      const answersOf: AzResult[] = [
        { status: 1, stdout: '', stderr: 'ERROR: Bad Gateway' },
        { status: 0, stdout: 'not json', stderr: '' },
        json(null),
        json({ properties: 'none' }),
      ];
      for (const answer of answersOf) {
        const az = new (class extends RecordingAz {
          override run(args: readonly string[]): AzResult {
            const url = args[args.indexOf('--url') + 1] ?? '';
            if (args[2] === 'get' && url.includes('/containerApps/ca-agentx-stg-api?')) {
              this.calls.push({ args });
              return answer;
            }
            return super.run(args);
          }
        })();
        const done = await apps(az);
        expect(done.status).toBe(1);
        expect(done.terminal.said.at(-1)).toContain('(Azure named no revision of the new image)');
      }
    });

    it("finds the API's container among the revision's, or none", async () => {
      const az = new (class extends RecordingAz {
        override run(args: readonly string[]): AzResult {
          const url = args[args.indexOf('--url') + 1] ?? '';
          if (url.includes('/revisions/')) {
            this.calls.push({ args });
            return json({ properties: { provisioningState: 'Provisioned', template: { containers: 'none' } } });
          }
          return super.run(args);
        }
      })();
      const done = await apps(az);
      expect(done.status).toBe(1);
      expect(done.terminal.said.at(-1)).toContain('(Azure named no revision of the new image)');
    });
  });

  describe("never deploys the image ahead of the database's migrations (AZ6, S174)", () => {
    const HOST = `${OWN_SERVER}.postgres.database.azure.com`;
    const OLD = 'd'.repeat(40);
    const behind: MigrationState = {
      kind: 'behind',
      run: 'job-agentx-stg-migrate-old1x',
      ran: OLD,
      missing: ['0090_new_rule.sql', '0091_other.sql'],
    };
    const apps = (migrations: RecordingMigrations, ...flags: string[]) =>
      run(['apps', ...flags], {
        // --migrate-first asks before it changes the database (Rule Book §1.9): yes, after every other answer.
        answers: flags.includes('--migrate-first') ? [...answers, 'y'] : answers,
        images: recordingImages(),
        migrations,
      });

    it("reads what the database on staging's server holds of the image's migrations, and goes on when it holds them all", async () => {
      const migrations = new RecordingMigrations();
      const done = await apps(migrations);
      expect(done.status).toBe(0);
      expect(migrations.asked).toEqual([`state ${SUBSCRIPTION} ${HOST} ${COMMIT}`]);
      expect(done.terminal.said).toContain(
        `The database on ${OWN_SERVER} holds every migration this image brings (migrate's run job-agentx-stg-migrate-old1x ran ${COMMIT}).`,
      );
    });

    it('refuses, before anything is asked or sent, when the database lacks one, saying to run it first', async () => {
      const cases: [MigrationState, string][] = [
        [
          behind,
          `The database on ${OWN_SERVER} lacks 2 migrations this image brings (0090_new_rule.sql, 0091_other.sql): migrate's newest successful run there, job-agentx-stg-migrate-old1x, ran ${OLD}.`,
        ],
        [
          { ...behind, missing: ['0090_new_rule.sql'] },
          `The database on ${OWN_SERVER} lacks 1 migration this image brings (0090_new_rule.sql)`,
        ],
        [
          { kind: 'unknown', why: `Azure lists no successful run of migrate on ${HOST}` },
          `Whether the database on ${OWN_SERVER} holds every migration this image brings can't be told: Azure lists no successful run of migrate on ${HOST}.`,
        ],
      ];
      for (const [state, why] of cases) {
        const done = await apps(new RecordingMigrations(state));
        const message = done.error instanceof Error ? done.error.message : '';
        expect(message).toContain(why);
        expect(message).toContain('refuse to start, and raise a false tamper alarm (S174)');
        expect(message).toContain('run apps again with --migrate-first added (and the same options)');
        expect(message).toMatch(/Nothing was deployed\.$/);
        expect(done.az.deployment).toBeUndefined();
        expect(done.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
      }
    });

    it('with --migrate-first, runs the migration with the verified image once all is asked and checked, then deploys', async () => {
      const az = new RecordingAz();
      const migrations = new (class extends RecordingMigrations {
        override runFirst(subscription: string, commit: string, digest: string): Promise<void> {
          expect(az.deployment).toBeUndefined();
          return super.runFirst(subscription, commit, digest);
        }
      })(behind);
      const done = await run(['apps', '--migrate-first'], {
        answers: [...answers, 'y'],
        images: recordingImages(),
        az,
        migrations,
      });
      expect(done.status).toBe(0);
      expect(done.terminal.said.join(' ')).toContain("A migration can't be undone");
      expect(migrations.asked).toEqual([
        `state ${SUBSCRIPTION} ${HOST} ${COMMIT}`,
        `run first ${SUBSCRIPTION} ${COMMIT} ${DIGEST}`,
      ]);
      expect(az.deployment).toBeDefined();
      expect(done.terminal.said.join('\n')).toContain(
        '--migrate-first: the migration job runs this image first, before the deployment is sent.',
      );
      expect(done.terminal.said.join('\n')).toContain('The migration has run.');
    });

    it('with --migrate-first, asks before the database changes: a no runs nothing and sends nothing', async () => {
      const az = new RecordingAz();
      const migrations = new RecordingMigrations(behind);
      const done = await run(['apps', '--migrate-first'], {
        answers: [...answers, 'n'],
        images: recordingImages(),
        az,
        migrations,
      });
      expect(done.error).toBeInstanceOf(Cancelled);
      expect(migrations.asked).toEqual([`state ${SUBSCRIPTION} ${HOST} ${COMMIT}`]);
      expect(az.deployment).toBeUndefined();
    });

    it('with --migrate-first, sends nothing when the run fails, and runs nothing when there is nothing to run', async () => {
      const failing = await apps(new RecordingMigrations(behind, true), '--migrate-first');
      expect(failing.error).toBeInstanceOf(Error);
      expect(failing.az.deployment).toBeUndefined();
      const current = new RecordingMigrations();
      const done = await apps(current, '--migrate-first');
      expect(done.status).toBe(0);
      expect(current.asked).toHaveLength(1);
      expect(done.terminal.said.join('\n')).toContain('--migrate-first: nothing to run first.');
    });

    it('goes on with a first deploy, whose jobs run after it, and leaves a restore to its playbook', async () => {
      const first = await apps(new RecordingMigrations({ kind: 'no-job' }));
      expect(first.status).toBe(0);
      expect(first.terminal.said).toContain(
        'No migration job yet, so this is a first deploy: run migrate after it, with the other jobs.',
      );
      const restore = new RecordingMigrations(behind);
      const stopped = await run(['apps', '--api-stopped'], {
        answers,
        images: recordingImages(),
        migrations: restore,
        az: new RecordingAz({ apiStates: ['Stopped'] }),
      });
      expect(stopped.status).toBe(0);
      expect(restore.asked).toEqual([]);
      expect(stopped.terminal.said.join('\n')).toContain("The database's migrations aren't checked here");
    });

    it('needs a way to read them, and takes --migrate-first once, never with --api-stopped or --load-run', async () => {
      const done = await run(['apps'], { answers, images: recordingImages(), migrations: null });
      expect(done.error).toEqual(new Error("No way to read the database's migrations was given."));
      expect(parseArguments(['apps', '--migrate-first'])).toMatchObject({ migrateFirst: true });
      expect(parseArguments(['apps'])).not.toHaveProperty('migrateFirst');
      expect(() => parseArguments(['apps', '--migrate-first', '--migrate-first'])).toThrow(UsageError);
      expect(() => parseArguments(['apps', '--migrate-first', '--api-stopped'])).toThrow(
        /--migrate-first is never with --api-stopped/,
      );
      // S186 review: migrate reaches staging's own server alone, never Stage G's copy.
      expect(() => parseArguments(['apps', '--migrate-first', '--load-run'])).toThrow(
        /--migrate-first is never with --load-run/,
      );
    });
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
      'keyvault list --subscription',
      'postgres flexible-server list',
      // The vault holds the API's client secret (B2-6), its directory token and the email key (B5-3), which the
      // API reads: three, a full page, and the empty page Azure ends with.
      'keyvault list --subscription',
      'rest --method get',
      'rest --method get',
      'deployment group create',
      'deployment group show',
      'containerapp list --subscription',
      'containerapp job list',
      // The API's newest revision, then that revision: it runs the new image and is the ready one (AZ7).
      'rest --method get',
      'rest --method get',
      'resource show --subscription',
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
      // Always sent, so a value left in the shell is never what's deployed (D2c).
      AGENTX_AZURE_LOAD_RUN: 'false',
      AGENTX_AZURE_LOAD_IMAGE_DIGEST: '',
      AGENTX_AZURE_LOAD_DATABASE_HOST: '',
    });
    expect(done.checked).toEqual([deployment?.values]);
    expect(done.terminal.said).toContain('Each app will scale to zero while nothing uses it.');
    expect(done.terminal.said.join('\n')).not.toContain('load test');
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

  it.each([
    [
      ['apps'],
      true,
      'The alerts on the jobs stopping are on, and staging now sleeps, so they will email you every 10 minutes. To stop the emails, run node deploy/azure/deploy.ts foundation.',
    ],
    [
      ['apps', '--keep-running'],
      false,
      'Nothing is watching for stopped jobs: those alerts are off. To turn them on while this keeps running, run node deploy/azure/deploy.ts foundation --always-on.',
    ],
  ] as const)(
    '%j with those alerts on %j warns in plain words, and still deploys (4D2e D)',
    async (argv, deadMen, said) => {
      const done = await run(argv, { answers, images: recordingImages(), az: new RecordingAz({ deadMen }) });
      expect(done.status).toBe(0);
      expect(done.az.deployment).toBeDefined();
      expect(done.terminal.said).toContain(said);
    },
  );

  it.each([
    [['apps'], false],
    [['apps', '--keep-running'], true],
    [['apps'], 'unreadable'],
    [['apps', '--keep-running'], 'unreadable'],
  ] as const)('%j with those alerts on %j says nothing of them', async (argv, deadMen) => {
    const done = await run(argv, { answers, images: recordingImages(), az: new RecordingAz({ deadMen }) });
    expect(done.status).toBe(0);
    expect(done.terminal.said.join('\n')).not.toMatch(/stopped jobs|jobs stopping/);
  });

  it('keeps one replica of each app running when asked, and says so before and after', async () => {
    const done = await run(['apps', '--keep-running'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ deadMen: true }),
    });
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

  it("deploys the load run (D2c) with the load test's image for the same commit, verified against its own signer", async () => {
    const images = recordingImages();
    const done = await run(['apps', '--load-run'], { answers, images });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(images.asked).toEqual([
      'latest',
      `digest ${COMMIT}`,
      `verify ghcr.io/shahbaz242630/agent-x@${DIGEST} ${COMMIT}`,
      `load digest ${COMMIT}`,
      `verify ghcr.io/shahbaz242630/agent-x-load@${LOAD_DIGEST} ${COMMIT} by .github/workflows/load-image.yml`,
    ]);
    const values = done.az.deployment?.values;
    expect(values?.AGENTX_AZURE_LOAD_RUN).toBe('true');
    expect(values?.AGENTX_AZURE_LOAD_IMAGE_DIGEST).toBe(LOAD_DIGEST);
    expect(values?.AGENTX_AZURE_APP_IMAGE_DIGEST).toBe(DIGEST);
    expect(done.checked).toEqual([values]);
    const said = done.terminal.said;
    const cost = said.findIndex((line) =>
      line.startsWith(
        'The load run: the API as three copies at 2 CPUs and 4 GiB each beside the jobs app at 1 CPU and 2 GiB, all always running (roughly $0.70 to $0.90 an hour',
      ),
    );
    expect(cost).toBeGreaterThan(-1);
    expect(cost).toBeLessThan(said.findIndex((line) => line.startsWith("Azure's what-if follows")));
    expect(said.join('\n')).not.toContain('load.ts finish');
  });

  it('sends nothing for a load run when the load image for that commit is missing or not signed by its workflow', async () => {
    const missing = await run(['apps', '--load-run'], { answers, images: recordingImages({ noLoadImage: true }) });
    expect(missing.error).toMatchObject({
      message: `The load test's image for ${COMMIT} isn't there (ghcr.io has no image for ${COMMIT} (404)). Build it for main's newest commit first (gh workflow run load-image.yml --ref main, about 10 minutes), then run apps --load-run again. Nothing was deployed.`,
    });
    expect(missing.az.deployment).toBeUndefined();
    const refused = await run(['apps', '--load-run'], { answers, images: recordingImages({ refuseLoad: true }) });
    expect(refused.error).toMatchObject({
      message: expect.stringMatching(
        /^The load image was refused \(SIGNATURE_REFUSED\), so nothing was deployed:/,
      ) as unknown,
    });
    expect(refused.az.deployment).toBeUndefined();
    // Nothing is asked for a refused image: the hosts come after.
    expect(refused.terminal.questions).toEqual(['Deploy staging into it? [y/N] ']);
  });

  it("sends nothing for a load run when the live database allows fewer connections than the load size's, waits on a restart, or can't be read (4D2e D12)", async () => {
    const next =
      'Run node deploy/azure/deploy.ts foundation --load-size first (it restarts the server), then apps --load-run again. Nothing was deployed.';
    const loadRun = (options: AzAnswers) =>
      run(['apps', '--load-run'], { answers, images: recordingImages(), az: new RecordingAz(options) });
    const small = await loadRun({ connectionLimit: '50' });
    expect(small.error).toMatchObject({
      message: `The database allows 50 connections, but the load run is counted against 120: the API would be refused connections. ${next}`,
    });
    expect(small.az.deployment).toBeUndefined();
    const asked = small.az.calls.find((call) => call.args[2] === 'parameter');
    expect(asked?.args).toEqual(
      expect.arrayContaining(['--server-name', 'psql-agentx-stg-abcdef', '--name', 'max_connections']),
    );
    // A limit Azure gives as no number is too few, never enough.
    expect((await loadRun({ connectionLimit: 'unknown' })).az.deployment).toBeUndefined();
    const waiting = await loadRun({ limit: 'stays' });
    expect(waiting.error).toMatchObject({
      message: `The database allows 120 connections, and a change of it waits on a restart, but the load run is counted against 120: the API would be refused connections. ${next}`,
    });
    // No server, or a list that can't be read, is the generation's check to refuse first (AZ25).
    for (const servers of [[], 'unreadable'] as const) {
      const missing = await loadRun({ servers });
      expect((missing.error as Error | undefined)?.message).toMatch(/live (database )?server is (missing|there)/);
      expect(missing.az.deployment).toBeUndefined();
    }
    for (const options of [{ limit: 'unreadable' }] as const) {
      const unread = await loadRun(options);
      expect({ options, message: (unread.error as Error | undefined)?.message }).toEqual({
        options,
        message: expect.stringMatching(
          /^The database's connection limit couldn't be read \([\s\S]+\), and the load run is counted against 120\. Run node/,
        ) as unknown,
      });
      expect(unread.az.deployment).toBeUndefined();
    }
    // A plain apps reads no limit: staging's own is the policy's to count.
    const plain = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ connectionLimit: '50' }),
    });
    expect(plain.status).toBe(0);
    expect(plain.az.calls.some((call) => call.args[2] === 'parameter')).toBe(false);
  });

  describe("Stage G's run on its throwaway copy (4D2e)", () => {
    const COPY = 'psql-agentx-stg-g-a1b2c3d4';
    const stageG = (servers: readonly unknown[], options: AzAnswers = {}) =>
      run(['apps', '--load-run', '--load-database', COPY], {
        answers,
        images: recordingImages(),
        az: new RecordingAz({ servers, ...options }),
      });

    it("points the load run at the copy's host, its connection limit read there, not on staging's server", async () => {
      const done = await stageG([
        { name: 'psql-agentx-stg-abcdef' },
        { name: COPY },
        { name: 'psql-agentx-stg-drill' },
      ]);
      expect(done.error).toBeUndefined();
      expect(done.status).toBe(0);
      const values = done.az.deployment?.values;
      expect(values?.AGENTX_AZURE_LOAD_RUN).toBe('true');
      expect(values?.AGENTX_AZURE_LOAD_DATABASE_HOST).toBe(`${COPY}.postgres.database.azure.com`);
      expect(done.checked).toEqual([values]);
      const asked = done.az.calls.filter((call) => call.args[2] === 'parameter');
      expect(asked.map((call) => call.args[call.args.indexOf('--server-name') + 1])).toEqual([COPY]);
      expect(done.terminal.said).toContain(
        `Stage G's run: the API, its jobs app and the load jobs reach ${COPY}, never staging's own database, and keep its anchors in its own container; email, the activity downloads and the second-factor resets are off on it. Every other job stays on staging's server.`,
      );
    });

    it('sends nothing when the copy isn’t there, or is below the load size', async () => {
      const missing = await stageG([{ name: 'psql-agentx-stg-abcdef' }]);
      expect(missing.error).toMatchObject({
        message: `rg-agentx-staging holds no server ${COPY}: make Stage G's copy first (deploy/azure/stage-g.ts create). Nothing was deployed.`,
      });
      expect(missing.az.deployment).toBeUndefined();
      expect(missing.az.calls.some((call) => call.args[2] === 'parameter')).toBe(false);
      const small = await stageG([{ name: 'psql-agentx-stg-abcdef' }, { name: COPY }], { connectionLimit: '50' });
      expect(small.error).toMatchObject({
        message: `The database allows 50 connections, but the load run is counted against 120: the API would be refused connections. Make Stage G's copy at the load size (deploy/azure/stage-g.ts create), then apps --load-run --load-database ${COPY} again. Nothing was deployed.`,
      });
      expect(small.az.deployment).toBeUndefined();
    });

    it("reads staging's own server beside a copy or the drill's for a plain load run, and refuses two of its own", async () => {
      const plain = await run(['apps', '--load-run'], {
        answers,
        images: recordingImages(),
        az: new RecordingAz({ servers: [{ name: COPY }, { name: 'psql-agentx-stg-abcdef' }] }),
      });
      expect(plain.status).toBe(0);
      expect(plain.az.deployment?.values?.AGENTX_AZURE_LOAD_DATABASE_HOST).toBe('');
      const asked = plain.az.calls.find((call) => call.args[2] === 'parameter');
      expect(asked?.args).toEqual(expect.arrayContaining(['--server-name', 'psql-agentx-stg-abcdef']));
      const two = await stageG([
        { name: 'psql-agentx-stg-abcdef' },
        { name: 'psql-agentx-stg-ghijkl' },
        { name: COPY },
      ]);
      expect((two.error as Error | undefined)?.message).toMatch(
        /^The database's connection limit couldn't be read \(rg-agentx-staging holds 2 database servers of its own at generation 0, not one\)/,
      );
      expect(two.az.deployment).toBeUndefined();
    });

    it("reads the configured generation's server beside the one before it and a -before copy (AZ25)", async () => {
      const restored = await run(['apps', '--load-run'], {
        answers,
        images: recordingImages(),
        generation: 1,
        az: new RecordingAz({
          servers: [{ name: 'psql-agentx-stg-before' }, { name: OWN_SERVER }, { name: `${OWN_SERVER}-r1` }],
        }),
      });
      expect(restored.status).toBe(0);
      const asked = restored.az.calls.find((call) => call.args[2] === 'parameter');
      expect(asked?.args).toEqual(expect.arrayContaining(['--server-name', `${OWN_SERVER}-r1`]));
      const live = await run(['apps', '--load-run'], {
        answers,
        images: recordingImages(),
        az: new RecordingAz({ servers: [{ name: 'psql-agentx-stg-before' }, { name: OWN_SERVER }] }),
      });
      expect(live.status).toBe(0);
      expect(live.az.calls.find((call) => call.args[2] === 'parameter')?.args).toEqual(
        expect.arrayContaining(['--server-name', OWN_SERVER]),
      );
    });

    it('counts staging own servers at every generation, never a -before, -drill or Stage G copy', () => {
      for (const own of [OWN_SERVER, `${OWN_SERVER}-r1`, `${OWN_SERVER}-r42`]) expect(isOwnServer(own)).toBe(true);
      for (const other of [
        'psql-agentx-stg-before',
        'psql-agentx-stg-drill',
        COPY,
        `${OWN_SERVER}-r0`,
        `${OWN_SERVER}-before`,
        'psql-agentx-prd-abcdef',
      ]) {
        expect(isOwnServer(other)).toBe(false);
      }
      expect(servedServerOf([{ name: OWN_SERVER }, { name: `${OWN_SERVER}-r2` }], 2)).toEqual({
        name: `${OWN_SERVER}-r2`,
      });
      expect(() => servedServerOf([{ name: OWN_SERVER }], 1)).toThrow(
        'rg-agentx-staging holds 0 database servers of its own at generation 1, not one',
      );
    });
  });

  it("says the load test's jobs are still there after a plain apps, which never removes them", async () => {
    const jobs = ['job-agentx-stg-db-setup', 'job-agentx-stg-load-first'];
    const plain = await run(['apps'], { answers, images: recordingImages(), az: new RecordingAz({ jobs }) });
    expect(plain.status).toBe(0);
    expect(plain.terminal.said).toContain(
      "The load test's jobs are still there (PL-38's, and Stage G's where its run left them): load.ts finish removes them (D2c).",
    );
    const loadRun = await run(['apps', '--load-run'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ jobs }),
    });
    expect(loadRun.terminal.said.join('\n')).not.toContain('load.ts finish');
  });

  it('removes the jobs app a load run left once a plain apps has put the API back, and keeps it in a load run (4D2e D13)', async () => {
    const listedApps = ['ca-agentx-stg-api', 'ca-agentx-stg-jobs'];
    const removed = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/containerApps/ca-agentx-stg-jobs?api-version=2026-01-01`;
    const deletes = (az: RecordingAz) =>
      az.calls.filter((call) => call.args[2] === 'delete').map((call) => call.args[call.args.indexOf('--url') + 1]);
    const plain = await run(['apps'], { answers, images: recordingImages(), az: new RecordingAz({ listedApps }) });
    expect(plain.status).toBe(0);
    expect(deletes(plain.az)).toEqual([removed]);
    // Only once the deployment that put the API back has gone.
    expect(plain.az.calls.findIndex((call) => call.args[2] === 'delete')).toBeGreaterThan(
      plain.az.calls.findIndex((call) => call.values !== undefined),
    );
    expect(plain.terminal.said).toContain('Removed ca-agentx-stg-jobs: the API holds the jobs again (4D2e D13).');
    // Said removed only once a read finds it gone: Azure takes the removal before it is done.
    expect(plain.az.calls.filter((call) => call.args[2] === 'get' && call.args.includes(removed))).toHaveLength(2);
    const lingering = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ listedApps, removalReads: Infinity }),
    });
    expect(lingering.error).toMatchObject({
      message:
        'Deployed, and Azure took the removal of ca-agentx-stg-jobs, but it was still there 10 minutes later, beside the API now holding the jobs again: two hold them until it goes. Remove it in the Azure portal (Container Apps, ca-agentx-stg-jobs, Delete), or run apps again.',
    });
    expect(lingering.terminal.said.join(' ')).not.toContain('Removed ca-agentx-stg-jobs');
    // A load run keeps it, and a plain apps with none left removes nothing.
    const loadRun = await run(['apps', '--load-run'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ listedApps }),
    });
    expect(deletes(loadRun.az)).toEqual([]);
    const none = await run(['apps'], { answers, images: recordingImages() });
    expect(deletes(none.az)).toEqual([]);
    // A deployment that didn't go removes nothing either.
    const declined = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ listedApps, ended: 'Declined' }),
    });
    expect(deletes(declined.az)).toEqual([]);
    const refused = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ listedApps, removeRefused: true }),
    });
    expect(refused.error).toMatchObject({
      message:
        'Deployed, but Azure refused to remove ca-agentx-stg-jobs, which a load run left beside the API, now holding the jobs again: two hold them until it goes. Remove it in the Azure portal (Container Apps, ca-agentx-stg-jobs, Delete), or run apps again.',
    });
  });

  it("sends no load run while the jobs app's identity is missing or can't be read, saying to run foundation first (4D2e D13)", async () => {
    const loadRun = (jobsIdentity: 'missing' | 'unreadable') =>
      run(['apps', '--load-run'], { answers, images: recordingImages(), az: new RecordingAz({ jobsIdentity }) });
    const missing = await loadRun('missing');
    expect(missing.error).toMatchObject({
      message:
        "The jobs app's identity (id-agentx-stg-jobs) isn't there yet: the load run's jobs app runs as it. Run node deploy/azure/deploy.ts foundation first, then secrets (which lets it read its secrets), then apps --load-run again. Nothing was deployed.",
    });
    expect(missing.az.deployment).toBeUndefined();
    const unreadable = await loadRun('unreadable');
    expect(unreadable.error).toMatchObject({
      message: expect.stringMatching(
        /^The jobs app's identity \(id-agentx-stg-jobs\) couldn't be read \(ERROR: Bad Gateway\): .* Nothing was deployed\.$/,
      ) as unknown,
    });
    expect(unreadable.az.deployment).toBeUndefined();
    // A plain apps needs no jobs identity: it reads none.
    const plain = await run(['apps'], {
      answers,
      images: recordingImages(),
      az: new RecordingAz({ jobsIdentity: 'missing' }),
    });
    expect(plain.status).toBe(0);
    expect(plain.az.calls.some((call) => call.args[0] === 'identity')).toBe(false);
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
  const keys = [...Object.keys(VAULT_SECRETS), ...COPIED_SECRETS, ...CREATED_ONCE];
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

describe('foundation and log alerts that move to another workspace, which Azure refuses mid-deployment (S172)', () => {
  const WORKSPACES = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.OperationalInsights/workspaces`;
  const MAIN_LOGS = `${WORKSPACES}/log-agentx-stg`;
  const LOGIN_LOGS = `${WORKSPACES}/log-agentx-stg-logins`;
  const ERRORS = 'alert-agentx-stg-app-errors';
  const PRIVILEGED = 'alert-psql-agentx-stg-abcdef-privileged-login';
  const OWNER = 'alert-psql-agentx-stg-abcdef-owner-login';
  const PLANNED: readonly PlannedAlert[] = [
    { name: ERRORS, scopes: [MAIN_LOGS], apiVersion: '2026-03-01' },
    { name: PRIVILEGED, scopes: [LOGIN_LOGS], apiVersion: '2026-03-01' },
    { name: OWNER, scopes: [LOGIN_LOGS], apiVersion: '2026-03-01' },
  ];
  /** An alert as Azure lists it: its type in lower case, as the real list gives it. */
  const idOf = (name: string): string =>
    `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/microsoft.insights/scheduledqueryrules/${name}`;
  const held = (name: string, ...scopes: readonly string[]) => ({ id: idOf(name), name, properties: { scopes } });

  const foundation = (az: RecordingAz, ...answers: readonly string[]) => {
    const admin = aPaste();
    return run(['foundation'], {
      answers: ['y', 'ops@example.invalid', ...answers],
      hidden: [admin, admin],
      az,
      planned: PLANNED,
    });
  };
  const QUESTION = 'Delete them now so this run recreates them? [y/N] ';
  const deletes = (az: RecordingAz) => az.calls.filter((call) => call.args.slice(0, 2).join(' ') === 'resource delete');

  it.each([
    ['none is there yet', []],
    ['the group is not there yet, as on a first deploy', 'no group'],
  ] as const)('deploys without a question when %s', async (_, alerts) => {
    const done = await foundation(new RecordingAz({ alerts }));
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.planned).toEqual([
      { part: 'foundation', subscription: SUBSCRIPTION, values: done.az.deployment?.values },
    ]);
    expect(done.az.calls.find((call) => call.args[0] === 'rest')?.args).toEqual([
      'rest',
      '--method',
      'get',
      '--url',
      ALERTS_URL,
      '--output',
      'json',
    ]);
    expect(done.terminal.questions).not.toContain(QUESTION);
    expect(done.terminal.said).toContain(
      'Checking whether this run moves a log alert to another workspace (about 30 seconds)...',
    );
    expect(deletes(done.az)).toEqual([]);
  });

  it('deploys without a question when every alert there reads the workspace it is to read, whatever the case', async () => {
    const az = new RecordingAz({
      alerts: [
        held(ERRORS, MAIN_LOGS),
        held(PRIVILEGED.toUpperCase(), LOGIN_LOGS.toLowerCase()),
        held(OWNER, LOGIN_LOGS),
        // Alerts this deployment doesn't make are none of its business.
        held('alert-made-by-hand', LOGIN_LOGS),
        { id: idOf('alert-odd'), name: 'alert-odd' },
      ],
    });
    const done = await foundation(az);
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.terminal.questions).not.toContain(QUESTION);
    expect(deletes(done.az)).toEqual([]);
    expect(done.az.deployment).toBeDefined();
  });

  it('says which alerts move and why, and on a y deletes them by their IDs before the deployment, which creates them again', async () => {
    const az = new RecordingAz({
      alerts: [held(ERRORS, MAIN_LOGS), held(PRIVILEGED, MAIN_LOGS), held(OWNER, MAIN_LOGS)],
    });
    const done = await foundation(az, 'y');
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.terminal.questions.at(-1)).toBe(QUESTION);
    const said = done.terminal.said.join('\n');
    expect(said).toContain('This run moves 2 log alerts to another workspace.');
    expect(said).toContain('Scope can not be updated');
    expect(done.terminal.said).toContain(`  ${PRIVILEGED}: from log-agentx-stg to log-agentx-stg-logins`);
    expect(done.terminal.said).toContain(`  ${OWNER}: from log-agentx-stg to log-agentx-stg-logins`);
    expect(said).not.toContain(`  ${ERRORS}:`);
    expect(deletes(done.az).map((call) => call.args)).toEqual([
      ['resource', 'delete', '--ids', idOf(PRIVILEGED)],
      ['resource', 'delete', '--ids', idOf(OWNER)],
    ]);
    expect(done.terminal.said).toContain(`Deleted ${OWNER}.`);
    expect(said).toContain(
      'If you then answer no at the what-if, or the deployment fails, they stay deleted until foundation runs again:',
    );
    // Deployed, so they are back: no word of them missing.
    expect(said).not.toContain('are not back');
    // Read, then deleted, then deployed: never the other way round.
    const sequence = done.az.sequence;
    expect(sequence.indexOf('rest --method get')).toBeLessThan(sequence.indexOf('resource delete --ids'));
    expect(sequence.lastIndexOf('resource delete --ids')).toBeLessThan(sequence.indexOf('deployment sub create'));
  });

  it.each(['n', '', 'yes please'])(
    'stops on %j with nothing deleted or deployed, and prints the commands to delete them by hand',
    async (answer) => {
      const done = await foundation(new RecordingAz({ alerts: [held(OWNER, MAIN_LOGS)] }), answer);
      expect(done.status).toBeUndefined();
      expect(done.terminal.said).toContainEqual(
        expect.stringContaining('This run moves a log alert to another workspace.'),
      );
      expect((done.error as Error).message).toBe(
        `Nothing was deployed, and nothing deleted. To delete them yourself, run:\n  az resource delete --ids ${idOf(OWNER)}\nthen run node deploy/azure/deploy.ts foundation again, which creates them.`,
      );
      expect(deletes(done.az)).toEqual([]);
      expect(done.az.deployment).toBeUndefined();
    },
  );

  it('stops with nothing deployed when the alerts there cannot be read, never taking that for none moving', async () => {
    const done = await foundation(new RecordingAz({ alerts: 'unreadable' }));
    expect(done.status).toBeUndefined();
    expect((done.error as Error).message).toMatch(
      /^Couldn't read the log alerts Azure holds now, .* Nothing was deployed\. .*\n.*Bad Gateway/s,
    );
    expect(done.terminal.questions).not.toContain(QUESTION);
    expect(done.az.deployment).toBeUndefined();
  });

  it('stops with nothing deployed when Azure refuses a delete, saying a run again picks up the rest', async () => {
    const done = await foundation(new RecordingAz({ alerts: [held(OWNER, MAIN_LOGS)], deleteRefused: true }), 'y');
    expect(done.status).toBeUndefined();
    expect((done.error as Error).message).toMatch(
      new RegExp(`^Azure didn't delete ${OWNER}, so nothing was deployed\\..*AuthorizationFailed`, 's'),
    );
    expect(done.terminal.said).not.toContain(`Deleted ${OWNER}.`);
    expect(done.az.deployment).toBeUndefined();
  });

  it('stops with nothing read or deployed when Bicep cannot say which workspace an alert reads', async () => {
    const admin = aPaste();
    const done = await run(['foundation'], {
      answers: ['y', 'ops@example.invalid'],
      hidden: [admin, admin],
      az: new RecordingAz({ alerts: [held(OWNER, MAIN_LOGS)] }),
      planned: [...PLANNED, { name: 'alert-later', scopes: ["[reference('x').id]"], apiVersion: '2026-03-01' }],
    });
    expect(done.status).toBeUndefined();
    expect((done.error as Error).message).toMatch(/^Bicep can't say which workspace alert-later reads/);
    expect(done.az.calls.some((call) => call.args[0] === 'rest')).toBe(false);
    expect(done.az.deployment).toBeUndefined();
  });

  it('deletes one alert moved on a y, and deploys', async () => {
    const done = await foundation(new RecordingAz({ alerts: [held(OWNER, MAIN_LOGS)] }), 'Y');
    expect(done.status).toBe(0);
    expect(deletes(done.az).map((call) => call.args)).toEqual([['resource', 'delete', '--ids', idOf(OWNER)]]);
    expect(done.terminal.said).toContainEqual(
      expect.stringContaining('This run moves a log alert to another workspace.'),
    );
  });

  const NOT_BACK = `These alerts were deleted and are not back: ${PRIVILEGED}, ${OWNER}. Run node deploy/azure/deploy.ts foundation again to create them.`;

  it.each([
    ['the operator answers no at the what-if', { ended: 'Declined' }],
    ['the deployment fails', { ended: 'Failed' }],
    ['the CLI ends with a failure', { status: 1 }],
  ] as const)('ends saying which deleted alerts are not back when %s', async (_, ending) => {
    const az = new RecordingAz({ alerts: [held(PRIVILEGED, MAIN_LOGS), held(OWNER, MAIN_LOGS)], ...ending });
    const done = await foundation(az, 'y');
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(1);
    expect(deletes(done.az)).toHaveLength(2);
    expect(done.terminal.said.at(-1)).toBe(NOT_BACK);
  });

  it('names the alerts already deleted when Azure refuses a later delete', async () => {
    const az = new RecordingAz({
      alerts: [held(PRIVILEGED, MAIN_LOGS), held(OWNER, MAIN_LOGS)],
      deleteRefused: 'after one',
    });
    const done = await foundation(az, 'y');
    expect(done.status).toBeUndefined();
    expect((done.error as Error).message).toContain(
      `Azure didn't delete ${OWNER}, so nothing was deployed. These alerts were deleted and are not back: ${PRIVILEGED}. Run node deploy/azure/deploy.ts foundation again to create them.`,
    );
    expect(done.az.deployment).toBeUndefined();
  });
});

describe('the tool and the deployment agree', () => {
  let snapshot: Snapshot;
  let environment: EnvironmentSnapshot;
  let privateHalf: string;

  beforeAll(() => {
    // A real key pair, made for this test and thrown away: its halves are PEM
    // text over several lines, which must reach Bicep through the environment.
    const values = secretValues(all, pasted(aPaste(), aPaste()));
    privateHalf = values.AGENTX_AZURE_LOGIN_CLIENT_PRIVATE_KEY ?? '';
    environment = inCopy((dir) => environmentSnapshot(dir, 'staging', values));
    snapshot = environment.together;
  });

  it('asks about moved log alerts for each deployment that creates any, and only those (S172)', () => {
    const alerting = (part: Snapshot): boolean =>
      part.predictedResources.some((resource) => resource.type === 'Microsoft.Insights/scheduledQueryRules');
    const deployments = new Map([
      ['foundation', environment.foundation],
      ...[...environment.parts].map(([file, part]) => [file.split('.')[1] ?? file, part] as const),
    ]);
    expect([...deployments.keys()].toSorted()).toEqual(['apps', 'certificates', 'foundation', 'secrets']);
    expect([...deployments].filter(([, part]) => alerting(part)).map(([name]) => name)).toEqual([...ALERTING]);
  });

  it("plans the foundation's log alerts by the names and workspaces Azure holds in the real subscription (S172)", () => {
    const real = '6e99c9cb-0000-4000-8000-000000000000';
    const alerts = plannedAlerts('foundation', real, secretValues(all, pasted(aPaste(), aPaste())));
    const workspaces = `/subscriptions/${real}/resourceGroups/rg-agentx-staging/providers/Microsoft.OperationalInsights/workspaces`;
    const SERVER_ALERT = /^alert-psql-agentx-stg-([a-z0-9]+)-(?:privileged|owner)-login$/;
    const login = alerts.filter((alert) => SERVER_ALERT.test(alert.name));
    expect(login).toHaveLength(2);
    for (const alert of login) expect(alert.scopes).toEqual([`${workspaces}/log-agentx-stg-logins`]);
    expect(alerts.find((alert) => alert.name === 'alert-agentx-stg-app-errors')?.scopes).toEqual([
      `${workspaces}/log-agentx-stg`,
    ]);
    // The server's suffix is the subscription's (names.bicep): the stand-in's names aren't the ones Azure holds.
    const suffixes = (names: readonly string[]) => new Set(names.map((name) => SERVER_ALERT.exec(name)?.[1]));
    const inSubscription = suffixes(login.map((alert) => alert.name));
    const standIn = suffixes(
      snapshot.predictedResources
        .filter((resource) => SERVER_ALERT.test(resource.name))
        .map((resource) => resource.name),
    );
    expect(inSubscription.size).toBe(1);
    expect(standIn.size).toBe(1);
    expect(inSubscription).not.toEqual(standIn);
    expect(new Set(alerts.map((alert) => alert.apiVersion))).toEqual(new Set(['2026-03-01']));
    // A part goes into the group, and creates none.
    expect(plannedAlerts('certificates', real, {})).toEqual([]);
  });

  it('names every secret the deployment creates, by the variable its parameters file reads', () => {
    const created = snapshot.predictedResources
      .filter((resource) => resource.type === 'Microsoft.KeyVault/vaults/secrets')
      .map((resource) => resource.name.split('/').at(-1));
    expect(created.toSorted()).toEqual([...Object.keys(VAULT_SECRETS), ...COPIED_SECRETS, ...CREATED_ONCE].toSorted());
    const paramsText = readFileSync(path.join(AZURE_DIR, 'staging.secrets.bicepparam'), 'utf8');
    const read = [...paramsText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(read.toSorted()).toEqual(
      [...Object.values(VAULT_SECRETS).map((secret) => secret.variable), APP_KEYS_VARIABLE].toSorted(),
    );
    const appsText = readFileSync(path.join(AZURE_DIR, 'staging.apps.bicepparam'), 'utf8');
    const appsRead = [...appsText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(appsRead.toSorted()).toEqual(Object.values(APP_VARIABLES).toSorted());
    // The load run's two (D2c), which apps always sets: their defaults serve the policy tests alone.
    expect(appsText).toContain(`readEnvironmentVariable('${LOAD_VARIABLES.run}', 'false')`);
    expect(appsText).toContain(`readEnvironmentVariable('${LOAD_VARIABLES.digest}', '')`);
    const foundationText = readFileSync(path.join(AZURE_DIR, 'staging.bicepparam'), 'utf8');
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD')");
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')");
  });

  it('reads the certificates’ hosts from the apps’ variables, and finds the environment the foundation creates', () => {
    const certificatesText = readFileSync(path.join(AZURE_DIR, 'staging.certificates.bicepparam'), 'utf8');
    const read = [...certificatesText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(read.toSorted()).toEqual(Object.values(CERTIFICATE_VARIABLES).toSorted());
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
    expect(Object.keys(standIns).toSorted()).toEqual([...CREATED_ONCE].toSorted());
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
      [LOAD_VARIABLES.run]: 'false',
      [LOAD_VARIABLES.digest]: '',
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
