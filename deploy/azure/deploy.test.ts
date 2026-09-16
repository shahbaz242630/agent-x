// SEC-OPS-11: the deploy tool (G3a). Nothing here reaches Azure: the terminal
// and the Azure CLI are stand-ins that record what the tool asked and sent, so
// the safety properties can be read off them — a secret travels only in the
// child process's environment, is never said, and nothing is sent before the
// operator has confirmed the subscription, the rules have passed and Azure's
// what-if has been answered.
import { createPublicKey, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { BICEP_VERSION } from '../../tooling/bicep/bicep.ts';
import { newPassword } from '../compose/prepare.ts';
import {
  askPassword,
  type Az,
  azInvocation,
  type AzResult,
  Cancelled,
  deploy,
  deploymentName,
  describePlan,
  HiddenLine,
  main,
  type Makers,
  parseArguments,
  passwordProblems,
  peopleAskedFor,
  policyCheck,
  RESOURCE_GROUP,
  secretValues,
  shapedForPolicy,
  type Steps,
  type Terminal,
  USAGE,
  UsageError,
  VAULT_SECRETS,
} from './deploy.ts';
import { environmentSnapshot, inCopy, type Snapshot } from './snapshot.ts';

const AZURE_DIR = import.meta.dirname;
const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000a';

/** What an operator would paste: assembled when the tests run, all four kinds, never written down. */
const aPaste = (): string => ['Str0ng', 'Enough', '#', randomBytes(8).toString('hex')].join('');

const all = { kind: 'all' } as const;
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
  it('reads the three ways the tool is run', () => {
    expect(parseArguments(['foundation'])).toEqual({ command: 'foundation' });
    expect(parseArguments(['secrets', '--all'])).toEqual({ command: 'secrets', plan: all });
    expect(parseArguments(['secrets', '--rotate', 'db-app-password', 'db-owner-password'])).toEqual({
      command: 'secrets',
      plan: rotating('db-app-password', 'db-owner-password'),
    });
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
      [['deploy'], /say foundation or secrets, not deploy/],
      [['foundation', '--all'], /foundation takes no options/],
      [['secrets'], /needs --all .* or --rotate/],
      [['secrets', '--all', 'db-app-password'], /--all takes no names/],
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
      Object.values(VAULT_SECRETS)
        .map((s) => s.variable)
        .sort(),
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
    expect(written.sort()).toEqual([variableOf('db-app-password'), variableOf('zitadel-masterkey')].sort());
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
    ]);
    expect(describePlan(all)).toContain('  zitadel-admin-password: written, from what you paste');
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

interface AzAnswers {
  /** What `az bicep version` prints. */
  readonly bicep?: string;
  /** The key vaults the resource group holds. */
  readonly vaults?: readonly string[];
  /** The secrets the vault holds before the deployment, and after it. */
  readonly before?: readonly string[];
  readonly after?: readonly string[];
  /** How the deployment ends: 0, or what a declined what-if or a failure returns. */
  readonly status?: number;
}

/** An Azure CLI that answers from the options and records every call. */
class RecordingAz implements Az {
  readonly calls: Call[] = [];
  readonly options: AzAnswers;
  #deployed = false;

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
        return json({ databaseHost: { type: 'String', value: 'db.example.invalid' } });
      case 'keyvault list':
        return json(this.options.vaults ?? ['kv-agentx-stg-abcdef']);
      case 'rest --method': {
        const names = (this.#deployed ? this.options.after : this.options.before) ?? [];
        return json({ value: names.map((name) => ({ name })) });
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
    ]);
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

describe('deploy secrets', () => {
  const nine = Object.keys(VAULT_SECRETS);

  it('on a first run, asks for both pastes, writes every secret, and lists the vault afterwards', async () => {
    const admin = aPaste();
    const zitadel = aPaste();
    const done = await run(['secrets', '--all'], {
      answers: ['y'],
      hidden: [admin, admin, zitadel, zitadel],
      az: new RecordingAz({ before: [], after: nine }),
    });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'bicep version',
      'keyvault list --subscription',
      'rest --method get',
      'deployment group create',
      'rest --method get',
    ]);
    const deployment = done.az.deployment;
    expect(deployment?.args).toContain('staging.secrets.bicepparam');
    expect(deployment?.args).toContain(RESOURCE_GROUP);
    const values = deployment?.values ?? {};
    expect(Object.values(values).filter((value) => value === '')).toEqual([]);
    expect(values.AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD).toBe(admin);
    expect(values.AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD).toBe(zitadel);
    for (const call of done.az.calls) {
      for (const value of Object.values(values)) expect(call.args.join(' ')).not.toContain(value);
    }
    done.terminal.neverSaid(Object.values(values));
    expect(done.terminal.said.slice(-9)).toEqual([...nine].sort().map((name) => `  ${name}`));
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
      az: new RecordingAz({ before: nine, after: nine }),
    });
    expect(agreed.status).toBe(0);
  });

  it('on a rotation, asks for nothing, writes the named login and the master key, and says to run the set-up job', async () => {
    const done = await run(['secrets', '--rotate', 'db-app-password'], {
      answers: ['y'],
      az: new RecordingAz({ before: nine, after: nine }),
    });
    expect(done.status).toBe(0);
    expect(done.terminal.hiddenQuestions).toEqual([]);
    const written = Object.entries(done.az.deployment?.values ?? {})
      .filter(([, value]) => value !== '')
      .map(([variable]) => variable)
      .sort();
    expect(written).toEqual(['AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY']);
    expect(done.terminal.said.at(-1)).toMatch(/start the set-up job now/);
  });

  it('refuses before asking anything when the foundation has no vault', async () => {
    const done = await run(['secrets', '--all'], { answers: ['y'], az: new RecordingAz({ vaults: [] }) });
    expect(done.error).toMatchObject({ message: expect.stringMatching(/deploy the foundation first/) as unknown });
    expect(done.terminal.hiddenQuestions).toEqual([]);
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
    expect(created.sort()).toEqual(Object.keys(VAULT_SECRETS).sort());
    const paramsText = readFileSync(path.join(AZURE_DIR, 'staging.secrets.bicepparam'), 'utf8');
    const read = [...paramsText.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1]);
    expect(read.sort()).toEqual(
      Object.values(VAULT_SECRETS)
        .map((secret) => secret.variable)
        .sort(),
    );
    const foundationText = readFileSync(path.join(AZURE_DIR, 'staging.bicepparam'), 'utf8');
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD')");
    expect(foundationText).toContain("readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')");
  });

  it('deploys into the resource group the foundation creates', () => {
    const groups = snapshot.predictedResources.filter(
      (resource) => resource.type === 'Microsoft.Resources/resourceGroups',
    );
    expect(groups.map((group) => group.name)).toEqual([RESOURCE_GROUP]);
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
    for (const [variable, value] of Object.entries(values)) {
      expect(shaped[variable]).not.toBe(value);
      expect(shaped[variable]?.length).toBe(variable === 'AGENTX_AZURE_ZITADEL_MASTERKEY' ? 32 : 48);
    }
    expect(shaped.AGENTX_AZURE_ALERT_EMAIL).toBe('ops@example.invalid');
    const rotation = shapedForPolicy(secretValues(rotating('db-app-password'), {}, quickMakers()), randomBytes);
    expect(
      Object.entries(rotation)
        .filter(([, value]) => value !== '')
        .map(([variable]) => variable)
        .sort(),
    ).toEqual(['AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY']);
    expect(policyCheck(values)).toEqual([]);
  });
});
