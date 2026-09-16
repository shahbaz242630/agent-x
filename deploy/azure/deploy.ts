// Deploys staging's foundation and its secrets from an operator's own terminal
// (0e G3a):
//
//   node deploy/azure/deploy.ts foundation
//   node deploy/azure/deploy.ts secrets --all
//   node deploy/azure/deploy.ts secrets --rotate db-app-password [more names]
//
// The two secrets that belong to people — the database admin's password and
// Zitadel's first admin's — are pasted from the password manager into a prompt
// that doesn't show what is typed. The six that belong to machines are made
// here, in memory. Every one of them reaches Azure only through the
// environment of the child process that runs the deployment: never printed,
// never written to a file, never on a command line, where the process list
// would show it.
//
// Every run, in this order: the signed-in subscription is shown and confirmed;
// the Azure CLI is made to use the pinned Bicep the checks ran, never one it
// downloads for itself; the deployment the run would send is checked by the
// same rules CI runs, with stand-ins in place of every secret; and Azure's own
// what-if is shown, the deployment waiting for a "y" (`--confirm-with-what-if`).
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';

import { BICEP_VERSION, installedBicep } from '../../tooling/bicep/bicep.ts';
import { type KeyPair, newKeyPair, newMasterKey, newPassword, type Random } from '../compose/prepare.ts';
import { describeProblem, policyProblems } from './policy.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const ENVIRONMENT = 'staging';
const REGION = 'uaenorth';
const AZURE_DIR = import.meta.dirname;
/** The group the foundation creates for staging (names.bicep); a test holds the two equal. */
export const RESOURCE_GROUP = 'rg-agentx-staging';

/**
 * Every secret the vault holds, by its name there, with the variable
 * staging.secrets.bicepparam reads it from and who makes it. A test holds this
 * equal to the parameters file and to the secrets the deployment creates.
 * - person: pasted from the password manager
 * - machine: a fresh login, made here
 * - pair: the login container's key pair, both halves made together
 * - once: Zitadel's master key; a fresh one goes every run, and Azure keeps only the first
 */
export const VAULT_SECRETS: Readonly<
  Record<string, { readonly variable: string; readonly source: 'person' | 'machine' | 'pair' | 'once' }>
> = {
  'db-admin-password': { variable: 'AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD', source: 'person' },
  'db-owner-password': { variable: 'AGENTX_AZURE_DB_OWNER_PASSWORD', source: 'machine' },
  'db-app-password': { variable: 'AGENTX_AZURE_DB_APP_PASSWORD', source: 'machine' },
  'db-backup-password': { variable: 'AGENTX_AZURE_DB_BACKUP_PASSWORD', source: 'machine' },
  'db-zitadel-password': { variable: 'AGENTX_AZURE_DB_ZITADEL_PASSWORD', source: 'machine' },
  'zitadel-admin-password': { variable: 'AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD', source: 'person' },
  'login-client-private-key': { variable: 'AGENTX_AZURE_LOGIN_CLIENT_PRIVATE_KEY', source: 'pair' },
  'login-client-public-key': { variable: 'AGENTX_AZURE_LOGIN_CLIENT_PUBLIC_KEY', source: 'pair' },
  'zitadel-masterkey': { variable: 'AGENTX_AZURE_ZITADEL_MASTERKEY', source: 'once' },
};

const ADMIN_PASSWORD = 'AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD';
const ALERT_EMAIL = 'AGENTX_AZURE_ALERT_EMAIL';

/** Every variable that carries a secret: the ones the policy check replaces with stand-ins. */
const SECRET_VARIABLES: ReadonlySet<string> = new Set(Object.values(VAULT_SECRETS).map((secret) => secret.variable));

/** What each person-held secret is called when the operator is asked for it. */
const PERSON_LABELS: Readonly<Record<string, string>> = {
  'db-admin-password': "the database admin's password",
  'zitadel-admin-password': "Zitadel's first admin's password",
};

export type SecretPlan = { readonly kind: 'all' } | { readonly kind: 'rotate'; readonly names: ReadonlySet<string> };

export type Request = { readonly command: 'foundation' } | { readonly command: 'secrets'; readonly plan: SecretPlan };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage, from your own terminal window:
  node deploy/azure/deploy.ts foundation
  node deploy/azure/deploy.ts secrets --all
  node deploy/azure/deploy.ts secrets --rotate <secret name> [...]`;

/** What the operator asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, ...rest] = argv;
  if (command === 'foundation') {
    if (rest.length > 0) throw new UsageError(`foundation takes no options, not ${rest.join(' ')}`);
    return { command };
  }
  if (command !== 'secrets') throw new UsageError(`say foundation or secrets, not ${command ?? 'nothing'}`);
  const [mode, ...names] = rest;
  if (mode === '--all') {
    if (names.length > 0) throw new UsageError('--all takes no names: it writes every secret');
    return { command, plan: { kind: 'all' } };
  }
  if (mode !== '--rotate') throw new UsageError('secrets needs --all (the first run) or --rotate <names>');
  if (names.length === 0) throw new UsageError('--rotate needs at least one secret name');
  for (const name of names) {
    const secret = VAULT_SECRETS[name];
    if (secret === undefined) {
      throw new UsageError(`${name} isn't a secret the vault holds: ${Object.keys(VAULT_SECRETS).join(', ')}`);
    }
    if (secret.source === 'once') {
      throw new UsageError(
        `${name} is never rotated: Zitadel can't read what it encrypted with another key (ADR-002 Amendment G2c)`,
      );
    }
  }
  // The key pair is one thing: a new private half with the old public one would stop every sign-in.
  const pair = Object.keys(VAULT_SECRETS).filter((name) => VAULT_SECRETS[name]?.source === 'pair');
  const rotated = new Set(names);
  if (pair.some((name) => rotated.has(name))) for (const name of pair) rotated.add(name);
  return { command, plan: { kind: 'rotate', names: rotated } };
}

const planIncludes = (plan: SecretPlan, name: string): boolean => plan.kind === 'all' || plan.names.has(name);

/** The people's secrets a run must ask for. */
export const peopleAskedFor = (plan: SecretPlan): string[] =>
  Object.entries(VAULT_SECRETS)
    .filter(([name, secret]) => secret.source === 'person' && planIncludes(plan, name))
    .map(([name]) => name);

export interface Makers {
  readonly random: Random;
  readonly keyPair: KeyPair;
}

/**
 * Every variable a secrets run sets: a value for each secret the plan writes,
 * and an empty one for each it leaves as the vault has it (the parameters file
 * refuses a missing one, so a misspelt name can't pass for a rotation). The
 * master key always goes, fresh; Azure keeps only the first.
 */
export function secretValues(
  plan: SecretPlan,
  people: Readonly<Record<string, string>>,
  makers: Makers = { random: randomBytes, keyPair: newKeyPair },
): Record<string, string> {
  const pair = Object.entries(VAULT_SECRETS).some(
    ([name, secret]) => secret.source === 'pair' && planIncludes(plan, name),
  )
    ? makers.keyPair()
    : undefined;
  const values: Record<string, string> = {};
  for (const [name, secret] of Object.entries(VAULT_SECRETS)) {
    const written = planIncludes(plan, name);
    switch (secret.source) {
      case 'person': {
        const given = people[name];
        if (written && given === undefined) throw new Error(`${name} was to be written but nobody gave it`);
        values[secret.variable] = written ? (given ?? '') : '';
        break;
      }
      case 'machine':
        values[secret.variable] = written ? newPassword(makers.random) : '';
        break;
      case 'pair':
        values[secret.variable] =
          pair === undefined ? '' : name === 'login-client-private-key' ? pair.privatePem : pair.publicPem;
        break;
      case 'once':
        values[secret.variable] = newMasterKey(makers.random);
        break;
    }
  }
  return values;
}

/** One line per secret: what the run does with it. Names only, never a value. */
export function describePlan(plan: SecretPlan): string[] {
  return Object.entries(VAULT_SECRETS).map(([name, secret]) => {
    if (secret.source === 'once') return `  ${name}: written only if the vault has none yet`;
    if (!planIncludes(plan, name)) return `  ${name}: kept as the vault has it`;
    return secret.source === 'person'
      ? `  ${name}: written, from what you paste`
      : `  ${name}: written, made fresh by this run`;
  });
}

/**
 * Why a person's password won't do, or nothing. The same bar for both: a
 * password manager's generator meets it, and so do Postgres's rules (8 to 128
 * characters, three kinds of four) and Zitadel's default policy (all four
 * kinds). The message never repeats the value.
 */
export function passwordProblems(value: string): string[] {
  const problems: string[] = [];
  if (value.length < 16) problems.push('it is shorter than 16 characters');
  if (value.length > 128) problems.push('it is longer than the 128 characters Postgres accepts');
  if (value.trim() !== value) problems.push('it starts or ends with a space, which a paste may have added');
  const kinds: readonly (readonly [RegExp, string])[] = [
    [/[a-z]/, 'a lower-case letter'],
    [/[A-Z]/, 'an upper-case letter'],
    [/[0-9]/, 'a digit'],
    [/[^A-Za-z0-9]/, 'a symbol'],
  ];
  for (const [pattern, kind] of kinds) if (!pattern.test(value)) problems.push(`it has no ${kind}`);
  return problems;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * What a hidden prompt has been sent so far, one keystroke or paste at a time.
 * Nothing is echoed. Enter ends the line; Ctrl+C cancels it; backspace takes
 * the last character back; other control characters, and the markers a
 * terminal wraps a bracketed paste in, are dropped.
 */
// The keys a hidden prompt reacts to, spelled by code point so no control
// character sits in the source.
const ESCAPE = String.fromCharCode(0x1b);
const CTRL_C = String.fromCharCode(0x03);
const DELETE = String.fromCharCode(0x7f);
const BACKSPACE = String.fromCharCode(0x08);
const PASTE_START = `${ESCAPE}[200~`;
const PASTE_END = `${ESCAPE}[201~`;

export class HiddenLine {
  #value = '';

  feed(text: string): 'more' | 'done' | 'cancelled' {
    for (const character of text.replaceAll(PASTE_START, '').replaceAll(PASTE_END, '')) {
      if (character === '\r' || character === '\n') return 'done';
      if (character === CTRL_C) return 'cancelled';
      if (character === DELETE || character === BACKSPACE) {
        this.#value = this.#value.slice(0, -1);
      } else if (character >= ' ') {
        this.#value += character;
      }
    }
    return 'more';
  }

  get value(): string {
    return this.#value;
  }
}

export class Cancelled extends Error {
  constructor() {
    super('Cancelled: nothing was deployed.');
    this.name = 'Cancelled';
  }
}

export interface Terminal {
  say(line: string): void;
  ask(question: string): Promise<string>;
  askHidden(question: string): Promise<string>;
}

/** The operator's own terminal. Refused when either end isn't one: a hidden prompt needs a keyboard. */
function realTerminal(): Terminal {
  const { stdin, stdout } = process;
  return {
    say: (line) => {
      stdout.write(`${line}\n`);
    },
    ask: async (question) => {
      const lines = createInterface({ input: stdin, output: stdout });
      try {
        return (await lines.question(question)).trim();
      } finally {
        lines.close();
      }
    },
    askHidden: (question) =>
      new Promise((resolve, reject) => {
        const line = new HiddenLine();
        stdout.write(question);
        stdin.setRawMode(true);
        stdin.resume();
        const finish = (): void => {
          stdin.off('data', onData);
          stdin.setRawMode(false);
          stdin.pause();
          stdout.write('\n');
        };
        const onData = (chunk: Buffer): void => {
          const state = line.feed(chunk.toString('utf8'));
          if (state === 'more') return;
          finish();
          if (state === 'done') resolve(line.value);
          else reject(new Cancelled());
        };
        stdin.on('data', onData);
      }),
  };
}

const yes = (answer: string): boolean => /^y(?:es)?$/i.test(answer);

/** A person's password, asked twice so a slip of the paste is caught, and held to `passwordProblems`. */
export async function askPassword(terminal: Terminal, label: string, tries = 3): Promise<string> {
  for (let attempt = 1; attempt <= tries; attempt += 1) {
    const first = await terminal.askHidden(`Paste ${label} (nothing will show): `);
    const problems = passwordProblems(first);
    if (problems.length > 0) {
      terminal.say(`That won't do: ${problems.join('; ')}.`);
      continue;
    }
    const second = await terminal.askHidden('Paste it again: ');
    if (second === first) return first;
    terminal.say('The two pastes differ. Try again.');
  }
  throw new Error(`No usable ${label} after ${String(tries)} tries: nothing was deployed.`);
}

export interface AzResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export interface Az {
  /** Runs the CLI with the operator's own terminal for its input and output: the status it ends with. */
  interactive(args: readonly string[], values: Readonly<Record<string, string>>): number | null;
  /** Runs the CLI and returns what it printed. */
  run(args: readonly string[]): AzResult;
}

export interface AzInvocation {
  readonly command: string;
  readonly prefix: readonly string[];
  readonly env: Record<string, string>;
}

/**
 * How to start the Azure CLI, and the environment it runs in. On Windows the
 * `az` on the PATH is a .cmd file that runs the CLI's own Python, which Node
 * won't start without a shell; starting that Python directly keeps a shell out
 * of it. The pinned Bicep goes first on the PATH, and the CLI is told to use
 * the one it finds there and not to look for a newer one.
 */
export function azInvocation(
  platform: NodeJS.Platform,
  base: Readonly<Record<string, string | undefined>>,
  bicep: string,
  exists: (file: string) => boolean = existsSync,
): AzInvocation {
  // The platform's own path rules, so the Windows case reads the same when a test runs it elsewhere.
  const paths = platform === 'win32' ? path.win32 : path.posix;
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(base)) if (value !== undefined) env[name] = value;
  // Windows names it Path; a second PATH beside it would leave which one wins to chance.
  const pathKey = Object.keys(env).find((name) => name.toUpperCase() === 'PATH') ?? 'PATH';
  const searched = (env[pathKey] ?? '').split(paths.delimiter).filter((entry) => entry !== '');
  env[pathKey] = [paths.dirname(bicep), ...searched].join(paths.delimiter);
  env.AZURE_BICEP_USE_BINARY_FROM_PATH = 'true';
  env.AZURE_BICEP_CHECK_VERSION = 'false';
  if (platform !== 'win32') return { command: 'az', prefix: [], env };
  const launcher = searched.map((entry) => paths.join(entry, 'az.cmd')).find((file) => exists(file));
  if (launcher === undefined) {
    throw new Error('The Azure CLI is not on the PATH: install it (winget install -e --id Microsoft.AzureCLI).');
  }
  const python = paths.join(paths.dirname(launcher), '..', 'python.exe');
  if (!exists(python)) throw new Error(`The Azure CLI's own Python isn't at ${python}.`);
  env.AZ_INSTALLER = 'MSI';
  return { command: python, prefix: ['-IBm', 'azure.cli'], env };
}

function realAz(): Az {
  const invocation = azInvocation(process.platform, process.env, installedBicep());
  return {
    interactive: (args, values) =>
      spawnSync(invocation.command, [...invocation.prefix, ...args], {
        cwd: AZURE_DIR,
        env: { ...invocation.env, ...values },
        stdio: 'inherit',
        windowsHide: true,
      }).status,
    run: (args) => {
      const done = spawnSync(invocation.command, [...invocation.prefix, ...args], {
        cwd: AZURE_DIR,
        env: invocation.env,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      });
      return { status: done.status, stdout: done.stdout, stderr: done.stderr };
    },
  };
}

/** Runs the CLI for JSON, or says what went wrong. */
function azJson(az: Az, args: readonly string[]): unknown {
  const done = az.run([...args, '--output', 'json']);
  if (done.status !== 0) throw new Error(`az ${args.join(' ')} failed:\n${done.stderr.trim()}`);
  return JSON.parse(done.stdout) as unknown;
}

const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/**
 * A run's values with every secret replaced by a stand-in of the same shape:
 * an empty one stays empty, since that is what decides whether a secret is
 * written, and the master key stays 32 characters. Everything else is as given.
 */
export function shapedForPolicy(values: Readonly<Record<string, string>>, random: Random): Record<string, string> {
  const shaped: Record<string, string> = {};
  for (const [name, value] of Object.entries(values)) {
    const bytes = name === VAULT_SECRETS['zitadel-masterkey']?.variable ? 16 : 24;
    shaped[name] = SECRET_VARIABLES.has(name) && value !== '' ? random(bytes).toString('hex') : value;
  }
  return shaped;
}

/**
 * The rules CI runs, over the deployment this run would send, with its secrets
 * shaped by `shapedForPolicy`, so a real one never reaches a snapshot file.
 */
export function policyCheck(values: Readonly<Record<string, string>>, random: Random = randomBytes): string[] {
  const shaped = shapedForPolicy(values, random);
  return inCopy((dir) => {
    const { together } = environmentSnapshot(dir, ENVIRONMENT, shaped);
    return policyProblems(together, { region: REGION, environment: ENVIRONMENT }).map(describeProblem);
  });
}

/** A deployment's name: what it deploys and when, in the characters and the 64 Azure allows. */
export const deploymentName = (part: string, at: Date): string =>
  `agentx-${ENVIRONMENT}-${part}-${at
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')}`;

export interface Steps {
  readonly terminal: Terminal;
  readonly az: Az;
  readonly policy: (values: Readonly<Record<string, string>>) => string[];
  /** Whether GitHub's published ranges still match the file the rules are built from. */
  readonly rangesCurrent: () => boolean;
  readonly now: () => Date;
  readonly makers?: Makers;
}

/** The subscription the CLI is signed in to, confirmed by the operator. */
async function confirmSubscription(steps: Steps): Promise<string> {
  const account = azJson(steps.az, ['account', 'show']);
  const name = text((account as { name?: unknown }).name);
  const id = text((account as { id?: unknown }).id);
  steps.terminal.say(`Signed in to the subscription "${name}" (${id}).`);
  if (!yes(await steps.terminal.ask(`Deploy ${ENVIRONMENT} into it? [y/N] `))) throw new Cancelled();
  return id;
}

/** The CLI must be using the pinned compiler, so what Azure receives is what the checks compiled. */
function confirmBicep(steps: Steps): void {
  const done = steps.az.run(['bicep', 'version']);
  if (done.status !== 0 || !done.stdout.includes(`Bicep CLI version ${BICEP_VERSION} `)) {
    throw new Error(`The Azure CLI isn't using the pinned Bicep ${BICEP_VERSION}:\n${done.stdout}${done.stderr}`);
  }
}

function checkPolicy(steps: Steps, values: Readonly<Record<string, string>>): void {
  steps.terminal.say("Checking the deployment against the project's rules (about 30 seconds)...");
  const problems = steps.policy(values);
  if (problems.length > 0) {
    throw new Error(`The deployment breaks the project's rules, so it wasn't sent:\n${problems.join('\n')}`);
  }
}

async function deployFoundation(steps: Steps): Promise<number> {
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  if (!steps.rangesCurrent()) {
    throw new Error(
      "GitHub's published addresses have changed, and an image pull would fail. Run node deploy/azure/github-ranges.ts, take the change, and redeploy from a merged commit.",
    );
  }
  const email = await steps.terminal.ask('Address the alerts go to: ');
  if (!EMAIL.test(email)) throw new Error("That isn't an email address: nothing was deployed.");
  steps.terminal.say(
    "The database admin's password is set on the server by this run. It must be the one in the password manager: a different one replaces it.",
  );
  const admin = await askPassword(steps.terminal, PERSON_LABELS['db-admin-password'] ?? 'the password');
  const values = { [ALERT_EMAIL]: email, [ADMIN_PASSWORD]: admin };
  checkPolicy(steps, values);
  const name = deploymentName('foundation', steps.now());
  steps.terminal.say(`Azure's what-if follows. Read it, then answer y to deploy (${name}).`);
  const status = steps.az.interactive(
    [
      'deployment',
      'sub',
      'create',
      '--subscription',
      subscription,
      '--location',
      REGION,
      '--name',
      name,
      '--parameters',
      `${ENVIRONMENT}.bicepparam`,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  const outputs = azJson(steps.az, [
    'deployment',
    'sub',
    'show',
    '--subscription',
    subscription,
    '--name',
    name,
    '--query',
    'properties.outputs',
  ]);
  steps.terminal.say('Deployed. What the foundation reports:');
  for (const [key, output] of Object.entries(outputs as Record<string, { value?: unknown }>)) {
    steps.terminal.say(`  ${key}: ${text(output.value)}`);
  }
  return 0;
}

/** The names of the secrets the vault already holds, read through Azure Resource Manager (never their values). */
function secretsInVault(steps: Steps, subscription: string, vault: string): string[] {
  const listed = azJson(steps.az, [
    'rest',
    '--method',
    'get',
    '--url',
    `https://management.azure.com/subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${vault}/secrets?api-version=2025-05-01`,
  ]);
  return ((listed as { value?: readonly { name?: unknown }[] }).value ?? []).map((secret) => text(secret.name));
}

async function deploySecrets(steps: Steps, plan: SecretPlan): Promise<number> {
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  const vaults = azJson(steps.az, [
    'keyvault',
    'list',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--query',
    '[].name',
  ]);
  const vault = Array.isArray(vaults) && vaults.length === 1 ? text(vaults[0]) : '';
  if (vault === '') throw new Error(`${RESOURCE_GROUP} must hold one key vault: deploy the foundation first.`);
  const existing = secretsInVault(steps, subscription, vault);
  if (plan.kind === 'all' && existing.length > 0) {
    steps.terminal.say(
      `The vault already holds ${String(existing.length)} secrets. --all replaces every one but the master key: every login changes, so run the set-up job straight after.`,
    );
    if ((await steps.terminal.ask('Type "rotate everything" to go on: ')) !== 'rotate everything') {
      throw new Cancelled();
    }
  }
  steps.terminal.say('This run:');
  for (const line of describePlan(plan)) steps.terminal.say(line);
  const people: Record<string, string> = {};
  for (const name of peopleAskedFor(plan)) {
    people[name] = await askPassword(steps.terminal, PERSON_LABELS[name] ?? name);
  }
  const values = secretValues(plan, people, steps.makers);
  checkPolicy(steps, values);
  const name = deploymentName('secrets', steps.now());
  steps.terminal.say(`Azure's what-if follows. Read it, then answer y to deploy (${name}).`);
  const status = steps.az.interactive(
    [
      'deployment',
      'group',
      'create',
      '--subscription',
      subscription,
      '--resource-group',
      RESOURCE_GROUP,
      '--name',
      name,
      '--parameters',
      `${ENVIRONMENT}.secrets.bicepparam`,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  steps.terminal.say('Deployed. The vault now holds:');
  for (const secret of secretsInVault(steps, subscription, vault).sort()) steps.terminal.say(`  ${secret}`);
  if (plan.kind === 'rotate' && [...plan.names].some((secret) => secret.startsWith('db-'))) {
    steps.terminal.say('A database login changed: start the set-up job now, so the server takes it.');
  }
  return 0;
}

export async function deploy(request: Request, steps: Steps): Promise<number> {
  return request.command === 'foundation' ? deployFoundation(steps) : deploySecrets(steps, request.plan);
}

/** Whether GitHub's ranges match the pinned file, by running the refresher's own check. */
function rangesCurrent(): boolean {
  const done = spawnSync(process.execPath, [path.join(AZURE_DIR, 'github-ranges.ts')], {
    stdio: 'inherit',
    windowsHide: true,
  });
  return done.status === 0;
}

export async function main(
  argv: readonly string[],
  isTerminal: boolean = process.stdin.isTTY && process.stdout.isTTY,
  say: (line: string) => void = console.log,
): Promise<number> {
  let request: Request;
  try {
    request = parseArguments(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    say(`${error.message}\n${USAGE}`);
    return 2;
  }
  if (!isTerminal) {
    say(
      "Run this in your own terminal window (on Windows, Windows Terminal or PowerShell; Git Bash's window doesn't pass the keyboard through): it asks for passwords with the typing hidden, and nothing here should be piped.",
    );
    return 1;
  }
  try {
    return await deploy(request, {
      terminal: realTerminal(),
      az: realAz(),
      policy: (values) => policyCheck(values),
      rangesCurrent,
      now: () => new Date(),
    });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
