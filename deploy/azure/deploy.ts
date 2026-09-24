// Deploys staging from an operator's own terminal (0e G3a), in this order:
//
//   node deploy/azure/deploy.ts foundation
//   node deploy/azure/deploy.ts secrets --all
//   node deploy/azure/deploy.ts apps
//
// and, later, `secrets --rotate db-app-password [more names]`; `secrets
// --keys`, which creates the app's keys the vault doesn't hold yet (a new one,
// or a new version) and changes nothing else; `apps
// --keep-running`, which keeps one replica of each app running, billed, until
// `apps` runs again without it (for a test, or while something needs the apps
// up); `alerts`, which changes nothing and says whether the alerts can reach
// their address (the foundation ends with the same check); `dns`, which changes
// nothing and says which DNS records the public doors' hosts still need; and
// `certificates`, which deploys the doors' managed certificates once those
// records are in place and the apps are kept running (G2e-3).
//
// The two secrets that belong to people — the database admin's password and
// Zitadel's first admin's — are pasted from the password manager into a prompt
// that doesn't show what is typed. The six that belong to machines, and the
// app's keys, are made here, in memory. Every one of them reaches Azure only through the
// environment of the child process that runs the deployment: never printed,
// never written to a file, never on a command line, where the process list
// would show it.
//
// Every run, in this order: the signed-in subscription is shown and confirmed;
// the Azure CLI is made to use the pinned Bicep the checks ran, never one it
// downloads for itself; the deployment the run would send is checked by the
// same rules CI runs, with stand-ins in place of every secret; and Azure's own
// what-if is shown, the deployment waiting for a "y" (`--confirm-with-what-if`).
// The apps run only an image that verify.ts has found signed by CI on main at
// the commit being deployed, named by its digest (ADR-002 Amendment E2), and
// only from a clean checkout of that commit: the apps are stamped with it,
// and CI's release job reads the stamp as what Azure was built from (G4-3).
// foundation, secrets and certificates also run only from a clean checkout,
// and once Azure says the deployment succeeded, each records the commit it
// sent in a tag on the migration job, which the release reads too (T1b).
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promises as systemDns } from 'node:dns';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';

import { BICEP_VERSION, installedBicep } from '../../tooling/bicep/bicep.ts';
import { installedCosign } from '../../tooling/cosign/cosign.ts';
import { type KeyPair, newKeyPair, newMasterKey, newPassword, type Random } from '../compose/prepare.ts';
import { IMAGE_REPOSITORY, type Outcome, runCosign, SOURCE_REPOSITORY, verifyImage } from '../image/verify.ts';
import { APP_KEYS, newAppKeys } from './app-keys.ts';
import { type Checkout, realCheckout } from './git.ts';
import { describeProblem, policyProblems } from './policy.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const ENVIRONMENT = 'staging';
const REGION = 'uaenorth';
const AZURE_DIR = import.meta.dirname;
/** The group the foundation creates for staging (names.bicep); a test holds the two equal. */
export const RESOURCE_GROUP = 'rg-agentx-staging';
/** The group every alert notifies (names.bicep); a test holds the two equal. */
export const ACTION_GROUP = 'ag-agentx-stg';

/** What the apps deployment reads from the shell (staging.apps.bicepparam); a test holds the two equal. */
export const APP_VARIABLES = {
  digest: 'AGENTX_AZURE_APP_IMAGE_DIGEST',
  release: 'AGENTX_AZURE_RELEASE',
  authHost: 'AGENTX_AZURE_AUTH_HOST',
  appHost: 'AGENTX_AZURE_APP_HOST',
  adminEmail: 'AGENTX_AZURE_ZITADEL_ADMIN_EMAIL',
  apiClientId: 'AGENTX_AZURE_API_OIDC_CLIENT_ID',
  minReplicas: 'AGENTX_AZURE_APP_MIN_REPLICAS',
} as const;

/**
 * The parameters file each hand deploy sends, in the order a first deploy runs
 * them. CI's release asks Bicep what each reads (release.ts), to say which to
 * run when a file changes; a test holds this to every parameters file here.
 */
export const DEPLOYMENTS = {
  foundation: `${ENVIRONMENT}.bicepparam`,
  secrets: `${ENVIRONMENT}.secrets.bicepparam`,
  apps: `${ENVIRONMENT}.apps.bicepparam`,
  certificates: `${ENVIRONMENT}.certificates.bicepparam`,
} as const;
export type Deployment = keyof typeof DEPLOYMENTS;

/**
 * The hand deploys that record the commit they sent (T1b), each in its own tag
 * on the migration job, which CI's release reads already: the gate then takes
 * a changed file only these read as deployed once each one's record has it
 * (release.ts). apps needs none: its stamp is what the workloads run.
 */
export const RECORDED = ['foundation', 'secrets', 'certificates'] as const satisfies readonly Deployment[];
export type Recorded = (typeof RECORDED)[number];

/** The tag that holds a hand deploy's record. */
export const recordTag = (deployment: Recorded): string => `agentx-deployed-${deployment}`;

/** The job that holds the records (apps.bicep); a test holds it to the one CI releases. */
export const RECORDS_JOB = 'job-agentx-stg-migrate';

/** The Container Apps environment the foundation creates (names.bicep), which holds the doors; a test holds the two equal. */
export const APPS_ENVIRONMENT = 'cae-agentx-staging';

/** What the certificates deployment reads from the shell (staging.certificates.bicepparam): the apps' two hosts. */
export const CERTIFICATE_VARIABLES = { authHost: APP_VARIABLES.authHost, appHost: APP_VARIABLES.appHost } as const;

/**
 * Every secret the vault holds, by its name there, with the variable
 * staging.secrets.bicepparam reads it from and who makes it. A test holds this
 * equal to the parameters file and to the secrets the deployment creates.
 * - person: pasted from the password manager
 * - machine: a fresh login, made here
 * - pair: the login container's key pair, both halves made together
 * - once: Zitadel's master key; a fresh one goes every run, and Azure keeps only the first
 * - issued: given by a service we are a client of, pasted by a person, and
 *   written only by name (`--rotate`): it exists only once that service does,
 *   so a first `--all` can't have it (B2-6)
 */
export const VAULT_SECRETS: Readonly<
  Record<string, { readonly variable: string; readonly source: 'person' | 'machine' | 'pair' | 'once' | 'issued' }>
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
  'api-oidc-client-secret': { variable: 'AGENTX_AZURE_API_OIDC_CLIENT_SECRET', source: 'issued' },
};

/**
 * The app's keys (app-keys.json), fresh on every run as one JSON value
 * (staging.secrets.bicepparam). Each is created once: a key the vault holds
 * keeps its value, whatever a run brings.
 */
export const APP_KEYS_VARIABLE = 'AGENTX_AZURE_APP_KEYS';

const ADMIN_PASSWORD = 'AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD';
const ALERT_EMAIL = 'AGENTX_AZURE_ALERT_EMAIL';

/** Every variable that carries a secret: the ones the policy check replaces with stand-ins. */
const SECRET_VARIABLES: ReadonlySet<string> = new Set(Object.values(VAULT_SECRETS).map((secret) => secret.variable));

/** What each person-held secret is called when the operator is asked for it. */
const PERSON_LABELS: Readonly<Record<string, string>> = {
  'db-admin-password': "the database admin's password",
  'zitadel-admin-password': "Zitadel's first admin's password",
  'api-oidc-client-secret': "the API's client secret, as Zitadel showed it",
};

/** Every secret (`all`), the ones named (`rotate`), or only the app's keys the vault lacks (`keys`). */
export type SecretPlan =
  | { readonly kind: 'all' }
  | { readonly kind: 'rotate'; readonly names: ReadonlySet<string> }
  | { readonly kind: 'keys' };

export type Request =
  | { readonly command: 'foundation' }
  | { readonly command: 'secrets'; readonly plan: SecretPlan }
  | { readonly command: 'apps'; readonly commit: string | undefined; readonly keepRunning: boolean }
  | { readonly command: 'alerts' }
  | { readonly command: 'dns' }
  | { readonly command: 'certificates' };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage, from your own terminal window:
  node deploy/azure/deploy.ts foundation
  node deploy/azure/deploy.ts secrets --all
  node deploy/azure/deploy.ts secrets --rotate <secret name> [...]
  node deploy/azure/deploy.ts secrets --keys
  node deploy/azure/deploy.ts apps [--commit <40-hex commit on main>] [--keep-running]
  node deploy/azure/deploy.ts alerts
  node deploy/azure/deploy.ts dns
  node deploy/azure/deploy.ts certificates`;

/** `apps`'s options, each at most once, in either order. */
function parseApps(options: readonly string[]): Request {
  let commit: string | undefined;
  let keepRunning = false;
  for (let at = 0; at < options.length; at += 1) {
    const option = options[at];
    if (option === '--keep-running' && !keepRunning) {
      keepRunning = true;
    } else if (option === '--commit' && commit === undefined && COMMIT.test(options[at + 1] ?? '')) {
      commit = options[at + 1];
      at += 1;
    } else {
      throw new UsageError('apps takes --keep-running, and --commit with one full 40-hex commit, each at most once');
    }
  }
  return { command: 'apps', commit, keepRunning };
}

/** What the operator asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, ...rest] = argv;
  if (command === 'foundation' || command === 'alerts' || command === 'dns' || command === 'certificates') {
    if (rest.length > 0) throw new UsageError(`${command} takes no options, not ${rest.join(' ')}`);
    return { command };
  }
  if (command === 'apps') return parseApps(rest);
  if (command !== 'secrets') {
    throw new UsageError(`say foundation, secrets, apps, alerts, dns or certificates, not ${command ?? 'nothing'}`);
  }
  const [mode, ...names] = rest;
  if (mode === '--all') {
    if (names.length > 0) throw new UsageError('--all takes no names: it writes every secret');
    return { command, plan: { kind: 'all' } };
  }
  if (mode === '--keys') {
    if (names.length > 0)
      throw new UsageError('--keys takes no names: it creates every key in app-keys.json the vault lacks');
    return { command, plan: { kind: 'keys' } };
  }
  if (mode !== '--rotate') {
    throw new UsageError('secrets needs --all (the first run), --rotate <names> or --keys');
  }
  if (names.length === 0) throw new UsageError('--rotate needs at least one secret name');
  for (const name of names) {
    if (APP_KEYS.includes(name)) {
      throw new UsageError(
        `${name} is never written again: what it sealed or signed needs it as it was. A key rotates by a new version in app-keys.json, then secrets --keys (Azure.md)`,
      );
    }
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

/** Whether a run writes the secret: `--all` writes all but an issued one, which only its name writes. */
const planIncludes = (plan: SecretPlan, name: string): boolean =>
  (plan.kind === 'all' && VAULT_SECRETS[name]?.source !== 'issued') || (plan.kind === 'rotate' && plan.names.has(name));

/** The secrets a person pastes (theirs, and the issued ones) that a run must ask for. */
export const peopleAskedFor = (plan: SecretPlan): string[] =>
  Object.entries(VAULT_SECRETS)
    .filter(([name, secret]) => (secret.source === 'person' || secret.source === 'issued') && planIncludes(plan, name))
    .map(([name]) => name);

export interface Makers {
  readonly random: Random;
  readonly keyPair: KeyPair;
}

/**
 * Every variable a secrets run sets: a value for each secret the plan writes,
 * and an empty one for each it leaves as the vault has it (the parameters file
 * refuses a missing one, so a misspelt name can't pass for a rotation). The
 * master key and the app's keys always go, fresh; Azure keeps only the first
 * of each.
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
      case 'person':
      case 'issued': {
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
  values[APP_KEYS_VARIABLE] = newAppKeys(makers.random);
  return values;
}

/** One line per secret: what the run does with it. Names only, never a value. */
export function describePlan(plan: SecretPlan): string[] {
  const secrets = Object.entries(VAULT_SECRETS).map(([name, secret]) => {
    if (secret.source === 'once') return `  ${name}: written only if the vault has none yet`;
    if (!planIncludes(plan, name)) return `  ${name}: kept as the vault has it`;
    return secret.source === 'person' || secret.source === 'issued'
      ? `  ${name}: written, from what you paste`
      : `  ${name}: written, made fresh by this run`;
  });
  return [...secrets, ...APP_KEYS.map((key) => `  ${key}: written only if the vault has none yet`)];
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

/**
 * Why a secret a service issued won't do, or nothing: it is taken as the
 * service showed it, so only what a paste could have got wrong is refused. The
 * message never repeats the value.
 */
export function issuedProblems(value: string): string[] {
  const problems: string[] = [];
  if (value.length < 16) problems.push('it is shorter than 16 characters, shorter than any service issues');
  if (value.length > 2048) problems.push('it is longer than the 2048 characters the API takes');
  if (value.trim() !== value) problems.push('it starts or ends with a space, which a paste may have added');
  else if (!/^[!-~]*$/.test(value)) problems.push('it holds a space or a character that is not plain visible ASCII');
  return problems;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** A host name as DNS writes it: lower case, two labels or more, none starting or ending with a hyphen. */
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const COMMIT = /^[0-9a-f]{40}$/;

/** A client ID as the API's config takes one (AGENTX_OIDC_CLIENT_ID). */
const CLIENT_ID = /^[!-~]{1,255}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

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

/**
 * A person's password, asked twice so a slip of the paste is caught, and held
 * to `passwordProblems`, or to `issuedProblems` for a secret a service issued.
 */
export async function askPassword(
  terminal: Terminal,
  label: string,
  tries = 3,
  problemsWith: (value: string) => string[] = passwordProblems,
): Promise<string> {
  for (let attempt = 1; attempt <= tries; attempt += 1) {
    const first = await terminal.askHidden(`Paste ${label} (nothing will show): `);
    const problems = problemsWith(first);
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
 * the one it finds there, not to look for a newer one, and never to install an
 * extension of its own accord.
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
  // A command that needs an extension fails rather than installing one unpinned (it offers to, unasked).
  env.AZURE_EXTENSION_USE_DYNAMIC_INSTALL = 'no';
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

/** The CLI as every command here runs it (jobs.ts too). */
export function realAz(): Az {
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
export function azJson(az: Az, args: readonly string[]): unknown {
  const done = az.run([...args, '--output', 'json']);
  if (done.status !== 0) throw new Error(`az ${args.join(' ')} failed:\n${done.stderr.trim()}`);
  return JSON.parse(done.stdout) as unknown;
}

export const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/**
 * A run's values with every secret replaced by a stand-in of the same shape:
 * an empty one stays empty, since that is what decides whether a secret is
 * written, the master key stays 32 characters, and the app's keys stay one
 * JSON value with a key each. Everything else is as given.
 */
export function shapedForPolicy(values: Readonly<Record<string, string>>, random: Random): Record<string, string> {
  const shaped: Record<string, string> = {};
  for (const [name, value] of Object.entries(values)) {
    const bytes = name === VAULT_SECRETS['zitadel-masterkey']?.variable ? 16 : 24;
    shaped[name] =
      name === APP_KEYS_VARIABLE
        ? newAppKeys(random)
        : SECRET_VARIABLES.has(name) && value !== ''
          ? random(bytes).toString('hex')
          : value;
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

/** Finding the image a commit on main was published as, and checking it. */
export interface Images {
  /** The newest commit on main, from GitHub. */
  latestCommit(): Promise<string>;
  /** The digest ghcr.io gives the image CI tagged with that commit. */
  digestOf(commit: string): Promise<string>;
  /** verify.ts's answer for the image, by digest, at that commit. */
  verify(image: string, commit: string): Outcome;
}

/** Media types a registry may answer a manifest request with. */
const MANIFEST_TYPES = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');

async function json(url: string, headers: Readonly<Record<string, string>> = {}): Promise<unknown> {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${url} answered ${String(response.status)}`);
  return await response.json();
}

/** GitHub and ghcr.io, both public, so nothing here holds a credential. */
export function realImages(cosign: () => string = installedCosign): Images {
  const repository = IMAGE_REPOSITORY.replace(/^ghcr\.io\//, '');
  return {
    latestCommit: async () =>
      text(
        (
          (await json(`https://api.github.com/repos/${SOURCE_REPOSITORY}/commits/main`, {
            accept: 'application/vnd.github+json',
          })) as { sha?: unknown }
        ).sha,
      ),
    digestOf: async (commit) => {
      const token = text(
        (
          (await json(`https://ghcr.io/token?scope=repository:${repository}:pull&service=ghcr.io`)) as {
            token?: unknown;
          }
        ).token,
      );
      const response = await fetch(`https://ghcr.io/v2/${repository}/manifests/${commit}`, {
        method: 'HEAD',
        headers: { authorization: `Bearer ${token}`, accept: MANIFEST_TYPES },
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) {
        throw new Error(
          `ghcr.io has no image for ${commit} (${String(response.status)}): has CI published it on main yet?`,
        );
      }
      return response.headers.get('docker-content-digest') ?? '';
    },
    verify: (image, commit) => {
      const binary = cosign();
      return verifyImage(image, commit, (args) => runCosign(args, binary));
    },
  };
}

export interface Steps {
  readonly terminal: Terminal;
  readonly az: Az;
  readonly policy: (values: Readonly<Record<string, string>>) => string[];
  /** Whether GitHub's published ranges still match the file the rules are built from. */
  readonly rangesCurrent: () => boolean;
  readonly now: () => Date;
  readonly makers?: Makers;
  readonly images?: Images;
  readonly dns?: DnsLookup;
  /** The folder this runs from, which apps sends the Bicep of (git.ts). */
  readonly checkout?: () => Checkout;
}

/** The subscription the CLI is signed in to, said to the operator: its ID. */
export function signedIn(az: Az, say: (line: string) => void): string {
  const account = azJson(az, ['account', 'show']);
  const name = text((account as { name?: unknown }).name);
  const id = text((account as { id?: unknown }).id);
  say(`Signed in to the subscription "${name}" (${id}).`);
  return id;
}

/** The subscription the CLI is signed in to, confirmed by the operator. */
async function confirmSubscription(steps: Steps): Promise<string> {
  const id = signedIn(steps.az, (line) => {
    steps.terminal.say(line);
  });
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

/** How a deployment the operator was asked about ended: Azure's state, or Declined when none was made. */
interface Ended {
  readonly state: string;
  readonly outputs: unknown;
}

/**
 * Reads back how a deployment ended. It is never assumed from the CLI's exit
 * status: `--confirm-with-what-if` ends with status 0 when the operator answers
 * no, and then no deployment exists to show (found on the first rehearsal, S18).
 */
function howItEnded(steps: Steps, show: readonly string[]): Ended {
  const done = steps.az.run([
    ...show,
    '--query',
    '{state: properties.provisioningState, outputs: properties.outputs}',
    '--output',
    'json',
  ]);
  if (done.status !== 0) {
    if (done.stderr.includes('DeploymentNotFound')) return { state: 'Declined', outputs: undefined };
    throw new Error(`az ${show.join(' ')} failed:\n${done.stderr.trim()}`);
  }
  const parsed = JSON.parse(done.stdout) as { state?: unknown; outputs?: unknown };
  return { state: text(parsed.state), outputs: parsed.outputs };
}

/** Says how a deployment ended unless it succeeded; true only when it did. */
function succeeded(steps: Steps, name: string, ended: Ended): boolean {
  if (ended.state === 'Succeeded') return true;
  steps.terminal.say(
    ended.state === 'Declined'
      ? 'You answered no at the what-if: nothing was deployed.'
      : `The deployment ${name} ended ${ended.state === '' ? 'in a state Azure did not say' : ended.state}: nothing more was done.`,
  );
  return false;
}

/**
 * The commit this folder is at, which a recorded deploy records: refused when
 * anything in it differs from that commit, since the record says the commit's
 * Bicep is what Azure was built from.
 */
function sentFrom(steps: Steps, deployment: Recorded): string {
  if (steps.checkout === undefined) throw new Error('No way to read this folder was given.');
  const here = steps.checkout();
  if (!here.clean) {
    throw new Error(
      `This folder is at ${here.head} with changes not committed. ${deployment} records the commit it sends, and CI's release takes the record as what Azure was built from, so the Bicep sent must be a commit's with nothing changed (git switch main, then git pull). Nothing was deployed.`,
    );
  }
  return here.head;
}

/**
 * Records on the migration job that this deploy sent the commit, then reads
 * the record back; true once it holds. Before the first apps run there is no
 * job to hold it, and no release to accept it either, so nothing is recorded.
 * A record that can't be written leaves CI's release red, as it was before T1b.
 */
function leaveRecord(steps: Steps, subscription: string, deployment: Recorded, commit: string): boolean {
  const job = `/subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/jobs/${RECORDS_JOB}`;
  const tag = recordTag(deployment);
  const unrecorded = (why: string): false => {
    steps.terminal.say(
      `Deployed, but not recorded (${why}): CI's release stays red on what ${deployment} reads until apps runs.`,
    );
    return false;
  };
  try {
    azJson(steps.az, ['tag', 'update', '--resource-id', job, '--operation', 'Merge', '--tags', `${tag}=${commit}`]);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    if (error.message.includes('(ResourceNotFound)')) {
      steps.terminal.say(
        `No ${RECORDS_JOB} yet (apps creates it), so nothing was recorded: the first apps run stamps what staging runs.`,
      );
      return true;
    }
    return unrecorded(error.message);
  }
  let held: unknown;
  try {
    const read = azJson(steps.az, ['tag', 'list', '--resource-id', job]) as { properties?: { tags?: unknown } } | null;
    held = (read?.properties?.tags as Readonly<Record<string, unknown>> | null | undefined)?.[tag];
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return unrecorded(error.message);
  }
  if (held !== commit) return unrecorded(`${tag} reads back as ${typeof held === 'string' ? held : 'nothing'}`);
  steps.terminal.say(
    `Recorded on ${RECORDS_JOB}: ${deployment} sent ${commit}. CI's release takes it for what ${deployment} reads.`,
  );
  return true;
}

async function deployFoundation(steps: Steps): Promise<number> {
  const commit = sentFrom(steps, 'foundation');
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
      DEPLOYMENTS.foundation,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  const ended = howItEnded(steps, ['deployment', 'sub', 'show', '--subscription', subscription, '--name', name]);
  if (!succeeded(steps, name, ended)) return 1;
  steps.terminal.say('Deployed. What the foundation reports:');
  for (const [key, output] of Object.entries((ended.outputs ?? {}) as Record<string, { value?: unknown }>)) {
    steps.terminal.say(`  ${key}: ${text(output.value)}`);
  }
  const recorded = leaveRecord(steps, subscription, 'foundation', commit);
  if (await alertsReachable(steps, subscription)) return recorded ? 0 : 1;
  steps.terminal.say(
    'The foundation is deployed, but no alert email can reach you yet. Once the address is confirmed, run node deploy/azure/deploy.ts alerts to check.',
  );
  return 1;
}

/** Where Azure Resource Manager answers: a list's next page must be there too. */
export const ARM = 'https://management.azure.com/';

/** The first version of the action group API that says whether an address is confirmed (`verificationStatus`, S20). */
const ACTION_GROUP_API = '2026-03-01-preview';

/** How many times the operator is asked to confirm the alert address before the run gives up. */
const CONFIRM_TRIES = 3;

/** Why an alert address gets nothing, or nothing when it gets every alert. */
function addressProblem(receiver: { readonly status?: unknown; readonly verificationStatus?: unknown }): string {
  if (receiver.status !== 'Enabled') return `Azure has it switched off (${text(receiver.status) || 'no status'})`;
  if (receiver.verificationStatus !== 'Verified') {
    return `it isn't confirmed (${text(receiver.verificationStatus) || 'Azure did not say'})`;
  }
  return '';
}

/**
 * Each email address the alert group notifies that gets nothing, with why.
 * A group that is off sends nothing to anyone, whatever its receivers say.
 */
function unreachedAddresses(steps: Steps, subscription: string): string[] {
  const group = azJson(steps.az, [
    'rest',
    '--method',
    'get',
    '--url',
    `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Insights/actionGroups/${ACTION_GROUP}?api-version=${ACTION_GROUP_API}`,
  ]) as {
    properties?: {
      enabled?: unknown;
      emailReceivers?: readonly { emailAddress?: unknown; status?: unknown; verificationStatus?: unknown }[];
    };
  };
  const receivers = group.properties?.emailReceivers ?? [];
  if (receivers.length === 0) throw new Error(`${ACTION_GROUP} has no email address, so no alert is emailed.`);
  if (group.properties?.enabled !== true) return [`  every address: ${ACTION_GROUP} itself is switched off`];
  return receivers
    .map((receiver) => ({ address: text(receiver.emailAddress), problem: addressProblem(receiver) }))
    .filter((each) => each.problem !== '')
    .map((each) => `  ${each.address}: ${each.problem}`);
}

/**
 * Whether every alert email reaches its address, the operator asked to
 * confirm any that doesn't. Azure emails a new address a one-time code when the
 * group is saved, valid for 30 minutes, and until the code is entered sends the
 * address nothing, not even a SEV-1, while still calling it Enabled and logging
 * the group as executed: every alert of the first deploy was lost that way
 * (S19). A free trial can't send a test notification, so this reading is the
 * only check short of a real alert (S20).
 */
async function alertsReachable(steps: Steps, subscription: string): Promise<boolean> {
  for (let asked = 0; ; asked += 1) {
    const unreached = unreachedAddresses(steps, subscription);
    if (unreached.length === 0) {
      steps.terminal.say('Alert email: confirmed, so every alert reaches it.');
      return true;
    }
    steps.terminal.say(['No alert email reaches:', ...unreached].join('\n'));
    if (asked === CONFIRM_TRIES) return false;
    if (asked === 0) {
      steps.terminal.say(
        `Azure emails a one-time code, valid for 30 minutes, when the alert group is saved (from azure-noreply@microsoft.com; look in Junk too). In the Azure portal open Monitor, Alerts, Action groups, ${ACTION_GROUP}, and select Resend if the code has expired or never came.`,
      );
    }
    if (
      (await steps.terminal.ask('Press Enter once the address is confirmed, or type skip: ')).toLowerCase() === 'skip'
    ) {
      return false;
    }
  }
}

/** Says whether the alerts reach their address, changing nothing. */
async function checkAlerts(steps: Steps): Promise<number> {
  const subscription = signedIn(steps.az, (line) => {
    steps.terminal.say(line);
  });
  steps.terminal.say(`Reading ${ACTION_GROUP} in ${RESOURCE_GROUP}; nothing is changed.`);
  if (await alertsReachable(steps, subscription)) return 0;
  steps.terminal.say('Until that changes, no alert email reaches you.');
  return 1;
}

/** More pages than any list of ours fills (Azure gives three secrets a page): a list that runs past it isn't trusted. */
const MAX_PAGES = 100;

/**
 * Every item of a list read through Azure Resource Manager, `what` naming it
 * in any message. Azure answers a page at a time with a link to the next, and
 * may end with an empty one (the vault's secrets, three a page, S19), so every
 * page is read, and only while the links stay on Resource Manager.
 */
function armList(steps: Steps, first: string, what: string): unknown[] {
  const items: unknown[] = [];
  let url = first;
  for (let page = 1; url !== ''; page += 1) {
    if (page > MAX_PAGES) {
      throw new Error(`Azure's list of ${what} went past ${String(MAX_PAGES)} pages, so it wasn't trusted.`);
    }
    if (!url.startsWith(ARM)) {
      throw new Error(`Azure's list of ${what} led outside Azure Resource Manager, so it wasn't followed.`);
    }
    const listed = azJson(steps.az, ['rest', '--method', 'get', '--url', url]) as {
      value?: readonly unknown[];
      nextLink?: unknown;
    };
    items.push(...(listed.value ?? []));
    url = text(listed.nextLink);
  }
  return items;
}

/** A secret as the vault lists it: its name, and its current version's URL (never its value). */
interface Listed {
  readonly name: string;
  readonly version: string;
}

/**
 * The secrets the vault already holds. A first page alone showed three of
 * nine, and an empty one would let `--all` skip its question (S19).
 */
function secretsInVault(steps: Steps, subscription: string, vault: string): Listed[] {
  return armList(
    steps,
    `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${vault}/secrets?api-version=2025-05-01`,
    "the vault's secrets",
  ).map((secret) => {
    const listed = secret as { name?: unknown; properties?: { secretUriWithVersion?: unknown } };
    return { name: text(listed.name), version: text(listed.properties?.secretUriWithVersion) };
  });
}

/**
 * What a run did to the app's keys, from the vault's list before and after it:
 * every key must be there, and one the vault held before must still be the
 * version it was. A key written again would leave what it sealed unreadable
 * and what it signed unchecked, so every run checks that `@onlyIfNotExists()`
 * held for each key in the list.
 */
export function keyProblems(before: readonly Listed[], after: readonly Listed[]): string[] {
  return APP_KEYS.flatMap((key) => {
    const now = after.find((secret) => secret.name === key);
    if (now === undefined) return [`${key} isn't in the vault, so the API won't start: run secrets --keys again`];
    const was = before.find((secret) => secret.name === key);
    return was !== undefined && was.version !== now.version
      ? [
          `${key} was written again, so what it sealed may not open and what it signed may not check: stop, and follow Azure.md, "A key written again"`,
        ]
      : [];
  });
}

/** The one key vault the foundation made. */
function vaultIn(steps: Steps, subscription: string): string {
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
  return vault;
}

/**
 * The issued secrets the vault doesn't hold yet (B2-6). An app reads each by
 * its URL, so a deployment without one leaves that app unable to start; each
 * is issued by a service already running, then written by name.
 */
export function issuedMissing(held: readonly string[]): string[] {
  return Object.entries(VAULT_SECRETS)
    .filter(([name, secret]) => secret.source === 'issued' && !held.includes(name))
    .map(([name]) => name);
}

async function deploySecrets(steps: Steps, plan: SecretPlan): Promise<number> {
  const commit = sentFrom(steps, 'secrets');
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  const vault = vaultIn(steps, subscription);
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
    const issued = VAULT_SECRETS[name]?.source === 'issued';
    people[name] = await askPassword(
      steps.terminal,
      PERSON_LABELS[name] ?? name,
      3,
      issued ? issuedProblems : passwordProblems,
    );
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
      DEPLOYMENTS.secrets,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  const ended = howItEnded(steps, [
    'deployment',
    'group',
    'show',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--name',
    name,
  ]);
  if (!succeeded(steps, name, ended)) return 1;
  const now = secretsInVault(steps, subscription, vault);
  steps.terminal.say('Deployed. The vault now holds:');
  for (const secret of now.map((listed) => listed.name).sort()) steps.terminal.say(`  ${secret}`);
  const problems = keyProblems(existing, now);
  for (const problem of problems) steps.terminal.say(problem);
  if (problems.length > 0) return 1;
  steps.terminal.say(
    `The app's ${String(APP_KEYS.length)} keys are there, and none that was there before was written again.`,
  );
  // Recorded only once the keys are sound: a release on a vault missing one would start an API that can't.
  const recorded = leaveRecord(steps, subscription, 'secrets', commit);
  if (plan.kind === 'rotate' && [...plan.names].some((secret) => secret.startsWith('db-'))) {
    steps.terminal.say('A database login changed: start the set-up job now, so the server takes it.');
  }
  return recorded ? 0 : 1;
}

/** A host name the operator types, held to DNS's shape. */
async function askHost(steps: Steps, question: string): Promise<string> {
  const host = (await steps.terminal.ask(question)).toLowerCase();
  if (!HOST.test(host)) throw new Error(`${host} isn't a host name: nothing was deployed.`);
  return host;
}

/** The two doors' hosts, typed by the operator, in lower case, and not the same. */
async function askHosts(steps: Steps): Promise<{ readonly authHost: string; readonly appHost: string }> {
  const authHost = await askHost(steps, 'Host for sign-in (Zitadel): ');
  const appHost = await askHost(steps, 'Host for the app (the API): ');
  if (authHost === appHost) throw new Error('The two hosts must differ: nothing was deployed.');
  return { authHost, appHost };
}

/** Looking a host's records up in public DNS. */
export interface DnsLookup {
  /** The host's IPv4 addresses; none when it has none. */
  addresses(host: string): Promise<readonly string[]>;
  /** The host's TXT records, each one's strings joined; none when it has none. */
  texts(host: string): Promise<readonly string[]>;
}

/** Answers that mean the name has no record of the kind asked: nothing found, not a failure. */
const NO_RECORD: ReadonlySet<unknown> = new Set(['ENOTFOUND', 'ENODATA']);

/** The machine's own resolver, as a browser on it would see the hosts. */
export function realDns(resolver: Pick<typeof systemDns, 'resolve4' | 'resolveTxt'> = systemDns): DnsLookup {
  const found = async <T>(host: string, look: () => Promise<T[]>): Promise<T[]> => {
    try {
      return await look();
    } catch (error) {
      if (NO_RECORD.has((error as { code?: unknown }).code)) return [];
      throw new Error(`Looking up ${host} failed: ${String(error)}`, { cause: error });
    }
  };
  return {
    addresses: (host) => found(host, () => resolver.resolve4(host)),
    texts: async (host) => (await found(host, () => resolver.resolveTxt(host))).map((strings) => strings.join('')),
  };
}

/** What a door's host's DNS records carry: the environment's public address and its verification code. */
export interface EnvironmentDns {
  readonly ip: string;
  readonly verification: string;
}

/** The API version the apps and jobs are deployed with (apps.bicep), for reading the environment and its certificates. */
const ENVIRONMENT_API = '2026-01-01';

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const VERIFICATION_CODE = /^[0-9A-F]{64}$/;

const environmentUrl = (subscription: string): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/managedEnvironments/${APPS_ENVIRONMENT}`;

/** The environment's address and verification code, read through Azure Resource Manager. */
function environmentDns(steps: Steps, subscription: string): EnvironmentDns {
  const environment = azJson(steps.az, [
    'rest',
    '--method',
    'get',
    '--url',
    `${environmentUrl(subscription)}?api-version=${ENVIRONMENT_API}`,
  ]) as { properties?: { staticIp?: unknown; customDomainConfiguration?: { customDomainVerificationId?: unknown } } };
  const ip = text(environment.properties?.staticIp);
  const verification = text(environment.properties?.customDomainConfiguration?.customDomainVerificationId);
  if (!IPV4.test(ip) || !VERIFICATION_CODE.test(verification)) {
    throw new Error(
      `Azure gave no public address and verification code for ${APPS_ENVIRONMENT}: deploy the foundation first.`,
    );
  }
  return { ip, verification };
}

export interface DoorRecord {
  readonly type: 'A' | 'TXT';
  readonly name: string;
  readonly value: string;
  /** What the name answers with now. */
  readonly answers: readonly string[];
  readonly ready: boolean;
}

/**
 * The two records each door's host needs (Microsoft, for a custom domain on a
 * route config): an A record for the environment's address, and the only one,
 * since a certificate's validation could otherwise reach another; and a TXT
 * record `asuid.<host>` holding the environment's verification code.
 */
export async function doorRecords(
  dns: DnsLookup,
  hosts: readonly string[],
  environment: EnvironmentDns,
): Promise<DoorRecord[]> {
  const records: DoorRecord[] = [];
  for (const host of hosts) {
    const addresses = await dns.addresses(host);
    records.push({
      type: 'A',
      name: host,
      value: environment.ip,
      answers: addresses,
      ready: addresses.length === 1 && addresses[0] === environment.ip,
    });
    const texts = await dns.texts(`asuid.${host}`);
    records.push({
      type: 'TXT',
      name: `asuid.${host}`,
      value: environment.verification,
      answers: texts,
      ready: texts.includes(environment.verification),
    });
  }
  return records;
}

/** Says each record and whether it is in place; true only when all are. */
function sayRecords(steps: Steps, records: readonly DoorRecord[]): boolean {
  steps.terminal.say(
    "The DNS records the public doors need, at the domain's DNS provider (there, a name is the part before the domain):",
  );
  for (const record of records) {
    const now = record.ready
      ? 'in place'
      : record.answers.length === 0
        ? 'MISSING'
        : `WRONG: it answers ${record.answers.join(', ')}`;
    steps.terminal.say(`  ${record.type.padEnd(3)}  ${record.name}  ${record.value}  (${now})`);
  }
  return records.every((record) => record.ready);
}

function dnsOf(steps: Steps): DnsLookup {
  if (steps.dns === undefined) throw new Error('No way to look up DNS was given.');
  return steps.dns;
}

/** Says which DNS records the doors' hosts still need, changing nothing. */
async function checkDns(steps: Steps): Promise<number> {
  const dns = dnsOf(steps);
  const subscription = signedIn(steps.az, (line) => {
    steps.terminal.say(line);
  });
  const { authHost, appHost } = await askHosts(steps);
  steps.terminal.say(`Reading ${APPS_ENVIRONMENT}'s address and the hosts' DNS; nothing is changed.`);
  const ready = sayRecords(steps, await doorRecords(dns, [appHost, authHost], environmentDns(steps, subscription)));
  steps.terminal.say(
    ready
      ? 'Every record is in place.'
      : 'Add or fix the records marked above. A new record can take a few minutes to show.',
  );
  return ready ? 0 : 1;
}

/**
 * The apps that keep no replica running. Microsoft asks for an app to be
 * running while its certificate is issued ("When the app is stopped, its
 * ingress doesn't serve the domain validation request"), and whether an app
 * scaled to zero counts isn't written down, so issuance waits for `apps
 * --keep-running`. Every app is asked, since the doors reach all three today;
 * an app no door reaches (the worker, Phase 4) must be left out of this.
 */
function appsKeptAtZero(steps: Steps, subscription: string): string[] {
  const found = azJson(steps.az, [
    'containerapp',
    'list',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--query',
    '[].{name: name, fewest: properties.template.scale.minReplicas}',
  ]);
  const apps = Array.isArray(found) ? (found as readonly { name?: unknown; fewest?: unknown }[]) : [];
  if (apps.length === 0) throw new Error(`${RESOURCE_GROUP} holds no apps: deploy them first.`);
  return apps.filter((app) => typeof app.fewest !== 'number' || app.fewest < 1).map((app) => text(app.name));
}

async function deployCertificates(steps: Steps): Promise<number> {
  const dns = dnsOf(steps);
  const commit = sentFrom(steps, 'certificates');
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  const { authHost, appHost } = await askHosts(steps);
  const records = await doorRecords(dns, [appHost, authHost], environmentDns(steps, subscription));
  if (!sayRecords(steps, records)) {
    throw new Error(
      'Every record above must be in place first (node deploy/azure/deploy.ts dns says when): nothing was deployed.',
    );
  }
  const idle = appsKeptAtZero(steps, subscription);
  if (idle.length > 0) {
    throw new Error(
      `A certificate is issued only while its app runs, and ${idle.join(', ')} keep no replica running: run apps --keep-running first. Nothing was deployed.`,
    );
  }
  const values = { [CERTIFICATE_VARIABLES.authHost]: authHost, [CERTIFICATE_VARIABLES.appHost]: appHost };
  checkPolicy(steps, values);
  const name = deploymentName('certificates', steps.now());
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
      DEPLOYMENTS.certificates,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  const ended = howItEnded(steps, [
    'deployment',
    'group',
    'show',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--name',
    name,
  ]);
  if (!succeeded(steps, name, ended)) return 1;
  steps.terminal.say('Deployed. The certificates, and how Azure left each:');
  const certificates = armList(
    steps,
    `${environmentUrl(subscription)}/managedCertificates?api-version=${ENVIRONMENT_API}`,
    "the environment's certificates",
  ) as readonly { name?: unknown; properties?: { subjectName?: unknown; provisioningState?: unknown } }[];
  for (const certificate of certificates) {
    steps.terminal.say(
      `  ${text(certificate.name)}: ${text(certificate.properties?.subjectName)}, ${text(certificate.properties?.provisioningState)}`,
    );
  }
  const recorded = leaveRecord(steps, subscription, 'certificates', commit);
  steps.terminal.say(
    'A door answers over https once its certificate has succeeded. Then run apps without --keep-running to stop the billing.',
  );
  return recorded ? 0 : 1;
}

async function deployApps(steps: Steps, commit: string | undefined, keepRunning: boolean): Promise<number> {
  const images = steps.images;
  if (images === undefined) throw new Error('No way to find the image was given.');
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  // Before anything else is asked: the API reads its client secret from the vault.
  const missing = issuedMissing(
    secretsInVault(steps, subscription, vaultIn(steps, subscription)).map((listed) => listed.name),
  );
  if (missing.length > 0) {
    throw new Error(
      `The vault doesn't hold ${missing.join(', ')} yet, which the API reads, so the API couldn't start. Register the API with Zitadel, then run secrets --rotate ${missing.join(' ')} (Azure.md, "Sign-in"). A new environment, where Zitadel doesn't run yet, needs its first apps without sign-in (Carry-Forward.md). Nothing was deployed.`,
    );
  }
  const release = commit ?? (await images.latestCommit());
  if (!COMMIT.test(release)) throw new Error(`GitHub gave ${release} as main's newest commit, which isn't one.`);
  // The apps are stamped with the release, and CI's release job takes the stamp
  // to say which commit Azure's set-up was built from (release.ts): so the
  // Bicep sent must be that commit's, exactly.
  if (steps.checkout === undefined) throw new Error('No way to read this folder was given.');
  const here = steps.checkout();
  if (here.head !== release || !here.clean) {
    throw new Error(
      `This folder is at ${here.head}${here.clean ? '' : ' with changes not committed'}, but the image is for ${release}. apps sends this folder's Bicep and stamps the apps with ${release}, so the two must be the same commit, with nothing changed (git switch main, then git pull). Nothing was deployed.`,
    );
  }
  const digest = await images.digestOf(release);
  if (!DIGEST.test(digest)) throw new Error(`ghcr.io gave ${digest} as the image's digest, which isn't one.`);
  const image = `${IMAGE_REPOSITORY}@${digest}`;
  steps.terminal.say(`The image for commit ${release}:\n  ${image}`);
  steps.terminal.say('Checking it was signed by CI on main at that commit, with its SBOM...');
  const outcome = images.verify(image, release);
  if (!outcome.verified) {
    throw new Error(`The image was refused (${outcome.reason}), so nothing was deployed:\n${outcome.detail}`);
  }
  steps.terminal.say('Verified.');
  steps.terminal.say(
    keepRunning
      ? 'Each app will keep one replica running, billed, until apps runs again without --keep-running.'
      : 'Each app will scale to zero while nothing uses it.',
  );
  steps.terminal.say('Zitadel keeps the address it is first set up with, so type the two hosts as they will stay.');
  const { authHost, appHost } = await askHosts(steps);
  const adminEmail = await steps.terminal.ask("Zitadel's first admin's address: ");
  if (!EMAIL.test(adminEmail)) throw new Error("That isn't an email address: nothing was deployed.");
  const apiClientId = (await steps.terminal.ask("The API's client ID in Zitadel (its app's page shows it): ")).trim();
  if (!CLIENT_ID.test(apiClientId)) {
    throw new Error("That isn't a client ID (1 to 255 visible characters, no spaces): nothing was deployed.");
  }
  const values = {
    [APP_VARIABLES.digest]: digest,
    [APP_VARIABLES.release]: release,
    [APP_VARIABLES.authHost]: authHost,
    [APP_VARIABLES.appHost]: appHost,
    [APP_VARIABLES.adminEmail]: adminEmail,
    [APP_VARIABLES.apiClientId]: apiClientId,
    [APP_VARIABLES.minReplicas]: keepRunning ? '1' : '0',
  };
  checkPolicy(steps, values);
  const name = deploymentName('apps', steps.now());
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
      DEPLOYMENTS.apps,
      '--confirm-with-what-if',
    ],
    values,
  );
  if (status !== 0) return 1;
  const ended = howItEnded(steps, [
    'deployment',
    'group',
    'show',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--name',
    name,
  ]);
  if (!succeeded(steps, name, ended)) return 1;
  const listed = (kind: 'containerapp' | 'containerapp job'): readonly { name?: unknown; state?: unknown }[] => {
    const found = azJson(steps.az, [
      ...kind.split(' '),
      'list',
      '--subscription',
      subscription,
      '--resource-group',
      RESOURCE_GROUP,
      '--query',
      '[].{name: name, state: properties.provisioningState}',
    ]);
    return Array.isArray(found) ? (found as { name?: unknown; state?: unknown }[]) : [];
  };
  steps.terminal.say('Deployed. The apps and jobs, and how Azure left each:');
  for (const each of [...listed('containerapp'), ...listed('containerapp job')]) {
    steps.terminal.say(`  ${text(each.name)}: ${text(each.state)}`);
  }
  steps.terminal.say("A public door answers once its host's DNS records point at the environment (G3b).");
  // Most deploys need no job (S21): only a first one needs all four.
  steps.terminal.say(
    'On a first deploy, run the four jobs next, in order (deploy/azure/jobs.ts). Later, run migrate when a release adds a migration, and zitadel-setup when Zitadel moves to a new version.',
  );
  if (keepRunning) {
    steps.terminal.say('Each app now keeps one replica running, billed: run apps without --keep-running to stop it.');
  }
  return 0;
}

export async function deploy(request: Request, steps: Steps): Promise<number> {
  switch (request.command) {
    case 'foundation':
      return deployFoundation(steps);
    case 'secrets':
      return deploySecrets(steps, request.plan);
    case 'apps':
      return deployApps(steps, request.commit, request.keepRunning);
    case 'alerts':
      return checkAlerts(steps);
    case 'dns':
      return checkDns(steps);
    case 'certificates':
      return deployCertificates(steps);
  }
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
      images: realImages(),
      dns: realDns(),
      checkout: () => realCheckout(),
    });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
