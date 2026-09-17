// Deploys staging from an operator's own terminal (0e G3a), in this order:
//
//   node deploy/azure/deploy.ts foundation
//   node deploy/azure/deploy.ts secrets --all
//   node deploy/azure/deploy.ts apps
//
// and, later, `secrets --rotate db-app-password [more names]`; and
// `alerts`, which changes nothing and says whether the alerts can reach their
// address (the foundation ends with the same check).
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
// The apps run only an image that verify.ts has found signed by CI on main at
// the commit being deployed, named by its digest (ADR-002 Amendment E2).
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';

import { BICEP_VERSION, installedBicep } from '../../tooling/bicep/bicep.ts';
import { installedCosign } from '../../tooling/cosign/cosign.ts';
import { type KeyPair, newKeyPair, newMasterKey, newPassword, type Random } from '../compose/prepare.ts';
import { IMAGE_REPOSITORY, type Outcome, runCosign, SOURCE_REPOSITORY, verifyImage } from '../image/verify.ts';
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
} as const;

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

export type Request =
  | { readonly command: 'foundation' }
  | { readonly command: 'secrets'; readonly plan: SecretPlan }
  | { readonly command: 'apps'; readonly commit: string | undefined }
  | { readonly command: 'alerts' };

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
  node deploy/azure/deploy.ts apps [--commit <40-hex commit on main>]
  node deploy/azure/deploy.ts alerts`;

/** What the operator asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, ...rest] = argv;
  if (command === 'foundation' || command === 'alerts') {
    if (rest.length > 0) throw new UsageError(`${command} takes no options, not ${rest.join(' ')}`);
    return { command };
  }
  if (command === 'apps') {
    if (rest.length === 0) return { command, commit: undefined };
    const [flag, commit, ...extra] = rest;
    if (flag !== '--commit' || commit === undefined || extra.length > 0 || !COMMIT.test(commit)) {
      throw new UsageError('apps takes nothing, or --commit and one full 40-hex commit');
    }
    return { command, commit };
  }
  if (command !== 'secrets') {
    throw new UsageError(`say foundation, secrets, apps or alerts, not ${command ?? 'nothing'}`);
  }
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

/** A host name as DNS writes it: lower case, two labels or more, none starting or ending with a hyphen. */
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const COMMIT = /^[0-9a-f]{40}$/;
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
  const ended = howItEnded(steps, ['deployment', 'sub', 'show', '--subscription', subscription, '--name', name]);
  if (!succeeded(steps, name, ended)) return 1;
  steps.terminal.say('Deployed. What the foundation reports:');
  for (const [key, output] of Object.entries((ended.outputs ?? {}) as Record<string, { value?: unknown }>)) {
    steps.terminal.say(`  ${key}: ${text(output.value)}`);
  }
  if (await alertsReachable(steps, subscription)) return 0;
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

/** More pages than any vault of ours fills (Azure gives three secrets a page): a list that runs past it isn't trusted. */
const MAX_PAGES = 100;

/**
 * The names of the secrets the vault already holds, read through Azure
 * Resource Manager (never their values). Azure answers three at a time with a
 * link to the next page, and ends with an empty one (the first real run, S19),
 * so every page is read: a first page alone showed three of nine, and an empty
 * one would let `--all` skip its question.
 */
function secretsInVault(steps: Steps, subscription: string, vault: string): string[] {
  const names: string[] = [];
  let url = `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${vault}/secrets?api-version=2025-05-01`;
  for (let page = 1; url !== ''; page += 1) {
    if (page > MAX_PAGES) {
      throw new Error(
        `Azure's list of the vault's secrets went past ${String(MAX_PAGES)} pages, so it wasn't trusted.`,
      );
    }
    if (!url.startsWith(ARM)) {
      throw new Error("Azure's list of the vault's secrets led outside Azure Resource Manager, so it wasn't followed.");
    }
    const listed = azJson(steps.az, ['rest', '--method', 'get', '--url', url]) as {
      value?: readonly { name?: unknown }[];
      nextLink?: unknown;
    };
    names.push(...(listed.value ?? []).map((secret) => text(secret.name)));
    url = text(listed.nextLink);
  }
  return names;
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
  steps.terminal.say('Deployed. The vault now holds:');
  for (const secret of secretsInVault(steps, subscription, vault).sort()) steps.terminal.say(`  ${secret}`);
  if (plan.kind === 'rotate' && [...plan.names].some((secret) => secret.startsWith('db-'))) {
    steps.terminal.say('A database login changed: start the set-up job now, so the server takes it.');
  }
  return 0;
}

/** A host name the operator types, held to DNS's shape. */
async function askHost(steps: Steps, question: string): Promise<string> {
  const host = (await steps.terminal.ask(question)).toLowerCase();
  if (!HOST.test(host)) throw new Error(`${host} isn't a host name: nothing was deployed.`);
  return host;
}

async function deployApps(steps: Steps, commit: string | undefined): Promise<number> {
  const images = steps.images;
  if (images === undefined) throw new Error('No way to find the image was given.');
  const subscription = await confirmSubscription(steps);
  confirmBicep(steps);
  const release = commit ?? (await images.latestCommit());
  if (!COMMIT.test(release)) throw new Error(`GitHub gave ${release} as main's newest commit, which isn't one.`);
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
  steps.terminal.say('Zitadel keeps the address it is first set up with, so type the two hosts as they will stay.');
  const authHost = await askHost(steps, 'Host for sign-in (Zitadel): ');
  const appHost = await askHost(steps, 'Host for the app (the API): ');
  if (authHost === appHost) throw new Error('The two hosts must differ: nothing was deployed.');
  const adminEmail = await steps.terminal.ask("Zitadel's first admin's address: ");
  if (!EMAIL.test(adminEmail)) throw new Error("That isn't an email address: nothing was deployed.");
  const values = {
    [APP_VARIABLES.digest]: digest,
    [APP_VARIABLES.release]: release,
    [APP_VARIABLES.authHost]: authHost,
    [APP_VARIABLES.appHost]: appHost,
    [APP_VARIABLES.adminEmail]: adminEmail,
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
      `${ENVIRONMENT}.apps.bicepparam`,
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
  steps.terminal.say('Nothing is reachable from outside yet (G2e). Next, the four jobs, in order.');
  return 0;
}

export async function deploy(request: Request, steps: Steps): Promise<number> {
  switch (request.command) {
    case 'foundation':
      return deployFoundation(steps);
    case 'secrets':
      return deploySecrets(steps, request.plan);
    case 'apps':
      return deployApps(steps, request.commit);
    case 'alerts':
      return checkAlerts(steps);
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
    });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
