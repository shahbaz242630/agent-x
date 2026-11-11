// The database server's generation (Outstanding-Work AZ25, playbook L): which
// server each environment's deployments name. Generation 0 is the server made
// at the start, named as it always was (`psql-agentx-<short>-<suffix>`); a real
// restore's replacement is the next generation, `-r<n>` after it, restored by
// `az postgres flexible-server restore` beside the live server, which is kept
// with every restore point it has until the partner signs the new one off.
// database-generation.json holds the number, read by names.bicep for every
// deployment and here by deploy.ts foundation, secrets and apps, which refuse
// one whose server isn't there (a foundation would make it new and empty, and
// the apps would reach it) or one older than a server still there (two live
// databases at once) unless the operator says so (serverGenerationVerdict).
import { readFileSync } from 'node:fs';

/** The environments a generation is kept for, as names.bicep's `shortName` knows them. */
const ENVIRONMENTS = ['staging', 'production'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** Far more restores than a server will ever see; a name with it stays well under Azure's 63 characters. */
export const MOST_GENERATIONS = 99;

/** Why database-generation.json can't be used, or nothing. */
export function generationsProblems(parsed: unknown): string[] {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return ['database-generation.json must hold each environment and its generation'];
  }
  const record = parsed as Record<string, unknown>;
  const problems = Object.keys(record)
    .filter((key) => !(ENVIRONMENTS as readonly string[]).includes(key))
    .map((key) => `${key} is no environment: only ${ENVIRONMENTS.join(' and ')} have a server`);
  for (const environment of ENVIRONMENTS) {
    const generation = record[environment];
    if (!Number.isSafeInteger(generation) || (generation as number) < 0 || (generation as number) > MOST_GENERATIONS) {
      problems.push(`${environment}'s generation must be a whole number from 0 to ${String(MOST_GENERATIONS)}`);
    }
  }
  return problems;
}

/** Each environment's generation, from the file beside the Bicep. */
export function readGenerations(
  read: () => string = () => readFileSync(new URL('./database-generation.json', import.meta.url), 'utf8'),
): Readonly<Record<Environment, number>> {
  const parsed: unknown = JSON.parse(read());
  const problems = generationsProblems(parsed);
  if (problems.length > 0) throw new Error(`database-generation.json can't be used:\n- ${problems.join('\n- ')}`);
  return Object.freeze(parsed as Record<Environment, number>);
}

/** The server a generation names, as names.bicep's `serverName` makes it. */
export const serverNameOf = (short: string, suffix: string, generation: number): string =>
  `psql-agentx-${short}-${suffix}${generation === 0 ? '' : '-r' + String(generation)}`;

/** The generation of one of the environment's own servers, by its name, or undefined for any other server. */
export function generationOf(name: string, short: string, suffix: string): number | undefined {
  const base = `psql-agentx-${short}-${suffix}`;
  if (name === base) return 0;
  const generation = /^-r([1-9]\d{0,1})$/.exec(name.slice(base.length))?.[1];
  return name.startsWith(base) && generation !== undefined ? Number(generation) : undefined;
}

/** The base server's name a generation's server is restored from: its `-r<n>` taken off, any other name as it is. */
export const baseServerOf = (name: string): string => name.replace(/-r[1-9]\d?$/, '');

/** The suffix names.bicep gives the environment, read from the one key vault the foundation made under it. */
export const suffixOfVault = (vault: string, short: string): string | undefined =>
  new RegExp(`^kv-agentx-${short}-([a-z0-9]{6})$`).exec(vault)?.[1];

/**
 * The environment's key vault as the group lists it: none (no foundation has run, the one true first deploy), one
 * whose name gives the suffix, or anything else (a failed list, two vaults, a name of another shape).
 */
export type VaultRead =
  { readonly kind: 'none' } | { readonly kind: 'unread' } | { readonly kind: 'read'; readonly suffix: string };

/** What the vault list answered, as a VaultRead: undefined for a list that failed. */
export function vaultRead(listed: unknown, short: string): VaultRead {
  if (!Array.isArray(listed)) return { kind: 'unread' };
  if (listed.length === 0) return { kind: 'none' };
  const suffix = listed.length === 1 && typeof listed[0] === 'string' ? suffixOfVault(listed[0], short) : undefined;
  return suffix === undefined ? { kind: 'unread' } : { kind: 'read', suffix };
}

/** What the operator said on the command line, each only for the case it names. */
export interface ServerSaid {
  /** `foundation --first-server`: make generation 0 new and empty though a foundation ran here before. */
  readonly firstServer?: boolean;
  /** `--back-to-generation <n>`: deploy generation n though a newer server of the environment's is there. */
  readonly backTo?: number;
}

export interface GenerationAsked {
  readonly short: string;
  /** The generation database-generation.json names. */
  readonly generation: number;
  readonly vault: VaultRead;
  /** Every server the resource group holds, by name, or undefined when they couldn't be read. */
  readonly servers: readonly string[] | undefined;
  /** The hand deploy asking (foundation unless given): secrets and apps follow the foundation, never lead it. */
  readonly part?: 'foundation' | 'secrets' | 'apps';
  readonly said?: ServerSaid;
}

export type GenerationVerdict =
  | {
      readonly kind: 'go';
      /** The server the deployment names, or undefined when the names can't be read yet. */
      readonly server: string | undefined;
      /** What to tell the operator before anything is sent. */
      readonly said: string;
    }
  | { readonly kind: 'refused'; readonly why: string };

const NOTHING_SENT = 'Nothing was deployed.';

/** What to run once the generation's server is restored and checked: the foundation first, then the part asked. */
const thenRun = (part: GenerationAsked['part']): string =>
  part === undefined || part === 'foundation' ? 'run foundation again' : `run foundation, then ${part} again`;

const refused = (why: string): GenerationVerdict => ({ kind: 'refused', why: `${why} ${NOTHING_SENT}` });

/** The words a lost live server is refused with: a foundation ran, its server isn't there. */
const LIVE_MISSING =
  "The live database server is missing: the key vault shows a foundation ran here before, but there's no server of the environment's own";
/** What to do about a live server missing: look for a loss and restore first, never a new empty one by default. */
const checkForLoss = (part: GenerationAsked['part']): string =>
  `Check whether it was lost or deleted and restore it first (playbook L), then ${thenRun(part)}; only for a server that was never made, in a group holding no server at all, run foundation --first-server, which makes it new and empty.`;

/**
 * Whether a hand deploy may be sent for the generation asked. It may when the generation's server is already there
 * and none newer is (the deployment then only settles it, and names no other server, so an earlier generation is
 * never changed or deleted), or on a true first deploy (no key vault yet) at generation 0. Everything else is refused:
 * a generation raised before its restore, one going back to a server no longer there, one skipping ahead, one that
 * can't be checked because Azure couldn't be read, a live server missing (unless `--first-server`), and one going back
 * while a newer server is there (two live databases, unless `--back-to-generation` says that very generation).
 */
export function serverGenerationVerdict(asked: GenerationAsked): GenerationVerdict {
  const { generation, said = {} } = asked;
  if (said.backTo !== undefined && said.backTo !== generation) {
    return refused(
      `--back-to-generation ${String(said.backTo)} doesn't match database-generation.json, which names generation ${String(generation)}.`,
    );
  }
  const { vault, servers } = asked;
  if (vault.kind === 'none') return noVaultVerdict(asked);
  if (vault.kind === 'unread' || servers === undefined) return unreadVerdict(asked);
  return readVerdict(asked, vault.suffix, servers);
}

/** No key vault: a first deploy, so generation 0 and no server of any kind, or nothing goes. */
function noVaultVerdict({ generation, servers, part }: GenerationAsked): GenerationVerdict {
  if (generation === 0 && (servers === undefined || servers.length === 0)) {
    return {
      kind: 'go',
      server: undefined,
      said: 'No key vault yet, so no foundation has run here: the deployment makes the first database server, generation 0.',
    };
  }
  return refused(
    `The group holds no key vault, so no foundation has run here, but database-generation.json names generation ${String(generation)}${servers === undefined || servers.length === 0 ? '' : ' and the group holds ' + servers.join(', ')}. Check the subscription and the group, then deploy the foundation first, at generation 0${part === undefined || part === 'foundation' ? '' : ', then ' + part + ' again'}.`,
  );
}

/** The vault or the servers unread: only `foundation --first-server` at generation 0 goes, never a guess. */
function unreadVerdict({ generation, said = {}, part }: GenerationAsked): GenerationVerdict {
  if (generation === 0 && said.firstServer === true) {
    return {
      kind: 'go',
      server: undefined,
      said: "--first-server: the key vault or the servers couldn't be read, so the deployment makes or settles generation 0 as named.",
    };
  }
  if (generation === 0) {
    return refused(
      `The key vault or the database servers couldn't be read, so there's no telling the live server is there: a foundation would make it new and empty if it isn't. Run ${part ?? 'foundation'} again once Azure answers. ${checkForLoss(part)}`,
    );
  }
  return refused(
    `database-generation.json names the database server's generation ${String(generation)}, but the key vault or the servers couldn't be read, so there's no telling that its server was restored: a foundation could make it new and empty and the apps would reach it. Restore it first if it isn't there (playbook L), then ${thenRun(part)} once Azure answers.`,
  );
}

/** The vault and the servers read: the generation's server must be there, and no newer one unless said. */
function readVerdict(asked: GenerationAsked, suffix: string, servers: readonly string[]): GenerationVerdict {
  const { short, generation, said = {}, part } = asked;
  const wanted = serverNameOf(short, suffix, generation);
  const own = servers
    .map((name) => ({ name, generation: generationOf(name, short, suffix) }))
    .filter((server): server is { name: string; generation: number } => server.generation !== undefined)
    .sort((a, b) => a.generation - b.generation);
  const newest = own.at(-1)?.generation;
  if (own.some((server) => server.name === wanted)) {
    const newer = own.filter((server) => server.generation > generation).map((server) => server.name);
    if (newer.length > 0 && said.backTo !== generation) {
      return refused(
        `database-generation.json names generation ${String(generation)}, ${wanted}, but a newer server of the environment's is there (${newer.join(', ')}): going back would leave two live databases, each taking writes the other never sees. If going back is meant (the newer one failed its check), run ${part ?? 'foundation'} --back-to-generation ${String(generation)}.`,
      );
    }
    const others = own.filter((server) => server.name !== wanted).map((server) => server.name);
    const kept =
      others.length === 0
        ? ''
        : ` Kept as they are, with their restore points, never changed or deleted by this deployment: ${others.join(', ')}.`;
    return {
      kind: 'go',
      server: wanted,
      said: `The database server is ${wanted} (generation ${String(generation)}), which is there.${kept}`,
    };
  }
  if (generation === 0 && own.length === 0) return liveMissingVerdict(wanted, servers, said, part);
  const where =
    newest === undefined
      ? `the group holds no server of its own (${servers.length === 0 ? 'none at all' : 'only ' + servers.join(', ')})`
      : `the newest server there is generation ${String(newest)}`;
  return refused(
    `database-generation.json names the database server's generation ${String(generation)}, ${wanted}, and ${where}: it ${whichWay(generation, newest)}. A foundation would make it new and empty and the apps would reach it, while the data stays on the old one. First restore it under that name (playbook L: az postgres flexible-server restore --name ${wanted}, the same subnet, private zone and zone), check it, then ${thenRun(part)}.`,
  );
}

/**
 * Generation 0 with no server of the environment's own though a foundation ran: a lost live server until the operator
 * says `--first-server`, and that only in a group holding no server at all. Any copy there (-before, -drill, Stage
 * G's) means data to look at, never a new, empty server beside it.
 */
function liveMissingVerdict(
  wanted: string,
  servers: readonly string[],
  said: ServerSaid,
  part: GenerationAsked['part'],
): GenerationVerdict {
  if (said.firstServer === true && servers.length === 0) {
    return {
      kind: 'go',
      server: wanted,
      said: `--first-server: the deployment makes ${wanted}, new and empty, though the key vault shows a foundation ran here before.`,
    };
  }
  const firstRefused =
    said.firstServer === true
      ? ' --first-server is for an empty group alone, and this one holds a copy: never a new, empty server beside it.'
      : '';
  return refused(
    `${LIVE_MISSING} (${servers.length === 0 ? 'no server at all' : 'only ' + servers.join(', ')}). ${checkForLoss(part)}${firstRefused}`,
  );
}

/** How a generation whose server is missing stands to the newest one there. */
function whichWay(generation: number, newest: number | undefined): string {
  if (newest !== undefined && generation < newest) return 'goes back to a generation whose server is no longer there';
  if (newest !== undefined && generation > newest + 1) {
    return `skips ahead (the next generation is ${String(newest + 1)})`;
  }
  return 'names a server that is not there yet';
}
