// The database server's generation (Outstanding-Work AZ25, playbook L): which
// server each environment's deployments name. Generation 0 is the server made
// at the start, named as it always was (`psql-agentx-<short>-<suffix>`); a real
// restore's replacement is the next generation, `-r<n>` after it, restored by
// `az postgres flexible-server restore` beside the live server, which is kept
// with every restore point it has until the partner signs the new one off.
// database-generation.json holds the number, read by names.bicep for every
// deployment and here by deploy.ts foundation, which refuses to send one whose
// server isn't there: the deployment would make it new and empty, and point the
// apps at it (serverGenerationVerdict).
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

/** The suffix names.bicep gives the environment, read from the one key vault the foundation made under it. */
export const suffixOfVault = (vault: string, short: string): string | undefined =>
  new RegExp(`^kv-agentx-${short}-([a-z0-9]{6})$`).exec(vault)?.[1];

export interface GenerationAsked {
  readonly short: string;
  /** The generation database-generation.json names. */
  readonly generation: number;
  /** The environment's suffix (its key vault's), or undefined when it couldn't be read or there is no vault yet. */
  readonly suffix: string | undefined;
  /** Every server the resource group holds, by name, or undefined when they couldn't be read. */
  readonly servers: readonly string[] | undefined;
  /** The hand deploy asking (foundation unless given): secrets and apps follow the foundation, never lead it. */
  readonly part?: 'foundation' | 'secrets' | 'apps';
}

/** What to run once the generation's server is restored and checked: the foundation first, then the part asked. */
const thenRun = (part: GenerationAsked['part']): string =>
  part === undefined || part === 'foundation' ? 'run foundation again' : `run foundation, then ${part} again`;

export type GenerationVerdict =
  | {
      readonly kind: 'go';
      /** The server the deployment names, or undefined on a first deploy whose names can't be read yet. */
      readonly server: string | undefined;
      /** What to tell the operator before anything is sent. */
      readonly said: string;
    }
  | { readonly kind: 'refused'; readonly why: string };

const NOTHING_SENT = 'Nothing was deployed.';

/**
 * Whether a foundation may be sent for the generation asked. It may when the generation's server is already there
 * (the deployment then only settles it, and names no other server, so an earlier generation is never changed or
 * deleted), or on a first deploy at generation 0 (no server in the group at all). Anything else would make a
 * new, empty server and point the apps at it, so it is refused: a generation raised before its restore, one going
 * back to a server no longer there, one skipping ahead, or one that can't be checked because Azure couldn't be read.
 */
export function serverGenerationVerdict({
  short,
  generation,
  suffix,
  servers,
  part,
}: GenerationAsked): GenerationVerdict {
  if (suffix === undefined || servers === undefined) return unreadVerdict(generation, part);
  const wanted = serverNameOf(short, suffix, generation);
  const own = servers
    .map((name) => ({ name, generation: generationOf(name, short, suffix) }))
    .filter((server): server is { name: string; generation: number } => server.generation !== undefined)
    .sort((a, b) => a.generation - b.generation);
  if (own.some((server) => server.name === wanted)) {
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
  // A first deploy only when the group holds no server at all: a drill's or a `-before` copy beside a lost live
  // server means the data is somewhere, and an empty server in its place would hide that.
  if (servers.length === 0 && generation === 0) {
    return {
      kind: 'go',
      server: wanted,
      said: `The group holds no database server yet: the foundation makes ${wanted}, the first, empty.`,
    };
  }
  const newest = own.at(-1)?.generation;
  const where =
    newest === undefined
      ? `the group holds no server of its own (${servers.length === 0 ? 'none at all' : 'only ' + servers.join(', ')})`
      : `the newest server there is generation ${String(newest)}`;
  return {
    kind: 'refused',
    why: `database-generation.json names the database server's generation ${String(generation)}, ${wanted}, and ${where}: it ${whichWay(generation, newest)}. A foundation would make it new and empty and the apps would reach it, while the data stays on the old one. First restore it under that name (playbook L: az postgres flexible-server restore --name ${wanted}, the same subnet, private zone and zone), check it, then ${thenRun(part)}. ${NOTHING_SENT}`,
  };
}

/** Without the vault's suffix or the servers, only generation 0 goes: the name every first deploy makes. */
function unreadVerdict(generation: number, part: GenerationAsked['part']): GenerationVerdict {
  if (generation === 0) {
    return {
      kind: 'go',
      server: undefined,
      said: "The database server's generation is 0, its first name: the group's servers couldn't be read, as before a first foundation, which makes or settles that one.",
    };
  }
  return {
    kind: 'refused',
    why: `database-generation.json names the database server's generation ${String(generation)}, but the key vault or the servers couldn't be read, so there's no telling that its server was restored: a foundation could make it new and empty and the apps would reach it. Restore it first if it isn't there (playbook L), then ${thenRun(part)} once Azure answers. ${NOTHING_SENT}`,
  };
}

/** How a generation whose server is missing stands to the newest one there. */
function whichWay(generation: number, newest: number | undefined): string {
  if (newest !== undefined && generation < newest) return 'goes back to a generation whose server is no longer there';
  if (newest !== undefined && generation > newest + 1) {
    return `skips ahead (the next generation is ${String(newest + 1)})`;
  }
  return 'names a server that is not there yet';
}
