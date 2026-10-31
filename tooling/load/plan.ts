// The load test of the money paths (Phase 4 D2, PL-38): what it seeds, where
// its files go, the stack it runs against and the targets it is held to.
// Shared by the runner (run.ts), its seed and verify steps (*.load.test.ts)
// and the report. The k6 script (money-paths.k6.js) reads the seed's file and
// holds its own request target, since k6 runs no TypeScript.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { APP_KEYS, SECRETS_DIR } from '../../deploy/compose/prepare.ts';

/** Its own compose project, so its database and containers are never the dev stack's (`agentx`). */
export const LOAD_PROJECT = 'agentx-load';

/** Where the seed and verify steps reach its database: loopback only (compose.load.yaml), clear of another project's 554xx. */
export const LOAD_DB_PORT = 56_540;

/** Staging's API has half a CPU (deploy/azure/apps.bicep): a run's size unless told otherwise. */
export const STAGING_API_CPUS = 0.5;

/** The most a run may give the API: past this a laptop's own cores are the limit, not the API. */
export const MOST_API_CPUS = 4;

/** How the runner tells compose.load.yaml the API's CPUs. */
export const API_CPUS_VARIABLE = 'AGENTX_LOAD_API_CPUS';

/** The least a run may give the API: Docker refuses less, and only once the stack starts. */
export const LEAST_API_CPUS = 0.01;

/** How the runner tells compose.load.yaml's `delay` the milliseconds to add. */
export const DELAY_VARIABLE = 'AGENTX_LOAD_DELAY_MS';

/** The most `--delay-ms` adds: past this it measures a network no one runs on. */
export const MOST_DELAY_MS = 20;

/** What the runner was asked: whether to leave the stack up, the API's CPUs (staging's unless given), the database's added delay. */
export interface LoadOptions {
  readonly keep: boolean;
  readonly apiCpus: number;
  /** Whole milliseconds added to every packet the database sends (4D2d P0): 0 is the laptop as it is. */
  readonly delayMs: number;
}

/**
 * The runner's arguments (`--keep`, `--cpus 2`, `--delay-ms 2`), or undefined
 * for any it can't run: an unknown one (`--cpus=2`, `--cpu 2`) is refused,
 * never a run at another size or delay than asked.
 */
export function optionsOf(args: readonly string[]): LoadOptions | undefined {
  let keep = false;
  let apiCpus = STAGING_API_CPUS;
  let delayMs = 0;
  for (let at = 0; at < args.length; at++) {
    if (args[at] === '--keep') {
      keep = true;
    } else if (args[at] === '--cpus') {
      apiCpus = Number(args[++at]);
      if (!(apiCpus >= LEAST_API_CPUS && apiCpus <= MOST_API_CPUS)) return undefined;
    } else if (args[at] === '--delay-ms') {
      delayMs = Number(args[++at]);
      if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > MOST_DELAY_MS) return undefined;
    } else {
      return undefined;
    }
  }
  return { keep, apiCpus, delayMs };
}

/** The run's working files (the seed's agent keys, k6's results, the API's log): gitignored. */
export const OUT_DIR = fileURLToPath(new URL('./.out', import.meta.url));

/** The reports kept in the repository, numbers only. */
export const REPORTS_DIR = fileURLToPath(new URL('./reports', import.meta.url));

export const SEED_FILE = path.join(OUT_DIR, 'seed.json');

/** The keys the stack's API reads (deploy/compose/prepare.ts): the seed signs with them, so the API believes it. */
export const APP_KEYS_DIR = path.join(SECRETS_DIR, APP_KEYS);

/** Agents that never reach a limit, each in an organisation of its own: the steady traffic. */
export const AMPLE_AGENTS = 10;

/**
 * Agents of one organisation, in each of the two many-agents phases (4D2d,
 * S164): they share its chain head, and in phase 4 its suppliers' locks,
 * which the steady traffic's agents, an organisation each, never do.
 */
export const CROWD_AGENTS = 10;

/**
 * The neighbours phase's (4D2d, PL-63): ten calm agents, an organisation each,
 * sending what the steady agents send, beside a busy organisation's ten and a
 * stuck one's ten. Their own, so the steady traffic's numbers stay phases 1 and 2's.
 */
const NEIGHBOUR_AGENTS = 3 * CROWD_AGENTS;

/** Every agent a run seeds: the ample ones, the capped one, the two crowds and the neighbours. */
export const SEEDED_AGENTS = AMPLE_AGENTS + 1 + 2 * CROWD_AGENTS + NEIGHBOUR_AGENTS;

/**
 * A run's k6 phases: 1 and 2 the steady traffic (2 with the spike); 3 and 4 the
 * crowds, reported apart; 5 the neighbours, one organisation's trouble beside others.
 */
export type LoadPhase = 1 | 2 | 3 | 4 | 5;

export const NEIGHBOURS_PHASE = 5;

/** Above AED 5 a request waits for a person, so the steady traffic is both allowed and held for approval. */
export const APPROVAL_THRESHOLD_MINOR = 500n;

/** The capped agent's month, AED 100: the spike's 50 requests of AED 4 at once must stop at 25. */
export const CAPPED_MONTHLY_MINOR = 10_000n;

/** The Pilot's policy target (PRD §8): a decision's p95, from its own log line (D2a). */
export const POLICY_P95_MS = 150;

/** A crowd's agents: each with three suppliers of its own (phase 3), or all sharing the same three (phase 4). */
export type CrowdKind = 'crowd-own' | 'crowd-shared' | NeighbourCrowdKind;

/** Phase 5's two organisations in trouble, ten agents each sharing three suppliers. */
type NeighbourCrowdKind = 'neighbour-busy' | 'neighbour-stuck';

export interface SeededAgent {
  readonly kind: 'ample' | 'capped' | 'neighbour-calm' | CrowdKind;
  readonly orgId: string;
  readonly agentId: string;
  /** The agent's key as it sends it: a local, throwaway stack's, never kept. */
  readonly key: string;
  readonly sourceId: string;
  readonly supplierIds: readonly string[];
  readonly monthlyLimitMinor: string;
}

export interface Seeded {
  readonly agents: readonly SeededAgent[];
}

export const readSeeded = (): Seeded => JSON.parse(readFileSync(SEED_FILE, 'utf8')) as Seeded;

/** The agents' organisations, each once: a crowd's agents share one. */
export const orgsOf = (agents: readonly { readonly orgId: string }[]): string[] => [
  ...new Set(agents.map(({ orgId }) => orgId)),
];

/** Where a run happens: the laptop's compose stack, or staging on Azure (D2c), production-sized. */
export type LoadSite = 'local' | 'azure';

/**
 * The name every organisation a run seeds is given: on staging the run's
 * organisations stay (audit chains are append-only), so they must be told
 * apart from anyone else's at a glance, and found again by the run's ID.
 */
export const loadOrgName = (runId: string): string => `Load test D2c ${runId}`;

/**
 * The app's login to the run's database, from the environment the runner
 * gives the seed and verify steps: the load stack's loopback port with no TLS,
 * or, when AGENTX_LOAD_DB_HOST names staging's private server (D2c, from a job
 * inside its network), port 5432 with the server's certificate checked.
 */
export function loadConnection(env: NodeJS.ProcessEnv = process.env) {
  const password = env.AGENTX_LOAD_DB_PASSWORD;
  if (password === undefined) throw new Error('Run the load test with `corepack pnpm load`, which sets its login.');
  // Set but empty is not set: never an empty host with the certificate check on.
  const named = env.AGENTX_LOAD_DB_HOST;
  const azureHost = named === undefined || named === '' ? undefined : named;
  return {
    host: azureHost ?? '127.0.0.1',
    port: azureHost === undefined ? LOAD_DB_PORT : 5432,
    database: 'agentx',
    user: 'agentx_app',
    password,
    tls: azureHost === undefined ? ('disable' as const) : ('verify-full' as const),
    applicationName: 'agentx-load',
  };
}
