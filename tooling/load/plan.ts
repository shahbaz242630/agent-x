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

/** The run's working files (the seed's agent keys, k6's results, the API's log): gitignored. */
export const OUT_DIR = fileURLToPath(new URL('./.out', import.meta.url));

/** The reports kept in the repository, numbers only. */
export const REPORTS_DIR = fileURLToPath(new URL('./reports', import.meta.url));

export const SEED_FILE = path.join(OUT_DIR, 'seed.json');

/** The keys the stack's API reads (deploy/compose/prepare.ts): the seed signs with them, so the API believes it. */
export const APP_KEYS_DIR = path.join(SECRETS_DIR, APP_KEYS);

/** Agents that never reach a limit, each in an organisation of its own: the steady traffic. */
export const AMPLE_AGENTS = 10;

/** Above AED 5 a request waits for a person, so the steady traffic is both allowed and held for approval. */
export const APPROVAL_THRESHOLD_MINOR = 500n;

/** The capped agent's month, AED 100: the spike's 50 requests of AED 4 at once must stop at 25. */
export const CAPPED_MONTHLY_MINOR = 10_000n;

/** The Pilot's policy target (PRD §8): a decision's p95, from its own log line (D2a). */
export const POLICY_P95_MS = 150;

export interface SeededAgent {
  readonly kind: 'ample' | 'capped';
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

/** The app's login to the load stack's database, from the environment the runner gives the seed and verify steps. */
export function loadConnection() {
  const password = process.env.AGENTX_LOAD_DB_PASSWORD;
  if (password === undefined) throw new Error('Run the load test with `corepack pnpm load`, which sets its login.');
  return {
    host: '127.0.0.1',
    port: LOAD_DB_PORT,
    database: 'agentx',
    user: 'agentx_app',
    password,
    tls: 'disable' as const,
    applicationName: 'agentx-load',
  };
}
