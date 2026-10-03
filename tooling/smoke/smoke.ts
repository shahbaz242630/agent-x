// The post-release smoke test (Security-Handoff §13b, partner S69): after each
// release, staging's test agent reads what every agent reads, through the
// public door, with its own key. A release that starts clean but is wired
// wrong (the database, the key check's pepper, the partner switch, the door)
// turns red here. The key is the repository secret STAGING_SMOKE_AGENT_KEY
// (not an environment's: the job names none, or its own deployment would start
// it again) and the address the repository secret STAGING_APP_ORIGIN, neither
// ever in the repository; the log shows each read's path and status, never a
// body. Node builtins only.
import { setTimeout as sleep } from 'node:timers/promises';

import { originOf } from '../dast/scan.ts';

/** The one shape a smoke key may have: reads alone, so a leaked key can ask for nothing. */
export const SMOKE_SCOPES = ['sources:read', 'suppliers:read'] as const;

/** A key this close to its end turns the smoke test red, so it is rotated before the releases go unchecked. */
export const KEY_WARNING_DAYS = 14;

// The shared kernel's, copied: this runs on CI's bare Node, with no packages installed.
const DAY_MS = 86_400_000;

type Body = Record<string, unknown>;

interface Read {
  readonly path: string;
  /** What's wrong with the answer's body, or nothing. */
  readonly problem: (body: Body, now: Date) => string | undefined;
}

const isList = (field: string) => (body: Body) => (Array.isArray(body[field]) ? undefined : `no ${field} list`);

/** What the smoke key reads, in order: who it is first, so a wrong key fails before the lists. */
export const READS: readonly Read[] = [
  {
    path: '/v1/agent',
    problem: (body, now) => {
      const scopes = Array.isArray(body.scopes) ? [...(body.scopes as unknown[])].sort() : undefined;
      if (JSON.stringify(scopes) !== JSON.stringify(SMOKE_SCOPES)) {
        return `the key's scopes must be exactly ${SMOKE_SCOPES.join(' ')}: register the smoke agent with those alone`;
      }
      const expires = typeof body.keyExpiresAt === 'string' ? Date.parse(body.keyExpiresAt) : Number.NaN;
      if (Number.isNaN(expires)) return 'no keyExpiresAt';
      if (expires - now.getTime() < KEY_WARNING_DAYS * DAY_MS) {
        return `the key ends within ${String(KEY_WARNING_DAYS)} days: rotate it and update STAGING_SMOKE_AGENT_KEY`;
      }
      return undefined;
    },
  },
  { path: '/v1/agent/funding-sources', problem: isList('sources') },
  { path: '/v1/agent/suppliers', problem: isList('suppliers') },
];

/** A fetch that answers, or throws on a dropped line. */
type Fetch = (url: string, init: { headers: Record<string, string>; signal: AbortSignal }) => Promise<Response>;

/** How the reads reach the door and wait, real by default. */
interface Ways {
  readonly fetcher: Fetch;
  readonly now: () => Date;
  /** How long a read may keep meeting a waking API. */
  readonly wakeMs: number;
  /** The wait between tries. */
  readonly pause: () => Promise<unknown>;
}

const REAL: Ways = {
  fetcher: fetch,
  now: () => new Date(),
  wakeMs: 180_000,
  pause: () => sleep(10_000),
};

/**
 * One read, retried while the API wakes from zero (a 502, 503 or 504, or no
 * answer) for at most `wakeMs`; any other answer is final.
 */
async function readOnce(
  origin: string,
  key: string,
  read: Read,
  { fetcher, now, wakeMs, pause }: Ways,
): Promise<string> {
  const until = now().getTime() + wakeMs;
  for (;;) {
    let last: string;
    try {
      const answer = await fetcher(`${origin}${read.path}`, {
        headers: { authorization: `Bearer ${key}`, accept: 'application/json' },
        signal: AbortSignal.timeout(30_000),
      });
      last = String(answer.status);
      // A 200 is final: one that isn't a JSON object (the door serving a page) is wrong, not asleep.
      if (answer.status === 200) return `${read.path}: ${verdict(read, await answer.text(), now())}`;
      if (![502, 503, 504].includes(answer.status)) return `${read.path}: ${last}`;
    } catch {
      last = 'no answer';
    }
    if (now().getTime() >= until) return `${read.path}: ${last} after ${String(wakeMs / 1000)} s`;
    await pause();
  }
}

/** A 200's body judged: `200`, or what's wrong with it. */
function verdict(read: Read, text: string, now: Date): string {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return '200, but the body is not JSON';
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return '200, but the body is not an object';
  const problem = read.problem(body as Body, now);
  return problem === undefined ? '200' : `200, but ${problem}`;
}

/** Every read's line, each said as soon as it is known (a job cut off at its limit still shows how far it got), and whether all passed. */
export async function smoke(
  origin: string,
  key: string,
  ways: Partial<Ways> = {},
  say: (line: string) => void = () => undefined,
): Promise<{ readonly lines: string[]; readonly passed: boolean }> {
  const lines: string[] = [];
  for (const read of READS) {
    const line = await readOnce(origin, key, read, { ...REAL, ...ways });
    say(line);
    lines.push(line);
  }
  return { lines, passed: lines.every((line) => line.endsWith(': 200')) };
}

async function main(): Promise<number> {
  const key = process.env.AGENTX_SMOKE_KEY ?? '';
  if (!/^axk_\S+$/.test(key)) {
    console.log('The repository secret STAGING_SMOKE_AGENT_KEY is not set, or is not an agent key.');
    return 1;
  }
  const origin = originOf(process.env.AGENTX_SMOKE_ORIGIN, 'AGENTX_SMOKE_ORIGIN');
  const { passed } = await smoke(origin, key, {}, (line) => {
    console.log(line);
  });
  return passed ? 0 : 1;
}

if (import.meta.main) process.exitCode = await main();
