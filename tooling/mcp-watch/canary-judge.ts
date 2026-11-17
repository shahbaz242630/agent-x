// 6E4 (MCP-Guide §7, partner S201: most customers reach us through an agent's
// MCP client, so we learn of a breaking client before they do): the judge of
// the daily real-client canaries (.github/workflows/mcp-watch.yml). Each
// canary, TS (canary.ts) or Python (canary.py), connects to staging's MCP
// endpoint with the smoke agent's key, lists the tools and calls get_agent,
// and writes what it saw as a report; this judges every report the same way,
// red in plain words on what needs a person. Node builtins only: the Python
// job runs it on CI's bare Node.
//
//   node tooling/mcp-watch/canary-judge.ts wake                 wakes staging (it scales to zero) before the canaries
//   node tooling/mcp-watch/canary-judge.ts judge FILE [FILE…]   judges canary reports (JSON), one a file
//
// The staging address comes in AGENTX_MCP_ORIGIN and the key in AGENTX_MCP_KEY,
// both repository secrets. Neither is ever printed: a client's error text is
// cut short and any key or bearer token in it is blanked before it is shown.
import { appendFileSync, readFileSync } from 'node:fs';

import { originOf } from '../dast/scan.ts';
import { escapeCommand, type Verdict } from '../image-watch/watch.ts';
import { askAwake, REAL, type Ways } from '../smoke/ask.ts';
import { storedKey } from '../smoke/smoke.ts';

/** The MCP endpoint's path (apps/api/src/mcp.ts's MCP_PATH). */
export const MCP_PATH = '/v1/mcp';

/**
 * The tools every agent's client must see (apps/api/src/mcp-tools.ts's MCP_TOOLS, docs/api/README.md §9), copied:
 * this runs with no packages installed. canary-judge.test.ts keeps the copy equal to the API's own list.
 */
export const EXPECTED_TOOLS = [
  'get_agent',
  'get_mandate',
  'list_funding_sources',
  'list_suppliers',
  'create_spend_request',
  'get_spend_request',
  'cancel_spend_request',
] as const;

/** How much of a client's own error text a red line keeps. */
const MOST_ERROR_TEXT = 300;

/** The step a canary was on when it stopped. */
export type CanaryStep = 'connect' | 'list the tools' | 'call get_agent';

/** What one canary saw: written by canary.ts or canary.py, judged here. */
export interface CanaryReport {
  /** The canary's own name: ts-legacy, ts-modern, mcp-remote, ai-sdk, python-legacy, python-auto, openai-agents. */
  readonly canary: string;
  /** The client library, as its users know it, and its installed version. */
  readonly client: string;
  readonly version: string;
  /** The protocol version the client and the server settled on, when the client says. */
  readonly protocol?: string | undefined;
  /** Set when the canary stopped: where, and the client's own words. */
  readonly failed?: { readonly step: CanaryStep; readonly error: string };
  /** The tools' names, as tools/list gave them. */
  readonly tools?: readonly string[];
  /** get_agent's result: whether it was an error, and its structured content. */
  readonly agent?: { readonly isError?: boolean; readonly structuredContent?: unknown } | undefined;
}

/** A client's error text, safe to show: no key, no bearer token, one line, cut short. */
export function shownError(text: string): string {
  const blanked = text
    .replaceAll(/axk_[A-Za-z0-9_-]+/g, 'axk_[hidden]')
    .replaceAll(/(bearer\s+)\S+/gi, '$1[hidden]')
    .replaceAll(/\s+/g, ' ')
    .trim();
  return blanked.length > MOST_ERROR_TEXT ? `${blanked.slice(0, MOST_ERROR_TEXT)}…` : blanked;
}

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** What is wrong with the tool list, or nothing. */
export function toolsProblem(tools: readonly string[] | undefined): string | undefined {
  if (tools === undefined) return 'it gave no tool list';
  const missing = EXPECTED_TOOLS.filter((name) => !tools.includes(name));
  const extra = tools.filter((name) => !(EXPECTED_TOOLS as readonly string[]).includes(name));
  const twice = tools.length !== new Set(tools).size;
  if (missing.length === 0 && extra.length === 0 && !twice) return undefined;
  const parts = [
    missing.length > 0 ? `missing ${missing.join(', ')}` : '',
    extra.length > 0 ? `unexpected ${extra.map(shownError).join(', ')}` : '',
    twice ? 'a tool listed twice' : '',
  ].filter((part) => part !== '');
  return `its tool list was not our ${String(EXPECTED_TOOLS.length)} tools: ${parts.join('; ')}`;
}

/** What is wrong with get_agent's answer, or nothing: a typed answer names the agent, its organisation, scopes and key's end. */
export function agentProblem(agent: CanaryReport['agent']): string | undefined {
  if (agent === undefined) return 'it gave no answer from get_agent';
  if (agent.isError === true) return 'get_agent answered with an error (isError)';
  const content = agent.structuredContent;
  if (!isRecord(content)) return "get_agent's answer had no structured content";
  const strings = ['agentId', 'organizationId', 'keyExpiresAt'].filter((field) => typeof content[field] !== 'string');
  const scopes = content.scopes;
  const scopesTyped = Array.isArray(scopes) && scopes.every((scope) => typeof scope === 'string');
  if (strings.length > 0 || !scopesTyped) {
    const wrong = [...strings, ...(scopesTyped ? [] : ['scopes'])];
    return `get_agent's structured content lacked or mistyped ${wrong.join(', ')}`;
  }
  if (Number.isNaN(Date.parse(String(content.keyExpiresAt)))) return "get_agent's keyExpiresAt was not a date";
  return undefined;
}

/** What a client does for our customers, by canary, for the red line. */
const WHO_USES: Readonly<Record<string, string>> = {
  'ts-legacy': "Agents built on the official TypeScript SDK's 2025 handshake (OpenClaw among them)",
  'ts-modern': "Agents built on the official TypeScript SDK's 2026-07-28 revision",
  'mcp-remote': 'Hosts that reach us through the mcp-remote bridge (docs/api/README.md §9)',
  'ai-sdk': "Agents built on Vercel's AI SDK",
  'python-legacy': "Agents built on the official Python SDK's 2025 handshake",
  'python-auto': "Agents built on the official Python SDK's own negotiation (Hermes Agent among them)",
  'openai-agents': "Agents built on OpenAI's Agents SDK",
};

/** One canary's report, judged: red, in plain words, when it couldn't list our tools or read get_agent's answer. */
export function judgeCanary(report: CanaryReport): Verdict {
  const name = `${report.client} ${report.version}`;
  const problem =
    report.failed === undefined
      ? (toolsProblem(report.tools) ?? agentProblem(report.agent))
      : `it could not ${report.failed.step}: ${shownError(report.failed.error)}`;
  const protocol = report.protocol === undefined ? '' : ` (protocol ${report.protocol})`;
  const who = WHO_USES[report.canary] ?? 'Agents built on this client';
  const errors =
    problem === undefined
      ? []
      : [
          `The ${report.canary} canary, ${name}${protocol}, failed against staging's MCP endpoint: ${problem}. ` +
            `${who} may break the same way. Read this step's log, then try the client by hand: if our server is ` +
            `wrong, fix it (MCP-Guide.md §7); if the client changed, check its notes and tell its builder, and ` +
            `pin this canary's version until it is understood.`,
        ];
  const verdict = problem === undefined ? 'passed' : `red: ${problem.replaceAll('|', '\\|')}`;
  const summary = `| ${report.canary} | ${name} | ${report.protocol ?? '?'} | ${verdict} |`;
  return { errors, summary };
}

/** A report as read from a file: the fields a canary wrote, or a red line when it is not one. */
export function readReport(text: string, file: string): CanaryReport {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    data = undefined;
  }
  if (!isRecord(data) || typeof data.canary !== 'string' || typeof data.client !== 'string') {
    return {
      canary: 'unknown',
      client: file,
      version: '?',
      failed: { step: 'connect', error: 'its report is not a canary report (the canary crashed before writing it)' },
    };
  }
  return {
    ...(data as unknown as CanaryReport),
    version: typeof data.version === 'string' ? data.version : '?',
  };
}

const SUMMARY_HEAD =
  '## MCP client canaries (staging)\n\n| Canary | Client | Protocol | Verdict |\n| --- | --- | --- | --- |\n';

/** Every report judged, as one verdict: its red lines and one summary table. */
export function judgeReports(reports: readonly CanaryReport[]): Verdict {
  const verdicts = reports.map(judgeCanary);
  return {
    errors: verdicts.flatMap((verdict) => verdict.errors),
    summary: `${SUMMARY_HEAD}${verdicts.map((verdict) => verdict.summary).join('\n')}\n`,
  };
}

/** Writes a verdict: the summary to the job's, one ::error:: a red line, or the all-clear line; 1 when red. */
export function report(verdict: Verdict, clear = 'Every canary passed.'): number {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile !== undefined && summaryFile !== '') appendFileSync(summaryFile, `${verdict.summary}\n`);
  for (const error of verdict.errors) process.stdout.write(`::error::${escapeCommand(error)}\n`);
  if (verdict.errors.length === 0) process.stdout.write(`${clear}\n`);
  return verdict.errors.length === 0 ? 0 : 1;
}

/** Staging's MCP address and the smoke key, from the environment, or a red line saying which is missing. */
export function target(
  env: NodeJS.ProcessEnv,
): { readonly url: string; readonly key: string } | { readonly problem: string } {
  const stored = storedKey(env.AGENTX_MCP_KEY);
  if ('problem' in stored) return { problem: stored.problem };
  try {
    return { url: `${originOf(env.AGENTX_MCP_ORIGIN, 'AGENTX_MCP_ORIGIN')}${MCP_PATH}`, key: stored.key };
  } catch {
    return { problem: 'The repository secret STAGING_APP_ORIGIN is not set, or is not an https origin.' };
  }
}

/**
 * Wakes staging before the canaries: a POST that is no MCP message, with the key (so no 401 reaches the 401 alert),
 * asked again while the app wakes from zero. Any answer but a 502, 503 or 504 means it is up (the API answers this
 * 400); `waited` means it never woke.
 */
export async function wake(url: string, key: string, ways: Partial<Ways> = {}): Promise<string | undefined> {
  const asked = await askAwake(
    url,
    { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: '{}' },
    { ...REAL, ...ways },
  );
  return 'waited' in asked ? asked.waited : undefined;
}

/** A report file's text, or none when the canary never wrote it (readReport makes that red). */
function readText(file: string): string {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

export async function main(args: readonly string[], env: NodeJS.ProcessEnv, ways: Partial<Ways> = {}): Promise<number> {
  const [command, ...files] = args;
  if (command === 'judge' && files.length > 0) {
    return report(judgeReports(files.map((file) => readReport(readText(file), file))));
  }
  if (command === 'wake') {
    const where = target(env);
    if ('problem' in where) return report({ errors: [where.problem], summary: '' });
    const waited = await wake(where.url, where.key, ways);
    if (waited === undefined) {
      process.stdout.write('Staging is awake.\n');
      return 0;
    }
    return report({
      errors: [
        `Staging's MCP endpoint never answered while it woke (${waited}), so no canary could run today. Check ` +
          `staging is up (its smoke test, Azure's portal), then re-run this workflow.`,
      ],
      summary: '',
    });
  }
  process.stderr.write('usage: canary-judge.ts wake | judge <report.json> [<report.json> …]\n');
  return 2;
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2), process.env);
