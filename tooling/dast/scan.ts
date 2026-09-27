/**
 * The free dynamic scan of staging (B7, partner S59): OWASP ZAP's API scan and
 * Schemathesis's fuzzing, each from its pinned image, against the API's own
 * `apps/api/openapi.json`, the staging origin given as AGENTX_DAST_ORIGIN.
 * Run by `.github/workflows/dast.yml` (weekly and on demand, never on a pull
 * request: staging is Free Trial compute) and by hand the same way:
 * `node tooling/dast/scan.ts`, with Docker running. With `--stack`, the End to
 * end job runs Schemathesis alone against the compose stack on every pull
 * request, failing it on any finding not accepted (B7-3).
 *
 * **Nothing about staging reaches the public log.** The repository is public
 * until pre-launch, so the scanners' own output (which names the host and
 * every request) is never printed: the findings go to `dast-results/dast.sarif`,
 * which the workflow uploads to code scanning (read only by the repository's
 * writers), and the log shows counts by tool and severity alone.
 *
 * Signed out, both scanners reach what anyone on the internet reaches: the
 * public routes, and every other route's refusal. The signed-in routes are B8's
 * attack pass. Every write carries our own Origin, so the Origin check (SEC-WEB-01)
 * lets it through to the route's own checks. Both scan gently: two threads for
 * ZAP, 120 requests a minute for Schemathesis (below the API's limit per client
 * address), each with its own time limit.
 *
 * A finding the project has decided to keep is listed in ACCEPTED with its
 * reason, counted, and not uploaded; informational notes are counted only.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

/** The scanners, each pinned by digest (SEC-SC-02; tooling/checks/images.test.ts). */
export const SCANNER_IMAGES = {
  zap: 'ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef',
  schemathesis:
    'schemathesis/schemathesis:v4.28.0@sha256:0a71757c60ccdba270c154a859d9dd3d019625f782f23ab36ad604771e15f78b',
} as const;

/** The document both scanners read, and where the findings are placed in code scanning. */
export const OPENAPI_FILE = 'apps/api/openapi.json';

/** Where the scanners write, and the SARIF file the workflow uploads. */
export const RESULTS_DIR = 'dast-results';
export const SARIF_FILE = 'dast.sarif';

export type Severity = 'high' | 'medium' | 'low' | 'info';

/** One finding, as either scanner reports it: a rule, at an operation. */
export interface Finding {
  readonly tool: 'zap' | 'schemathesis';
  /** Stable across runs: the scanner's rule. */
  readonly rule: string;
  readonly title: string;
  readonly severity: Severity;
  readonly method: string;
  /** The address's path, never its host or query. */
  readonly path: string;
  /** The status the API answered with, where the scanner reports one. */
  readonly status?: number;
}

/** A finding the project keeps, and why. */
interface Accepted {
  readonly tool: Finding['tool'];
  readonly rule: string;
  /** Accepted only at addresses the document doesn't hold, or at any. */
  readonly undocumentedOnly?: true;
  /** The statuses it is accepted with, or any. */
  readonly statuses?: readonly number[];
  readonly reason: string;
}

export const ACCEPTED: readonly Accepted[] = [
  {
    tool: 'schemathesis',
    rule: 'schemathesis/unsupported-methods',
    reason:
      'A method the document lists nowhere gets the same 404 as an unknown address, not 405: an answer says nothing of what exists (SEC-DATA-04).',
  },
  {
    tool: 'zap',
    rule: 'zap/100001',
    undocumentedOnly: true,
    reason:
      "ZAP's cloud-metadata probes (/latest/meta-data/ and the like, more with each version) send another Host, which Azure's edge answers with its own 404 page (text/html) before the app sees it; nothing is exposed. At an address the API serves it is a finding.",
  },
  {
    tool: 'schemathesis',
    rule: 'schemathesis/api-accepted-schema-violating-request',
    statuses: [413, 431],
    reason:
      "Refused, before any route runs: a body past its route's limit is answered 413 PAYLOAD_TOO_LARGE, and an address past Node's limit on a request's head (its first line counts) 431 HEADERS_TOO_LARGE; Schemathesis counts neither as a refusal.",
  },
];

/** The paths the API's document holds, read once. */
let documented: readonly string[] | undefined;
const documentedPaths = (): readonly string[] =>
  (documented ??= Object.keys(
    (JSON.parse(readFileSync(OPENAPI_FILE, 'utf8')) as { paths?: Record<string, unknown> }).paths ?? {},
  ));

/** Why a finding is kept, if it is. */
export const acceptedReason = (finding: Finding): string | undefined =>
  ACCEPTED.find(
    (one) =>
      one.tool === finding.tool &&
      one.rule === finding.rule &&
      (one.undocumentedOnly === undefined || documentedPath(finding.path, documentedPaths()) === undefined) &&
      (one.statuses === undefined || (finding.status !== undefined && one.statuses.includes(finding.status))),
  )?.reason;

/** The staging origin, checked: https, a host, nothing after it. */
export function originOf(value: string | undefined): string {
  if (value === undefined || value === '') throw new Error('AGENTX_DAST_ORIGIN is not set');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value.replace(/\/$/, '') || url.username !== '') {
    throw new Error('AGENTX_DAST_ORIGIN must be an https origin alone, like https://app.example.com');
  }
  return url.origin;
}

/** ZAP's API scan, as `docker run` arguments, writing `zap.json` in the mounted directory. */
export function zapArgs(origin: string, dir: string): string[] {
  const replacer = (key: string, value: string) => ['-config', `replacer.full_list(0).${key}=${value}`];
  const options = [
    ['-config', 'scanner.threadPerHost=2'],
    ['-config', 'scanner.maxScanDurationInMins=20'],
    replacer('description', 'origin'),
    replacer('enabled', 'true'),
    replacer('matchtype', 'REQ_HEADER'),
    replacer('matchstr', 'Origin'),
    replacer('regex', 'false'),
    replacer('replacement', origin),
  ].flat();
  return [
    'run',
    '--rm',
    '--volume',
    `${dir}:/zap/wrk:rw`,
    SCANNER_IMAGES.zap,
    'zap-api-scan.py',
    '-t',
    '/zap/wrk/openapi.json',
    '-f',
    'openapi',
    '-O',
    origin,
    '-J',
    'zap.json',
    '-I',
    '-s',
    '-T',
    '10',
    '-z',
    options.join(' '),
  ];
}

/** The compose stack's API, as the end-to-end tests reach it (tooling/e2e/compose.ts). */
export const STACK_ORIGIN = 'http://localhost:8080';

/**
 * Schemathesis's run, as `docker run` arguments, writing `junit.xml` in the
 * mounted directory. Against the compose stack (B7-3, every pull request) it
 * shares the runner's network, so localhost is the stack's front door, and
 * runs shorter.
 */
export function schemathesisArgs(origin: string, dir: string, target: 'staging' | 'stack' = 'staging'): string[] {
  const stack = target === 'stack';
  return [
    'run',
    '--rm',
    ...(stack ? ['--network', 'host'] : []),
    '--volume',
    `${dir}:/wrk`,
    SCANNER_IMAGES.schemathesis,
    'run',
    '/wrk/openapi.json',
    '--url',
    origin,
    '--header',
    `Origin: ${origin}`,
    '--rate-limit',
    '120/m',
    '--max-examples',
    stack ? '10' : '20',
    '--max-time',
    stack ? '300' : '900',
    '--phases',
    'examples,coverage,fuzzing',
    '--continue-on-failure',
    // A redirect is the answer (sign-in's to the login service), never a page to follow.
    '--max-redirects',
    '0',
    '--report',
    'junit',
    '--report-junit-path',
    '/wrk/junit.xml',
    '--no-color',
  ];
}

const ZAP_SEVERITY: Readonly<Record<string, Severity>> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };

interface ZapReport {
  readonly site?: readonly {
    readonly alerts?: readonly {
      readonly pluginid: string;
      readonly name: string;
      readonly riskcode: string;
      readonly instances?: readonly { readonly uri: string; readonly method: string }[];
    }[];
  }[];
}

/** The findings of ZAP's JSON report: one per rule, method and path. */
export function zapFindings(report: ZapReport): Finding[] {
  return (report.site ?? []).flatMap((site) =>
    (site.alerts ?? []).flatMap((alert) =>
      (alert.instances ?? []).map((instance) => ({
        tool: 'zap' as const,
        rule: `zap/${alert.pluginid}`,
        title: alert.name,
        severity: ZAP_SEVERITY[alert.riskcode] ?? 'high',
        method: instance.method.toUpperCase(),
        path: new URL(instance.uri).pathname,
      })),
    ),
  );
}

const XML_ENTITIES: Readonly<Record<string, string>> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

const unescapeXml = (text: string): string =>
  text.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (_, name: string) =>
    name.startsWith('#x') || name.startsWith('#X')
      ? String.fromCodePoint(Number.parseInt(name.slice(2), 16))
      : name.startsWith('#')
        ? String.fromCodePoint(Number.parseInt(name.slice(1), 10))
        : (XML_ENTITIES[name.toLowerCase()] ?? ''),
  );

/** A check's name as a rule: `Server error` is `schemathesis/server-error`. */
const ruleOf = (check: string): string =>
  `schemathesis/${check
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')}`;

/** How much a failed check matters: a server error most, the document's own mismatches least. */
const schemathesisSeverity = (check: string): Severity =>
  /server error|response time/i.test(check) ? 'medium' : 'low';

/**
 * The findings of Schemathesis's JUnit report: each test case is an operation
 * (`POST /v1/…`), and each failure holds one or more cases (`1. Test Case ID: …`),
 * each listing the checks it failed as lines of their own beginning `- ` at the
 * line's start, then its answer's status as `[431] …`.
 */
export function schemathesisFindings(xml: string): Finding[] {
  const findings: Finding[] = [];
  for (const [, attributes = '', body = ''] of xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)) {
    const name = unescapeXml(/\bname="([^"]*)"/.exec(attributes)?.[1] ?? '');
    const [method = '', operationPath = ''] = name.split(' ');
    for (const [, text = ''] of body.matchAll(/<(?:failure|error)\b[^>]*>([\s\S]*?)<\/(?:failure|error)>/g)) {
      for (const failure of unescapeXml(text).split(/^(?=\d+\. Test Case ID:)/m)) {
        const status = /^\[(\d{3})\] /m.exec(failure)?.[1];
        for (const [, check = ''] of failure.matchAll(/^- (.+)$/gm)) {
          findings.push({
            tool: 'schemathesis',
            rule: ruleOf(check.trim()),
            title: check.trim(),
            severity: schemathesisSeverity(check),
            method: method.toUpperCase(),
            path: operationPath,
            ...(status !== undefined && { status: Number(status) }),
          });
        }
      }
    }
  }
  return findings;
}

/** Each finding once: the same rule at the same operation is one finding. */
export const distinct = (findings: readonly Finding[]): Finding[] => [
  ...new Map(findings.map((finding) => [keyOf(finding), finding])).values(),
];

const keyOf = (finding: Finding): string => `${finding.rule} ${finding.method} ${finding.path}`;

/** The document's path an address falls under (`/v1/members/{id}/role` for `/v1/members/0199…/role`), if any. */
export function documentedPath(address: string, paths: readonly string[]): string | undefined {
  return paths.find((documented) =>
    new RegExp(`^${documented.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\\?\{[^}]+\\?\}/g, '[^/]+')}$`).test(
      address,
    ),
  );
}

const SARIF_LEVEL: Readonly<Record<Severity, string>> = { high: 'error', medium: 'warning', low: 'note', info: 'none' };

/**
 * The findings as SARIF 2.1.0, one run a tool, each placed on the line of the
 * document that holds its path (line 1 when the document has no such path).
 */
export function sarifOf(findings: readonly Finding[], openapiText: string): object {
  const lines = openapiText.split('\n');
  const paths = Object.keys((JSON.parse(openapiText) as { paths?: Record<string, unknown> }).paths ?? {});
  const lineOf = (address: string): number => {
    const documented = documentedPath(address, paths);
    if (documented === undefined) return 1;
    const index = lines.findIndex((line) => line.trimStart().startsWith(`${JSON.stringify(documented)}:`));
    return index === -1 ? 1 : index + 1;
  };
  const runOf = (tool: Finding['tool'], name: string, informationUri: string) => {
    const mine = findings.filter((finding) => finding.tool === tool);
    const rules = [...new Map(mine.map((finding) => [finding.rule, finding.title])).entries()].sort();
    return {
      tool: {
        driver: {
          name,
          informationUri,
          rules: rules.map(([id, title]) => ({ id, shortDescription: { text: title } })),
        },
      },
      automationDetails: { id: `dast/${tool}/` },
      results: mine.map((finding) => ({
        ruleId: finding.rule,
        level: SARIF_LEVEL[finding.severity],
        message: { text: `${finding.title}: ${finding.method} ${finding.path}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: OPENAPI_FILE },
              region: { startLine: lineOf(finding.path) },
            },
          },
        ],
        partialFingerprints: { 'dastFinding/v1': createHash('sha256').update(keyOf(finding)).digest('hex') },
      })),
    };
  };
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      runOf('zap', 'OWASP ZAP API scan', 'https://www.zaproxy.org/docs/docker/api-scan/'),
      runOf('schemathesis', 'Schemathesis', 'https://schemathesis.readthedocs.io/'),
    ],
  };
}

/** What the public log may show: counts by tool and severity, and how many are accepted. Never a host or a path. */
export function summaryOf(findings: readonly Finding[], accepted: number): string[] {
  const count = (tool: Finding['tool'], severity: Severity) =>
    findings.filter((finding) => finding.tool === tool && finding.severity === severity).length;
  return [
    ...(['zap', 'schemathesis'] as const).map(
      (tool) =>
        `${tool}: ${(['high', 'medium', 'low', 'info'] as const).map((severity) => `${severity} ${String(count(tool, severity))}`).join(', ')}`,
    ),
    `accepted (listed in tooling/dast/scan.ts): ${String(accepted)}`,
    'Details: the repository Security tab, code scanning, category dast.',
  ];
}

/** Runs one scanner in Docker, its own output kept out of the log unless shown. Exits the run for an error it reports. */
function runScanner(tool: string, args: readonly string[], allowed: readonly number[], shown = false): void {
  const done = spawnSync('docker', args, { stdio: shown ? 'inherit' : 'ignore', timeout: 40 * 60_000 });
  if (done.error !== undefined) throw new Error(`${tool} could not be run: ${done.error.message}`);
  if (done.status === null || !allowed.includes(done.status)) {
    throw new Error(`${tool} ended with ${String(done.status ?? done.signal)}, not a finished scan`);
  }
}

/** Waits for the API, which sleeps when idle, to answer its health check: at most 3 minutes. */
async function wake(origin: string): Promise<void> {
  const until = Date.now() + 3 * 60_000;
  while (Date.now() < until) {
    try {
      const answer = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(30_000) });
      if (answer.ok) return;
    } catch {
      // Still waking.
    }
    await new Promise((resolve) => setTimeout(resolve, 10_000));
  }
  throw new Error('the API did not answer its health check within 3 minutes');
}

/** The findings a gate stops on, one line each: every one not accepted, informational notes aside. */
export const gateLines = (findings: readonly Finding[]): string[] =>
  findings
    .filter((finding) => finding.severity !== 'info' && acceptedReason(finding) === undefined)
    .map(
      (finding) =>
        `${finding.severity} ${finding.rule}: ${finding.method} ${finding.path}${finding.status === undefined ? '' : ` (answered ${String(finding.status)})`}`,
    );

/** The results directory, made writable for the scanners (their images' own users, not the runner's), with the document in it. */
function resultsDir(): { dir: string; openapiText: string } {
  const dir = path.resolve(RESULTS_DIR);
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777);
  const openapiText = readFileSync(OPENAPI_FILE, 'utf8');
  writeFileSync(path.join(dir, 'openapi.json'), openapiText, 'utf8');
  return { dir, openapiText };
}

/**
 * B7-3, every pull request: Schemathesis against the compose stack the
 * end-to-end job has started, failing on any finding not accepted. Nothing
 * here is staging's, so the scanner's output and the findings are shown.
 */
function gateOnStack(): number {
  const { dir } = resultsDir();
  runScanner('Schemathesis', schemathesisArgs(STACK_ORIGIN, dir, 'stack'), [0, 1], true);
  const lines = gateLines(distinct(schemathesisFindings(readFileSync(path.join(dir, 'junit.xml'), 'utf8'))));
  for (const line of lines) console.log(line);
  console.log(
    lines.length === 0
      ? 'No finding beyond those accepted in tooling/dast/scan.ts.'
      : `${String(lines.length)} finding(s): fix each, with a test that holds it, or accept it in tooling/dast/scan.ts with its reason.`,
  );
  return lines.length === 0 ? 0 : 1;
}

async function main(argv: readonly string[]): Promise<number> {
  if (argv.includes('--stack')) return gateOnStack();
  const origin = originOf(process.env.AGENTX_DAST_ORIGIN);
  const { dir, openapiText } = resultsDir();
  await wake(origin);
  // ZAP answers 0 to 2 for a finished scan (-I: warnings don't fail it); Schemathesis 0, or 1 when a check failed.
  runScanner('ZAP', zapArgs(origin, dir), [0, 1, 2]);
  await wake(origin);
  runScanner('Schemathesis', schemathesisArgs(origin, dir), [0, 1]);
  const all = distinct([
    ...zapFindings(JSON.parse(readFileSync(path.join(dir, 'zap.json'), 'utf8')) as ZapReport),
    ...schemathesisFindings(readFileSync(path.join(dir, 'junit.xml'), 'utf8')),
  ]);
  const open = all.filter((finding) => acceptedReason(finding) === undefined);
  const reported = open.filter((finding) => finding.severity !== 'info');
  writeFileSync(path.join(dir, SARIF_FILE), JSON.stringify(sarifOf(reported, openapiText), null, 2), 'utf8');
  for (const line of summaryOf(open, all.length - open.length)) console.log(line);
  return 0;
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
