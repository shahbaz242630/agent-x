// B7: the dynamic scan's own logic, without Docker or staging: the origin it
// accepts, the scanners' commands, their reports read into findings, the
// accepted ones, the SARIF the workflow uploads, and a log that never names the
// host or a path. The report shapes are those the pinned images wrote against
// staging (S60), with the host replaced.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  acceptedReason,
  distinct,
  documentedPath,
  type Finding,
  gateLines,
  OPENAPI_FILE,
  originOf,
  sarifOf,
  SCANNER_IMAGES,
  schemathesisArgs,
  schemathesisFindings,
  STACK_ORIGIN,
  summaryOf,
  zapArgs,
  zapFindings,
} from './scan.ts';

const ORIGIN = 'https://app.example.test';

const ZAP_REPORT = {
  site: [
    {
      '@name': ORIGIN,
      alerts: [
        {
          pluginid: '100001',
          name: 'Unexpected Content-Type was returned',
          riskcode: '1',
          instances: [
            { uri: `${ORIGIN}/latest/meta-data/`, method: 'HEAD' },
            { uri: `${ORIGIN}/v1/members/0199a0f0-0000-7000-8000-000000000001/role?x=1`, method: 'post' },
          ],
        },
        {
          pluginid: '40018',
          name: 'SQL Injection',
          riskcode: '3',
          instances: [{ uri: `${ORIGIN}/v1/factor-resets/confirm`, method: 'POST' }],
        },
        {
          pluginid: '10049',
          name: 'Non-Storable Content',
          riskcode: '0',
          instances: [{ uri: `${ORIGIN}/health`, method: 'GET' }],
        },
      ],
    },
  ],
};

const JUNIT = `<?xml version="1.0" encoding="utf-8"?>
<testsuites errors="0" failures="3" skipped="0" tests="4" time="1.0">
  <testsuite name="schemathesis" errors="0" failures="3" skipped="0" tests="4" time="1.0">
    <testcase name="POST /v1/auth/sign-out" time="0.5">
      <failure type="failure">1. Test Case ID: wORqH9

- Unsupported methods

    Unsupported method TRACE returned 404, expected 405 Method Not Allowed

Reproduce with:

    curl -X TRACE -H 'Origin: ${ORIGIN}' ${ORIGIN}/v1/auth/sign-out</failure>
      <failure type="failure">1. Test Case ID: jCiSec

- JSON deserialization error

- Missing Content-Type header

    The following media types are documented in the schema:
    - \`application/json\`

[204] No Content:

    &lt;EMPTY&gt;</failure>
    </testcase>
    <testcase name="POST /v1/factor-resets/confirm" time="0.3">
      <failure type="failure">1. Test Case ID: aaaaaa

- API accepted schema-violating request

[413] Content Too Large:

2. Test Case ID: bbbbbb

- API accepted schema-violating request

[302] Found:</failure>
    </testcase>
    <testcase name="POST /v1/integrity-hold/clear" time="3.3" />
    <testcase name="GET /v1/auth/callback" time="0.2">
      <failure type="failure">- API accepted schema-violating request &amp; more
- Server error</failure>
    </testcase>
  </testsuite>
</testsuites>`;

const finding = (changes: Partial<Finding>): Finding => ({
  tool: 'zap',
  rule: 'zap/1',
  title: 'A rule',
  severity: 'low',
  method: 'GET',
  path: '/health',
  ...changes,
});

describe('B7 the dynamic scan of staging', () => {
  it('takes an https origin alone, and refuses anything else', () => {
    expect(originOf(ORIGIN)).toBe(ORIGIN);
    expect(originOf(`${ORIGIN}/`)).toBe(ORIGIN);
    for (const wrong of [
      undefined,
      '',
      'http://app.example.test',
      `${ORIGIN}/v1`,
      `${ORIGIN}?a=1`,
      'https://u:p@app.example.test',
    ]) {
      expect(() => originOf(wrong), String(wrong)).toThrow();
    }
  });

  it('runs ZAP from its pinned image on the document, against the origin, with our Origin on every request and two threads', () => {
    const args = zapArgs(ORIGIN, '/r');

    expect(args.slice(0, 5)).toEqual(['run', '--rm', '--volume', '/r:/zap/wrk:rw', SCANNER_IMAGES.zap]);
    expect(args).toEqual(expect.arrayContaining(['-t', '/zap/wrk/openapi.json', '-O', ORIGIN, '-J', 'zap.json', '-I']));
    const options = args.at(-1) ?? '';
    expect(options).toContain('-config scanner.threadPerHost=2');
    expect(options).toContain('-config replacer.full_list(0).matchstr=Origin');
    expect(options).toContain(`-config replacer.full_list(0).replacement=${ORIGIN}`);
    expect(options).toContain('-config replacer.full_list(0).matchtype=REQ_HEADER');
  });

  it('runs Schemathesis from its pinned image, gently, with our Origin, never the stateful phase', () => {
    const args = schemathesisArgs(ORIGIN, '/r');

    expect(args.slice(0, 5)).toEqual(['run', '--rm', '--volume', '/r:/wrk', SCANNER_IMAGES.schemathesis]);
    expect(args).toEqual(
      expect.arrayContaining(['--url', ORIGIN, '--header', `Origin: ${ORIGIN}`, '--rate-limit', '120/m']),
    );
    expect(args[args.indexOf('--phases') + 1]).toBe('examples,coverage,fuzzing');
    expect(args[args.indexOf('--report-junit-path') + 1]).toBe('/wrk/junit.xml');
  });

  it("reads ZAP's report: each rule at each method and path, its risk as the severity, never the host or query", () => {
    expect(zapFindings(ZAP_REPORT)).toEqual([
      finding({
        rule: 'zap/100001',
        title: 'Unexpected Content-Type was returned',
        method: 'HEAD',
        path: '/latest/meta-data/',
      }),
      finding({
        rule: 'zap/100001',
        title: 'Unexpected Content-Type was returned',
        method: 'POST',
        path: '/v1/members/0199a0f0-0000-7000-8000-000000000001/role',
      }),
      finding({
        rule: 'zap/40018',
        title: 'SQL Injection',
        severity: 'high',
        method: 'POST',
        path: '/v1/factor-resets/confirm',
      }),
      finding({ rule: 'zap/10049', title: 'Non-Storable Content', severity: 'info' }),
    ]);
    // A report of no site is a scan that never reached the API.
    expect(() => zapFindings({})).toThrow(/no site/);
    expect(() => zapFindings({ site: [] })).toThrow(/no site/);
    expect(zapFindings({ site: [{ alerts: [] }] })).toEqual([]);
  });

  it("reads Schemathesis's report: each failed check at its operation, not the lines indented under it", () => {
    const st = (rule: string, title: string, severity: Finding['severity'], method: string, path: string) =>
      finding({ tool: 'schemathesis', rule, title, severity, method, path });

    expect(schemathesisFindings(JUNIT)).toEqual([
      st('schemathesis/unsupported-methods', 'Unsupported methods', 'low', 'POST', '/v1/auth/sign-out'),
      {
        ...st(
          'schemathesis/json-deserialization-error',
          'JSON deserialization error',
          'low',
          'POST',
          '/v1/auth/sign-out',
        ),
        status: 204,
      },
      {
        ...st(
          'schemathesis/missing-content-type-header',
          'Missing Content-Type header',
          'low',
          'POST',
          '/v1/auth/sign-out',
        ),
        status: 204,
      },
      // Two cases in one failure, each with its own answer.
      {
        ...st(
          'schemathesis/api-accepted-schema-violating-request',
          'API accepted schema-violating request',
          'low',
          'POST',
          '/v1/factor-resets/confirm',
        ),
        status: 413,
      },
      {
        ...st(
          'schemathesis/api-accepted-schema-violating-request',
          'API accepted schema-violating request',
          'low',
          'POST',
          '/v1/factor-resets/confirm',
        ),
        status: 302,
      },
      st(
        'schemathesis/api-accepted-schema-violating-request-more',
        'API accepted schema-violating request & more',
        'low',
        'GET',
        '/v1/auth/callback',
      ),
      st('schemathesis/server-error', 'Server error', 'medium', 'GET', '/v1/auth/callback'),
    ]);
  });

  it('fails closed: a case that could not run is a high finding, and a report that tested nothing or miscounts throws', () => {
    const report = (counts: string, cases: string) =>
      `<testsuites ${counts}><testsuite name="schemathesis" ${counts}>${cases}</testsuite></testsuites>`;
    const crashed = `<testcase name="GET /v1/members"><error type="error">Traceback (most recent call last):
  ConnectionError: the stack went away</error></testcase><testcase name="GET /health"><error/></testcase>`;
    const unreadable = (method: string, path: string): Finding => ({
      tool: 'schemathesis',
      rule: 'schemathesis/unreadable-failure',
      title: 'A case that failed without a check it names',
      severity: 'high',
      method,
      path,
    });

    expect(schemathesisFindings(report('tests="2" failures="0" errors="2"', crashed))).toEqual([
      unreadable('GET', '/v1/members'),
      unreadable('GET', '/health'),
    ]);
    expect(gateLines(schemathesisFindings(report('tests="2" failures="0" errors="2"', crashed)))).toHaveLength(2);
    expect(() => schemathesisFindings(report('tests="0" failures="0" errors="0"', ''))).toThrow(/no test case/);
    expect(() => schemathesisFindings('')).toThrow(/no test case/);
    expect(() => schemathesisFindings(report('tests="2" failures="0" errors="1"', crashed))).toThrow(
      /2 were read|and 2/,
    );
    expect(() => schemathesisFindings(report('tests="2" failures="1" errors="2"', crashed))).toThrow(/counts 1 failed/);
  });

  it('keeps only what is accepted with a reason: an unknown method’s 404, and ZAP’s metadata probe answered by the edge', () => {
    expect(acceptedReason(finding({ tool: 'schemathesis', rule: 'schemathesis/unsupported-methods' }))).toMatch(
      /SEC-DATA-04/,
    );
    expect(acceptedReason(finding({ rule: 'zap/100001', path: '/latest/meta-data/' }))).toMatch(/Azure's edge/);
    expect(acceptedReason(finding({ rule: 'zap/100001', path: '/openstack/latest/meta_data.json' }))).toMatch(/edge/);
    // At an address the API serves, whatever its parameters, it is a finding.
    expect(acceptedReason(finding({ rule: 'zap/100001', path: '/v1/members' }))).toBeUndefined();
    expect(acceptedReason(finding({ rule: 'zap/100001', path: '/v1/members/abc/role' }))).toBeUndefined();
    expect(
      acceptedReason(finding({ tool: 'schemathesis', rule: 'zap/100001', path: '/latest/meta-data/' })),
    ).toBeUndefined();
    expect(acceptedReason(finding({ tool: 'zap', rule: 'schemathesis/unsupported-methods' }))).toBeUndefined();
    // A schema-violating request is accepted only when the answer was the 431 refusal.
    const violating = finding({ tool: 'schemathesis', rule: 'schemathesis/api-accepted-schema-violating-request' });
    expect(acceptedReason({ ...violating, status: 431 })).toMatch(/HEADERS_TOO_LARGE/);
    expect(acceptedReason({ ...violating, status: 413 })).toMatch(/PAYLOAD_TOO_LARGE/);
    expect(acceptedReason({ ...violating, status: 414 })).toMatch(/nginx/);
    // The stack's front door's own page, at its 414 only (CI, S60).
    const htmlPage = finding({ tool: 'schemathesis', rule: 'schemathesis/undocumented-content-type' });
    expect(acceptedReason({ ...htmlPage, status: 414 })).toMatch(/front door/);
    expect(acceptedReason({ ...htmlPage, status: 200 })).toBeUndefined();
    expect(acceptedReason(htmlPage)).toBeUndefined();
    expect(acceptedReason({ ...violating, status: 302 })).toBeUndefined();
    expect(acceptedReason(violating)).toBeUndefined();
  });

  it('counts the same rule at the same operation once', () => {
    const one = finding({});
    expect(distinct([one, { ...one }, finding({ method: 'HEAD' }), finding({ rule: 'zap/2' })])).toHaveLength(3);
  });

  it("finds the document's path an address falls under, a parameter matching one segment only", () => {
    const paths = [
      '/v1/members',
      '/v1/members/{id}/role',
      '/v1/factor-resets/{id}/confirm',
      '/v1/factor-resets/confirm',
    ];

    expect(documentedPath('/v1/members/abc/role', paths)).toBe('/v1/members/{id}/role');
    expect(documentedPath('/v1/members', paths)).toBe('/v1/members');
    expect(documentedPath('/v1/members/a/b/role', paths)).toBeUndefined();
    expect(documentedPath('/latest/meta-data/', paths)).toBeUndefined();
  });

  it("writes SARIF a run a tool, each result on its path's line of the document, fingerprinted by rule and operation", () => {
    const openapi = readFileSync(OPENAPI_FILE, 'utf8');
    const lines = openapi.split('\n');
    const sarif = sarifOf(
      [
        finding({
          rule: 'zap/40018',
          title: 'SQL Injection',
          severity: 'high',
          method: 'POST',
          path: '/v1/members/abc/role',
        }),
        finding({
          tool: 'schemathesis',
          rule: 'schemathesis/server-error',
          title: 'Server error',
          severity: 'medium',
          path: '/nowhere',
        }),
      ],
      openapi,
    ) as {
      version: string;
      runs: {
        tool: { driver: { name: string; rules: { id: string }[] } };
        automationDetails: { id: string };
        results: {
          ruleId: string;
          level: string;
          message: { text: string };
          locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[];
          partialFingerprints: Record<string, string>;
        }[];
      }[];
    };

    expect(sarif.version).toBe('2.1.0');
    const [zap, schemathesis] = sarif.runs;
    expect(zap?.automationDetails.id).toBe('dast/zap/');
    expect(zap?.tool.driver.rules).toEqual([{ id: 'zap/40018', shortDescription: { text: 'SQL Injection' } }]);
    const result = zap?.results[0];
    expect(result).toMatchObject({
      ruleId: 'zap/40018',
      level: 'error',
      message: { text: 'SQL Injection: POST /v1/members/abc/role' },
    });
    const location = result?.locations[0]?.physicalLocation;
    expect(location?.artifactLocation.uri).toBe('apps/api/openapi.json');
    expect(lines[(location?.region.startLine ?? 0) - 1]?.trim().startsWith('"/v1/members/{id}/role":')).toBe(true);
    expect(result?.partialFingerprints['dastFinding/v1']).toMatch(/^[0-9a-f]{64}$/);
    expect(schemathesis?.results[0]).toMatchObject({
      level: 'warning',
      locations: [{ physicalLocation: { region: { startLine: 1 } } }],
    });
  });

  it('logs counts by tool and severity alone, never a host or a path', () => {
    const summary = summaryOf(
      [...zapFindings(ZAP_REPORT), ...schemathesisFindings(JUNIT)].filter((one) => acceptedReason(one) === undefined),
      2,
    ).join('\n');

    expect(summary).toContain('zap: high 1, medium 0, low 1, info 1');
    expect(summary).toContain('schemathesis: high 0, medium 1, low 4, info 0');
    expect(summary).toContain('accepted (listed in tooling/dast/scan.ts): 2');
    expect(summary).not.toMatch(/example\.test|\/v1\/|\/health|https?:/);
  });

  it('runs Schemathesis on every pull request against the compose stack, on the runner’s network, shorter', () => {
    const args = schemathesisArgs(STACK_ORIGIN, '/r', 'stack');

    expect(STACK_ORIGIN).toBe('http://localhost:8080');
    expect(args.slice(0, 7)).toEqual([
      'run',
      '--rm',
      '--network',
      'host',
      '--volume',
      '/r:/wrk',
      SCANNER_IMAGES.schemathesis,
    ]);
    expect(args).toEqual(expect.arrayContaining(['--url', STACK_ORIGIN, '--header', `Origin: ${STACK_ORIGIN}`]));
    expect(args[args.indexOf('--max-time') + 1]).toBe('300');
    expect(schemathesisArgs(ORIGIN, '/r')).not.toContain('--network');
    // Redirects followed as Schemathesis does by default: forbidding them made sign-in a network error (CI, S60).
    expect(args).not.toContain('--max-redirects');
  });

  it("keeps the login service's page that sign-in's redirect leads to, at that operation and a 200 only", () => {
    const followed = (rule: string, changes: Partial<Finding> = {}) =>
      finding({ tool: 'schemathesis', rule, method: 'GET', path: '/v1/auth/sign-in', status: 200, ...changes });

    expect(acceptedReason(followed('schemathesis/undocumented-http-status-code'))).toMatch(/302/);
    expect(acceptedReason(followed('schemathesis/undocumented-content-type'))).toMatch(/sign-in page/);
    expect(acceptedReason(followed('schemathesis/undocumented-http-status-code', { status: 500 }))).toBeUndefined();
    expect(acceptedReason(followed('schemathesis/undocumented-http-status-code', { method: 'HEAD' }))).toBeUndefined();
    expect(
      acceptedReason(followed('schemathesis/undocumented-http-status-code', { path: '/v1/members' })),
    ).toBeUndefined();
  });

  it('stops a pull request on each finding not accepted, informational notes aside, naming its answer', () => {
    const violating = finding({
      tool: 'schemathesis',
      rule: 'schemathesis/api-accepted-schema-violating-request',
      path: '/v1/auth/callback',
    });

    expect(
      gateLines([
        { ...violating, status: 431 },
        { ...violating, status: 302 },
        finding({ tool: 'schemathesis', rule: 'schemathesis/unsupported-methods' }),
        finding({ severity: 'info' }),
        finding({ rule: 'zap/2', severity: 'high', method: 'POST' }),
      ]),
    ).toEqual([
      'low schemathesis/api-accepted-schema-violating-request: GET /v1/auth/callback (answered 302)',
      'high zap/2: POST /health',
    ]);
    expect(gateLines([])).toEqual([]);
  });
});
