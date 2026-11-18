// 6E4: the canaries' judge. A canary that saw our seven tools and a typed
// get_agent answer passes; anything else is red, in plain words naming the
// client and its version, and never shows a key. The positive controls are
// here (a missing tool, a refused call, a crashed canary each go red) and in
// canary.test.ts (real clients with a wrong key).
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { MCP_TOOLS } from '../../apps/api/src/mcp-tools.ts';
import { MCP_PATH as API_MCP_PATH } from '../../apps/api/src/mcp-protocols.ts';
import {
  agentProblem,
  type CanaryReport,
  EXPECTED_TOOLS,
  judgeCanary,
  judgeReports,
  main,
  MCP_PATH,
  readReport,
  report,
  shownError,
  target,
  toolsProblem,
  wake,
} from './canary-judge.ts';

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const AGENT = {
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  organizationId: '0199a0f0-0000-7000-8000-00000000abcd',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes: ['sources:read', 'suppliers:read'],
  keyExpiresAt: '2099-12-28T09:00:00.000Z',
};
const PASSING: CanaryReport = {
  canary: 'python-auto',
  client: 'mcp',
  version: '2.3.0',
  protocol: '2026-07-28',
  tools: [...EXPECTED_TOOLS],
  agent: { isError: false, structuredContent: AGENT },
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("the canaries' judge (6E4)", () => {
  it("keeps its copy of the tools and the endpoint equal to the API's own", () => {
    expect(EXPECTED_TOOLS).toEqual(MCP_TOOLS.map((tool) => tool.name));
    expect(MCP_PATH).toBe(API_MCP_PATH);
  });

  it('passes a canary that saw the seven tools, in any order, and a typed get_agent answer', () => {
    expect(judgeCanary(PASSING).errors).toEqual([]);
    expect(judgeCanary({ ...PASSING, tools: [...EXPECTED_TOOLS].reverse() }).errors).toEqual([]);
    expect(judgeCanary(PASSING).summary).toContain('| python-auto | mcp 2.3.0 | 2026-07-28 | passed |');
  });

  it('goes red on a tool missing, one too many, one twice, or no list, naming them', () => {
    expect(toolsProblem(EXPECTED_TOOLS.slice(1))).toContain('missing get_agent');
    expect(toolsProblem([...EXPECTED_TOOLS, 'execute_payment'])).toContain('unexpected execute_payment');
    expect(toolsProblem([...EXPECTED_TOOLS, 'get_agent'])).toContain('a tool listed twice');
    expect(toolsProblem(undefined)).toBe('it gave no tool list');
    const { errors } = judgeCanary({ ...PASSING, tools: EXPECTED_TOOLS.slice(1) });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/^The python-auto canary, mcp 2\.3\.0 \(protocol 2026-07-28\), failed against staging/);
    expect(errors[0]).toContain('Hermes Agent');
  });

  it("goes red on get_agent's answer missing, an error, untyped, or with a date that isn't one", () => {
    expect(agentProblem(undefined)).toBe('it gave no answer from get_agent');
    expect(agentProblem({ isError: true, structuredContent: AGENT })).toContain('isError');
    expect(agentProblem({ isError: false })).toContain('no structured content');
    expect(agentProblem({ structuredContent: [AGENT] })).toContain('no structured content');
    expect(agentProblem({ structuredContent: { ...AGENT, agentId: 7 } })).toContain('mistyped agentId');
    expect(agentProblem({ structuredContent: { ...AGENT, scopes: 'sources:read' } })).toContain('mistyped scopes');
    expect(agentProblem({ structuredContent: { ...AGENT, scopes: [1] } })).toContain('scopes');
    expect(agentProblem({ structuredContent: { ...AGENT, keyExpiresAt: 'soon' } })).toContain('not a date');
    expect(judgeCanary({ ...PASSING, agent: undefined }).errors).toHaveLength(1);
  });

  it('goes red on a canary that stopped, saying where, never showing a key or a token', () => {
    const { errors, summary } = judgeCanary({
      canary: 'mcp-remote',
      client: 'mcp-remote',
      version: '0.16.6',
      failed: { step: 'connect', error: `HTTP 401 for Bearer ${KEY}\nand ${KEY} again, | piped` },
    });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('it could not connect: HTTP 401 for Bearer [hidden] and axk_[hidden] again');
    expect(errors[0]).toContain('the mcp-remote bridge');
    expect(errors.join('') + summary).not.toContain(KEY.slice(4));
    expect(summary).toContain('\\| piped');
    // An unknown canary still says who it may break.
    expect(judgeCanary({ ...PASSING, canary: 'other', tools: [] }).errors[0]).toContain('Agents built on this client');
    expect(judgeCanary({ ...PASSING, protocol: undefined, tools: [] }).summary).toContain('| ? |');
  });

  it('cuts a long error short', () => {
    expect(shownError('x'.repeat(500))).toHaveLength(301);
    expect(shownError('  a \n\t b ')).toBe('a b');
  });

  it("reads a report, and makes one that isn't (a crashed canary) red", () => {
    expect(readReport(JSON.stringify(PASSING), 'a.json')).toEqual(PASSING);
    expect(readReport(JSON.stringify({ ...PASSING, version: 3 }), 'a.json').version).toBe('?');
    for (const text of ['', 'not json', '[]', '{"canary":"x"}']) {
      const read = readReport(text, 'b.json');
      expect(read.failed?.error).toContain('not a canary report');
      expect(judgeCanary(read).errors).toHaveLength(1);
    }
  });

  it('judges every report as one table, red when any one is', () => {
    const verdict = judgeReports([PASSING, { ...PASSING, canary: 'python-legacy', tools: [] }]);
    expect(verdict.errors).toHaveLength(1);
    expect(verdict.summary.split('\n').filter((line) => line.startsWith('| python-'))).toHaveLength(2);
  });

  it('writes the summary and each red line as a workflow command, outside text unable to start another', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'canary-judge-'));
    try {
      const summary = path.join(dir, 'summary.md');
      vi.stubEnv('GITHUB_STEP_SUMMARY', summary);
      const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      expect(report({ errors: ['one\n::error::two'], summary: 'S' })).toBe(1);
      expect(out).toHaveBeenCalledWith('::error::one%0A::error::two\n');
      expect(report({ errors: [], summary: 'S' }, 'All clear.')).toBe(0);
      expect(out).toHaveBeenCalledWith('All clear.\n');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads the address and the key from the environment, saying which is wrong without showing it', () => {
    expect(target({ AGENTX_MCP_ORIGIN: 'https://app.example.com', AGENTX_MCP_KEY: ` ${KEY}\n` })).toEqual({
      url: 'https://app.example.com/v1/mcp',
      key: KEY,
    });
    expect(target({ AGENTX_MCP_ORIGIN: 'https://app.example.com' })).toEqual({
      problem: 'The repository secret STAGING_SMOKE_AGENT_KEY is not set.',
    });
    for (const origin of [undefined, 'http://app.example.com', 'https://app.example.com/v1']) {
      expect(target({ AGENTX_MCP_ORIGIN: origin, AGENTX_MCP_KEY: KEY })).toEqual({
        problem: expect.stringContaining('STAGING_APP_ORIGIN') as unknown,
      });
    }
  });

  it('wakes staging: asks again while it is asleep, with the key, and says when it never woke', async () => {
    const asked: { status: number }[] = [{ status: 503 }, { status: 400 }];
    const fetcher = vi.fn((_url: string, init: { headers: Record<string, string> }) => {
      expect(init.headers.authorization).toBe(`Bearer ${KEY}`);
      return Promise.resolve(new Response(null, asked.shift() ?? { status: 504 }));
    });
    const ways = { fetcher, pause: () => Promise.resolve(), now: () => new Date(0), wakeMs: 1 };
    expect(await wake('https://app.example.com/v1/mcp', KEY, ways)).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
    let clock = 0;
    const late = {
      ...ways,
      now: () => {
        clock += 1000;
        return new Date(clock);
      },
    };
    expect(await wake('https://app.example.com/v1/mcp', KEY, late)).toBe('504 after 0.001 s');
  });

  describe('the command line', () => {
    const env = { AGENTX_MCP_ORIGIN: 'https://app.example.com', AGENTX_MCP_KEY: KEY };

    it('wake: 0 once awake, 1 in plain words when it never woke or the secrets are wrong', async () => {
      const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      const awake = { fetcher: () => Promise.resolve(new Response(null, { status: 400 })) };
      expect(await main(['wake'], env, awake)).toBe(0);
      const asleep = {
        fetcher: () => Promise.reject(new Error('down')),
        pause: () => Promise.resolve(),
        wakeMs: 0,
      };
      expect(await main(['wake'], env, asleep)).toBe(1);
      expect(out).toHaveBeenCalledWith(expect.stringContaining('never answered while it woke (no answer after 0 s)'));
      expect(await main(['wake'], {}, awake)).toBe(1);
    });

    it('judge: reads each report file, a missing one red', async () => {
      const dir = mkdtempSync(path.join(tmpdir(), 'canary-judge-'));
      try {
        vi.spyOn(process.stdout, 'write').mockReturnValue(true);
        const file = path.join(dir, 'a.json');
        writeFileSync(file, JSON.stringify(PASSING));
        expect(await main(['judge', file], env)).toBe(0);
        expect(await main(['judge', file, path.join(dir, 'missing.json')], env)).toBe(1);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it('anything else: its usage, 2', async () => {
      vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      expect(await main(['judge'], env)).toBe(2);
      expect(await main([], env)).toBe(2);
    });
  });
});
