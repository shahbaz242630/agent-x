// 6E4 (MCP-Guide §7): the daily real-client canaries written in TypeScript,
// against staging's MCP endpoint with the smoke agent's key. Each one is a
// real client, as a customer's agent uses it, pinned in package.json's dev
// dependencies (never in the image: the Dockerfile installs production
// dependencies only): it connects, lists the tools and calls get_agent, and
// canary-judge.ts judges what it saw. The Python canaries are canary.py.
//
//   node tooling/mcp-watch/canary.ts ts-legacy | ts-modern | mcp-remote | ai-sdk
//
// - ts-legacy: the official TypeScript SDK client, the 2025 `initialize` handshake (its default);
// - ts-modern: the same client pinned to the 2026-07-28 revision (`server/discover`, per-request `_meta`);
// - mcp-remote: the stdio bridge many hosts start, driven over stdio by the same client;
// - ai-sdk: Vercel's AI SDK MCP client (tools only: no model, no model key).
//
// The key reaches each client as a header, never in an address or an argument:
// mcp-remote reads it from its environment (`${AGENTX_MCP_AUTH}`, which it
// expands itself), and its own log names headers, never their values.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

import { createMCPClient } from '@ai-sdk/mcp';
import { Client, StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import { type CanaryReport, type CanaryStep, judgeReports, report, target } from './canary-judge.ts';

const require = createRequire(import.meta.url);

/** An installed package's own version, from its package.json (some export no `./package.json`, so it is read whole). */
const versionOf = (name: string): string =>
  (
    JSON.parse(readFileSync(new URL(`../../node_modules/${name}/package.json`, import.meta.url), 'utf8')) as {
      version: string;
    }
  ).version;

/** The mcp-remote bridge's command line, as its package installs it. */
const MCP_REMOTE = path.join(path.dirname(require.resolve('mcp-remote/package.json')), 'dist', 'proxy.js');

/** Who the canaries say they are, on staging's request lines (mcpClient). */
const CLIENT_INFO = { name: 'agent-x-canary', version: '1' };

/** How long one step may take: staging is awake by now (canary-judge.ts wake). */
const STEP_MS = 60_000;

/** Where a canary connects, and how a local run (canary.test.ts) differs from staging. */
export interface Target {
  readonly url: string;
  readonly key: string;
  /** mcp-remote refuses a plain-http address unless told; staging's is https. */
  readonly allowHttp?: boolean;
}

/** What one canary does: list the tools and call get_agent, through its own client. */
interface Session {
  readonly protocol?: string | undefined;
  readonly tools: () => Promise<readonly string[]>;
  readonly getAgent: () => Promise<{ readonly isError?: boolean; readonly structuredContent?: unknown }>;
  readonly close: () => Promise<void>;
}

/** Runs one canary's three steps, each named, so a failure says where it stopped. */
async function run(
  base: Omit<CanaryReport, 'failed' | 'tools' | 'agent'>,
  open: () => Promise<Session>,
): Promise<CanaryReport> {
  let step: CanaryStep = 'connect';
  let session: Session | undefined;
  let found: Pick<CanaryReport, 'tools' | 'agent' | 'protocol'> = {};
  try {
    session = await open();
    found = { protocol: session.protocol };
    step = 'list the tools';
    const tools = await session.tools();
    found = { ...found, tools };
    step = 'call get_agent';
    found = { ...found, agent: await session.getAgent() };
    return { ...base, ...found };
  } catch (error) {
    return { ...base, ...found, failed: { step, error: String(error) } };
  } finally {
    await session?.close().catch(() => undefined);
  }
}

/** The official client over a transport: its era, its tools, and get_agent. */
async function officialSession(transport: Transport, modern: boolean): Promise<Session> {
  const client = new Client(CLIENT_INFO, {
    versionNegotiation: { mode: modern ? { pin: '2026-07-28' } : 'legacy' },
  });
  await client.connect(transport, { timeout: STEP_MS });
  return {
    protocol: client.getNegotiatedProtocolVersion(),
    tools: async () => (await client.listTools(undefined, { timeout: STEP_MS })).tools.map((tool) => tool.name),
    getAgent: async () => {
      const result = await client.callTool({ name: 'get_agent', arguments: {} }, { timeout: STEP_MS });
      return { isError: result.isError === true, structuredContent: result.structuredContent };
    },
    close: () => client.close(),
  };
}

const httpTransport = ({ url, key }: Target): Transport =>
  new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${key}` } } });

/** Every TS canary, by name. */
export const CANARIES: Readonly<Record<string, (where: Target) => Promise<CanaryReport>>> = {
  'ts-legacy': (where) =>
    run(
      {
        canary: 'ts-legacy',
        client: '@modelcontextprotocol/client',
        version: versionOf('@modelcontextprotocol/client'),
      },
      () => officialSession(httpTransport(where), false),
    ),
  'ts-modern': (where) =>
    run(
      {
        canary: 'ts-modern',
        client: '@modelcontextprotocol/client',
        version: versionOf('@modelcontextprotocol/client'),
      },
      () => officialSession(httpTransport(where), true),
    ),
  'mcp-remote': (where) =>
    run({ canary: 'mcp-remote', client: 'mcp-remote', version: versionOf('mcp-remote') }, () =>
      officialSession(
        new StdioClientTransport({
          command: process.execPath,
          args: [
            MCP_REMOTE,
            where.url,
            '--transport',
            'http-only',
            '--header',
            // Expanded by mcp-remote from its own environment: the key is never an argument.
            'Authorization:${AGENTX_MCP_AUTH}',
            ...(where.allowHttp === true ? ['--allow-http'] : []),
          ],
          env: { ...getDefaultEnvironment(), AGENTX_MCP_AUTH: `Bearer ${where.key}` },
          // Its log goes to the job's log: it names headers, never their values.
          stderr: 'inherit',
        }),
        false,
      ),
    ),
  'ai-sdk': (where) =>
    run({ canary: 'ai-sdk', client: '@ai-sdk/mcp', version: versionOf('@ai-sdk/mcp') }, async () => {
      const client = await createMCPClient({
        transport: { type: 'http', url: where.url, headers: { authorization: `Bearer ${where.key}` } },
        clientName: CLIENT_INFO.name,
        version: CLIENT_INFO.version,
      });
      return {
        protocol: client.initializeResult.protocolVersion,
        tools: async () => (await client.listTools()).tools.map((tool) => tool.name),
        getAgent: async () => {
          const result = await client.callTool({ name: 'get_agent', arguments: {} });
          return { isError: result.isError === true, structuredContent: result.structuredContent };
        },
        close: () => client.close(),
      };
    }),
};

export async function main(args: readonly string[], env: NodeJS.ProcessEnv): Promise<number> {
  const canary = CANARIES[args[0] ?? ''];
  if (canary === undefined) {
    process.stderr.write(`usage: canary.ts ${Object.keys(CANARIES).join(' | ')}\n`);
    return 2;
  }
  const where = target(env);
  if ('problem' in where) return report({ errors: [where.problem], summary: '' });
  return report(judgeReports([await canary(where)]));
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2), process.env);
