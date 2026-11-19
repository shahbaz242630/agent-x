/**
 * The MCP clients whose metadata documents the API fetches (AG5, 6E3c), read from mcp-clients.json, the one place
 * they are listed: network.bicep, dns-policy.bicep and apps.bicep compile the same file, and the policy holds the
 * deployment to what is read here.
 *
 * Run as `node deploy/azure/mcp-clients.ts` (mcp-watch.yml, daily; bare Node, nothing installed), it looks up each
 * listed host and warns, red, when one answers outside its listed ranges: the way out would refuse the fetch, and
 * that client would fail to connect by its document until the list moves.
 */
import { resolve4 } from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { covers } from './github-ranges.ts';

export interface McpClient {
  readonly client: string;
  /** What the API trusts (AGENTX_OAUTH_CLIENT_METADATA_ORIGINS): an origin, a path prefix or one document's address. */
  readonly metadata: string;
  /** The IPv4 ranges its host answers from, as its owner publishes them. */
  readonly prefixes: readonly string[];
  readonly source: string;
}

const CLIENTS_FILE = path.join(import.meta.dirname, 'mcp-clients.json');

export const readMcpClients = (): readonly McpClient[] =>
  (JSON.parse(readFileSync(CLIENTS_FILE, 'utf8')) as { readonly clients: readonly McpClient[] }).clients;

/** The origin an entry is fetched on, as apps.bicep reads it: the first three `/`-separated parts. */
export const originOf = (client: McpClient): string => new URL(client.metadata).origin;

/** Every client's ranges once each, in the order they first appear, as network.bicep's union() keeps them. */
export const mcpPrefixes = (clients: readonly McpClient[]): readonly string[] => [
  ...new Set(clients.flatMap((client) => client.prefixes)),
];

/** The names the network may look up for them (dns-policy.bicep): each host, as a DNS name ending in a dot. */
export const mcpNames = (clients: readonly McpClient[]): readonly string[] => [
  ...new Set(clients.map((client) => `${new URL(client.metadata).host}.`)),
];

/** The narrowest range accepted: wider than a /13 (Cloudflare's widest) is closer to "the internet" than a host. */
const WIDEST_BITS = 13;

const CIDR = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/;

/** Why one range won't do, or nothing: an IPv4 `a.b.c.d/len`, its network address exact, no wider than a /13. */
function prefixProblem(prefix: string): string | undefined {
  const [, network, bits] = CIDR.exec(prefix) ?? [];
  if (network === undefined || bits === undefined || !covers(prefix, network)) return 'is not an IPv4 range';
  if (Number(bits) < WIDEST_BITS) return `is wider than a /${String(WIDEST_BITS)}`;
  // The network address itself must be the range's first: 10.0.0.1/8 would be read as 10.0.0.0/8.
  const first = network.split('.').map(Number);
  const host = 32 - Number(bits);
  const value = first.reduce((sum, octet) => sum * 256 + octet, 0);
  return value % 2 ** host === 0 ? undefined : 'does not start at its network address';
}

/** What is wrong with one client's entry and ranges, its name first, or nothing. */
function clientProblems(client: McpClient): string[] {
  const name = client.client || '(unnamed)';
  const problems: string[] = [];
  if (client.client === '' || client.source === '') problems.push(`${name}: needs a name and a source`);
  if (!URL.canParse(client.metadata) || !client.metadata.startsWith('https://')) {
    return [...problems, `${name}: ${client.metadata} is not an https address`];
  }
  const url = new URL(client.metadata);
  const printed = url.pathname === '/' ? url.origin : `${url.origin}${url.pathname}`;
  if (printed !== client.metadata) problems.push(`${name}: ${client.metadata} is not written as ${printed}`);
  if (client.prefixes.length === 0) problems.push(`${name}: names no range`);
  for (const prefix of client.prefixes) {
    const problem = prefixProblem(prefix);
    if (problem !== undefined) problems.push(`${name}: ${prefix} ${problem}`);
  }
  return problems;
}

/**
 * What is wrong with the list, or nothing: each client named and sourced, its entry https and written as the URL
 * parser prints it with no user, query or fragment (the setting refuses the rest at start), no entry twice, and each
 * range a real one.
 */
export function mcpClientProblems(clients: readonly McpClient[]): string[] {
  const twice = clients
    .filter((client, index) => clients.findIndex((each) => each.metadata === client.metadata) !== index)
    .map((client) => `${client.client || '(unnamed)'}: ${client.metadata} is listed twice`);
  return [...clients.flatMap(clientProblems), ...twice];
}

/** A host's IPv4 addresses, as a lookup gives them. */
export type Resolve = (host: string) => Promise<string[]>;

/**
 * Each listed host looked up and held to its ranges, said in plain words: 0 when every address is inside them, 1
 * (with what broke and what next) when any is outside, or a host doesn't answer.
 */
export async function checkClientHosts(
  clients: readonly McpClient[],
  resolve: Resolve,
  say: (line: string) => void,
): Promise<number> {
  let problems = 0;
  for (const client of clients) {
    const host = new URL(client.metadata).host;
    const named = `${client.client} (${host})`;
    let addresses: string[];
    try {
      addresses = await resolve(host);
    } catch {
      say(`${named} didn't answer a lookup.`);
      problems += 1;
      continue;
    }
    const outside = addresses.filter((address) => !client.prefixes.some((prefix) => covers(prefix, address)));
    if (outside.length === 0) {
      say(`${named} answers inside its listed ranges.`);
    } else {
      say(`${named} answers at ${outside.join(', ')}, outside its listed ranges (${client.prefixes.join(', ')}).`);
      problems += 1;
    }
  }
  if (problems > 0) {
    say(
      "What broke: staging's way out allows only the listed ranges, so that client's document can't be fetched and it can't connect by it (it may still register by DCR). What next: read the client's owner's published addresses (the entry's source), update its prefixes in deploy/azure/mcp-clients.json in a PR, and deploy the foundation; a host now behind a shared front (Cloudflare) comes off the list instead (AZ22).",
    );
  }
  return problems > 0 ? 1 : 0;
}

if (import.meta.main) {
  process.exitCode = await checkClientHosts(readMcpClients(), resolve4, (line) => {
    console.log(line);
  });
}
