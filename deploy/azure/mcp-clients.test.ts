import { describe, expect, it } from 'vitest';

import { setting } from '../../packages/platform/src/config/settings.ts';
import { type McpClient, mcpClientProblems, mcpNames, mcpPrefixes, originOf, readMcpClients } from './mcp-clients.ts';

const CLIENTS = readMcpClients();

const client = (change: Partial<McpClient>): McpClient => ({
  client: 'Example',
  metadata: 'https://client.example',
  prefixes: ['203.0.113.0/24'],
  source: 'its owner',
  ...change,
});

describe('the MCP clients list (AG5)', () => {
  it('holds Claude and ChatGPT, each sound, and every entry is one the API setting takes', () => {
    expect(mcpClientProblems(CLIENTS)).toEqual([]);
    expect(CLIENTS.map((each) => each.metadata)).toEqual(
      expect.arrayContaining(['https://claude.ai', 'https://chatgpt.com']),
    );
    const entries = setting(
      { AGENTX_OAUTH_CLIENT_METADATA_ORIGINS: CLIENTS.map((each) => each.metadata).join(',') },
      'AGENTX_OAUTH_CLIENT_METADATA_ORIGINS',
    );
    // The setting keeps its entries sorted.
    expect(entries).toEqual({ ok: true, value: CLIENTS.map((each) => each.metadata).toSorted() });
    const origins = setting(
      { AGENTX_OUTBOUND_ALLOWED_ORIGINS: CLIENTS.map(originOf).join(',') },
      'AGENTX_OUTBOUND_ALLOWED_ORIGINS',
    );
    expect(origins.ok).toBe(true);
  });

  it('reads each host and origin as the Bicep reads them, ranges once each', () => {
    const two = [
      client({ metadata: 'https://a.example/oauth/', prefixes: ['203.0.113.0/24', '198.51.100.0/24'] }),
      client({ client: 'B', metadata: 'https://b.example', prefixes: ['198.51.100.0/24'] }),
    ];
    expect(mcpNames(two)).toEqual(['a.example.', 'b.example.']);
    expect(two.map(originOf)).toEqual(['https://a.example', 'https://b.example']);
    expect(mcpPrefixes(two)).toEqual(['203.0.113.0/24', '198.51.100.0/24']);
  });

  it('refuses an entry the setting would refuse, one listed twice, and a range that is not one or too wide', () => {
    for (const [change, problem] of [
      [{ metadata: 'http://client.example' }, 'is not an https address'],
      [{ metadata: 'client.example' }, 'is not an https address'],
      [{ metadata: 'https://Client.example' }, 'is not written as https://client.example'],
      [{ metadata: 'https://client.example/' }, 'is not written as https://client.example'],
      [{ metadata: 'https://client.example/a/../b' }, 'is not written as https://client.example/b'],
      [{ metadata: 'https://client.example/x?y=1' }, 'is not written as https://client.example/x'],
      [{ prefixes: [] }, 'names no range'],
      [{ prefixes: ['203.0.113.0'] }, 'is not an IPv4 range'],
      [{ prefixes: ['203.0.113.0/33'] }, 'is not an IPv4 range'],
      [{ prefixes: ['2606:4700::/32'] }, 'is not an IPv4 range'],
      [{ prefixes: ['0.0.0.0/0'] }, 'is wider than a /13'],
      [{ prefixes: ['10.0.0.0/8'] }, 'is wider than a /13'],
      [{ prefixes: ['203.0.113.1/24'] }, 'does not start at its network address'],
      [{ source: '' }, 'needs a name and a source'],
    ] as const) {
      expect(mcpClientProblems([client(change)]).join('; ')).toContain(problem);
    }
    expect(mcpClientProblems([client({}), client({})])).toEqual(['Example: https://client.example is listed twice']);
    // Cloudflare's widest is the widest taken.
    expect(mcpClientProblems([client({ prefixes: ['104.16.0.0/13'] })])).toEqual([]);
  });
});
