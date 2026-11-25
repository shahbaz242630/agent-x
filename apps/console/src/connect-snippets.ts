// CN1a (S218, Phase-6/Connect-Options-Plan.md): the one-line connects an
// agent's page shows, one per AI tool. Built from this console's own origin,
// which serves the API too (`/v1/mcp`), so staging's page shows staging's
// address and production's its own. No snippet ever holds a key: the sign-in
// form has none (the person signs in to Agent X and picks the agent), and the
// key form names the `AGENTX_KEY` environment variable (VS Code's asks for
// the key and keeps it in its secret store), never a key itself.
// Command shapes as each tool's own docs gave them on 25 Nov 2026 (MCP-Guide §3);
// "other" is Neon's add-mcp, which writes the config of each tool it finds.

/** The name each tool lists Agent X under. */
const SERVER_NAME = 'agentx';
/** The environment variable a key form reads its key from. */
export const KEY_VARIABLE = 'AGENTX_KEY';

export const CLIENTS = ['claude-code', 'codex', 'gemini', 'cursor', 'vscode', 'web', 'other'] as const;
export type Client = (typeof CLIENTS)[number];

/** Signing in to Agent X in the browser (OAuth, the default), or a key from the environment (servers, CI). */
export type Way = 'sign-in' | 'key';

export function mcpUrl(origin: string): string {
  return `${origin}/v1/mcp`;
}

/** Each tool's terminal line (or config, for "other"); none for the web apps, which take the address alone. */
export function command(client: Client, way: Way, url: string): string | undefined {
  const keyed = way === 'key';
  switch (client) {
    case 'claude-code':
      return keyed
        ? `claude mcp add --transport http ${SERVER_NAME} ${url} --header "Authorization: Bearer $${KEY_VARIABLE}"`
        : `claude mcp add --transport http ${SERVER_NAME} ${url}`;
    case 'codex':
      return keyed
        ? `codex mcp add ${SERVER_NAME} --url ${url} --bearer-token-env-var ${KEY_VARIABLE}`
        : `codex mcp add ${SERVER_NAME} --url ${url}`;
    case 'gemini':
      return keyed
        ? `gemini mcp add --transport http --header "Authorization: Bearer $${KEY_VARIABLE}" ${SERVER_NAME} ${url}`
        : `gemini mcp add --transport http ${SERVER_NAME} ${url}`;
    case 'cursor':
      return config(keyed, url, 'cursor');
    case 'vscode':
      return config(keyed, url, 'vscode');
    case 'other':
      return keyed
        ? `npx add-mcp ${url} -n ${SERVER_NAME} --header "Authorization: Bearer $${KEY_VARIABLE}"`
        : `npx add-mcp ${url} -n ${SERVER_NAME}`;
    case 'web':
      return undefined;
  }
}

/** The JSON a tool's settings file takes, for those who add it by hand: each tool reads its own variable syntax. */
function config(keyed: boolean, url: string, tool: 'cursor' | 'vscode'): string {
  const header =
    tool === 'cursor'
      ? { Authorization: `Bearer \${env:${KEY_VARIABLE}}` }
      : { Authorization: `Bearer \${input:${SERVER_NAME}-key}` };
  const server =
    tool === 'cursor'
      ? { url, ...(keyed ? { headers: header } : {}) }
      : { type: 'http', url, ...(keyed ? { headers: header } : {}) };
  const root = tool === 'cursor' ? 'mcpServers' : 'servers';
  const extra =
    tool === 'vscode' && keyed
      ? { inputs: [{ type: 'promptString', id: `${SERVER_NAME}-key`, description: 'Agent X key', password: true }] }
      : {};
  return JSON.stringify({ [root]: { [SERVER_NAME]: server }, ...extra }, null, 2);
}

/** Base64 of an ASCII string (the address is ASCII: the browser's origin is punycode). */
function base64(text: string): string {
  return btoa(text);
}

/** The one-click installs: Cursor's and VS Code's own links, always the sign-in form (a link can't carry a key). */
export function installLink(client: 'cursor' | 'vscode', url: string): string {
  if (client === 'cursor') {
    const params = new URLSearchParams({ name: SERVER_NAME, config: base64(JSON.stringify({ url })) });
    return `cursor://anysphere.cursor-deeplink/mcp/install?${params.toString()}`;
  }
  return `vscode:mcp/install?${encodeURIComponent(JSON.stringify({ name: SERVER_NAME, type: 'http', url }))}`;
}
