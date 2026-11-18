// An MCP connection's row as the signed state reads and records it (0093,
// 6E3a): a file of its own, as both the key lists (agent-keys.ts, which leave
// connection keys out) and the connections themselves (connections.ts) name it.
import type { SignedStateTable } from '@agentx/platform/db';

/** A connection's row: its ID is its key's, its fields made once (0032's `made_once`). */
export const CONNECTIONS = {
  table: 'agents.connections',
  subject: 'connection',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'client_id', type: 'text' },
    { column: 'resource', type: 'text' },
    { column: 'redirect_uri', type: 'text' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };
