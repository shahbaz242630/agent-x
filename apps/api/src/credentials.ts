// An agent's credential, told apart by its prefix (6E3a, ADR-016; plan §4):
// its own key, `axk_…`, checked by the key check (key-check.ts) wherever an
// agent may call; an MCP connection's access token, `axa_…`, checked by the
// connection check (connection-check.ts) on the MCP endpoint alone (SEC-OAUTH-
// 01: the audience rule), and refused anywhere else before any lookup, with
// the same answer as any key refused. With the OAuth server off there is no
// connection check, so no token is ever accepted. Anything else is the key
// check's to refuse as malformed. Each takes the same trips: five accepted,
// two for a wrong secret.
import type { AgentKeyChecker, ConnectionTokenChecker, KeyChecked } from '@agentx/core/modules/agents';
import type { Logger } from '@agentx/platform/observability';

import type { CheckAgentKey } from './access.ts';

/** What every MCP connection's access token starts with. */
const ACCESS_TOKEN = 'axa_';

const REFUSED: KeyChecked = { outcome: 'refused' };

export function createCredentialCheck({
  keys,
  connections,
  resource,
  logger,
}: {
  readonly keys: AgentKeyChecker;
  /** The connection check, while the OAuth server is on; none while it is off. */
  readonly connections: ConnectionTokenChecker | undefined;
  /** The MCP endpoint's own address: the one resource a connection's tokens are for. */
  readonly resource: string;
  readonly logger: Logger;
}): CheckAgentKey {
  return (text, correlationId, toolCalls) => {
    if (!text.startsWith(ACCESS_TOKEN)) return keys.check(text, correlationId);
    if (toolCalls && connections !== undefined) return connections.check(text, correlationId, resource);
    // A connection's token sent anywhere but the MCP endpoint, or while connections are off: never looked up.
    logger
      .child({ correlationId })
      .info('connection_token.refused', { reason: toolCalls ? 'connections_off' : 'not_the_mcp_endpoint' });
    return Promise.resolve(REFUSED);
  };
}
