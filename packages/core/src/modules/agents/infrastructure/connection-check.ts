// The connection check (6E3a, ADR-016; SEC-OAUTH-01, -07, -14): whether an
// MCP connection's access token, `axa_<keyId>_<tokenId>_<secret>`, may act at
// the MCP endpoint, and as which agent with which scopes. The key check's own
// steps (key-check.ts), with the token's row in place of the key's secret:
//
// 1. The text taken apart (parseConnectionToken): anything not exactly as an
//    access token is written is refused before any lookup.
// 2. The key's ID looked up in the directory, for its organisation alone:
//    where to look (one trip).
// 2a. At the door, outside the organisation's share, on one trip of its own:
//    the token's row read unlocked and its secret checked with exactly one
//    verifyMac, over zeros where there is no row (connection-tokens.ts), so a
//    caller holding only IDs never reaches the share, a lock or a brake's wait.
//    The row must be the key's own, an access token's, and not yet expired.
//    It grants nothing: what it is for is read next, through signed states.
// 3. Inside the organisation's withSignedStates (start, gather, commit: three
//    trips), credentialAt: the agent's brake, then the agent (3), the key (3a)
//    and the key's connection (3b) in one gather, each believed only if sound.
//    The connection must be made for exactly this MCP resource.
// 5. The agent ACTIVE; the key ACTIVE and not expired: a connection revoked,
//    or its agent suspended, refuses its tokens on their next call.
//
// So five trips for a token accepted, two for a wrong secret, as for a key.
// Every refusal is the same `refused`; the reason goes to the log alone, with
// the key's and token's IDs (public), never the token. What it may do is what
// its own scopes, its key's and its agent's all hold.
import {
  asAgentTraffic,
  isRetryable,
  isStatementLimit,
  OrganisationBusy,
  readAloneOnOneTrip,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedAgentKey } from '../../directory/index.ts';
import { scopesOf } from '../domain/agent.ts';
import { parseConnectionToken, type PresentedToken } from '../domain/connection.ts';
import { tokenProven, tokenRowFound, tokenRowRead, type TokenProof } from './connection-tokens.ts';
import { answeredAs, credentialAt, type KeyAtCheck, type KeyChecked, type KeyRefusal } from './key-check.ts';
import type { AgentsTables } from './tables.ts';

type Tables = AgentsTables & DirectoryTables & AuditTables;

/** Where an ID the directory doesn't list is read for: no organisation is this one, so no row is found. */
const NO_ORGANISATION = '00000000-0000-0000-0000-000000000000';

const refused = (reason: KeyRefusal): KeyAtCheck => ({ outcome: 'refused', reason });

/**
 * Step 2a: the token's row read alone, one trip, and its secret against it, one verifyMac whatever is found: for an
 * access token here, and a refresh token at the token endpoint (the API's oauth-grants.ts). `orgId`: where the
 * directory lists its key, if anywhere.
 */
export async function tokenAtTheDoor(
  database: Kysely<Tables>,
  keys: KeyProvider,
  orgId: string | undefined,
  presented: PresentedToken,
): Promise<TokenProof> {
  const under = orgId ?? NO_ORGANISATION;
  const rows = await readAloneOnOneTrip(database, tokenRowRead(database, under, presented.tokenId), {
    orgId: under,
    lockWaitBounded: true,
  });
  return tokenProven(keys, tokenRowFound(rows), presented);
}

export interface ConnectionTokenChecker {
  /**
   * Whether the access token a client sent may act at `resource`, the MCP endpoint's own address: the same `refused`
   * for every reason, logged with it.
   */
  check(text: string, correlationId: string, resource: string): Promise<KeyChecked>;
}

export function createConnectionTokenCheck({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): ConnectionTokenChecker {
  return {
    async check(text, correlationId, resource) {
      const log = logger.child({ correlationId });
      const answer = (checked: KeyAtCheck, named: Readonly<Record<string, string | null>>): KeyChecked => {
        if (checked.outcome === 'accepted') return checked;
        // A pepper version this process doesn't hold is ours to fix, not the caller's doing.
        if (checked.reason === 'key_not_held')
          log.error('connection_token.refused', { reason: checked.reason, ...named });
        else log.info('connection_token.refused', { reason: checked.reason, ...named });
        return answeredAs(checked.reason);
      };
      const presented = parseConnectionToken(text, 'access');
      if (presented === undefined) return answer(refused('malformed'), { keyId: null, tokenId: null });
      const named = { keyId: presented.keyId, tokenId: presented.tokenId };
      const orgId = await listedAgentKey(database, presented.keyId);
      const started = performance.now();
      try {
        const atTheDoor = await tokenAtTheDoor(database, keys, orgId, presented);
        if (orgId === undefined) return answer(refused('unlisted'), named);
        if (atTheDoor.outcome === 'unread') return answer(refused('missing'), named);
        if (atTheDoor.outcome !== 'proven') return answer(refused(atTheDoor.outcome), named);
        const now = clock.now();
        if (atTheDoor.row.expiresAt.getTime() <= now.getTime()) return answer(refused('expired'), named);
        const tokenScopes = scopesOf(atTheDoor.row.scopes);
        // Counted against the organisation's share, as a key's check is (PL-63).
        const checked = await asAgentTraffic(() =>
          withSignedStates(database, orgId, { keys, ids, logger: log, correlationId }, (tx, states) =>
            credentialAt(tx, states, now, orgId, presented.keyId, { prove: () => undefined, resource }),
          ),
        );
        if (checked.outcome !== 'accepted') return answer(checked, named);
        // SEC-OAUTH-08: the token's own scopes narrow what its key and agent hold, never widen it.
        const scopes = checked.key.scopes.filter((scope) => tokenScopes.includes(scope));
        return { outcome: 'accepted', key: { ...checked.key, scopes } };
      } catch (error) {
        if (!isStatementLimit(error) && !isRetryable(error)) throw error;
        // Answered busy, never a 500 (partner, 4D2e C3), as a key's check is.
        const waitedMs = Math.round(performance.now() - started);
        (orgId === undefined ? log : log.child({ orgId })).warn('connection_token.check_in_trouble', {
          ...named,
          waitedMs,
        });
        throw new OrganisationBusy(waitedMs);
      }
    },
  };
}
