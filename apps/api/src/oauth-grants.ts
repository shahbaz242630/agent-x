// The token endpoint's grants and the revocation endpoint (6E3a, ADR-016;
// RFC 6749 §4.1.3, §6, RFC 7009; SEC-OAUTH-02, -04, -05, -06, -07, -08).
//
// - A code, for the connection a person's consent made: used once (its flow's
//   `used_at`, filled in by one statement), within its 60 seconds, by the
//   client it was given to, with the redirect address it was asked with and
//   the PKCE verifier its challenge was made from, for the MCP resource it was
//   asked for. Then, inside the organisation's own transaction, the
//   connection, its key and its agent are read through their signed states,
//   all live (credentialAt, as the MCP endpoint's check), and a pair issued.
//   A code used a second time revokes the connection it made: someone else
//   holds it (OAuth 2.1 §4.1.3).
// - A refresh token, its secret checked at the door as an access token's is,
//   then in the organisation's transaction: the connection, key and agent
//   live and for this client, the token's row locked (3c, after the
//   connection's 3b) and its use filled in where none was, and a new pair
//   issued with the scopes asked, which may only narrow. Used before, it is a
//   reuse (decision 4: strict, no grace): the connection is revoked, the
//   organisation's admins see a `connection_token_reused` event, and the
//   answer is `invalid_grant`, as for every other refusal.
// - A revocation (RFC 7009): either token, its secret proven, revokes its
//   connection, by the client it was made for; the answer is always the same.
//
// Every refusal of a grant is one of OAuth's errors with a fixed description,
// never why in detail: that goes to the log, with the key's and token's IDs
// (public), never a token or a code.
import {
  type AcceptedKey,
  AGENT_KEYS,
  agentKeyOf,
  agentOf,
  type AgentsTables,
  connectionOf,
  credentialAt,
  type IssuedTokens,
  issueTokens,
  parseConnectionToken,
  type PresentedToken,
  revokeKey,
  scopesOf,
  tokenAtTheDoor,
  tokenRowLocked,
  usedNow,
} from '@agentx/core/modules/agents';
import { type AuditActor, type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { type DirectoryTables, listedAgentKey } from '@agentx/core/modules/directory';
import {
  clientConnected,
  codeHeld,
  codeUsed,
  flowOfCode,
  type FlowRead,
  hashOf,
  isCodeText,
  type OauthTables,
  pkceMatches,
  scopesNarrowed,
} from '@agentx/core/modules/oauth';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import {
  AGENT_BRAKE,
  asAgentTraffic,
  type Database,
  type DatabaseTransaction,
  holdBrakeLookedUp,
  isRetryable,
  isStatementLimit,
  OrganisationBusy,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { OauthError } from './oauth-errors.ts';
import type { Capabilities } from './oauth-wire.ts';
import type { SecurityEventSink } from './security-recorder.ts';

type Tables = AgentsTables & DirectoryTables & AuditTables & OauthTables;
type Tx = DatabaseTransaction<Tables>;

/** A grant answered: a pair issued, for the agent its connection acts as; or one of OAuth's refusals. */
export type GrantAnswer =
  | { readonly outcome: 'issued'; readonly tokens: IssuedTokens; readonly agent: AcceptedKey }
  | {
      readonly outcome: 'refused';
      readonly status: 400 | 401 | 503;
      readonly error: OauthError;
      readonly description: string;
    };

/** A code sent for its tokens (RFC 6749 §4.1.3, RFC 7636 §4.5, RFC 8707). */
interface CodeExchange {
  readonly code: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
  readonly resource: string | undefined;
}

/** A refresh token sent for a new pair (RFC 6749 §6). */
interface RefreshAsked {
  readonly refreshToken: string;
  readonly clientId: string;
  readonly scope: string | undefined;
  readonly resource: string | undefined;
}

/** Where a request came from, for its security event: a clue, never proof. */
interface Caller {
  readonly correlationId: string;
  readonly ip: string | undefined;
}

export interface OauthGrants {
  exchangeCode(asked: CodeExchange, caller: Caller): Promise<GrantAnswer>;
  refresh(asked: RefreshAsked, caller: Caller): Promise<GrantAnswer>;
  /** Revokes the connection the token is for, if it is one and the client's own; nothing is answered of which, but busy. */
  revoke(
    asked: { readonly token: string; readonly clientId: string | undefined },
    caller: Caller,
  ): Promise<{ readonly outcome: 'taken' } | Busy>;
}

/** A grant, or a revocation, that hit a database limit or lost a deadlock: nothing of it kept, send it again. */
interface Busy {
  readonly outcome: 'refused';
  readonly status: 503;
  readonly error: 'temporarily_unavailable';
  readonly description: string;
}

const BUSY: Busy = {
  outcome: 'refused',
  status: 503,
  error: 'temporarily_unavailable',
  description: 'Agent X is busy; send the same request again in a few seconds.',
};

const INVALID_GRANT = {
  outcome: 'refused',
  status: 400,
  error: 'invalid_grant',
  description: 'The code or refresh token is not valid, has expired, or was used already.',
} as const;

/** What revokes a connection that a reused code or token gives away: the server itself. */
const OAUTH_SERVER: AuditActor = { type: 'system', id: 'oauth-server' };

/** Why a code's flow refuses this exchange, for the log alone; none if it may go on. */
/** `resource` is optional (RFC 8707): some clients send none, and the flow keeps our own MCP endpoint's either way. */
function codeRefusal(flow: FlowRead, asked: CodeExchange, resource: string, now: Date): string | undefined {
  if (flow.codeEndsAt === null || flow.codeEndsAt.getTime() <= now.getTime()) return 'code_expired';
  if (flow.clientId !== asked.clientId) return 'wrong_client';
  if (flow.redirectUri !== asked.redirectUri) return 'wrong_redirect';
  if (!pkceMatches(asked.codeVerifier, flow.codeChallenge)) return 'wrong_verifier';
  // The flow's resource is the MCP endpoint's, as the authorize endpoint kept it.
  return asked.resource === undefined || asked.resource === resource ? undefined : 'wrong_resource';
}

export function createOauthGrants({
  database,
  keys,
  ids,
  clock,
  logger,
  capabilities,
  securityEvents,
}: {
  readonly database: Database<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  readonly capabilities: Capabilities;
  readonly securityEvents: SecurityEventSink;
}): OauthGrants {
  /** The organisation's own transaction, counted against its share as an agent's work is (PL-63). */
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: Tx, states: SignedStates) => Promise<T>,
  ) =>
    asAgentTraffic(() =>
      withSignedStates(
        database,
        orgId,
        { keys, ids, logger: logger.child({ correlationId }), correlationId },
        (tx, states) => work(tx, states),
      ),
    );

  /**
   * Revokes the connection whose key this is, by `actor`, if it is a connection, live, and (with `clientId`) that
   * client's: whether it was revoked now. The agent's brake first (a kill switch's lock order), then the agent (3),
   * its key (3a) for change, and the connection (3b).
   */
  const revokeConnection = (
    orgId: string,
    keyId: string,
    correlationId: string,
    { actor, reason, clientId }: { readonly actor: AuditActor; readonly reason: string; readonly clientId?: string },
  ): Promise<AcceptedKey | undefined> =>
    inOrganisation(orgId, correlationId, async (tx, states) => {
      const ofKey = { table: AGENT_KEYS, id: keyId, column: 'agent_id' };
      await holdBrakeLookedUp(tx, AGENT_BRAKE, orgId, ofKey);
      const row = await tx
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; the key is then read through its signed state
        .selectFrom(AGENT_KEYS.table)
        .select('agent_id')
        .where('org_id', '=', orgId)
        .where('id', '=', keyId)
        .executeTakeFirst();
      if (row === undefined) return undefined;
      const agentRead = await agentOf(tx, states, { orgId, id: row.agent_id }, 'change');
      if (agentRead.outcome !== 'found') return undefined;
      const keyRead = await agentKeyOf(tx, states, { orgId, id: keyId }, 'change');
      if (keyRead.outcome !== 'found' || keyRead.key.agentId !== agentRead.agent.id) return undefined;
      const connectionRead = await connectionOf(tx, states, { orgId, id: keyId });
      if (connectionRead.outcome !== 'found') return undefined;
      if (clientId !== undefined && connectionRead.connection.clientId !== clientId) return undefined;
      if (keyRead.key.status !== 'ACTIVE') return undefined;
      await revokeKey(
        tx,
        states,
        { orgId, keyId, actor, details: { reason } },
        "a connection's live key didn't revoke",
      );
      return {
        orgId,
        agentId: agentRead.agent.id,
        keyId,
        scopes: [],
        expiresAt: keyRead.key.expiresAt,
        credential: 'connection',
      };
    });

  /** A code sent a second time: the connection it made is revoked, and the line says so. */
  const codeReused = async (used: FlowRead, caller: Caller): Promise<void> => {
    if (used.orgId === null || used.keyId === null) return;
    const revoked = await revokeConnection(used.orgId, used.keyId, caller.correlationId, {
      actor: OAUTH_SERVER,
      reason: 'code_reused',
    });
    logger
      .child({ correlationId: caller.correlationId, orgId: used.orgId })
      .warn('oauth.code_reused', { keyId: used.keyId, clientId: used.clientId, revoked: revoked !== undefined });
  };

  /** A grant refused, the reason logged with what was named (all public), never what was sent. */
  const refusedFor = (caller: Caller, reason: string, named: Readonly<Record<string, string | null>>): GrantAnswer => {
    logger.child({ correlationId: caller.correlationId }).info('oauth.grant_refused', { reason, ...named });
    securityEvents.note({ kind: 'oauth_refused', reason: 'invalid_grant', ip: caller.ip });
    return INVALID_GRANT;
  };

  /** The door's check of a token the client sent, and its organisation: proven, or why not. */
  const proven = async (presented: PresentedToken) => {
    const orgId = await listedAgentKey(database, presented.keyId);
    const door = await tokenAtTheDoor(database, keys, orgId, presented);
    return { orgId, door };
  };

  /**
   * The grant's work, a database limit or a lost deadlock answered busy, never a failure (as the access check's key
   * check does, 4D2e C3): nothing it began is kept, and the client sends it again.
   */
  const orBusy = async <T>(caller: Caller, work: () => Promise<T>): Promise<T | Busy> => {
    const started = performance.now();
    try {
      return await work();
    } catch (error) {
      if (!isStatementLimit(error) && !isRetryable(error) && !(error instanceof OrganisationBusy)) throw error;
      logger
        .child({ correlationId: caller.correlationId })
        .warn('oauth.grant_in_trouble', { waitedMs: Math.round(performance.now() - started) });
      return BUSY;
    }
  };

  /** A code used up without a pair issued: its connection's key goes at once, as it can never work (lead, 6E3a). */
  const codeSpent = async (flow: FlowRead, caller: Caller, reason: string): Promise<GrantAnswer> => {
    if (flow.orgId !== null && flow.keyId !== null) {
      await revokeConnection(flow.orgId, flow.keyId, caller.correlationId, {
        actor: OAUTH_SERVER,
        reason: 'code_spent',
      });
    }
    return refusedFor(caller, reason, { clientId: flow.clientId, flowId: flow.id, keyId: flow.keyId });
  };

  const grants = {
    async exchangeCode(asked: CodeExchange, caller: Caller): Promise<GrantAnswer> {
      if (!isCodeText(asked.code)) return refusedFor(caller, 'malformed', { clientId: asked.clientId });
      const codeHash = hashOf(asked.code);
      const now = clock.now();
      // Where its organisation is alone: the code is taken, and used, inside that organisation's transaction below.
      const known = await flowOfCode(database, codeHash);
      if (known === undefined || known.orgId === null || known.keyId === null) {
        return refusedFor(caller, 'code_unknown', { clientId: asked.clientId });
      }
      const { orgId, keyId } = known;
      // One transaction from the code's use to its tokens (lead's re-review): a busy rolls the use back too, so the
      // client's retry of the same code succeeds instead of reading as a stolen code.
      const answer = await inOrganisation(orgId, caller.correlationId, async (tx, states) => {
        const flow = await codeHeld(tx, codeHash);
        if (flow === undefined) return { outcome: 'unknown' as const };
        if (flow.usedAt !== null) return { outcome: 'reused' as const, flow };
        // Used once this commits, whatever comes next: a code is tried once.
        await codeUsed(tx, flow.id, now);
        const refusal = codeRefusal(flow, asked, capabilities.resource, now);
        if (refusal !== undefined) return { outcome: 'spent' as const, flow, reason: refusal };
        const checked = await credentialAt(tx, states, now, orgId, keyId, {
          prove: () => undefined,
          resource: capabilities.resource,
          clientId: flow.clientId,
        });
        if (checked.outcome !== 'accepted') return { outcome: 'spent' as const, flow, reason: checked.reason };
        const tokens = await issueTokens(
          tx,
          { keys, ids },
          { orgId, keyId, scopes: checked.key.scopes, now, keyExpiresAt: checked.key.expiresAt },
        );
        await clientConnected(tx, flow.clientId, now);
        return { outcome: 'issued' as const, tokens, agent: checked.key };
      });
      if (answer.outcome === 'unknown') return refusedFor(caller, 'code_unknown', { clientId: asked.clientId });
      if (answer.outcome === 'reused') {
        await codeReused(answer.flow, caller);
        return refusedFor(caller, 'code_used', { clientId: asked.clientId, flowId: answer.flow.id });
      }
      if (answer.outcome === 'spent') return codeSpent(answer.flow, caller, answer.reason);
      return answer;
    },

    async refresh(asked: RefreshAsked, caller: Caller): Promise<GrantAnswer> {
      const presented = parseConnectionToken(asked.refreshToken, 'refresh');
      if (presented === undefined) return refusedFor(caller, 'malformed', { clientId: asked.clientId });
      const named = { keyId: presented.keyId, tokenId: presented.tokenId };
      // Optional (RFC 8707): some clients send none; a connection is only ever for our MCP endpoint anyway.
      if (asked.resource !== undefined && asked.resource !== capabilities.resource) {
        return { outcome: 'refused', status: 400, error: 'invalid_target', description: 'The resource is not ours.' };
      }
      const { orgId, door } = await proven(presented);
      if (orgId === undefined || door.outcome !== 'proven') {
        if (door.outcome === 'key_not_held') {
          logger.child({ correlationId: caller.correlationId }).error('connection_token.refused', {
            reason: door.outcome,
            ...named,
          });
        }
        return refusedFor(caller, orgId === undefined ? 'unlisted' : door.outcome, named);
      }
      const now = clock.now();
      if (door.row.expiresAt.getTime() <= now.getTime()) return refusedFor(caller, 'expired', named);
      const scopes = scopesNarrowed(asked.scope, scopesOf(door.row.scopes));
      if (scopes === undefined) {
        return {
          outcome: 'refused',
          status: 400,
          error: 'invalid_scope',
          description: 'A refresh may only keep or narrow the scopes it was given.',
        };
      }
      const answer = await inOrganisation(orgId, caller.correlationId, async (tx, states) => {
        const checked = await credentialAt(tx, states, now, orgId, presented.keyId, {
          prove: () => undefined,
          resource: capabilities.resource,
          clientId: asked.clientId,
        });
        if (checked.outcome !== 'accepted') return checked;
        // Locked after its connection (3c), and used in one statement where it was not: two at once can't both rotate.
        const row = await tokenRowLocked(tx, orgId, presented.tokenId);
        if (row === undefined) return { outcome: 'refused' as const, reason: 'missing' as const };
        if (!(await usedNow(tx, orgId, presented.tokenId, now))) return { outcome: 'reused' as const };
        const tokens = await issueTokens(
          tx,
          { keys, ids },
          {
            orgId,
            keyId: presented.keyId,
            scopes: checked.key.scopes.filter((scope) => scopes.includes(scope)),
            now,
            keyExpiresAt: checked.key.expiresAt,
            parentId: presented.tokenId,
          },
        );
        return { outcome: 'issued' as const, tokens, agent: checked.key };
      });
      if (answer.outcome === 'issued') return answer;
      if (answer.outcome === 'refused') return refusedFor(caller, answer.reason, named);
      // SEC-OAUTH-05: used twice, so someone else holds it. The connection goes; its organisation's admins see it.
      const revoked = await revokeConnection(orgId, presented.keyId, caller.correlationId, {
        actor: OAUTH_SERVER,
        reason: 'refresh_reused',
      });
      logger
        .child({ correlationId: caller.correlationId, orgId })
        .warn('oauth.refresh_reused', { ...named, revoked: revoked !== undefined });
      securityEvents.note({
        kind: 'connection_token_reused',
        reason: 'refresh_reused',
        ip: caller.ip,
        orgId,
        ...(revoked === undefined ? {} : { agentId: revoked.agentId }),
      });
      return INVALID_GRANT;
    },

    async revoke(
      asked: { readonly token: string; readonly clientId: string | undefined },
      caller: Caller,
    ): Promise<void> {
      const presented =
        parseConnectionToken(asked.token, 'access') ?? parseConnectionToken(asked.token, 'refresh') ?? undefined;
      if (presented === undefined) return;
      const { orgId, door } = await proven(presented);
      if (orgId === undefined || door.outcome !== 'proven') return;
      const revoked = await revokeConnection(orgId, presented.keyId, caller.correlationId, {
        actor: OAUTH_SERVER,
        reason: 'revoked_by_client',
        ...(asked.clientId === undefined ? {} : { clientId: asked.clientId }),
      });
      logger
        .child({ correlationId: caller.correlationId, orgId })
        .info('oauth.connection_revoked', { keyId: presented.keyId, revoked: revoked !== undefined });
    },
  };

  return {
    exchangeCode: (asked, caller) => orBusy(caller, () => grants.exchangeCode(asked, caller)),
    refresh: (asked, caller) => orBusy(caller, () => grants.refresh(asked, caller)),
    revoke: (asked, caller) =>
      orBusy(caller, async () => {
        await grants.revoke(asked, caller);
        return { outcome: 'taken' as const };
      }),
  };
}
