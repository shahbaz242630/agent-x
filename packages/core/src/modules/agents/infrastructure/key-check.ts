// The key check (ADR-011 §1, ADR-005 §6; SEC-AG-01; Phase 1 C1-4a): whether
// a key an agent sends, `axk_<keyId>_<secret>`, may act, and as which agent
// with which scopes. C2 puts it in front of every agent request.
//
// 1. The text taken apart (parseAgentKey): anything not exactly as a key is
//    written is refused before any lookup.
// 2. The key's ID looked up in the directory, for its organisation alone:
//    where to look, never what is found there.
// 3. Inside that organisation's withSignedStates, each statement limited to
//    10 seconds: the key's row read for its agent's ID alone (where to look);
//    the agent read and verified (`share`, level 3); then the key read and
//    verified (`share`, 3a), so the lock order is the one a rotation takes.
//    The key's agent is sealed, so a row pointed at another agent is caught
//    as tampering by the key's own read.
// 4. The secret: HMAC-SHA-256 with the agent-key pepper's version the key was
//    made with, over ('agent-key', keyId, secret), compared with the sealed
//    MAC in constant time (the KeyProvider's verifyMac: two 32-byte MACs,
//    timingSafeEqual). Checked before anything else about the key, so a
//    caller without the secret is refused as one, whatever state the key is in.
// 5. The agent ACTIVE; the key ACTIVE and not yet expired (a key rotated out
//    is one whose expiry has come).
//
// Every refusal is the same answer, `refused`: a caller learns nothing of
// whether the key exists, whose it is, or why. The reason goes to the log
// alone, with the key's ID, which is public (ADR-011 §1), never its secret.
// A key or agent tampered with is refused too, and its organisation held, as
// every signed state's read does (with-signed-states.ts).
//
// What an accepted key may do is what both its own scopes and its agent's
// hold, so narrowing an agent narrows its keys at once (domain/agent.ts).
// The check's transaction ends before the request's own work: a request that
// decides on the agent (Phase 3's Tx A) reads it again (SEC-AG-12), and one
// that runs in the same transaction uses agentKeyAt with its own.
import { limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedAgentKey } from '../../directory/index.ts';
import { keySecretMessage, parseAgentKey, type PresentedKey, type Scope } from '../domain/agent.ts';
import { AGENT_KEYS, agentKeyOf } from './agent-keys.ts';
import { agentOf, type AgentsTransaction } from './agents.ts';
import type { AgentsTables } from './tables.ts';

/** A key that may act: its organisation, agent and ID, and the scopes it may use now. */
export interface AcceptedKey {
  readonly orgId: string;
  readonly agentId: string;
  readonly keyId: string;
  /** Those both the key's and its agent's scopes hold, in SCOPES' order. */
  readonly scopes: readonly Scope[];
}

/** Why a key was refused: for the log alone, never an answer. */
export type KeyRefusal =
  'malformed' | 'unlisted' | 'missing' | 'tampered' | 'wrong_secret' | 'agent_suspended' | 'revoked' | 'expired';

/** The key checked in a transaction: accepted, or refused with its reason (logged, never answered). */
export type KeyAtCheck =
  | { readonly outcome: 'accepted'; readonly key: AcceptedKey }
  | { readonly outcome: 'refused'; readonly reason: KeyRefusal };

/** What the check answers a caller: the same `refused` for every reason. */
export type KeyChecked = { readonly outcome: 'accepted'; readonly key: AcceptedKey } | { readonly outcome: 'refused' };

const refused = (reason: KeyRefusal): KeyAtCheck => ({ outcome: 'refused', reason });

/**
 * Checks the key in the caller's transaction, which must be withSignedStates'
 * for the organisation the directory lists the key in, with nothing of the
 * agents module locked yet: steps 3 to 5 above.
 */
export async function agentKeyAt(
  tx: AgentsTransaction,
  states: SignedStates,
  { keys, now }: { readonly keys: KeyProvider; readonly now: Date },
  orgId: string,
  presented: PresentedKey,
): Promise<KeyAtCheck> {
  const { keyId, secret } = presented;
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone: the agent is read and verified next, then the key, whose agent is sealed
    .selectFrom(AGENT_KEYS.table)
    .select('agent_id')
    .where('org_id', '=', orgId)
    .where('id', '=', keyId)
    .executeTakeFirst();
  if (row === undefined) return refused('missing');
  const agentRead = await agentOf(tx, states, { orgId, id: row.agent_id }, 'share');
  if (agentRead.outcome !== 'found') return refused(agentRead.outcome);
  const keyRead = await agentKeyOf(tx, states, { orgId, id: keyId }, 'share');
  if (keyRead.outcome !== 'found') return refused(keyRead.outcome);
  const { agent } = agentRead;
  const { key } = keyRead;
  if (!keys.verifyMac('agent-key-pepper', key.secretKeyVersion, keySecretMessage(keyId, secret), key.secretMac)) {
    return refused('wrong_secret');
  }
  if (agent.status !== 'ACTIVE') return refused('agent_suspended');
  if (key.status !== 'ACTIVE') return refused('revoked');
  if (key.expiresAt.getTime() <= now.getTime()) return refused('expired');
  return {
    outcome: 'accepted',
    key: {
      orgId,
      agentId: agent.id,
      keyId: key.id,
      scopes: key.scopes.filter((scope) => agent.scopes.includes(scope)),
    },
  };
}

export interface AgentKeyCheck {
  /** Whether the key text an agent sent may act: the same `refused` for every reason, logged with it. */
  check(text: string, correlationId: string): Promise<KeyChecked>;
}

type Tables = AgentsTables & DirectoryTables & AuditTables;

export function createAgentKeyCheck({
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
}): AgentKeyCheck {
  return {
    async check(text, correlationId) {
      const log = logger.child({ correlationId });
      const answer = (checked: KeyAtCheck, keyId: string | null): KeyChecked => {
        if (checked.outcome === 'accepted') return checked;
        log.info('agent_key.refused', { reason: checked.reason, keyId });
        return { outcome: 'refused' };
      };
      const presented = parseAgentKey(text);
      if (presented === undefined) return answer(refused('malformed'), null);
      const orgId = await listedAgentKey(database, presented.keyId);
      if (orgId === undefined) return answer(refused('unlisted'), presented.keyId);
      const checked = await withSignedStates(database, orgId, { keys, ids, logger: log }, async (tx, states) => {
        await limitStatements(tx);
        return agentKeyAt(tx, states, { keys, now: clock.now() }, orgId, presented);
      });
      return answer(checked, presented.keyId);
    },
  };
}
