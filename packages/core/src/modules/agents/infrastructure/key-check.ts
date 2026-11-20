// The key check (ADR-011 §1, ADR-005 §6; SEC-AG-01; Phase 1 C1-4a): whether
// a key an agent sends, `axk_<keyId>_<secret>`, may act, and as which agent
// with which scopes. C2 puts it in front of every agent request.
//
// 1. The text taken apart (parseAgentKey): anything not exactly as a key is
//    written is refused before any lookup.
// 2. The key's ID looked up in the directory, for its organisation alone:
//    where to look, never what is found there.
// 2a. At the door (AG1, PL-67): the key's secret checked against its row as
//    read, unlocked, outside the organisation's share of the connections, on
//    one trip of its own (readAloneOnOneTrip, its lock waits bounded at 5 s).
//    A caller holding only a key's ID is refused here, never taking a place in
//    that share, a lock or a brake's wait, so it can't slow the organisation's
//    agents. An ID not listed is read for under no organisation and compared
//    with a MAC of zeros: the same trip, the same one verifyMac. What differs
//    is only the database finding a row or none, within the trip's own noise.
//    Only the steps below are
//    believed: the row read here grants nothing. The row is judged against its
//    newest signed event's pointer, version and seal first (one local HMAC,
//    and one over zeros for an ID not listed); a row that disagrees is never
//    refused here but goes on to step 3, which raises the alarm and the hold.
// 3. Inside that organisation's withSignedStates, each statement limited to
//    10 seconds, ahead of all else on one trip, its agent's brake (4D2e C3): a
//    kill switch waiting goes first, however many checks a stolen key sends, and
//    a wait behind it past 5 s is told busy, as a decision's is, not a 500;
//    then one statement (4D2e C4): the key's row read unlocked for its
//    agent's ID alone (where to look); the agent locked (`share`, level 3); then
//    the key locked (`share`, 3a), so the lock order is the one a rotation
//    takes. Each row is believed only if it agrees with its log and the row
//    locked is the version the statement's snapshot saw; a row that isn't, and
//    any row after it, is read again alone, which alone raises an alarm: so a
//    revocation or suspension committed during the wait is seen, and there is
//    no cache for one to wait behind. The key's agent is sealed, so a row
//    pointed at another agent is caught as tampering by the key's own read,
//    and the agent locked must be the one sealed: a row pointed away and back
//    during the wait reads sound by then, and alarms here (`moved_back`).
// 4. The secret: HMAC-SHA-256 with the agent-key pepper's version the key was
//    made with (a version this process no longer holds is a refusal, logged
//    as an error), over ('agent-key', keyId, secret), compared with the sealed
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
import {
  AGENT_BRAKE,
  asAgentTraffic,
  brakeSharedLookedUp,
  isRetryable,
  isStatementLimit,
  lockWaitBoundedAlone,
  OrganisationBusy,
  readAloneOnOneTrip,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import {
  type AuditTables,
  sealedRowJudged,
  sealedRowRead,
  type SignedStates,
  withSignedStates,
} from '../../audit/index.ts';
import { type DirectoryTables, listedAgentKey } from '../../directory/index.ts';
import { keySecretMessage, parseAgentKey, type PresentedKey, type Scope } from '../domain/agent.ts';
import { AGENT_KEYS, agentKeyOf, type AgentKeyRecord } from './agent-keys.ts';
import { connectionOf, CONNECTIONS } from './connections.ts';
import { AGENTS, agentOf, type AgentsTransaction } from './agents.ts';
import type { AgentsTables } from './tables.ts';

/** A key that may act: its organisation, agent and ID, and the scopes it may use now. */
export interface AcceptedKey {
  readonly orgId: string;
  readonly agentId: string;
  readonly keyId: string;
  /** Those both the key's and its agent's scopes hold, in SCOPES' order. */
  readonly scopes: readonly Scope[];
  /** When the key stops working, so an agent can rotate it in time. */
  readonly expiresAt: Date;
  /** Sent as an MCP connection's access token (`axa_`, 6E3a) rather than the agent's own key: never a key's. */
  readonly credential?: 'connection';
}

/** Why a key was refused: for the log alone, never an answer. */
export type KeyRefusal =
  | 'malformed'
  | 'unlisted'
  | 'missing'
  | 'tampered'
  | 'key_not_held'
  | 'wrong_secret'
  | 'agent_suspended'
  | 'revoked'
  | 'expired'
  | 'not_a_connection'
  | 'wrong_resource'
  | 'wrong_client';

/** The key checked in a transaction: accepted, or refused with its reason (logged, never answered). */
export type KeyAtCheck =
  | { readonly outcome: 'accepted'; readonly key: AcceptedKey }
  | { readonly outcome: 'refused'; readonly reason: KeyRefusal };

/** What the check answers a caller: the same `refused` for every reason. */
export type KeyChecked = { readonly outcome: 'accepted'; readonly key: AcceptedKey } | { readonly outcome: 'refused' };

const refused = (reason: KeyRefusal): KeyAtCheck => ({ outcome: 'refused', reason });

/** What a credential's own check proves of the key it names, beside steps 3 and 5. */
export interface CredentialProof {
  /**
   * Step 4 for this credential, once its key is read sound: an agent key's secret against the key's MAC; a
   * connection token's was proven at the door against its own row (connection-check.ts), so nothing more.
   */
  readonly prove: (key: AgentKeyRecord) => KeyRefusal | undefined;
  /**
   * For a connection token (6E3a): the MCP resource it may be used at. The key's connection is then gathered too
   * (lock level 3b, after the key's 3a) and must be sound, the key's own agent's, and made for exactly this resource.
   * None for an agent key, whose own secret no connection's key has (it was thrown away).
   */
  readonly resource?: string;
  /** With a resource: the OAuth client the connection must have been made for (a refresh's, a revocation's). */
  readonly clientId?: string;
}

/**
 * Steps 3 and 5 for any credential naming the key (an agent key's own text, or a connection token pointing at it),
 * with its own step 4 (`proof`), in the caller's transaction, which must be withSignedStates' for the organisation
 * the directory lists the key in, with nothing of the agents module locked yet. One gather statement whatever the
 * credential, so a connection token takes the trips a key does.
 */
export async function credentialAt(
  tx: AgentsTransaction,
  states: SignedStates,
  now: Date,
  orgId: string,
  keyId: string,
  { prove, resource, clientId }: CredentialProof,
): Promise<KeyAtCheck> {
  const agentOfKey = { table: AGENT_KEYS, id: keyId, column: 'agent_id' };
  // A row pointed elsewhere only waits on another's brake: its alarm is still the key's own read.
  const {
    found: [agentId],
  } = await states.gatherBehind(
    tx,
    orgId,
    [lockWaitBoundedAlone(), brakeSharedLookedUp(AGENT_BRAKE, orgId, agentOfKey)],
    [
      { table: AGENTS, id: { lookedUp: agentOfKey }, lock: 'share' },
      { table: AGENT_KEYS, id: { id: keyId }, lock: 'share' },
      ...(resource === undefined ? [] : [{ table: CONNECTIONS, id: { id: keyId }, lock: 'share' } as const]),
    ],
  );
  // Both answered from the gather, or each read again alone (agentOf and agentKeyOf, through verifiedState).
  const agentRead =
    typeof agentId === 'string' ? await agentOf(tx, states, { orgId, id: agentId }, 'share') : undefined;
  if (agentRead?.outcome === 'tampered') return refused('tampered');
  // The key is judged even with no agent to be found: a row pointed nowhere, or deleted, is tampering, and alarms.
  const keyRead = await agentKeyOf(tx, states, { orgId, id: keyId }, 'share');
  if (keyRead.outcome !== 'found') return refused(keyRead.outcome);
  const { key } = keyRead;
  // The agent was found through the row as the statement's snapshot held it, the key's seal judged it as it now is. A
  // key's agent is written only with its first seal and never changes, so a sound key whose agent is another, or none,
  // was pointed away and back during the wait. Nothing else will ever show it: its alarm is raised here.
  if (agentRead?.outcome !== 'found' || key.agentId !== agentRead.agent.id) {
    states.movedBack(AGENT_KEYS.subject, { orgId, id: keyId });
    return refused('tampered');
  }
  const { agent } = agentRead;
  if (resource !== undefined) {
    const unconnected = await connectionRefusal(tx, states, { orgId, id: keyId }, key.agentId, {
      resource,
      clientId,
    });
    if (unconnected !== undefined) return refused(unconnected);
  }
  const unproven = prove(key);
  if (unproven !== undefined) return refused(unproven);
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
      expiresAt: key.expiresAt,
      ...(resource === undefined ? {} : { credential: 'connection' as const }),
    },
  };
}

/** Why the key's connection refuses a token for `resource`, if it does: none, tampered with, another's, elsewhere. */
async function connectionRefusal(
  tx: AgentsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  agentId: string,
  { resource, clientId }: { readonly resource: string; readonly clientId: string | undefined },
): Promise<KeyRefusal | undefined> {
  const read = await connectionOf(tx, states, key);
  if (read.outcome === 'tampered') return 'tampered';
  if (read.outcome === 'missing') return 'not_a_connection';
  // Its agent is the key's by the row's foreign key and both seals: another is tampering the seals didn't show.
  if (read.connection.agentId !== agentId) return 'tampered';
  // SEC-OAUTH-01: a token is for the one MCP resource its connection was made for, exactly.
  if (read.connection.resource !== resource) return 'wrong_resource';
  return clientId === undefined || read.connection.clientId === clientId ? undefined : 'wrong_client';
}

/** Whether this process holds the agent-key pepper's version a key or token was made with. */
export const pepperHeld = (keys: KeyProvider, version: number): boolean =>
  keys
    .describe()
    .some(
      ({ purpose, versions }) => purpose === 'agent-key-pepper' && versions.some((held) => held.version === version),
    );

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
  return credentialAt(tx, states, now, orgId, keyId, {
    prove: (key) => {
      // A pepper version retired while a key made with it still lives (Azure.md, "Rotating a key") can't
      // check its secret: refused, and logged as the fault it is, never taken for a wrong secret.
      if (!pepperHeld(keys, key.secretKeyVersion)) return 'key_not_held';
      return keys.verifyMac('agent-key-pepper', key.secretKeyVersion, keySecretMessage(keyId, secret), key.secretMac)
        ? undefined
        : 'wrong_secret';
    },
  });
}

/** Where an ID the directory doesn't list is read for: no organisation is this one, so no row is found. */
const NO_ORGANISATION = '00000000-0000-0000-0000-000000000000';

/** What a key's secret is compared with when there is no MAC to compare it with: the same one verify either way. */
const NO_MAC = Buffer.alloc(32);

/** The door's answer: the secret proven; left to step 3 (no row, or one that disagrees with its seal); or why refused. */
type AtTheDoor = 'proven' | 'unread' | 'wrong_secret' | 'key_not_held';

/** A field of the row as read, by its column: canonical text, or null. */
const fieldOf = (fields: readonly (readonly [string, string | null])[], column: string): string | null =>
  fields.find(([name]) => name === column)?.[1] ?? null;

/**
 * Step 2a: the secret against the key's row as read, outside any share, one trip, the row judged against its newest
 * signed event first (sealedRowJudged). Exactly one seal HMAC and one verifyMac whatever is found, so a listed ID's
 * wrong secret and an unlisted ID's take the same path, on the same one trip. A row that disagrees with its seal is
 * never refused here: step 3 reads it, and raises the alarm and the hold, as before the door. A caller holding only
 * an ID can't make a row disagree, so the share stays closed to them.
 */
async function secretAtTheDoor(
  database: Kysely<Tables>,
  keys: KeyProvider,
  orgId: string | undefined,
  { keyId, secret }: PresentedKey,
): Promise<AtTheDoor> {
  const key = { orgId: orgId ?? NO_ORGANISATION, id: keyId };
  const rows = await readAloneOnOneTrip(database, sealedRowRead(AGENT_KEYS, key), {
    orgId: key.orgId,
    lockWaitBounded: true,
  });
  const { row, agrees } = sealedRowJudged(keys, AGENT_KEYS, key, rows);
  const sound = agrees && row.outcome === 'found' ? row : undefined;
  const mac = sound === undefined ? null : fieldOf(sound.fields, 'secret_mac');
  const keyVersion = Number(sound === undefined ? Number.NaN : fieldOf(sound.fields, 'secret_key_version'));
  const pepper = keys.describe().find(({ purpose }) => purpose === 'agent-key-pepper');
  const held = mac !== null && pepper?.versions.some(({ version }) => version === keyVersion) === true;
  const version = held ? keyVersion : pepper?.current;
  // No pepper at all: nothing can be verified, so nothing is (and every key with a row is one it doesn't hold).
  const matches =
    version !== undefined &&
    keys.verifyMac(
      'agent-key-pepper',
      version,
      keySecretMessage(keyId, secret),
      held ? Buffer.from(mac, 'hex') : NO_MAC,
    );
  if (sound === undefined) return 'unread';
  if (!held) return 'key_not_held';
  return matches ? 'proven' : 'wrong_secret';
}

export interface AgentKeyChecker {
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
}): AgentKeyChecker {
  return {
    async check(text, correlationId) {
      const log = logger.child({ correlationId });
      const answer = (checked: KeyAtCheck, keyId: string | null): KeyChecked => {
        if (checked.outcome === 'accepted') return checked;
        // A pepper version this process doesn't hold is ours to fix, not the caller's doing.
        if (checked.reason === 'key_not_held') log.error('agent_key.refused', { reason: checked.reason, keyId });
        else log.info('agent_key.refused', { reason: checked.reason, keyId });
        return { outcome: 'refused' };
      };
      const presented = parseAgentKey(text);
      if (presented === undefined) return answer(refused('malformed'), null);
      const orgId = await listedAgentKey(database, presented.keyId);
      const started = performance.now();
      try {
        const atTheDoor = await secretAtTheDoor(database, keys, orgId, presented);
        if (orgId === undefined) return answer(refused('unlisted'), presented.keyId);
        // A listed ID with no row behind it goes on: step 3's read judges it, missing or tampered, and alarms.
        if (atTheDoor === 'wrong_secret' || atTheDoor === 'key_not_held') {
          return answer(refused(atTheDoor), presented.keyId);
        }
        // Counted against the organisation's share: it locks the agent's and key's rows, and waiting behind a change
        // of them, every copy would hold a connection, the agents of one organisation filling the pool (PL-63).
        const checked = await asAgentTraffic(() =>
          withSignedStates(database, orgId, { keys, ids, logger: log, correlationId }, (tx, states) =>
            agentKeyAt(tx, states, { keys, now: clock.now() }, orgId, presented),
          ),
        );
        return answer(checked, presented.keyId);
      } catch (error) {
        if (!isStatementLimit(error) && !isRetryable(error)) throw error;
        // Answered busy, never a 500 (partner, 4D2e C3): the agent sends it again, and nothing of it was kept.
        const waitedMs = Math.round(performance.now() - started);
        (orgId === undefined ? log : log.child({ orgId })).warn('agent_key.check_in_trouble', {
          keyId: presented.keyId,
          waitedMs,
        });
        throw new OrganisationBusy(waitedMs);
      }
    },
  };
}
