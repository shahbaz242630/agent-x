// A person's consent to connect an MCP client as one of their organisation's
// agents (6E3a, ADR-016; MCP-Guide M5; SEC-OAUTH-10). Composed in the API as
// a key's rotation is (agent-key-changes.ts): the step-up is the identity
// module's, the agent, its key and its connection the agents module's, the
// flow the oauth module's.
//
// - `request`: what the browser that opened the flow is asked: the client, by
//   what it says it is, where it sends the person back, what it asks for. Only
//   that browser (the flow's cookie) sees it, while it is open: else 404.
// - `consent` (`connections.make`), then its confirm: an admin or developer
//   (a developer, only for an agent they own, as for a rotation: the
//   connection is a working credential for the agent) picks the agent and
//   ticks scopes, which must be among those the client asked for and the agent
//   holds. Each with step-up, a passkey for an admin (SEC-HA-12). The ask: the
//   key claimed first; the flow open and this browser's; the member read
//   again; the agent, ACTIVE; the scopes; room for one more connection (10
//   live an agent, 100 in all, 20 made an organisation a day); a challenge
//   bound to the organisation, the flow, the agent, the scopes, the client,
//   its redirect address, the resource and the PKCE challenge, so it makes
//   exactly that connection. The confirm: the organisation's lock for issuing
//   keys; the same reads and checks; the challenge consumed; the flow decided,
//   once, its decision sealed with a key the database never holds (S205,
//   oauth/flow-seals.ts), so the token endpoint believes no flow planted or
//   changed in the database; then a key for the agent, its secret random and thrown away (no `axk_`
//   text can work for it), and its connection; the code, shown this once in
//   the address the browser goes back to, its hash kept on the flow for 60 s.
// - `deny`: the flow decided denied, and the browser sent back with
//   `access_denied`.
// - A device's flow (6E3c, RFC 8628), once the person's browser claimed it by
//   its user code (oauth-device.ts), is asked and decided here the same way,
//   by the person who claimed it alone (AG8: a shared browser is not enough):
//   only no address to send the browser back to (the device polls for its
//   tokens), and its connection made `via: device`, with no redirect address.
//
// Lock order (ADR-006 §6): the idempotency key, the agent's brake, the issue
// lock (the confirm), the flow (decided by one UPDATE, before any event), the
// member's membership (2a), the agent (3), the step-up challenge, the chain
// head last.
import { randomBytes } from 'node:crypto';

import {
  addAgentKey,
  addConnection,
  agentKeyOf,
  agentOf,
  type AgentRecord,
  connectionOf,
  connectionsCounted,
  connectionsMadeSince,
  KEY_SECRET_BYTES,
  keyExpiresAt,
  keySecretMessage,
  MOST_CONNECTIONS_MADE_A_DAY,
  MOST_KEYS_LISTED,
  MOST_LIVE_CONNECTIONS,
  oneKeyIssueAtATime,
  type Scope,
  SCOPES,
  scopesText,
} from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import {
  type AnyFlowRead,
  codeEndsFrom,
  decisionSealed,
  flowById,
  flowDecided,
  hashOf,
  pendingFlowSound,
  isFlowCookie,
  isLoopback,
  newCode,
  type OauthTables,
} from '@agentx/core/modules/oauth';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import {
  AGENT_BRAKE,
  type Database,
  type DatabaseTransaction,
  holdBrake,
  type IdempotentRequest,
  isUnwritten,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { KEY_CHANGING_ROLES } from './agent-key-changes.ts';
import { type AgentMember, AgentRefused, type AgentTables } from './agent-writes.ts';
import type { OauthClients } from './oauth-clients.ts';
import { backToClient } from './oauth-wire.ts';
import type { Refused, StepUpAsked } from './refused.ts';
import { createStepUps, createUseCaseWork } from './use-case-work.ts';

/** Asking to make a connection: its operation, which the step-up challenge names as its action too. */
export const CONSENT_OPERATION = 'connections.make';
/** Making it, once stepped up. */
export const CONSENT_CONFIRM_OPERATION = 'connections.make.confirm';
/** Saying no to the client. */
export const DENY_OPERATION = 'connections.deny';

/** Who may connect a client as an agent: anyone who may give an agent a key. */
export const CONNECTING_ROLES = KEY_CHANGING_ROLES;

type ConsentTables = AgentTables & OauthTables;
type Tx = DatabaseTransaction<ConsentTables>;

/** The flow a request is about, and the cookie of the browser asking. */
export interface FlowNamed {
  readonly flowId: string;
  readonly cookie: string | undefined;
}

/** What the person allows: the agent the connection acts as, and the scopes ticked. */
export interface ConsentAsked {
  readonly agentId: string;
  readonly scopes: readonly Scope[];
}

/** What the browser that opened a flow is shown. */
export interface RequestShown {
  readonly id: string;
  /** A browser's sign-in, or a device's (6E3c), which sends no one back. */
  readonly via: 'code' | 'device';
  readonly client: {
    readonly id: string;
    readonly name: string;
    /** The host whose metadata document named the client (CIMD); null for a client that registered itself. */
    readonly verifiedBy: string | null;
  };
  /** None for a device's. */
  readonly redirectUri: string | null;
  /** The host the person is sent back to, shown in bold: what a phishing client's name can't hide. None for a device's. */
  readonly redirectHost: string | null;
  /** Sent back to an app on the person's own computer. */
  readonly loopback: boolean;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly endsAt: Date;
}

/** A connection just made, as its confirm answers it. */
interface ConnectionMade {
  readonly via: 'code' | 'device';
  readonly keyId: string;
  readonly agentId: string;
  readonly clientId: string;
  readonly scopes: readonly Scope[];
  readonly expiresAt: Date;
}

export type ConsentWrite =
  | StepUpAsked
  | {
      readonly outcome: 'connected';
      /** Where the browser goes, with the code, this once; null on a retry of the same write. */
      readonly redirectTo: string | null;
      readonly connection: ConnectionMade;
    }
  /** Where the browser goes, told no; none for a device's, which learns it by polling. */
  | { readonly outcome: 'denied'; readonly redirectTo: string | null }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface ConnectionConsents {
  /**
   * The flow, as its own browser is shown it, to `userId` (a device's, only to the person who claimed it); undefined
   * for any other, or one decided or ended.
   */
  request(named: FlowNamed, userId: string): Promise<RequestShown | undefined>;
  consent(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: FlowNamed,
    asked: ConsentAsked,
    correlationId: string,
  ): Promise<ConsentWrite>;
  confirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: FlowNamed,
    asked: ConsentAsked,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<ConsentWrite>;
  deny(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: FlowNamed,
    correlationId: string,
  ): Promise<ConsentWrite>;
}

/**
 * The pending connection's SHA-256: the organisation, the flow, the agent, the scopes as kept, the client, its
 * redirect address and the resource, so the step-up makes exactly that connection and no other.
 */
const consentHash = (orgId: string, flow: AnyFlowRead, asked: ConsentAsked): Buffer =>
  changeHashOf([
    orgId.toLowerCase(),
    flow.id.toLowerCase(),
    asked.agentId.toLowerCase(),
    scopesText(asked.scopes),
    flow.clientId,
    // A device's has none: its kind, where the address would be, so neither can stand for the other.
    flow.kind === 'code' ? flow.redirectUri : 'device',
    flow.resource,
    // S205: its PKCE challenge, or a device's device code hash, too: never shown, so one changed between the ask and
    // the confirm is never decided.
    flow.kind === 'code' ? flow.codeChallenge : flow.deviceHash,
  ]);

/**
 * Whether the browser asking is the one that opened the flow (or claimed a device's), by its cookie's hash, as kept;
 * and, for a device's, whether the person asking is the one who claimed it (AG8): on a shared browser, another
 * person's flow is never theirs to read or decide.
 */
const fromItsBrowser = (flow: AnyFlowRead, cookie: string | undefined, userId: string): boolean =>
  cookie !== undefined &&
  flow.browserHash !== null &&
  isFlowCookie(cookie) &&
  hashOf(cookie) === flow.browserHash &&
  (flow.kind === 'code' || flow.personHash === hashOf(userId));

/** What a client no longer known is called: its redirect address's host, or its ID, at most 100 characters. */
const unnamed = (flow: AnyFlowRead): string =>
  (flow.kind === 'code' ? new URL(flow.redirectUri).host : flow.clientId).slice(0, 100);

/** A signed state's read as found, or the refusal it is: INTEGRITY_FAILED tampered with, NOT_FOUND missing. */
function foundIn<Read extends { readonly outcome: string }>(read: Read): Extract<Read, { readonly outcome: 'found' }> {
  if (read.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome !== 'found') throw new AgentRefused(404, 'NOT_FOUND');
  return read as Extract<Read, { readonly outcome: 'found' }>;
}

/** Whether the flow can still be decided at `now`. */
const isOpen = (flow: AnyFlowRead, now: Date): boolean =>
  flow.decided === null && flow.endsAt.getTime() > now.getTime();

export function createConnectionConsents({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
  issuer,
  clients,
}: {
  readonly database: Database<ConsentTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
  /** The authorization server's issuer, named on every answer to the client (RFC 9207, SEC-OAUTH-12). */
  readonly issuer: string;
  /** The clients known, registered or named by a metadata document (6E3c). */
  readonly clients: OauthClients;
}): ConnectionConsents {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: AgentRefused });
  const stepUps = createStepUps({ challenges, Refusal: AgentRefused });

  /**
   * The flow named, open and this browser's (a device's, this person's too): NOT_FOUND for any other, which says
   * nothing of whether it exists.
   */
  /** Open, this browser's and person's, and as its client opened it (S205: sealed); none else is shown or decided. */
  const shown = (flow: AnyFlowRead | undefined, cookie: string | undefined, userId: string, now: Date) =>
    flow !== undefined &&
    isOpen(flow, now) &&
    fromItsBrowser(flow, cookie, userId) &&
    pendingFlowSound(keys, logger, flow);

  const openFlow = async (tx: Tx, { flowId, cookie }: FlowNamed, userId: string, now: Date): Promise<AnyFlowRead> => {
    const flow = await flowById(tx, flowId);
    if (flow === undefined || !shown(flow, cookie, userId, now)) throw new AgentRefused(404, 'NOT_FOUND');
    return flow;
  };

  /**
   * The agent the connection would act as, read (`share`): there, ACTIVE, the member's own unless they are an admin,
   * and the scopes among those the client asked for and the agent holds.
   */
  const connectable = async (
    tx: Tx,
    states: SignedStates,
    { orgId, role, membershipId }: { readonly orgId: string; readonly role: string; readonly membershipId: string },
    flow: AnyFlowRead,
    asked: ConsentAsked,
  ): Promise<AgentRecord> => {
    const read = foundIn(await agentOf(tx, states, { orgId, id: asked.agentId }, 'share'));
    // SEC-OAUTH-10: a connection is a working credential for the agent, so another member's isn't a developer's to make.
    if (role !== 'admin' && read.agent.owner !== membershipId) throw new AgentRefused(403, 'FORBIDDEN');
    if (read.agent.status !== 'ACTIVE') throw new AgentRefused(409, 'CONNECTION_AGENT_NOT_ACTIVE');
    // SEC-OAUTH-08: never a scope the client didn't ask for, nor one the agent doesn't hold.
    const allowed = (scope: Scope) => read.agent.scopes.includes(scope) && flow.scopesAsked.includes(scope);
    const once = new Set(asked.scopes).size === asked.scopes.length;
    if (asked.scopes.length === 0 || !once || !asked.scopes.every(allowed)) {
      throw new AgentRefused(409, 'CONNECTION_SCOPES_REFUSED');
    }
    return read.agent;
  };

  /** Room for one more connection: the agent's live ones and all of them, and the organisation's day. */
  const room = async (tx: Tx, orgId: string, agentId: string, now: Date): Promise<void> => {
    const counted = await connectionsCounted(tx, orgId, agentId, now);
    // A list reads at most this many keys of one kind: a hand-over must be able to read every connection's.
    if (counted.all >= MOST_KEYS_LISTED) throw new AgentRefused(409, 'CONNECTIONS_TOO_MANY');
    if (counted.live >= MOST_LIVE_CONNECTIONS) throw new AgentRefused(409, 'CONNECTIONS_FULL');
    const made = await connectionsMadeSince(tx, orgId, new Date(now.getTime() - DAY_MS));
    if (made >= MOST_CONNECTIONS_MADE_A_DAY) throw new AgentRefused(409, 'CONNECTIONS_SPENT');
  };

  /** The agent's brake, before any row: a key issued for it waits behind a kill switch, as a rotation does. */
  const brakeOf = (member: AgentMember, asked: ConsentAsked) => (tx: Tx) =>
    holdBrake(tx, AGENT_BRAKE, member.orgId, asked.agentId);

  /** The reads both the ask and the confirm make, in the lock order. */
  const consentReads = async (
    tx: Tx,
    states: SignedStates,
    member: AgentMember,
    named: FlowNamed,
    asked: ConsentAsked,
  ) => {
    const now = clock.now();
    const flow = await openFlow(tx, named, member.userId, now);
    const membership = await work.memberIn(tx, states, member, CONNECTING_ROLES);
    const agent = await connectable(
      tx,
      states,
      { orgId: member.orgId, role: membership.role, membershipId: membership.id },
      flow,
      asked,
    );
    await room(tx, member.orgId, agent.id, now);
    return { now, flow, membership, agent };
  };

  /** The connection as its key and row now stand, answering a retry of the confirm. */
  const connectionNow = (orgId: string, keyId: string, correlationId: string) =>
    work.answered(orgId, correlationId, async (tx, states): Promise<ConnectionMade> => {
      const { key } = foundIn(await agentKeyOf(tx, states, { orgId, id: keyId }, 'share'));
      const connectionRead = foundIn(await connectionOf(tx, states, { orgId, id: keyId }));
      return {
        // Only a device's has no redirect address (0093's a_code_has_its_redirect).
        via: connectionRead.connection.redirectUri === null ? ('device' as const) : ('code' as const),
        keyId: key.id,
        agentId: key.agentId,
        clientId: connectionRead.connection.clientId,
        scopes: key.scopes,
        expiresAt: key.expiresAt,
      };
    });

  return {
    async request(named, userId) {
      const flow = await flowById(database, named.flowId);
      if (flow === undefined || !shown(flow, named.cookie, userId, clock.now())) return undefined;
      const client = await clients.find(flow.clientId);
      const redirectUri = flow.kind === 'code' ? flow.redirectUri : null;
      return {
        id: flow.id,
        via: flow.kind,
        client: {
          id: flow.clientId,
          name: client?.name ?? unnamed(flow),
          // Only a browser's flow is bound to the document's own addresses: a device's could be anyone's, under any
          // client's name, so it is never shown as verified (6E3c review).
          verifiedBy: flow.kind === 'code' ? (client?.verifiedBy ?? null) : null,
        },
        redirectUri,
        redirectHost: redirectUri === null ? null : new URL(redirectUri).host,
        loopback: redirectUri !== null && isLoopback(redirectUri),
        scopesAsked: SCOPES.filter((scope) => flow.scopesAsked.includes(scope)),
        resource: flow.resource,
        endsAt: flow.endsAt,
      };
    },

    async consent(member, idempotent, named, asked, correlationId) {
      const done = await work.brakeWrite(
        member,
        idempotent,
        correlationId,
        brakeOf(member, asked),
        async (tx, states) => {
          const { flow } = await consentReads(tx, states, member, named, asked);
          return stepUps.ask(tx, member, {
            action: CONSENT_OPERATION,
            changeHash: consentHash(member.orgId, flow, asked),
          });
        },
      );
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, named, asked, stepUpChallengeId, correlationId) {
      let made: { readonly redirectTo: string | null; readonly connection: ConnectionMade } | undefined;
      const done = await work.brakeWrite(
        member,
        idempotent,
        correlationId,
        brakeOf(member, asked),
        async (tx, states) => {
          await oneKeyIssueAtATime(tx, member.orgId);
          const held = await challenges.hold(tx, member.sessionId);
          const { now, flow, membership, agent } = await consentReads(tx, states, member, named, asked);
          const consumed = await stepUps.consumed(
            tx,
            member,
            held,
            stepUpChallengeId,
            { action: CONSENT_OPERATION, changeHash: consentHash(member.orgId, flow, asked) },
            { passkeyRequired: membership.role === 'admin' },
          );
          // As kept when the person was shown it: never fetched inside the transaction.
          const client = await clients.kept(tx, flow.clientId);
          const keyId = ids.next();
          // A device's flow has no code: its device code, polling, takes the tokens (oauth-grants.ts).
          const code = flow.kind === 'code' ? newCode() : null;
          const codeHash = code === null ? null : hashOf(code);
          // Sealed over the flow as read here, the one the step-up was bound to (S205): a row changed by anyone
          // without the app's keys, before or after, is never exchanged (oauth-grants.ts).
          const seal = decisionSealed(keys, flow, {
            orgId: member.orgId,
            keyId,
            codeHash,
            decidedAt: now,
            codeEndsAt: codeEndsFrom(now, codeHash),
          });
          // Decided first, by one UPDATE of an undecided flow in time: a second confirm of it finds none, and rolls back.
          const decided = await flowDecided(
            tx,
            flow.id,
            { outcome: 'allowed', orgId: member.orgId, keyId, codeHash, seal },
            now,
          );
          if (!decided) throw new AgentRefused(404, 'NOT_FOUND');
          const actor = { type: 'user' as const, id: member.userId };
          const details = stepUpDetails(consumed);
          // The key's secret is random and never kept, nor shown: no `axk_` text can ever work for a connection's key.
          const { mac, keyVersion } = keys.mac(
            'agent-key-pepper',
            keySecretMessage(keyId, randomBytes(KEY_SECRET_BYTES)),
          );
          const expiresAt = keyExpiresAt(now);
          await addAgentKey(tx, states, {
            orgId: member.orgId,
            id: keyId,
            agentId: agent.id,
            scopes: asked.scopes,
            secretMac: mac,
            secretKeyVersion: keyVersion,
            expiresAt,
            createdAt: now,
            actor,
            details: { ...details, connection: flow.clientId },
          });
          await addConnection(tx, states, {
            orgId: member.orgId,
            keyId,
            agentId: agent.id,
            clientId: flow.clientId,
            clientName: client?.name ?? unnamed(flow),
            resource: flow.resource,
            redirectUri: flow.kind === 'code' ? flow.redirectUri : null,
            via: flow.kind,
            madeBy: membership.id,
            createdAt: now,
            actor,
            details,
          });
          made = {
            // RFC 9207 (SEC-OAUTH-12): the issuer named, so a client talking to two servers can't be mixed up.
            redirectTo:
              flow.kind === 'code' && code !== null
                ? backToClient(flow.redirectUri, { code, state: flow.state, iss: issuer })
                : null,
            connection: {
              via: flow.kind,
              keyId,
              agentId: agent.id,
              clientId: flow.clientId,
              scopes: SCOPES.filter((scope) => asked.scopes.includes(scope)),
              expiresAt,
            },
          };
          return { status: 201, resourceId: keyId };
        },
      );
      if (isUnwritten(done)) return done;
      // The code is set only by a write done now: a retry answers no address, as the code was shown once.
      if (made !== undefined) return { outcome: 'connected', ...made };
      const connection = await connectionNow(member.orgId, done.result.resourceId, correlationId);
      if ('outcome' in connection) return connection;
      return { outcome: 'connected', redirectTo: null, connection };
    },

    async deny(member, idempotent, named, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const now = clock.now();
        await work.memberIn(tx, states, member, CONNECTING_ROLES);
        const flow = await openFlow(tx, named, member.userId, now);
        if (!(await flowDecided(tx, flow.id, { outcome: 'denied' }, now))) throw new AgentRefused(404, 'NOT_FOUND');
        return { status: 200, resourceId: flow.id };
      });
      if (isUnwritten(done)) return done;
      const flow = await flowById(database, done.result.resourceId);
      if (flow === undefined) return { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
      return {
        outcome: 'denied',
        redirectTo:
          flow.kind === 'code'
            ? backToClient(flow.redirectUri, { error: 'access_denied', state: flow.state, iss: issuer })
            : null,
      };
    },
  };
}
