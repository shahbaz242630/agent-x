// BR-04, PRD §7.1 ("the roles allowed for each endpoint are defined in
// OpenAPI"): every route says who may call it, in its `config.access`. The
// contract refuses a route without a valid one and writes it into the OpenAPI
// document as `x-access`, which the role matrix tests read (FX-ROLEMATRIX).
// This hook enforces it, denying by default: a route answers only a caller it
// names.
//
// A request to any route that isn't public is asked who it comes from. B2-4b:
// a signed-in person, by the live session its `__Host-` session cookie names,
// found with both timeouts applied and its last use moved on, and put on the
// request as `request.person`. With no live session the answer is 401
// UNAUTHENTICATED, with a challenge saying how to sign in (the Cookie scheme
// of draft-broyer-http-cookie-auth); a person the route doesn't name is 403
// FORBIDDEN. A route about a person's own account names `person`; an agent's
// names `agent` (C2-1, below).
//
// B4-2a: a route naming roles answers a person acting in one organisation,
// which the request names in its `AgentX-Organization` header, a UUID (400
// ORGANIZATION_INVALID without one). The header only says which: the person's
// membership there is read and verified against its signed state
// (membershipOf), and the request goes on only if it is active and its role
// is one the route names, with the organisation, the membership and the role
// put on the request as `request.member`. Anything else, an organisation the
// person isn't in, a membership deactivated or tampered with, is 403
// FORBIDDEN, which says nothing of whether the organisation exists. The
// organisation is named on each request, never kept on the session, so two
// tabs open on two organisations can't act in each other's.
//
// B3+-1 (SEC-HA-12, ADR-012 §7): an admin's or a finance approver's powers
// need a session signed in with a passkey (`user` in its `amr`); a code from
// an authenticator app alone won't do. Without one, such a person keeps only
// what a developer or a viewer may do there: a route naming neither is 403
// PASSKEY_REQUIRED, which tells them to sign in again with their passkey.
//
// B6-3d (SEC-OPS-04, ADR-003 §4): for 7 days after a second factor of theirs
// is removed, by a reset or at the login service, a person keeps the same
// only: a route naming neither is 403 SECOND_FACTOR_REMOVED, in every
// organisation. The restriction is read last, for those routes alone, and
// without its reader no one reaches them.
//
// C2-1 (ADR-011 §1, SEC-AG-01, SEC-AG-02): an AI agent sends its key as
// `Authorization: Bearer axk_<keyId>_<secret>`. A request carrying an
// Authorization header is an agent's, never a person's, whatever cookie comes
// with it: on a route that doesn't name `agent` it is 403 FORBIDDEN before
// any lookup, and the session is never read. On one that does, the key check
// (the agents module's key-check.ts) finds the agent, its organisation and its
// scopes; every refusal is the same 401 UNAUTHENTICATED with the Bearer
// scheme's `invalid_token` challenge (RFC 6750 §3), the reason logged alone.
// The organisation is the key's: an agent names none, so no header can point
// it at another's (SEC-AG-02). A route naming agents names no one else: an
// agent's answers are allowlisted apart from a member's (SEC-AG-05). A route names the scopes it needs in
// `config.agentScopes`; a key without all of them is 403 INSUFFICIENT_SCOPE,
// the challenge naming them. The agent goes on the request as `request.agent`.
// An organisation frozen or on hold is refused where it matters, at a new
// spend request (ORG_FROZEN, PRD §5.3) and at a hand-off, not here: its
// agents may still read.
import { type AcceptedKey, type KeyChecked, type Scope, SCOPES } from '@agentx/core/modules/agents';
import {
  type LiveSession,
  type MembershipCheck,
  PASSKEY_METHOD,
  type RemovalRestriction,
  type Role,
} from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import type { CountRequest } from './rate-limit.ts';
import { cookieValue, SESSION_COOKIE } from './sign-in.ts';

/**
 * Who a route can name: an organisation's four roles, any signed-in person
 * (for their own account, whatever their roles), an AI agent by its key, the
 * platform's operators, or anyone (BRD §2).
 */
const PRINCIPALS = ['admin', 'approver', 'developer', 'viewer', 'person', 'agent', 'operator', 'public'] as const;
export type Principal = (typeof PRINCIPALS)[number];

/** An organisation's roles: each is a signed-in person too, so `person` beside one adds nothing. */
const ROLES: readonly Principal[] = ['admin', 'approver', 'developer', 'viewer'];

/** Whether a route's access names any of an organisation's roles: it then takes the organisation's header. */
export const namesRole = (access: readonly unknown[]): boolean =>
  access.some((name) => ROLES.some((role) => role === name));

/** A person acting in an organisation, as the access hook found their membership there. */
export interface Member {
  /** The organisation, in lower case as Postgres prints a uuid. */
  readonly orgId: string;
  readonly membershipId: string;
  readonly role: Role;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    /** Who may call the route. Required on every route (contract.ts). */
    readonly access?: readonly Principal[];
    /** The scopes an agent's key must hold to call the route: on every route naming `agent`, and no other (contract.ts). */
    readonly agentScopes?: readonly Scope[];
  }
  interface FastifyRequest {
    /** The signed-in person the request comes from, once the access hook has found their session; null before, and for anyone else. */
    person: LiveSession | null;
    /** On a route naming roles, the person's verified membership in the organisation the request names; null otherwise. */
    member: Member | null;
    /** On a route naming `agent`, the agent its key was accepted as; null before, and for anyone else. */
    agent: AcceptedKey | null;
  }
}

/** An agent's route's own caller: the agent the access hook accepted, which lets no one else through. */
export function agentOf(request: Pick<FastifyRequest, 'agent'>): AcceptedKey {
  if (request.agent === null) throw new Error("an agent's route ran without an agent");
  return request.agent;
}

/** A member's route's caller: their organisation, and who they are in which session. The hooks let no one else through. */
export function memberInSessionOf(request: Pick<FastifyRequest, 'member' | 'person'>) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error("a member's route ran without a member");
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

/** A route's use case: without it the route is still documented, and no one reaches it, as no one holds a role. */
export function need<T>(useCase: T | undefined): T {
  if (useCase === undefined) throw new Error('a route ran without its use case');
  return useCase;
}

/** Checks the key text an agent sent (key-check.ts): the same `refused` for every reason. */
export type CheckAgentKey = (text: string, correlationId: string) => Promise<KeyChecked>;

/** Finds the live session a session cookie names, its last use moved on. */
export type FindSession = (cookie: string) => Promise<LiveSession | undefined>;

/** The person's membership of the organisation, verified, for the request with this correlation ID. */
export type FindMembership = (orgId: string, userId: string, correlationId: string) => Promise<MembershipCheck>;

/** The header naming the organisation a request acts in, as Node names it. */
export const ORGANIZATION_HEADER = 'agentx-organization';

/**
 * The header as the document shows it on each route naming roles. The hook
 * below checks it before the body is read, so the route's own check of it
 * never refuses.
 */
export const ORGANIZATION_SCHEMA = z.uuid().register(API_SCHEMAS, {
  description:
    'The organisation the request acts in, by its ID. The signed-in person must be an active member of it, in one of the roles the address answers.',
});

const isOrganizationId = (value: unknown): value is string =>
  typeof value === 'string' && ORGANIZATION_SCHEMA.safeParse(value).success;

/**
 * The challenge a 401 carries (RFC 9110 §11.6.1): sign in at the form's
 * address, and the session comes back in this cookie.
 */
export const SESSION_CHALLENGE = `Cookie realm="Agent X", form-action="/v1/auth/sign-in", cookie-name="${SESSION_COOKIE}"`;

/** The challenge a 401 carries on a route naming agents (RFC 6750 §3): send the key as a bearer token. */
export const AGENT_CHALLENGE = 'Bearer realm="Agent X"';

/** The challenge for a route's callers: the Bearer scheme's for agents, who stand alone, the Cookie scheme's for people. */
const challengeFor = (access: readonly Principal[]): string =>
  access.includes('agent') ? AGENT_CHALLENGE : SESSION_CHALLENGE;

/**
 * The token of an `Authorization: Bearer <token>` header (RFC 6750 §2.1,
 * the scheme's name in any case), or '' for any other: the key check then
 * refuses it as malformed, as it does anything not written as a key.
 */
export const bearerToken = (authorization: string): string => /^Bearer +(\S+)$/i.exec(authorization)?.[1] ?? '';

const isPrincipal = (value: unknown): value is Principal => PRINCIPALS.some((principal) => principal === value);

/**
 * Where the platform's operator tooling lives, apart from the tenant API
 * (PRD §7.1). A fixed prefix, so no address pattern of an operator route
 * (a parameter, a wildcard) can answer a customer's address instead.
 */
const OPERATOR_PREFIX = '/operator/';

/** Why a route's access can't stand, if it can't. */
export function accessProblems(access: unknown, url: string): string[] {
  if (!Array.isArray(access) || access.length === 0) {
    return ['it names no one who may call it (config.access)'];
  }
  // A hole in a sparse list would be skipped by every(); Array.from makes it undefined.
  const names: unknown[] = Array.from(access);
  if (!names.every(isPrincipal)) {
    return [`its access names someone unknown: only ${PRINCIPALS.join(', ')}`];
  }
  const problems: string[] = [];
  if (new Set(names).size !== names.length) problems.push('its access names someone twice');
  if (names.includes('public') && names.length > 1) {
    problems.push('its access names the public beside others, who would add nothing');
  }
  if (names.includes('person') && names.some((name) => ROLES.some((role) => role === name))) {
    problems.push('its access names any signed-in person beside roles, which would add nothing');
  }
  // SEC-OPS-01: operators can't create or change any customer's authority, so their routes stand apart.
  if (names.includes('operator') && names.length > 1) {
    problems.push('its access names operators beside others');
  }
  // SEC-AG-05 (C2-1): an agent's answers are allowlisted apart from a member's, and an agent names no
  // organisation (its key's is the one), so agents have routes of their own.
  if (names.includes('agent') && names.length > 1) {
    problems.push('its access names agents beside others: give agents a route of their own');
  }
  problems.push(...addressProblems(names, url));
  return problems;
}

/** Why a route's address can't stand with its access, if it can't. */
function addressProblems(names: readonly unknown[], url: string): string[] {
  const problems: string[] = [];
  const operatorAddress = url.startsWith(OPERATOR_PREFIX);
  if (names.includes('operator') && !operatorAddress) {
    problems.push(`its access names operators outside ${OPERATOR_PREFIX}`);
  }
  if (operatorAddress && !names.includes('operator')) {
    problems.push(`it sits under ${OPERATOR_PREFIX}, which only operators may call`);
  }
  // A first segment that is a parameter, a pattern or a wildcard would answer every
  // address no other route takes, those under the operator prefix among them.
  if (/^\/[:*(]/.test(url)) {
    problems.push("its address starts with a parameter or wildcard, which would answer other routes' addresses");
  }
  return problems;
}

/**
 * Why a route's agent scopes can't stand, if they can't: a route naming
 * agents says which scopes a key needs, none if it needs none, each scope
 * once; a route not naming them says nothing, so no scope is ever thought to
 * guard a route that agents can't reach anyway.
 */
export function agentScopeProblems(access: unknown, scopes: unknown): string[] {
  const agents = Array.isArray(access) && access.includes('agent');
  if (!agents) return scopes === undefined ? [] : ['it names scopes for agents, but not agents (config.agentScopes)'];
  if (!Array.isArray(scopes)) return ['it names agents, but not the scopes their keys need (config.agentScopes)'];
  const names: unknown[] = Array.from(scopes);
  if (!names.every((name) => SCOPES.some((scope) => scope === name))) {
    return [`its agent scopes name one there isn't: only ${SCOPES.join(', ')}`];
  }
  return new Set(names).size === names.length ? [] : ['its agent scopes name one twice'];
}

/**
 * The roles that may act without a passkey (ADR-012 §7): a developer or a
 * viewer may sign in with an authenticator app, and what either may do, anyone
 * in the organisation may. A route naming neither is for admins or approvers.
 */
const WITHOUT_PASSKEY: readonly Principal[] = ['developer', 'viewer'];

/**
 * Whether a route is for an admin's or an approver's powers: one only an admin
 * or an approver may call. Their role need not be asked again, as a
 * developer's or a viewer's route names it.
 */
const needsPowers = (access: readonly Principal[]): boolean => !access.some((name) => WITHOUT_PASSKEY.includes(name));

/** Whether a session, its role already named by the route, needs a passkey it wasn't signed in with. */
const passkeyMissing = (amr: readonly string[], access: readonly Principal[]): boolean =>
  !amr.includes(PASSKEY_METHOD) && needsPowers(access);

/** A signed-in person the route doesn't answer. */
const forbidden = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 403, 'FORBIDDEN', request.id);

/** No one the route names: the challenges say how to sign in, or send a key. */
const unauthenticated = (request: FastifyRequest, reply: FastifyReply, access: readonly Principal[]) =>
  sendErrorBody(reply.header('www-authenticate', challengeFor(access)), 401, 'UNAUTHENTICATED', request.id);

/** A key refused, for whatever reason: the one answer, which tells the caller nothing of why (RFC 6750 §3.1). */
const keyRefused = (request: FastifyRequest, reply: FastifyReply) =>
  sendErrorBody(
    reply.header('www-authenticate', `${AGENT_CHALLENGE}, error="invalid_token"`),
    401,
    'UNAUTHENTICATED',
    request.id,
  );

/** A key accepted, without every scope the route needs: the challenge names them all (RFC 6750 §3.1). */
const scopeMissing = (request: FastifyRequest, reply: FastifyReply, needed: readonly Scope[]) =>
  sendErrorBody(
    reply.header('www-authenticate', `${AGENT_CHALLENGE}, error="insufficient_scope", scope="${needed.join(' ')}"`),
    403,
    'INSUFFICIENT_SCOPE',
    request.id,
  );

/**
 * Refuses every request to a route that doesn't name its caller, before the
 * body is read. An unknown address is left to the not-found answer.
 * `findSession` is the console's sign-in; with sign-in off no one is signed in.
 * `findMembership` reads a person's membership; without it no one holds a role.
 * `restrictedUntil` reads whether a person is in the 7 days after a second
 * factor removed; without it no one has an admin's or approver's powers.
 * `checkKey` checks an agent's key; without it no agent is let in.
 *
 * In callback style, calling done() only to let a request through: an async
 * hook that returned the refusal would be waited on until the answer ended,
 * and a client hanging up before then ends it too, letting the route run. A
 * failure to look the session or the key up is a failure on our side (done
 * with the error).
 */
export function registerAccess(
  app: FastifyInstance,
  {
    findSession,
    findMembership,
    restrictedUntil,
    checkKey,
    counters,
  }: {
    readonly findSession: FindSession | undefined;
    readonly findMembership: FindMembership | undefined;
    readonly restrictedUntil: RemovalRestriction | undefined;
    readonly checkKey: CheckAgentKey | undefined;
    /**
     * The person's and the agent's own limits (rate-limit.ts), counted here
     * for a request refused once its caller is known (the S68 audit): a
     * request let through is counted by their hooks, after this one, and a
     * refused one never reaches them. Refused over the limit, it is the
     * limit's 429 instead.
     */
    readonly counters: { readonly person: CountRequest; readonly agent: CountRequest };
  },
): void {
  app.decorateRequest('person', null);
  app.decorateRequest('member', null);
  app.decorateRequest('agent', null);
  app.addHook('onRequest', (request, reply, done) => {
    const { access = [], agentScopes = [] } = request.routeOptions.config;
    if (request.is404 || access.includes('public')) {
      done();
      return;
    }
    const failed = (error: unknown) => {
      done(error instanceof Error ? error : new Error('the access lookup failed', { cause: error }));
    };
    /** A refusal of a caller now known: counted against their own limit first. */
    const refusedAfter = (count: CountRequest, refuse: () => void) => {
      count(request, reply).then(refuse, failed);
    };
    const { authorization } = request.headers;
    if (authorization !== undefined) {
      // An agent's request, never a person's: the cookie isn't read.
      if (!access.includes('agent')) {
        void forbidden(request, reply);
      } else if (checkKey === undefined) {
        void keyRefused(request, reply);
      } else {
        checkKey(bearerToken(authorization), request.id).then((checked) => {
          if (checked.outcome !== 'accepted') {
            void keyRefused(request, reply);
          } else if (!agentScopes.every((scope) => checked.key.scopes.includes(scope))) {
            // Known, and refused: counted as the agent (its line names it too, request-log.ts).
            request.agent = checked.key;
            refusedAfter(counters.agent, () => void scopeMissing(request, reply, agentScopes));
          } else {
            request.agent = checked.key;
            done();
          }
        }, failed);
      }
      return;
    }
    const cookie = cookieValue(request.headers.cookie, SESSION_COOKIE);
    if (findSession === undefined || cookie === undefined) {
      void unauthenticated(request, reply, access);
      return;
    }
    findSession(cookie).then((session) => {
      if (session === undefined) {
        void unauthenticated(request, reply, access);
        return;
      }
      /** The signed-in person refused: counted as them, though from many addresses (the S68 audit). */
      const refuse = (send: () => void) => {
        request.person = session;
        refusedAfter(counters.person, send);
      };
      if (access.includes('person')) {
        request.person = session;
        done();
      } else if (!namesRole(access)) {
        // Agents' and operators' routes: a person is neither.
        refuse(() => void forbidden(request, reply));
      } else {
        const orgId = request.headers[ORGANIZATION_HEADER];
        if (!isOrganizationId(orgId)) {
          refuse(() => void sendErrorBody(reply, 400, 'ORGANIZATION_INVALID', request.id));
        } else if (findMembership === undefined) {
          refuse(() => void forbidden(request, reply));
        } else {
          findMembership(orgId, session.userId, request.id).then((membership) => {
            if (membership.outcome !== 'active' || !access.includes(membership.role)) {
              refuse(() => void forbidden(request, reply));
            } else if (passkeyMissing(session.amr, access)) {
              refuse(() => void sendErrorBody(reply, 403, 'PASSKEY_REQUIRED', request.id));
            } else {
              const through = () => {
                request.person = session;
                request.member = { orgId: orgId.toLowerCase(), membershipId: membership.id, role: membership.role };
                done();
              };
              /** Refuses a person in the 7 days after a second factor of theirs was removed: no admin's or approver's powers yet. */
              const secondFactorRemoved = () => void sendErrorBody(reply, 403, 'SECOND_FACTOR_REMOVED', request.id);
              if (!needsPowers(access)) {
                through();
              } else if (restrictedUntil === undefined) {
                refuse(() => void forbidden(request, reply));
              } else {
                restrictedUntil(session.userId).then((until) => {
                  if (until === undefined) through();
                  else refuse(secondFactorRemoved);
                }, failed);
              }
            }
          }, failed);
        }
      }
    }, failed);
  });
}
