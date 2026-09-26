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
// FORBIDDEN. A route about a person's own account names `person`; agents
// come at C2.
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
import { type LiveSession, type MembershipCheck, PASSKEY_METHOD, type Role } from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
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
  }
  interface FastifyRequest {
    /** The signed-in person the request comes from, once the access hook has found their session; null before, and for anyone else. */
    person: LiveSession | null;
    /** On a route naming roles, the person's verified membership in the organisation the request names; null otherwise. */
    member: Member | null;
  }
}

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
 * The roles that may act without a passkey (ADR-012 §7): a developer or a
 * viewer may sign in with an authenticator app, and what either may do, anyone
 * in the organisation may. A route naming neither is for admins or approvers.
 */
const WITHOUT_PASSKEY: readonly Principal[] = ['developer', 'viewer'];

/**
 * Whether a session, its role already named by the route, needs a passkey it
 * wasn't signed in with: a route only an admin or an approver may call. Their
 * role need not be asked again, as a developer's or a viewer's route names it.
 */
const passkeyMissing = (amr: readonly string[], access: readonly Principal[]): boolean =>
  !amr.includes(PASSKEY_METHOD) && !access.some((name) => WITHOUT_PASSKEY.includes(name));

/** A signed-in person the route doesn't answer. */
const forbidden = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 403, 'FORBIDDEN', request.id);

/** No one the route names: the challenge says how to sign in. */
const unauthenticated = (request: FastifyRequest, reply: FastifyReply) =>
  sendErrorBody(reply.header('www-authenticate', SESSION_CHALLENGE), 401, 'UNAUTHENTICATED', request.id);

/**
 * Refuses every request to a route that doesn't name its caller, before the
 * body is read. An unknown address is left to the not-found answer.
 * `findSession` is the console's sign-in; with sign-in off no one is signed in.
 * `findMembership` reads a person's membership; without it no one holds a role.
 *
 * In callback style, calling done() only to let a request through: an async
 * hook that returned the refusal would be waited on until the answer ended,
 * and a client hanging up before then ends it too, letting the route run. A
 * failure to look the session up is a failure on our side (done with the error).
 */
export function registerAccess(
  app: FastifyInstance,
  findSession: FindSession | undefined,
  findMembership: FindMembership | undefined,
): void {
  app.decorateRequest('person', null);
  app.decorateRequest('member', null);
  app.addHook('onRequest', (request, reply, done) => {
    const access = request.routeOptions.config.access ?? [];
    if (request.is404 || access.includes('public')) {
      done();
      return;
    }
    const cookie = cookieValue(request.headers.cookie, SESSION_COOKIE);
    if (findSession === undefined || cookie === undefined) {
      void unauthenticated(request, reply);
      return;
    }
    const failed = (error: unknown) => {
      done(error instanceof Error ? error : new Error('the access lookup failed', { cause: error }));
    };
    findSession(cookie).then((session) => {
      if (session === undefined) {
        void unauthenticated(request, reply);
      } else if (access.includes('person')) {
        request.person = session;
        done();
      } else if (!namesRole(access)) {
        // Agents' and operators' routes: a person is neither.
        void forbidden(request, reply);
      } else {
        const orgId = request.headers[ORGANIZATION_HEADER];
        if (!isOrganizationId(orgId)) {
          void sendErrorBody(reply, 400, 'ORGANIZATION_INVALID', request.id);
        } else if (findMembership === undefined) {
          void forbidden(request, reply);
        } else {
          findMembership(orgId, session.userId, request.id).then((membership) => {
            if (membership.outcome !== 'active' || !access.includes(membership.role)) {
              void forbidden(request, reply);
            } else if (passkeyMissing(session.amr, access)) {
              void sendErrorBody(reply, 403, 'PASSKEY_REQUIRED', request.id);
            } else {
              request.person = session;
              request.member = { orgId: orgId.toLowerCase(), membershipId: membership.id, role: membership.role };
              done();
            }
          }, failed);
        }
      }
    }, failed);
  });
}
