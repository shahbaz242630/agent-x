// BR-04, PRD §7.1 ("the roles allowed for each endpoint are defined in
// OpenAPI"): every route says who may call it, in its `config.access`. The
// contract refuses a route without a valid one and writes it into the OpenAPI
// document as `x-access`, which the role matrix tests read (FX-ROLEMATRIX).
// This hook enforces it, denying by default: a route answers only a caller it
// names. No request carries a signed-in person or an agent yet, so for now
// only public routes answer; the rest are refused as UNAUTHENTICATED.
import type { FastifyInstance } from 'fastify';

import { sendErrorBody } from './errors.ts';

/**
 * Who a route can name: an organisation's four roles, an AI agent by its key,
 * the platform's operators, or anyone (BRD §2).
 */
export const PRINCIPALS = ['admin', 'approver', 'developer', 'viewer', 'agent', 'operator', 'public'] as const;
export type Principal = (typeof PRINCIPALS)[number];

declare module 'fastify' {
  interface FastifyContextConfig {
    /** Who may call the route. Required on every route (contract.ts). */
    readonly access?: readonly Principal[];
  }
}

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
  return problems;
}

/**
 * Refuses every request to a route that doesn't name its caller, before the
 * body is read. An unknown address is left to the not-found answer.
 *
 * In callback style, calling done() only to let a request through: an async
 * hook that returned the refusal would be waited on until the answer ended,
 * and a client hanging up before then ends it too, letting the route run.
 */
export function registerAccess(app: FastifyInstance): void {
  app.addHook('onRequest', (request, reply, done) => {
    if (request.is404 || request.routeOptions.config.access?.includes('public') === true) {
      done();
      return;
    }
    void sendErrorBody(reply, 401, 'UNAUTHENTICATED', request.id);
  });
}
