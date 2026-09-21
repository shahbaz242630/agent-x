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

/** The addresses of the product's tenant API; operator tooling lives outside them (PRD §7.1). */
const isTenantAddress = (url: string): boolean => url === '/v1' || url.startsWith('/v1/');

/** Why a route's access can't stand, if it can't. */
export function accessProblems(access: unknown, url: string): string[] {
  if (!Array.isArray(access) || access.length === 0) {
    return ['it names no one who may call it (config.access)'];
  }
  if (!access.every(isPrincipal)) {
    return [`its access names someone unknown: only ${PRINCIPALS.join(', ')}`];
  }
  const problems: string[] = [];
  if (new Set(access).size !== access.length) problems.push('its access names someone twice');
  if (access.includes('public') && access.length > 1) {
    problems.push('its access names the public beside others, who would add nothing');
  }
  // SEC-OPS-01: operators can't create or change any customer's authority.
  if (access.includes('operator') && access.length > 1) {
    problems.push('its access names operators beside customers');
  }
  if (access.includes('operator') && isTenantAddress(url)) {
    problems.push('its access names operators on a tenant address (/v1)');
  }
  return problems;
}

/**
 * Refuses every request to a route that doesn't name its caller, before the
 * body is read. An unknown address is left to the not-found answer.
 */
export function registerAccess(app: FastifyInstance): void {
  app.addHook('onRequest', async (request, reply) => {
    if (request.is404 || request.routeOptions.config.access?.includes('public') === true) return undefined;
    return sendErrorBody(reply, 401, 'UNAUTHENTICATED', request.id);
  });
}
