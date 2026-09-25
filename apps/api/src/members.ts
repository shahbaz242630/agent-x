// An organisation's members (PRD §7.1 `GET /v1/members`, B4-2b): the first
// route naming roles. Any of the organisation's four roles may see who
// belongs to it; the organisation is the one the request names, as the
// access hook verified the caller's own membership there (access.ts).
//
// Each member is read and verified against their membership's signed state.
// One that can't be believed withholds the whole list, 503 INTEGRITY_FAILED:
// the alarm is raised and the organisation held, and no list is given that
// holds a role or a status someone may have forged. People are shown by
// their Agent X IDs: names and email addresses stay with the login service.
import type { MemberRecord, MembersList } from '@agentx/core/modules/identity';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

/** The organisation's members, verified, for the request with this correlation ID. */
export type ListMembers = (orgId: string, correlationId: string) => Promise<MembersList>;

/** A member, as the list and a change to one answer it. */
export const MEMBER = z
  .object({
    id: z.uuid().describe('The membership, by its ID.'),
    userId: z.uuid().describe("The person's ID in Agent X."),
    role: z.enum(['admin', 'approver', 'developer', 'viewer']).describe('Their role in the organisation.'),
    status: z.enum(['ACTIVE', 'DEACTIVATED']).describe('ACTIVE, or DEACTIVATED once removed from the organisation.'),
    joinedAt: z.iso.datetime().describe('When they joined the organisation.'),
  })
  .register(API_SCHEMAS, { id: 'Member', description: 'A person in the organisation, and their role.' });

/** A member as the API answers it. */
export const memberOf = ({ id, userId, role, status, joinedAt }: MemberRecord) => ({
  id,
  userId,
  role,
  status,
  joinedAt: joinedAt.toISOString(),
});

const MEMBERS_SCHEMA = {
  summary: "Your organisation's members",
  response: {
    200: z
      .object({
        members: z.array(MEMBER),
      })
      .register(API_SCHEMAS, {
        id: 'Members',
        description: "The organisation's members, deactivated ones included, in order of membership ID.",
      }),
  },
};

/**
 * The members route. `listMembers` reads them; without it the route is
 * still documented, and no one reaches it, as no one holds a role.
 */
export function registerMembers(app: FastifyInstance, listMembers: ListMembers | undefined): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  routes.get(
    '/v1/members',
    { schema: MEMBERS_SCHEMA, config: { access: ['admin', 'approver', 'developer', 'viewer'] } },
    async (request, reply) => {
      const member = request.member;
      // The access hook lets no one else through; a route that runs without a member is a bug.
      if (member === null || listMembers === undefined) throw new Error('the members route ran without a member');
      const list = await listMembers(member.orgId, request.id);
      if (list.outcome === 'tampered') return sendErrorBody(reply, 503, 'INTEGRITY_FAILED', request.id);
      return { members: list.members.map(memberOf) };
    },
  );
}
