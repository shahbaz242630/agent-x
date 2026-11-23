// An organisation's members (PRD §7.1 `GET /v1/members`, B4-2b): the first
// route naming roles. Any of the organisation's four roles may see who
// belongs to it; the organisation is the one the request names, as the
// access hook verified the caller's own membership there (access.ts).
//
// Each member is read and verified against their membership's signed state.
// One that can't be believed withholds the whole list, 503 INTEGRITY_FAILED:
// the alarm is raised and the organisation held, and no list is given that
// holds a role or a status someone may have forged.
//
// An admin is shown each member by name and email beside their Agent X ID
// (S212 F3, partner decision 27), named as the audit and activity logs name
// people (actor-names.ts): the login service asked once for the whole list,
// after the transaction, the copy Agent X kept (decision 25) where it can't
// answer. Every other role sees the IDs alone, as before: no name, email or
// `shownFrom` in their answer.
import type { AuditTables } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type ActorName, createActorNamer, nameOf, SHOWN_FROM } from '@agentx/core/modules/evidence';
import {
  type DirectoryNames,
  type IdentityTables,
  keptMembersFor,
  type MemberRecord,
  membersFor,
  type MembersList,
} from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { EVERY_MEMBER } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

/** The organisation's members, verified; with `names` (by actor key) when they were asked to be named. */
export type MembersAnswer = MembersList & { readonly names?: ReadonlyMap<string, ActorName> };

/** The organisation's members, verified, for the request with this correlation ID; named for an admin. */
export type ListMembers = (orgId: string, correlationId: string, named: boolean) => Promise<MembersAnswer>;

/** A member, as the list and a change to one answer it. */
export const MEMBER = z
  .object({
    id: z.uuid().describe('The membership, by its ID.'),
    userId: z.uuid().describe("The person's ID in Agent X."),
    role: z.enum(['admin', 'approver', 'developer', 'viewer']).describe('Their role in the organisation.'),
    status: z.enum(['ACTIVE', 'DEACTIVATED']).describe('ACTIVE, or DEACTIVATED once removed from the organisation.'),
    joinedAt: z.iso.datetime().describe('When they joined the organisation.'),
    name: z
      .string()
      .nullable()
      .optional()
      .describe('Their name, on the members list for an admin alone; null when none is known.'),
    email: z
      .string()
      .nullable()
      .optional()
      .describe('Their verified email address, on the members list for an admin alone; null when none is known.'),
    shownFrom: z
      .enum(SHOWN_FROM)
      .nullable()
      .optional()
      .describe('Where the name was found, as on the audit log; on the members list for an admin alone.'),
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

/** A member with their name, as an admin's list answers them. */
const namedMemberOf = (member: MemberRecord, names: ReadonlyMap<string, ActorName>) => ({
  ...memberOf(member),
  ...nameOf(names, { type: 'user', id: member.userId }),
});

/**
 * The members route's reader: the list alone, or (`named`) the list, Agent X's
 * kept copy of each name read in the same transaction, and the login service
 * asked once for them all after it, as the activity log names its people.
 */
export function createMembersList({
  database,
  keys,
  ids,
  logger,
  directory,
}: {
  readonly database: Database<IdentityTables & DirectoryTables & AuditTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
}): ListMembers {
  return async (orgId, correlationId, named) => {
    const services = { keys, ids, logger: logger.child({ correlationId }), correlationId };
    if (!named) return membersFor(database, services, orgId);
    const read = await keptMembersFor(database, services, orgId);
    if (read.outcome === 'tampered') return read;
    const namer = createActorNamer({ directory, logger: services.logger });
    const people = read.members.map((member) => ({ type: 'user' as const, id: member.userId }));
    return {
      outcome: 'listed',
      members: read.members,
      names: await namer.namesOf(people, { people: read.people, agents: new Map() }),
    };
  };
}

const MEMBERS_SCHEMA = {
  summary: "Your organisation's members",
  response: {
    200: z
      .object({
        members: z.array(MEMBER),
      })
      .register(API_SCHEMAS, {
        id: 'Members',
        description:
          "The organisation's members, deactivated ones included, in order of membership ID; named for an admin (decision 27).",
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
    { schema: MEMBERS_SCHEMA, config: { access: [...EVERY_MEMBER] } },
    async (request, reply) => {
      const member = request.member;
      // The access hook lets no one else through; a route that runs without a member is a bug.
      if (member === null || listMembers === undefined) throw new Error('the members route ran without a member');
      // The role they act in: an admin kept to a developer's or viewer's powers (SEC-OPS-04) is shown no names.
      const list = await listMembers(member.orgId, request.id, member.role === 'admin');
      if (list.outcome === 'tampered') return sendErrorBody(reply, 503, 'INTEGRITY_FAILED', request.id);
      const { names } = list;
      return {
        members: list.members.map((one) => (names === undefined ? memberOf(one) : namedMemberOf(one, names))),
      };
    },
  );
}
