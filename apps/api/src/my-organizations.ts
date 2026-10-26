// A signed-in person's own organisations (6A1, ADR-005 §6 "showing a user
// their organisations"): what the console offers to choose from, before any
// one organisation is named, so the route names no role and needs no
// organisation header.
//
// The directory lists where to look (organizationsOf); each organisation is
// then read inside its own withSignedStates: the person's membership, verified
// (an inactive one, or an entry naming someone else's, is left out), and the
// organisation's status, verified, with its name (unsealed, fixed when it is
// made, 0008). An organisation whose records can't be believed is answered by
// its ID alone as unreadable: its alarm is raised and it is held, as on any
// read, while the person's other organisations stay usable. Each organisation
// is its own transaction (the tenant wall allows no other); a person belongs
// to few, and every one of them a list the organisation's admins chose.
import type { AuditTables, SignedStatesServices } from '@agentx/core/modules/audit';
import { withSignedStates } from '@agentx/core/modules/audit';
import { type DirectoryTables, organizationsOf } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import { ORGANIZATIONS, type OrganizationsTables } from '@agentx/core/modules/organizations';
import type { Database } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

/** One of the person's organisations, as their verified membership and its verified status say. */
export interface MyOrganization {
  readonly id: string;
  readonly name: string;
  readonly role: Role;
  readonly frozen: boolean;
}

/** The person's organisations, and those whose records can't be believed, by ID. */
export interface MyOrganizations {
  readonly organizations: readonly MyOrganization[];
  readonly unreadable: readonly string[];
}

/** Reads the person's organisations, for the request with this correlation ID. */
export type ListMyOrganizations = (userId: string, correlationId: string) => Promise<MyOrganizations>;

type MyOrganizationsTables = IdentityTables & DirectoryTables & AuditTables & OrganizationsTables;

type Read =
  { readonly outcome: 'member'; readonly organization: MyOrganization } | { readonly outcome: 'none' | 'tampered' };

/** The use case: the directory's entries, then each organisation read in its own transaction. */
export function createMyOrganizations({
  database,
  services,
}: {
  readonly database: Database<MyOrganizationsTables>;
  readonly services: (correlationId: string) => SignedStatesServices;
}): ListMyOrganizations {
  const readIn = (orgId: string, userId: string, correlationId: string): Promise<Read> =>
    withSignedStates(database, orgId, services(correlationId), async (tx, states): Promise<Read> => {
      const membership = await membershipOf(tx, states, orgId, userId);
      if (membership.outcome === 'tampered') return { outcome: 'tampered' };
      if (membership.outcome !== 'active') return { outcome: 'none' };
      const status = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
      if (status.outcome !== 'verified') return { outcome: 'tampered' };
      const row = await tx
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its name alone: not sealed, and fixed when it is made (0008); its status is read through its signed state just above
        .selectFrom('organizations.organizations')
        .select('name')
        .where('org_id', '=', orgId)
        .where('id', '=', orgId)
        .executeTakeFirstOrThrow();
      return {
        outcome: 'member',
        organization: {
          id: orgId,
          name: row.name,
          role: membership.role,
          frozen: status.fields.get('status') === 'FROZEN',
        },
      };
    });

  return async (userId, correlationId) => {
    const organizations: MyOrganization[] = [];
    const unreadable: string[] = [];
    for (const orgId of await organizationsOf(database, userId)) {
      const read = await readIn(orgId, userId, correlationId);
      if (read.outcome === 'member') organizations.push(read.organization);
      if (read.outcome === 'tampered') unreadable.push(orgId);
    }
    return { organizations, unreadable };
  };
}

const MY_ORGANIZATIONS_SCHEMA = {
  summary: 'Your organisations',
  response: {
    200: z
      .object({
        organizations: z.array(
          z.object({
            id: z.uuid().describe('The organisation, by its ID: what the agentx-organization header names.'),
            name: z.string().describe("The organisation's name."),
            role: z.enum(['admin', 'approver', 'developer', 'viewer']).describe('Your role in it.'),
            frozen: z.boolean().describe('Whether it is frozen: no agent spends while it is.'),
          }),
        ),
        unreadable: z
          .array(z.uuid())
          .describe(
            "Organisations you are listed in whose records can't be checked right now. Their admins are alerted and nothing in them can be changed until it is resolved.",
          ),
      })
      .register(API_SCHEMAS, {
        id: 'MyOrganizations',
        description: 'The organisations you are an active member of, in order of ID.',
      }),
  },
};

/** The route. Without `list` (no database: a test of other routes) it is still documented, and answers NOT_FOUND. */
export function registerMyOrganizations(app: FastifyInstance, list: ListMyOrganizations | undefined): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  routes.get(
    '/v1/auth/organizations',
    { schema: MY_ORGANIZATIONS_SCHEMA, config: { access: ['person'] } },
    async (request, reply) => {
      if (list === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const session = request.person;
      // The access hook lets no one else through; a route that runs without a person is a bug.
      if (session === null) throw new Error('the organisations route ran without a person');
      const { organizations, unreadable } = await list(session.userId, request.id);
      return { organizations: [...organizations], unreadable: [...unreadable] };
    },
  );
}
