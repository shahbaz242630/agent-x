// Adding and reading the organisation's suppliers (PRD §7.1, §7.3, ADR-012
// §1, BR-04, BR-21, SEC-AG-05; Phase 1 E1-2). Composed here, in the API, as
// ADR-004 §7 has it: the member is the identity module's, the supplier the
// suppliers module's.
//
// - `add` (`suppliers.add`), an admin (partner, S69): the key claimed first;
//   the organisation's lock for adding suppliers; the admin read again; the
//   day's budget (SUPPLIER_ADDS_SPENT: their records are never retired, the
//   B8-1 lesson); then the supplier, UNVERIFIED, with its first version,
//   entered by the admin. No step-up: an unverified supplier can be paid
//   nothing, and verifying it (E3) is the deliberate, stepped-up act
//   (ADR-003 §8). Answered from the supplier read again, on a retry too.
// - `list` and `show`: for the organisation's members, every supplier as
//   Agent X holds it, each through its signed state, so one tampered with
//   refuses the answer, 503 INTEGRITY_FAILED, and holds the organisation.
//   `show` opens the current version's contacts, which members call back.
// - `usableByAgent`: for an agent with `suppliers:read`, only the VERIFIED
//   suppliers (a payment rests on no other), each by ID and name alone
//   (PRD §7.4 `supplier_list`). The page is filtered after it is read, as
//   the agent's funding sources are, so a page may hold fewer than asked.
//
// Lock order (ADR-006 §6): the idempotency key, the add lock, the member's
// membership (2a), the supplier (6), its version, the chain head last.
import {
  addSupplier,
  MOST_SUPPLIERS_ADDED_A_DAY,
  oneSupplierAddAtATime,
  type SupplierDetails,
  type SupplierShown,
  suppliersAddedSince,
  suppliersPage,
} from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  createSupplierWork,
  type Refused,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierView,
} from './supplier-work.ts';

/** Adding a supplier. */
export const ADD_OPERATION = 'suppliers.add';

/** Who may add one: the admins (partner, S69). */
export const ADDING_ROLES = ['admin'] as const;

/** Where a page starts, and how many it holds at most (MOST_SUPPLIERS_A_PAGE). */
export interface SupplierPage {
  readonly after: string | null;
  readonly limit: number;
}

export type SupplierAddWrite =
  | ({ readonly outcome: 'added' } & SupplierView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type SuppliersListed =
  { readonly outcome: 'listed'; readonly suppliers: readonly SupplierShown[]; readonly next: string | null } | Refused;

type SupplierFound = ({ readonly outcome: 'found' } & SupplierView) | Refused;

export interface SupplierRegistry {
  add(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    details: SupplierDetails,
    correlationId: string,
  ): Promise<SupplierAddWrite>;
  list(orgId: string, page: SupplierPage, correlationId: string): Promise<SuppliersListed>;
  show(orgId: string, supplierId: string, correlationId: string): Promise<SupplierFound>;
  usableByAgent(orgId: string, page: SupplierPage, correlationId: string): Promise<SuppliersListed>;
}

const DAY_MS = 86_400_000;

export function createSupplierRegistry({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): SupplierRegistry {
  const work = createSupplierWork({ database, keys, ids, logger });

  const list = async (orgId: string, page: SupplierPage, correlationId: string): Promise<SuppliersListed> => {
    const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
      suppliersPage(tx, states, orgId, page),
    );
    if (listed.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    return listed;
  };

  return {
    async add(member, idempotent, details, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await oneSupplierAddAtATime(tx, member.orgId);
        const admin = await work.memberIn(tx, states, member, ADDING_ROLES);
        const now = clock.now();
        if (
          (await suppliersAddedSince(tx, member.orgId, new Date(now.getTime() - DAY_MS))) >= MOST_SUPPLIERS_ADDED_A_DAY
        ) {
          throw new SupplierRefused(409, 'SUPPLIER_ADDS_SPENT');
        }
        const id = ids.next();
        await addSupplier(tx, states, keys, {
          orgId: member.orgId,
          id,
          versionId: ids.next(),
          supplier: details,
          enteredBy: admin.id,
          createdAt: now,
          actor: { type: 'user', id: member.userId },
        });
        return { status: 201, resourceId: id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      const view = await work.view(member.orgId, done.result.resourceId, correlationId);
      if ('outcome' in view) return view;
      return { outcome: 'added', ...view };
    },

    list,

    async show(orgId, supplierId, correlationId) {
      const view = await work.view(orgId, supplierId, correlationId);
      if ('outcome' in view) return view;
      return { outcome: 'found', ...view };
    },

    async usableByAgent(orgId, page, correlationId) {
      const listed = await list(orgId, page, correlationId);
      if (listed.outcome === 'refused') return listed;
      // `next` still follows the page read: a page may hold fewer than asked, and the next picks up after it.
      return { ...listed, suppliers: listed.suppliers.filter((supplier) => supplier.status === 'VERIFIED') };
    },
  };
}
