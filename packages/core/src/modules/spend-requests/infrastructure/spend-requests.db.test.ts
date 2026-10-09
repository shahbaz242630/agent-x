// D1: spend requests and their order claims (0039), on the real migrated
// schema, as the app role. Deciding, adding and moving them come with D2–D4r
// and their seals' tamper tests with them; this holds the tables' own rules:
// a request born VALIDATING with its decision and moved only where that
// decision leads, then along its machine; fixed but for its status; its
// reasons with its decision; capacity held only on the versions weighed and
// its mandate's source; those versions its agent's and organisation's own;
// one open claim an order, by supplier and by payee, in the request's own
// canonical form, for a request holding capacity, released once after its
// request ends; and no other organisation's rows, no deletes.
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import fc from 'fast-check';
import type { Insertable, Updateable } from 'kysely';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type SeededSupplier as Supplier, seedRows } from '../../../seed-rows.helper.test.ts';
import { type Decision, DECISIONS } from '../../policies/index.ts';
import { claimOrder, hasOpenClaim, orderKeyOf, releaseClaim } from './order-claims.ts';
import type { SpendRequestsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendRequestsTables>;

const AT = new Date('2026-10-08T08:00:00Z');

type Tx = DatabaseTransaction<SpendRequestsTables>;
type RequestRow = Insertable<SpendRequestsTables['spend_requests.requests']>;
type ClaimRow = Insertable<SpendRequestsTables['spend_requests.order_claims']>;

interface Agent {
  readonly id: string;
  readonly key: string;
}

interface Org {
  readonly id: string;
  readonly agent: Agent;
  readonly source: string;
  readonly mandate: string;
  readonly mandateVersion: string;
  readonly supplier: Supplier;
}

const seed = () => seedRows(database.as('admin'), AT);

/** An agent of the organisation with its key, made past the app, as the steps that add them are tested elsewhere. */
const agentOf = async (org: string): Promise<Agent> => {
  const id = await seed().agent(org);
  return { id, key: await seed().agentKey(org, id) };
};

/** A supplier of the organisation with its first version, made past the app. */
const supplierOf = (org: string, payeeKey: string | null = null) => seed().supplier(org, payeeKey);

/** A policy and its first version, made past the app: the organisation's own (by its ID) or a mandate's (by the mandate's). */
const policyOf = async (org: string, scope: 'organization' | 'mandate', id: string): Promise<string> => {
  const version = randomUUID();
  await database.as('admin').query(
    `with policy as (
       insert into mandates.policies (org_id, id, scope, mandate_id, current_version_id, created_at)
       values ($1, $2, $3, $4, $5, $6) returning org_id)
     insert into mandates.policy_versions (org_id, id, policy_id, version, currency, monthly_cap_minor, rules_hash,
       made_by, made_at)
     select org_id, $5, $2, 1, 'AED', 3000000, $7, $2, $6 from policy`,
    [org, id, scope, scope === 'mandate' ? id : null, version, AT, 'b'.repeat(64)],
  );
  return version;
};

/** An organisation with an agent and its key, a funding source, a supplier and the agent's mandate, made past the app. */
const organisation = async (): Promise<Org> => {
  const id = randomUUID();
  await seed().org(id);
  const agent = await agentOf(id);
  const source = await seed().source(id);
  const supplier = await supplierOf(id);
  const mandate = await seed().mandate(id, { agent: agent.id, source, supplier: supplier.id });
  return { id, agent, source, mandate: mandate.id, mandateVersion: mandate.version, supplier };
};

const inOrg = <Result>(org: Org, work: (tx: Tx) => Promise<Result>) => withTenant(app, org.id, work);

/** A decision with reasons, as the engine gives one: none for ALLOW. */
const decided = (decision: Decision, reasons = 'APPROVAL_THRESHOLD') => ({
  decision,
  reason_codes: decision === 'ALLOW' ? null : reasons,
});

/** An ALLOW request as D4 will add it, VALIDATING with its decision, with any column given otherwise. */
const requestRow = (org: Org, overrides: Partial<RequestRow> = {}): RequestRow => ({
  org_id: org.id,
  id: randomUUID(),
  agent_id: org.agent.id,
  agent_key_id: org.agent.key,
  mandate_id: org.mandate,
  mandate_version_id: org.mandateVersion,
  organization_policy_version_id: null,
  mandate_policy_version_id: null,
  supplier_id: org.supplier.id,
  supplier_version_id: org.supplier.version,
  funding_source_id: org.source,
  amount_minor: 25_000n,
  currency: 'AED',
  purpose: 'Printer paper',
  order_reference: 'PO-2026/0042',
  idempotency_key: randomUUID(),
  input_hash: 'd'.repeat(64),
  input_hash_key_version: 1,
  decision: 'ALLOW',
  reason_codes: null,
  status: 'VALIDATING',
  created_at: AT,
  ...overrides,
});

/** The decided status each decision moves a new request to. */
const DECIDED_STATUS: Readonly<Record<Decision, string>> = {
  ALLOW: 'APPROVED',
  REQUIRE_APPROVAL: 'APPROVAL_REQUIRED',
  DENY: 'DENIED',
  REQUIRE_NEW_MANDATE: 'DENIED',
};

const add = (org: Org, row: RequestRow) =>
  inOrg(org, (tx) => tx.insertInto('spend_requests.requests').values(row).execute());

const change = (org: Org, id: string, values: Updateable<SpendRequestsTables['spend_requests.requests']>) =>
  inOrg(org, (tx) => tx.updateTable('spend_requests.requests').set(values).where('id', '=', id).execute());

/** Adds a request and moves it through the statuses given, each in its own statement. */
const moved = async (org: Org, row: RequestRow, ...statuses: string[]): Promise<string> => {
  await add(org, row);
  for (const status of statuses) await change(org, row.id, { status });
  return row.id;
};

const statusOf = (org: Org, id: string) =>
  inOrg(org, (tx) =>
    tx.selectFrom('spend_requests.requests').select('status').where('id', '=', id).executeTakeFirstOrThrow(),
  );

/** An approved request, ready to claim its order. */
const approved = (org: Org, overrides: Partial<RequestRow> = {}) => moved(org, requestRow(org, overrides), 'APPROVED');

/** A claim on a request's order, with any column given otherwise. */
const claimRow = (org: Org, request: string, overrides: Partial<ClaimRow> = {}): ClaimRow => ({
  org_id: org.id,
  id: randomUUID(),
  request_id: request,
  supplier_id: org.supplier.id,
  payee_key: null,
  order_reference: 'po-2026/0042',
  claimed_at: AT,
  released_at: null,
  ...overrides,
});

const claim = (org: Org, row: ClaimRow) =>
  inOrg(org, (tx) => tx.insertInto('spend_requests.order_claims').values(row).execute());

const changeClaim = (org: Org, id: string, values: Updateable<SpendRequestsTables['spend_requests.order_claims']>) =>
  inOrg(org, (tx) => tx.updateTable('spend_requests.order_claims').set(values).where('id', '=', id).execute());

/** A claim on an approved request, the request then cancelled so the claim may be released: the claim's ID. */
const claimedThenCancelled = async (org: Org): Promise<string> => {
  const request = await approved(org);
  const row = claimRow(org, request);
  await claim(org, row);
  await change(org, request, { status: 'CANCELLED' });
  return row.id;
};

/** A request's columns naming the supplier and the version weighed. */
const onSupplier = (supplier: Supplier) => ({ supplier_id: supplier.id, supplier_version_id: supplier.version });

/** One supplier a payee at a time (0033): the key moves from one to another, past the app, claims keeping it. */
const movePayeeKey = async (from: Supplier, to: Supplier, key: string) => {
  const admin = database.as('admin');
  await admin.query('update suppliers.suppliers set payee_key = null where id = $1', [from.id]);
  await admin.query('update suppliers.suppliers set payee_key = $2 where id = $1', [to.id, key]);
};

const refusedBy = (constraint: string, code?: string): unknown =>
  expect.objectContaining(code === undefined ? { constraint } : { code, constraint });
const DENIED: unknown = expect.objectContaining({ code: '42501' });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendRequestsTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('a spend request', () => {
  it('is born VALIDATING with any decision the engine makes, and moved by it', async () => {
    const org = await organisation();
    for (const decision of DECISIONS) {
      const id = await moved(org, requestRow(org, decided(decision)), DECIDED_STATUS[decision]);
      expect(await statusOf(org, id)).toEqual({ status: DECIDED_STATUS[decision] });
    }
    await expect(add(org, requestRow(org, { decision: 'MAYBE', reason_codes: 'X' }))).rejects.toEqual(
      refusedBy('requests_decision_check'),
    );
  });

  it('is never born in another status (status_guard)', async () => {
    const org = await organisation();
    await expect(add(org, requestRow(org, { status: 'APPROVED' }))).rejects.toEqual(refusedBy('status_guard'));
  });

  it('leaves VALIDATING only where its decision leads: needing approval is never approved unasked (decided_move)', async () => {
    const org = await organisation();
    for (const decision of DECISIONS) {
      for (const status of ['DENIED', 'APPROVAL_REQUIRED', 'APPROVED'].filter((s) => s !== DECIDED_STATUS[decision])) {
        const row = requestRow(org, decided(decision));
        await add(org, row);
        await expect(change(org, row.id, { status })).rejects.toEqual(refusedBy('decided_move'));
      }
    }
  });

  it('denied with no mandate, another organisation’s supplier and source, is still recorded as asked', async () => {
    const org = await organisation();
    const row = requestRow(org, {
      mandate_id: null,
      mandate_version_id: null,
      supplier_id: randomUUID(),
      supplier_version_id: null,
      funding_source_id: randomUUID(),
      ...decided('DENY', 'MANDATE_NOT_IN_FORCE SUPPLIER_NOT_ALLOWED SOURCE_NOT_MANDATED'),
    });

    expect(await statusOf(org, await moved(org, row, 'DENIED'))).toEqual({ status: 'DENIED' });
  });

  it('waiting for approval, is approved, made ready and handed off', async () => {
    const org = await organisation();
    const row = requestRow(org, decided('REQUIRE_APPROVAL'));
    const id = await moved(org, row, 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF');

    expect(await statusOf(org, id)).toEqual({ status: 'HANDED_OFF' });
  });

  it('waiting for approval, may be rejected, expired or cancelled', async () => {
    const org = await organisation();
    for (const end of ['DENIED', 'EXPIRED', 'CANCELLED']) {
      const id = await moved(org, requestRow(org, decided('REQUIRE_APPROVAL')), 'APPROVAL_REQUIRED', end);
      expect(await statusOf(org, id)).toEqual({ status: end });
    }
  });

  it('approved or ready, may be denied by the re-check or cancelled before hand-off', async () => {
    const org = await organisation();
    for (const ready of [[], ['INSTRUCTION_READY']]) {
      for (const end of ['DENIED', 'CANCELLED']) {
        const id = await moved(org, requestRow(org), 'APPROVED', ...ready, end);
        expect(await statusOf(org, id)).toEqual({ status: end });
      }
    }
  });

  it('moves only along its machine: never back, never on from an end, never handed off unready (status_guard)', async () => {
    const org = await organisation();
    const denied = await moved(org, requestRow(org, decided('DENY')), 'DENIED');
    const handedOff = await moved(org, requestRow(org), 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF');
    const approvedOne = await approved(org);

    for (const [id, status] of [
      [denied, 'APPROVED'],
      [handedOff, 'CANCELLED'],
      [approvedOne, 'VALIDATING'],
      [approvedOne, 'HANDED_OFF'],
      [approvedOne, 'EXPIRED'],
    ] as const) {
      await expect(change(org, id, { status })).rejects.toEqual(refusedBy('status_guard'));
    }
  });

  it('keeps all it was made with: its amount, decision, reasons, supplier and versions (fixed_at_creation)', async () => {
    const org = await organisation();
    const id = await approved(org);

    for (const values of [
      { amount_minor: 1n },
      { decision: 'DENY' },
      { reason_codes: 'APPROVAL_THRESHOLD' },
      { supplier_id: randomUUID() },
      { mandate_version_id: null, mandate_id: null },
      { order_reference: 'PO-2026/0043' },
      { idempotency_key: 'another' },
    ]) {
      await expect(change(org, id, values)).rejects.toEqual(refusedBy('fixed_at_creation'));
    }
    // Written again unchanged, as the audit module's record does, it is no change.
    await change(org, id, { amount_minor: 25_000n, decision: 'ALLOW' });
  });

  it('gives reasons for every decision but ALLOW, and none for ALLOW (reasons_with_the_decision)', async () => {
    const org = await organisation();
    await expect(add(org, requestRow(org, { reason_codes: 'APPROVAL_THRESHOLD' }))).rejects.toEqual(
      refusedBy('reasons_with_the_decision'),
    );
    await expect(add(org, requestRow(org, { decision: 'DENY', reason_codes: null }))).rejects.toEqual(
      refusedBy('reasons_with_the_decision'),
    );
  });

  it('writes its reason codes as codes, one space apart', async () => {
    const org = await organisation();
    for (const reasons of ['', 'agent_suspended', 'AGENT_SUSPENDED  POLICY_ORDER_CAP', ' AGENT_SUSPENDED']) {
      await expect(add(org, requestRow(org, decided('DENY', reasons)))).rejects.toEqual(
        refusedBy('requests_reason_codes_check'),
      );
    }
  });

  it('holds capacity only on the mandate and supplier versions it weighed (holds_on_what_it_weighed)', async () => {
    const org = await organisation();
    for (const decision of ['ALLOW', 'REQUIRE_APPROVAL'] as const) {
      for (const missing of [{ supplier_version_id: null }, { mandate_id: null, mandate_version_id: null }]) {
        await expect(add(org, requestRow(org, { ...decided(decision), ...missing }))).rejects.toEqual(
          refusedBy('holds_on_what_it_weighed'),
        );
      }
    }
  });

  it('holds capacity only on its mandate version’s source; denied, keeps the source as asked (from_its_mandates_source)', async () => {
    const org = await organisation();
    for (const decision of ['ALLOW', 'REQUIRE_APPROVAL'] as const) {
      await expect(
        add(org, requestRow(org, { ...decided(decision), funding_source_id: randomUUID() })),
      ).rejects.toEqual(refusedBy('from_its_mandates_source', '23503'));
    }
    await add(org, requestRow(org, { ...decided('DENY', 'SOURCE_NOT_MANDATED'), funding_source_id: randomUUID() }));
  });

  it('names a mandate with the version weighed, and a mandate’s policy only with its mandate', async () => {
    const org = await organisation();
    const denied = decided('DENY', 'MANDATE_NOT_IN_FORCE');
    await expect(add(org, requestRow(org, { ...denied, mandate_version_id: null }))).rejects.toEqual(
      refusedBy('a_mandate_with_its_version'),
    );
    const policyVersion = await policyOf(org.id, 'mandate', org.mandate);
    const noMandate = { mandate_id: null, mandate_version_id: null, mandate_policy_version_id: policyVersion };
    await expect(add(org, requestRow(org, { ...denied, ...noMandate }))).rejects.toEqual(
      refusedBy('a_mandate_policy_with_its_mandate'),
    );
  });

  it('is its own agent’s, with its key, under its mandate, weighing its own supplier’s version and policies', async () => {
    const org = await organisation();
    const other = await organisation();
    const anotherAgent = await agentOf(org.id);
    const otherSupplier = await supplierOf(org.id);
    const organizationPolicy = await policyOf(org.id, 'organization', org.id);
    const mandatePolicy = await policyOf(org.id, 'mandate', org.mandate);

    await add(
      org,
      requestRow(org, { organization_policy_version_id: organizationPolicy, mandate_policy_version_id: mandatePolicy }),
    );
    for (const [values, constraint] of [
      [{ agent_id: other.agent.id }, 'of_an_agent'],
      [{ agent_key_id: anotherAgent.key }, 'with_its_agents_key'],
      // Another agent of the organisation, with its own key, under this agent's mandate.
      [{ agent_id: anotherAgent.id, agent_key_id: anotherAgent.key }, 'under_its_agents_mandate'],
      [{ mandate_version_id: other.mandateVersion }, 'under_a_mandate_version'],
      [{ supplier_version_id: otherSupplier.version }, 'to_a_supplier_version'],
      // The mandate's policy is no organisation's, nor the organisation's any mandate's.
      [{ organization_policy_version_id: mandatePolicy }, 'under_the_organizations_policy'],
      [{ mandate_policy_version_id: organizationPolicy }, 'under_the_mandates_policy'],
    ] as const) {
      await expect(add(org, requestRow(org, values))).rejects.toEqual(refusedBy(constraint, '23503'));
    }
  });

  it('is in an allowed currency, for a positive amount, with a purpose', async () => {
    const org = await organisation();
    await expect(add(org, requestRow(org, { currency: 'USD' }))).rejects.toEqual(
      refusedBy('requests_currency_fkey', '23503'),
    );
    await expect(add(org, requestRow(org, { amount_minor: 0n }))).rejects.toEqual(
      refusedBy('requests_amount_minor_check'),
    );
    for (const purpose of ['', 'a'.repeat(201), 'line\nbreak']) {
      await expect(add(org, requestRow(org, { purpose }))).rejects.toEqual(refusedBy('requests_purpose_check'));
    }
  });

  it('keeps its order reference as written: the supplier’s own number, any script, up to 100 characters', async () => {
    const org = await organisation();
    for (const reference of ['PO#1', 'INV_22', 'فاتورة ١٢', 'Café/7', 'a'.repeat(100)]) {
      await add(org, requestRow(org, { order_reference: reference }));
    }
    for (const reference of ['a'.repeat(101), 'line\nbreak', 'tab\there']) {
      await expect(add(org, requestRow(org, { order_reference: reference }))).rejects.toEqual(
        refusedBy('requests_order_reference_check'),
      );
    }
    // Empty, or blank once its spaces, the Unicode ones too, are taken away.
    for (const reference of ['', '   ', '\u00a0\u2003']) {
      await expect(add(org, requestRow(org, { order_reference: reference }))).rejects.toEqual(
        refusedBy('an_order_not_blank'),
      );
    }
  });

  it('works out its order’s canonical form: NFKC, case-folded, trimmed, spaces collapsed (ADR-006 §5)', async () => {
    const org = await organisation();
    const keyOf = async (reference: string) => {
      const row = requestRow(org, { order_reference: reference });
      await add(org, row);
      return (
        await inOrg(org, (tx) =>
          tx
            .selectFrom('spend_requests.requests')
            .select('order_key')
            .where('id', '=', row.id)
            .executeTakeFirstOrThrow(),
        )
      ).order_key;
    };

    expect(await keyOf('  Inv 7/B   (26)  Q-ZA ')).toBe('inv 7/b (26) q-za');
    // Full-width letters and digits, a no-break and an em space: the same order as plain text.
    expect(await keyOf('\uff29\uff2e\uff36\u00a0\u2003\uff12\uff12')).toBe('inv 22');
    expect(await keyOf('ÉCOLE #9')).toBe('école #9');
    expect(await keyOf('  فاتورة   ١٢ ')).toBe('فاتورة ١٢');
  });

  it('keeps a keyed hash of what it weighed, with its key’s version, and its idempotency key', async () => {
    const org = await organisation();
    for (const [values, constraint] of [
      [{ input_hash: 'D'.repeat(64) }, 'requests_input_hash_check'],
      [{ input_hash_key_version: 0 }, 'requests_input_hash_key_version_check'],
      [{ idempotency_key: '' }, 'requests_idempotency_key_check'],
      [{ idempotency_key: 'k'.repeat(256) }, 'requests_idempotency_key_check'],
    ] as const) {
      await expect(add(org, requestRow(org, values))).rejects.toEqual(refusedBy(constraint));
    }
  });

  it('is never deleted, nor moved to another key', async () => {
    const org = await organisation();
    const id = await approved(org);

    await expect(
      inOrg(org, (tx) => tx.deleteFrom('spend_requests.requests').where('id', '=', id).execute()),
    ).rejects.toEqual(DENIED);
    await expect(change(org, id, { id: randomUUID() })).rejects.toEqual(DENIED);
    await expect(change(org, id, { created_at: new Date(AT.getTime() + 1) })).rejects.toEqual(DENIED);
  });
});

describe('an order claim', () => {
  it('holds an order once by its supplier: a second open claim is refused, a released one frees it', async () => {
    const org = await organisation();
    const first = await claimedThenCancelled(org);

    await expect(claim(org, claimRow(org, await approved(org)))).rejects.toEqual(
      refusedBy('one_open_claim_a_supplier_order', '23505'),
    );
    await changeClaim(org, first, { released_at: AT });
    await claim(org, claimRow(org, await approved(org)));
  });

  it('holds the same order written another way: case, spaces, full-width letters (ADR-006 §5)', async () => {
    const org = await organisation();
    await claim(org, claimRow(org, await approved(org)));

    for (const written of [' po-2026/0042', 'PO-2026/0042  ', 'ＰＯ-2026/0042']) {
      const again = await approved(org, { order_reference: written });
      await expect(claim(org, claimRow(org, again))).rejects.toEqual(
        refusedBy('one_open_claim_a_supplier_order', '23505'),
      );
    }
  });

  it('holds the same order for another supplier apart, and another order for the same one', async () => {
    const org = await organisation();
    const another = await supplierOf(org.id);
    await claim(org, claimRow(org, await approved(org)));

    const anotherRequest = await approved(org, { supplier_id: another.id, supplier_version_id: another.version });
    await claim(org, claimRow(org, anotherRequest, { supplier_id: another.id }));
    const anotherOrder = await approved(org, { order_reference: 'PO-2026/0043' });
    await claim(org, claimRow(org, anotherOrder, { order_reference: 'po-2026/0043' }));
  });

  it('holds an order once by its payee too: a supplier re-created with the same account is refused', async () => {
    const org = await organisation();
    const [first, second] = [await supplierOf(org.id, 'payee-1'), await supplierOf(org.id)];
    await claim(
      org,
      claimRow(org, await approved(org, onSupplier(first)), { supplier_id: first.id, payee_key: 'payee-1' }),
    );
    await movePayeeKey(first, second, 'payee-1');

    await expect(
      claim(
        org,
        claimRow(org, await approved(org, onSupplier(second)), { supplier_id: second.id, payee_key: 'payee-1' }),
      ),
    ).rejects.toEqual(refusedBy('one_open_claim_a_payee_order', '23505'));
  });

  it('keeps its supplier’s payee key as it is when claimed, none where it has none (claim_guard)', async () => {
    const org = await organisation();
    const keyed = await supplierOf(org.id, 'payee-7');
    const request = await approved(org, { supplier_id: keyed.id, supplier_version_id: keyed.version });

    for (const payee of [null, 'payee-8']) {
      await expect(claim(org, claimRow(org, request, { supplier_id: keyed.id, payee_key: payee }))).rejects.toEqual(
        refusedBy('claim_guard'),
      );
    }
    await expect(claim(org, claimRow(org, await approved(org), { payee_key: 'payee-7' }))).rejects.toEqual(
      refusedBy('claim_guard'),
    );
    await claim(org, claimRow(org, request, { supplier_id: keyed.id, payee_key: 'payee-7' }));
  });

  it('is only for a request holding capacity (claim_guard)', async () => {
    const org = await organisation();
    for (const decision of ['DENY', 'REQUIRE_NEW_MANDATE'] as const) {
      const denied = await moved(org, requestRow(org, decided(decision)), 'DENIED');
      await expect(claim(org, claimRow(org, denied))).rejects.toEqual(refusedBy('claim_guard'));
    }
    const waiting = await moved(org, requestRow(org, decided('REQUIRE_APPROVAL')), 'APPROVAL_REQUIRED');
    await claim(org, claimRow(org, waiting));
  });

  it('is its request’s only one, on its request’s own supplier and order in canonical form (for_its_request)', async () => {
    const org = await organisation();
    const request = await approved(org);
    await claim(org, claimRow(org, request));

    await expect(claim(org, claimRow(org, request))).rejects.toEqual(refusedBy('one_claim_a_request'));
    const another = await supplierOf(org.id);
    for (const values of [
      { supplier_id: another.id },
      // Its order as written, another order, or the canonical form with a space more.
      { order_reference: 'PO-2026/0042' },
      { order_reference: 'po-2026/0043' },
      { order_reference: 'po-2026/0042 ' },
    ]) {
      await expect(claim(org, claimRow(org, await approved(org), values))).rejects.toEqual(
        refusedBy('for_its_request', '23503'),
      );
    }
  });

  it('is released only once its request has ended, and only once (claim_guard)', async () => {
    const org = await organisation();
    const waitingRow = requestRow(org, { ...decided('REQUIRE_APPROVAL'), order_reference: 'PO-1' });
    const waiting = await moved(org, waitingRow, 'APPROVAL_REQUIRED');
    const ready = await moved(org, requestRow(org, { order_reference: 'PO-2' }), 'APPROVED', 'INSTRUCTION_READY');
    for (const [request, order] of [
      [waiting, 'po-1'],
      [ready, 'po-2'],
    ] as const) {
      const row = claimRow(org, request, { order_reference: order });
      await claim(org, row);
      await expect(changeClaim(org, row.id, { released_at: AT })).rejects.toEqual(refusedBy('claim_guard'));
    }

    const released = await claimedThenCancelled(org);
    await changeClaim(org, released, { released_at: AT });
    for (const again of [null, new Date(AT.getTime() + 1)]) {
      await expect(changeClaim(org, released, { released_at: again })).rejects.toEqual(refusedBy('claim_guard'));
    }
  });

  it('is released no earlier than it was made, and never deleted, nor its order changed', async () => {
    const org = await organisation();
    const id = await claimedThenCancelled(org);

    await expect(changeClaim(org, id, { released_at: new Date(AT.getTime() - 1) })).rejects.toEqual(
      refusedBy('released_after_its_claim'),
    );
    for (const values of [{ order_reference: 'po-other' }, { supplier_id: randomUUID() }, { payee_key: 'x' }]) {
      await expect(changeClaim(org, id, values)).rejects.toEqual(DENIED);
    }
    await expect(
      inOrg(org, (tx) => tx.deleteFrom('spend_requests.order_claims').where('id', '=', id).execute()),
    ).rejects.toEqual(DENIED);
  });
});

describe('the duplicate check and claiming an order (D3)', () => {
  /** Characters that canonical forms fold: case, full-width, other spaces, ligatures, accents composed or not, Arabic digits. */
  const PIECES = [
    'P',
    'o',
    '-',
    '/',
    '#',
    '_',
    '4',
    'Ｐ',
    'ｏ',
    '４',
    ' ',
    '\u3000',
    '\u00a0',
    'ﬁ',
    'é',
    'e\u0301',
    '٢',
    'İ',
    'ß',
    'Σ',
  ];
  const reference = fc
    .array(fc.constantFrom(...PIECES), { minLength: 1, maxLength: 40 })
    .map((pieces) => pieces.join(''))
    .filter((written) => written.trim() !== '');

  const check = (org: Org, written: string, order: { supplierId?: string; payeeKey?: string | null } = {}) =>
    inOrg(org, (tx) =>
      hasOpenClaim(tx, {
        supplierId: order.supplierId ?? org.supplier.id,
        payeeKey: order.payeeKey ?? null,
        reference: written,
      }),
    );

  interface ClaimOptions {
    readonly id?: string;
    readonly supplier?: string;
    readonly payeeKey?: string | null;
    readonly reference?: string;
  }

  /** What claimOrder is given for the request's order: by default its first supplier's PO-2026/0042, no payee key. */
  const claimOf = (org: Org, request: string, options: ClaimOptions = {}) => ({
    orgId: org.id,
    id: options.id ?? randomUUID(),
    requestId: request,
    supplierId: options.supplier ?? org.supplier.id,
    payeeKey: options.payeeKey ?? null,
    reference: options.reference ?? 'PO-2026/0042',
    claimedAt: AT,
  });

  const claimed = (org: Org, request: string, options: ClaimOptions = {}) =>
    inOrg(org, (tx) => claimOrder(tx, claimOf(org, request, options)));

  const released = (org: Org, request: string) =>
    inOrg(org, (tx) => releaseClaim(tx, { requestId: request, releasedAt: AT }));

  it('works out the canonical form exactly as the request’s own order_key (ADR-006 §5)', async () => {
    const org = await organisation();
    await fc.assert(
      fc.asyncProperty(reference, async (written) => {
        const id = await approved(org, { order_reference: written });
        const row = await inOrg(org, (tx) =>
          tx
            .selectFrom('spend_requests.requests')
            .select((select) => [
              'order_key',
              orderKeyOf(written).as('asked'),
              orderKeyOf(select.ref('order_reference')).as('kept'),
            ])
            .where('id', '=', id)
            .executeTakeFirstOrThrow(),
        );
        expect(row.asked).toBe(row.order_key);
        expect(row.kept).toBe(row.order_key);
      }),
      // And always: two runs of spaces apart, each collapsed.
      { numRuns: 60, examples: [['P  o   4']] },
    );
  });

  it('finds an order claimed and open for the supplier, however it is written, and none once released', async () => {
    const org = await organisation();
    expect(await check(org, 'PO-2026/0042')).toBe(false);
    const request = await approved(org);
    expect(await claimed(org, request)).toBe('claimed');

    for (const written of ['PO-2026/0042', ' po-2026/0042 ', 'ＰＯ-2026/0042', 'po-2026/0042\u3000']) {
      expect(await check(org, written)).toBe(true);
    }
    // The same supplier, asked with a payee key it has since been given.
    expect(await check(org, 'PO-2026/0042', { payeeKey: 'payee-9' })).toBe(true);
    // Another order, or another supplier with no payee key in common.
    expect(await check(org, 'PO-2026/0043')).toBe(false);
    expect(await check(org, 'PO-2026/0042', { supplierId: (await supplierOf(org.id)).id })).toBe(false);

    await change(org, request, { status: 'CANCELLED' });
    expect(await released(org, request)).toBe(true);
    expect(await released(org, request)).toBe(false);
    expect(await check(org, 'PO-2026/0042')).toBe(false);
  });

  it('finds an order claimed under the same payee key by another supplier (ADR-014 §3)', async () => {
    const org = await organisation();
    const [first, second] = [await supplierOf(org.id, 'payee-1'), await supplierOf(org.id)];
    const request = await approved(org, { supplier_id: first.id, supplier_version_id: first.version });
    expect(await claimed(org, request, { supplier: first.id, payeeKey: 'payee-1' })).toBe('claimed');

    expect(await check(org, 'po-2026/0042', { supplierId: second.id, payeeKey: 'payee-1' })).toBe(true);
    expect(await check(org, 'po-2026/0042', { supplierId: second.id, payeeKey: 'payee-2' })).toBe(false);
    expect(await check(org, 'po-2026/0042', { supplierId: second.id })).toBe(false);
  });

  it('answers taken for an order already claimed, the transaction still usable', async () => {
    const org = await organisation();
    expect(await claimed(org, await approved(org))).toBe('claimed');
    const again = await approved(org, { order_reference: 'po-2026/0042 ' });
    const after = await inOrg(org, async (tx) => {
      const outcome = await claimOrder(tx, claimOf(org, again, { reference: 'po-2026/0042 ' }));
      return { outcome, seen: await hasOpenClaim(tx, claimOf(org, again)) };
    });
    expect(after).toEqual({ outcome: 'taken', seen: true });
  });

  it('answers taken for an order another supplier claimed under the same payee key (ADR-014 §3)', async () => {
    const org = await organisation();
    const [first, second] = [await supplierOf(org.id, 'payee-1'), await supplierOf(org.id)];
    expect(
      await claimed(org, await approved(org, onSupplier(first)), { supplier: first.id, payeeKey: 'payee-1' }),
    ).toBe('claimed');
    await movePayeeKey(first, second, 'payee-1');

    expect(
      await claimed(org, await approved(org, onSupplier(second)), { supplier: second.id, payeeKey: 'payee-1' }),
    ).toBe('taken');
  });

  it('fails, never answering taken, for a request claimed again or a claim ID used again', async () => {
    const org = await organisation();
    const request = await approved(org);
    const id = randomUUID();
    expect(await claimed(org, request, { id })).toBe('claimed');
    const conflicted = /no other request’s open claim/u;

    // Its own claim still open, and the same ID for another order.
    await expect(claimed(org, request)).rejects.toThrow(conflicted);
    await expect(
      claimed(org, await approved(org, { order_reference: 'PO-7' }), { id, reference: 'PO-7' }),
    ).rejects.toThrow(conflicted);
    // Its own claim released.
    await change(org, request, { status: 'CANCELLED' });
    await released(org, request);
    await expect(claimed(org, request)).rejects.toThrow(conflicted);
  });

  it('claims the request’s own order and supplier, or fails: never another', async () => {
    const org = await organisation();
    const request = await approved(org, { order_reference: '  ＰＯ  2026   0042 ' });
    expect(await claimed(org, request, { reference: '  ＰＯ  2026   0042 ' })).toBe('claimed');
    const kept = await inOrg(org, (tx) =>
      tx
        .selectFrom('spend_requests.order_claims')
        .select('order_reference')
        .where('request_id', '=', request)
        .executeTakeFirstOrThrow(),
    );
    expect(kept).toEqual({ order_reference: 'po 2026 0042' });

    // Another supplier, or another order, than the request's.
    const nine = await approved(org, { order_reference: 'PO-9' });
    for (const other of [{ supplier: (await supplierOf(org.id)).id, reference: 'PO-9' }, { reference: 'PO-10' }]) {
      await expect(claimed(org, nine, other)).rejects.toEqual(refusedBy('for_its_request', '23503'));
    }
    await expect(claimed(org, randomUUID())).rejects.toEqual(refusedBy('claim_guard'));
  });

  it('sees no other organisation’s claims', async () => {
    const org = await organisation();
    const other = await organisation();
    await claimed(org, await approved(org));
    expect(await check(other, 'PO-2026/0042', { supplierId: org.supplier.id })).toBe(false);
  });
});

describe('another organisation', () => {
  it('sees none of its requests or claims, and can’t add one in its name', async () => {
    const org = await organisation();
    const other = await organisation();
    await claim(org, claimRow(org, await approved(org)));

    const seen = await inOrg(other, async (tx) => [
      ...(await tx.selectFrom('spend_requests.requests').select('id').execute()),
      ...(await tx.selectFrom('spend_requests.order_claims').select('id').execute()),
    ]);
    expect(seen).toEqual([]);
    await expect(add(other, requestRow(org))).rejects.toEqual(DENIED);
  });
});
