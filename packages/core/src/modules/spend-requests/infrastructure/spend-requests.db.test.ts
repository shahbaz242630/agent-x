// D1: spend requests and their order claims (0039), on the real migrated
// schema, as the app role. The steps that decide, add and move them come with
// D3–D4 and their seals' tamper tests with them; this holds the tables' own
// rules: a request born VALIDATING with its decision, moved only along its
// machine and only where its decision leads, fixed but for its status, its
// reasons with its decision, capacity held only on the versions weighed,
// those versions its organisation's own and of the mandate and supplier
// named; one open claim an order, by supplier and by payee, released only;
// and no other organisation's rows, no deletes.
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import type { Insertable, Updateable } from 'kysely';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DECISIONS } from '../../policies/index.ts';
import type { SpendRequestsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendRequestsTables>;

const AT = new Date('2026-10-08T08:00:00Z');

type Tx = DatabaseTransaction<SpendRequestsTables>;
type RequestRow = Insertable<SpendRequestsTables['spend_requests.requests']>;
type ClaimRow = Insertable<SpendRequestsTables['spend_requests.order_claims']>;

interface Supplier {
  readonly id: string;
  readonly version: string;
}

interface Org {
  readonly id: string;
  readonly agent: string;
  readonly key: string;
  readonly mandate: string;
  readonly mandateVersion: string;
  readonly supplier: Supplier;
}

/** A supplier of the organisation with its first version, made past the app, as the steps that add them are tested elsewhere. */
const supplierOf = async (org: string, payeeKey: string | null = null): Promise<Supplier> => {
  const supplier = { id: randomUUID(), version: randomUUID() };
  await database.as('admin').query(
    `with supplier as (
       insert into suppliers.suppliers (org_id, id, status, current_version_id, payee_key, created_at)
       values ($1, $2, 'UNVERIFIED', $3, $4, $5) returning org_id)
     insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts,
       phone_ciphertext, contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
     select org_id, $3, $2, 1, 'Gulf Office Supplies LLC', 'phone', pg_catalog.decode(pg_catalog.repeat('00', 40), 'hex'),
       1, $5, 'registry', 'trade-licence-1', $2, $5 from supplier`,
    [org, supplier.id, supplier.version, payeeKey, AT],
  );
  return supplier;
};

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

/** An organisation with an agent, its key, a mandate waiting with its draft, and a supplier, made past the app. */
const organisation = async (): Promise<Org> => {
  const org = randomUUID();
  const [agent, key, source, link, mandate, mandateVersion] = [
    randomUUID(),
    randomUUID(),
    randomUUID(),
    randomUUID(),
    randomUUID(),
    randomUUID(),
  ];
  const admin = database.as('admin');
  await admin.query('insert into directory.orgs (org_id) values ($1)', [org]);
  await admin.query(
    `insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
     values ($1, $2, 'Purchasing agent', $3, 'ACTIVE', 'requests:write', $4)`,
    [org, agent, randomUUID(), AT],
  );
  await admin.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [key, org]);
  await admin.query(
    `insert into agents.agent_keys (org_id, id, agent_id, status, scopes, secret_mac, secret_key_version, expires_at,
       created_at)
     values ($1, $2, $3, 'ACTIVE', 'requests:write', $4, 1, '2027-10-08T08:00:00Z', $5)`,
    [org, key, agent, 'c'.repeat(64), AT],
  );
  await admin.query(
    `insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at)
     values ($1, $2, $3, 'fake', 'session-1', $5, $4)`,
    [org, link, randomUUID(), AT, new Date(AT.getTime() + 86_400_000)],
  );
  await admin.query(
    `insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability,
       consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor,
       max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at)
     values ($1, $2, $3, 'fake', $4, 'ACTIVE', 'ACTIVE', 'Authorized', 'consent-1', '2027-10-06T08:00:00Z', 'AED',
       'month', 5000000, 20000000, 100, 'Acme Trading LLC', 'sme', 'AE…1234', $5, $5)`,
    [org, source, link, `acct-${source}`, AT],
  );
  const supplier = await supplierOf(org);
  await admin.query(
    `with mandate as (
       insert into mandates.mandates (org_id, id, agent_id, time_zone, split_window_hours, status, pending_version_id,
         created_at)
       values ($1, $2, $3, 'Asia/Dubai', 24, 'PENDING_ACCEPTANCE', $4, $5) returning org_id)
     insert into mandates.versions (org_id, id, mandate_id, version, purpose, currency, per_order_limit_minor,
       monthly_limit_minor, approval_threshold_minor, supplier_ids, funding_source_id, split_check, consent_limits,
       terms_hash, drafted_by, drafted_at)
     select org_id, $4, $2, 1, 'Office supplies', 'AED', 500000, 2000000, 100000, $6, $7, 'on', 'strict', $8, $3, $5
     from mandate`,
    [org, mandate, agent, mandateVersion, AT, supplier.id, source, 'a'.repeat(64)],
  );
  return { id: org, agent, key, mandate, mandateVersion, supplier };
};

const inOrg = <Result>(org: Org, work: (tx: Tx) => Promise<Result>) => withTenant(app, org.id, work);

/** An ALLOW request as D4 will add it, VALIDATING with its decision, with any column given otherwise. */
const requestRow = (org: Org, overrides: Partial<RequestRow> = {}): RequestRow => ({
  org_id: org.id,
  id: randomUUID(),
  agent_id: org.agent,
  agent_key_id: org.key,
  mandate_id: org.mandate,
  mandate_version_id: org.mandateVersion,
  organization_policy_version_id: null,
  mandate_policy_version_id: null,
  supplier_id: org.supplier.id,
  supplier_version_id: org.supplier.version,
  funding_source_id: randomUUID(),
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

const statusOf = async (org: Org, id: string) =>
  inOrg(org, (tx) =>
    tx.selectFrom('spend_requests.requests').select('status').where('id', '=', id).executeTakeFirstOrThrow(),
  );

/** A claim on an approved request's order, with any column given otherwise. */
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

/** An approved request, ready to claim its order. */
const approved = (org: Org, overrides: Partial<RequestRow> = {}) => moved(org, requestRow(org, overrides), 'APPROVED');

const refusedBy = (constraint: string): unknown => expect.objectContaining({ constraint });
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
  it('is born VALIDATING with its decision, and moved by it: ALLOW to APPROVED', async () => {
    const org = await organisation();
    const id = await moved(org, requestRow(org), 'APPROVED');

    expect(await statusOf(org, id)).toEqual({ status: 'APPROVED' });
  });

  it('is never born in another status (status_guard)', async () => {
    const org = await organisation();
    await expect(add(org, requestRow(org, { status: 'APPROVED' }))).rejects.toEqual(refusedBy('status_guard'));
  });

  it('takes every decision the engine makes', async () => {
    const org = await organisation();
    for (const decision of DECISIONS) {
      const reasons = decision === 'ALLOW' ? null : 'APPROVAL_THRESHOLD';
      await add(org, requestRow(org, { decision, reason_codes: reasons }));
    }
    await expect(add(org, requestRow(org, { decision: 'MAYBE', reason_codes: 'X' }))).rejects.toEqual(
      refusedBy('requests_decision_check'),
    );
  });

  it('denied with no mandate, another organisation’s supplier and source, is still recorded as asked', async () => {
    const org = await organisation();
    const row = requestRow(org, {
      mandate_id: null,
      mandate_version_id: null,
      supplier_id: randomUUID(),
      supplier_version_id: null,
      decision: 'DENY',
      reason_codes: 'MANDATE_NOT_IN_FORCE SUPPLIER_NOT_ALLOWED SOURCE_NOT_MANDATED',
    });

    expect(await statusOf(org, await moved(org, row, 'DENIED'))).toEqual({ status: 'DENIED' });
  });

  it('REQUIRE_APPROVAL waits, then is approved, made ready and handed off', async () => {
    const org = await organisation();
    const row = requestRow(org, { decision: 'REQUIRE_APPROVAL', reason_codes: 'APPROVAL_THRESHOLD' });
    const id = await moved(org, row, 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF');

    expect(await statusOf(org, id)).toEqual({ status: 'HANDED_OFF' });
  });

  it('waiting for approval, may be rejected, expired or cancelled', async () => {
    const org = await organisation();
    const waiting = { decision: 'REQUIRE_APPROVAL', reason_codes: 'AGGREGATE_THRESHOLD' };
    for (const end of ['DENIED', 'EXPIRED', 'CANCELLED']) {
      const id = await moved(org, requestRow(org, waiting), 'APPROVAL_REQUIRED', end);
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

  it('denied, is never approved, waiting or ready (a_status_on_its_decision)', async () => {
    const org = await organisation();
    for (const decision of ['DENY', 'REQUIRE_NEW_MANDATE']) {
      const row = requestRow(org, { decision, reason_codes: 'MANDATE_ORDER_LIMIT' });
      await add(org, row);
      for (const status of ['APPROVED', 'APPROVAL_REQUIRED']) {
        await expect(change(org, row.id, { status })).rejects.toEqual(refusedBy('a_status_on_its_decision'));
      }
    }
  });

  it('allowed, never waits for an approval (a_status_on_its_decision)', async () => {
    const org = await organisation();
    const row = requestRow(org);
    await add(org, row);

    await expect(change(org, row.id, { status: 'APPROVAL_REQUIRED' })).rejects.toEqual(
      refusedBy('a_status_on_its_decision'),
    );
  });

  it('moves only along its machine: never back, never on from an end, never handed off unready (status_guard)', async () => {
    const org = await organisation();
    const denied = await moved(org, requestRow(org), 'DENIED');
    const handedOff = await moved(org, requestRow(org), 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF');
    const approvedOne = await moved(org, requestRow(org), 'APPROVED');

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
    const id = await moved(org, requestRow(org), 'APPROVED');

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
      await expect(add(org, requestRow(org, { decision: 'DENY', reason_codes: reasons }))).rejects.toEqual(
        refusedBy('requests_reason_codes_check'),
      );
    }
  });

  it('holds capacity only on the mandate and supplier versions it weighed (holds_on_what_it_weighed)', async () => {
    const org = await organisation();
    for (const decision of ['ALLOW', 'REQUIRE_APPROVAL']) {
      const reasons = decision === 'ALLOW' ? null : 'APPROVAL_THRESHOLD';
      for (const missing of [{ supplier_version_id: null }, { mandate_id: null, mandate_version_id: null }]) {
        await expect(add(org, requestRow(org, { decision, reason_codes: reasons, ...missing }))).rejects.toEqual(
          refusedBy('holds_on_what_it_weighed'),
        );
      }
    }
  });

  it('names a mandate with the version weighed, and a mandate’s policy only with its mandate', async () => {
    const org = await organisation();
    const denied = { decision: 'DENY', reason_codes: 'MANDATE_NOT_IN_FORCE' };
    await expect(add(org, requestRow(org, { ...denied, mandate_version_id: null }))).rejects.toEqual(
      refusedBy('a_mandate_with_its_version'),
    );
    const policyVersion = await policyOf(org.id, 'mandate', org.mandate);
    await expect(
      add(
        org,
        requestRow(org, {
          ...denied,
          mandate_id: null,
          mandate_version_id: null,
          mandate_policy_version_id: policyVersion,
        }),
      ),
    ).rejects.toEqual(refusedBy('a_mandate_policy_with_its_mandate'));
  });

  it('weighs only its own mandate’s version, its supplier’s and its policies: the organisation’s and the mandate’s', async () => {
    const org = await organisation();
    const other = await organisation();
    const otherSupplier = await supplierOf(org.id);
    const organizationPolicy = await policyOf(org.id, 'organization', org.id);
    const mandatePolicy = await policyOf(org.id, 'mandate', org.mandate);

    await add(
      org,
      requestRow(org, { organization_policy_version_id: organizationPolicy, mandate_policy_version_id: mandatePolicy }),
    );
    for (const [values, constraint] of [
      [{ supplier_version_id: otherSupplier.version }, 'to_a_supplier_version'],
      [{ mandate_version_id: other.mandateVersion }, 'under_a_mandate_version'],
      // The mandate's policy is no organisation's, nor the organisation's any mandate's.
      [{ organization_policy_version_id: mandatePolicy }, 'under_the_organizations_policy'],
      [{ mandate_policy_version_id: organizationPolicy }, 'under_the_mandates_policy'],
      [{ agent_key_id: other.key }, 'with_a_key'],
      [{ agent_id: other.agent }, 'of_an_agent'],
    ] as const) {
      await expect(add(org, requestRow(org, values))).rejects.toEqual(
        expect.objectContaining({ code: '23503', constraint }),
      );
    }
  });

  it('is in an allowed currency, for a positive amount, with a purpose', async () => {
    const org = await organisation();
    await expect(add(org, requestRow(org, { currency: 'USD' }))).rejects.toEqual(
      expect.objectContaining({ code: '23503', constraint: 'requests_currency_fkey' }),
    );
    await expect(add(org, requestRow(org, { amount_minor: 0n }))).rejects.toEqual(
      refusedBy('requests_amount_minor_check'),
    );
    for (const purpose of ['', 'a'.repeat(201), 'line\nbreak']) {
      await expect(add(org, requestRow(org, { purpose }))).rejects.toEqual(refusedBy('requests_purpose_check'));
    }
  });

  it('keeps its order reference as written, in the rail’s 1 to 35 ASCII characters, not blank', async () => {
    const org = await organisation();
    await add(org, requestRow(org, { order_reference: " Inv 7/B (26): 1,200.50+VAT-'x'? " }));
    for (const reference of ['', '   ', 'a'.repeat(36), 'فاتورة', 'PO_1', 'PO#1', 'Café']) {
      await expect(add(org, requestRow(org, { order_reference: reference }))).rejects.toEqual(
        refusedBy('requests_order_reference_check'),
      );
    }
  });

  it('keeps a keyed hash of what it weighed, with its key’s version, and its idempotency key', async () => {
    const org = await organisation();
    for (const values of [
      [{ input_hash: 'D'.repeat(64) }, 'requests_input_hash_check'],
      [{ input_hash_key_version: 0 }, 'requests_input_hash_key_version_check'],
      [{ idempotency_key: '' }, 'requests_idempotency_key_check'],
      [{ idempotency_key: 'k'.repeat(256) }, 'requests_idempotency_key_check'],
    ] as const) {
      await expect(add(org, requestRow(org, values[0]))).rejects.toEqual(refusedBy(values[1]));
    }
  });

  it('is never deleted, nor moved to another key', async () => {
    const org = await organisation();
    const id = await moved(org, requestRow(org), 'APPROVED');

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
    const first = claimRow(org, await approved(org));
    await claim(org, first);

    await expect(claim(org, claimRow(org, await approved(org)))).rejects.toEqual(
      expect.objectContaining({ code: '23505', constraint: 'one_open_claim_a_supplier_order' }),
    );
    await inOrg(org, (tx) =>
      tx.updateTable('spend_requests.order_claims').set({ released_at: AT }).where('id', '=', first.id).execute(),
    );
    await claim(org, claimRow(org, await approved(org)));
  });

  it('holds the same order for another supplier apart, and another order for the same one', async () => {
    const org = await organisation();
    const another = await supplierOf(org.id);
    await claim(org, claimRow(org, await approved(org)));

    const anotherRequest = await approved(org, { supplier_id: another.id, supplier_version_id: another.version });
    await claim(org, claimRow(org, anotherRequest, { supplier_id: another.id }));
    await claim(org, claimRow(org, await approved(org), { order_reference: 'po-2026/0043' }));
  });

  it('holds an order once by its payee too: a supplier re-created with the same account is refused', async () => {
    const org = await organisation();
    // One supplier a payee at a time (0033): the claim keeps the key the first had when it claimed, after it moved on.
    const [first, second] = [await supplierOf(org.id), await supplierOf(org.id)];
    const on = (supplier: Supplier) => ({ supplier_id: supplier.id, supplier_version_id: supplier.version });
    await claim(org, claimRow(org, await approved(org, on(first)), { supplier_id: first.id, payee_key: 'payee-1' }));

    await expect(
      claim(org, claimRow(org, await approved(org, on(second)), { supplier_id: second.id, payee_key: 'payee-1' })),
    ).rejects.toEqual(expect.objectContaining({ code: '23505', constraint: 'one_open_claim_a_payee_order' }));
    await claim(org, claimRow(org, await approved(org, on(second)), { supplier_id: second.id, payee_key: 'payee-2' }));
  });

  it('is its request’s only one, on its request’s own supplier', async () => {
    const org = await organisation();
    const request = await approved(org);
    await claim(org, claimRow(org, request));

    await expect(claim(org, claimRow(org, request, { order_reference: 'po-2026/0099' }))).rejects.toEqual(
      refusedBy('one_claim_a_request'),
    );
    const another = await supplierOf(org.id);
    await expect(claim(org, claimRow(org, await approved(org), { supplier_id: another.id }))).rejects.toEqual(
      expect.objectContaining({ code: '23503', constraint: 'for_its_request' }),
    );
  });

  it('keeps the canonical form: lower case, words one space apart, in the rail’s characters', async () => {
    const org = await organisation();
    for (const reference of ['PO-2026/0042', 'po  2026', ' po', 'po ', '', 'a'.repeat(36), 'po_1']) {
      await expect(claim(org, claimRow(org, await approved(org), { order_reference: reference }))).rejects.toEqual(
        refusedBy('order_claims_order_reference_check'),
      );
    }
  });

  it('is released no earlier than it was made, and only released: never deleted, nor its order changed', async () => {
    const org = await organisation();
    const row = claimRow(org, await approved(org));
    await claim(org, row);
    const update = (values: Updateable<SpendRequestsTables['spend_requests.order_claims']>) =>
      inOrg(org, (tx) => tx.updateTable('spend_requests.order_claims').set(values).where('id', '=', row.id).execute());

    await expect(update({ released_at: new Date(AT.getTime() - 1) })).rejects.toEqual(
      refusedBy('released_after_its_claim'),
    );
    for (const values of [{ order_reference: 'po-other' }, { supplier_id: randomUUID() }, { payee_key: 'x' }]) {
      await expect(update(values)).rejects.toEqual(DENIED);
    }
    await expect(
      inOrg(org, (tx) => tx.deleteFrom('spend_requests.order_claims').where('id', '=', row.id).execute()),
    ).rejects.toEqual(DENIED);
  });
});

describe('another organisation', () => {
  it('sees none of its requests or claims, and can’t add one in its name', async () => {
    const org = await organisation();
    const other = await organisation();
    const request = await approved(org);
    await claim(org, claimRow(org, request));

    const seen = await inOrg(other, async (tx) => [
      ...(await tx.selectFrom('spend_requests.requests').select('id').execute()),
      ...(await tx.selectFrom('spend_requests.order_claims').select('id').execute()),
    ]);
    expect(seen).toEqual([]);
    await expect(add(other, requestRow(org))).rejects.toEqual(DENIED);
  });
});
