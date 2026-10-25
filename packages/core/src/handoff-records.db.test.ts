// Phase 4 B3 (0058; PRD §3, §4.3; ADR-007 §7–§13): a handed-off request's
// instruction and transaction on the real migrated schema, as the app role.
// The instruction is made once, signed, entered in the directory and read
// back through its seal; one a request, whoever makes a second. The
// transaction is born SUBMISSION_PENDING and moved by its machine with the
// partner's facts beside; a move the machine doesn't allow changes nothing.
// Each changed past the app (FX-TAMPER) is read as tampered; the database's
// guards refuse what the app must never do; one organisation's are no
// other's.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { seedRows } from './seed-rows.helper.test.ts';
import { type AuditTables, withSignedStates } from './modules/audit/index.ts';
import type { DirectoryTables } from './modules/directory/index.ts';
import { createOrganization, type OrganizationsTables } from './modules/organizations/index.ts';
import {
  moveTransaction,
  noteTransactionFacts,
  openTransaction,
  type ProviderFacts,
  transactionOf,
  type TransactionsTables,
} from './modules/transactions/index.ts';
import {
  instructionOf,
  instructionOfRequest,
  intentHashOf,
  makeInstruction,
  type NewInstruction,
  organizationOfInstruction,
} from './modules/instructions/index.ts';
import type { InstructionsTables } from './modules/instructions/index.ts';

type Tables = InstructionsTables & TransactionsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb300_0000_0000);
const AT = new Date('2026-10-22T08:00:00Z');
const ACTOR = { type: 'system' as const, id: 'api' };
const NO_FACTS: ProviderFacts = {
  providerStatus: null,
  paymentInstructionRef: null,
  rejectCode: null,
  providerChangedAt: null,
};

const services = () => ({ keys, ids, logger: testLogger() });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** An organisation with an agent, a source, a supplier and a mandate, and an agent's request APPROVED on them: their IDs. */
async function approvedRequest() {
  const orgId = ids.next();
  await withSignedStates(app, orgId, services(), (tx, states) =>
    createOrganization(tx, states, { id: orgId, name: 'Acme Trading LLC', actor: ACTOR }),
  );
  const seed = seedRows(database.as('admin'), AT);
  const agent = await seed.agent(orgId);
  const key = await seed.agentKey(orgId, agent);
  const source = await seed.source(orgId);
  const supplier = await seed.supplier(orgId);
  const mandate = await seed.mandate(orgId, { agent, source, supplier: supplier.id });
  const request = randomUUID();
  await database.as('admin').query(
    `insert into spend_requests.requests (org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id,
       supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference,
       idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, created_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 100000, 'AED', 'Printer paper', 'INV-1', $10, $11, 1, 'ALLOW', null,
       'VALIDATING', $12)`,
    [
      orgId,
      request,
      agent,
      key,
      mandate.id,
      mandate.version,
      supplier.id,
      supplier.version,
      source,
      randomUUID(),
      'd'.repeat(64),
      AT,
    ],
  );
  return { orgId, request, source, supplierVersion: supplier.version };
}

/** What an instruction is made for: the organisation, the request, its source and the supplier version. */
interface Approved {
  readonly orgId: string;
  readonly request: string;
  readonly source: string;
  readonly supplierVersion: string;
}

const instructionFor = (
  { orgId, request, source, supplierVersion }: Approved,
  overrides: Partial<NewInstruction> = {},
): NewInstruction => ({
  orgId,
  id: ids.next(),
  spendRequestId: request,
  route: 'push',
  routeReason: 'one_source_one_rail',
  fundingSourceId: source,
  partner: 'fake',
  partnerLegalEntityId: 'FAKE-LEI-0001',
  partnerLicenceRef: 'FAKE-LICENCE-0001',
  accountConsentId: 'fake-consent-1',
  beneficiaryRef: 'fake-payee-1',
  supplierVersionId: supplierVersion,
  amountMinor: 100_000n,
  currency: 'AED',
  paymentReference: 'INV-1',
  createdAt: AT,
  ...overrides,
});

/** The instruction made and its transaction opened, in one transaction, as Tx A will: their IDs. */
async function handedOff(world: Approved, overrides: Partial<NewInstruction> = {}) {
  const instruction = instructionFor(world, overrides);
  const transactionId = ids.next();
  await withSignedStates(app, world.orgId, services(), async (tx, states) => {
    await makeInstruction(tx, states, instruction, { actor: ACTOR, details: {} });
    await openTransaction(
      tx,
      states,
      { orgId: world.orgId, id: transactionId, instructionId: instruction.id, createdAt: AT },
      { actor: ACTOR, details: {} },
    );
  });
  return { instruction, transactionId };
}

/**
 * The organisation's row changed as its owner can, the table's guards switched
 * off: what an attacker with owner-level access could do (its tenant wall binds
 * the owner too, so the organisation is named).
 */
const owner = async (
  orgId: string,
  table: 'instructions' | 'transactions',
  statement: string,
  values: unknown[],
): Promise<void> => {
  const session = await database.connect('owner');
  try {
    await session.query('begin');
    await session.query("select pg_catalog.set_config('app.org_id', $1, true)", [orgId]);
    if (table === 'instructions') await session.query('alter table instructions.instructions disable trigger user');
    else await session.query('alter table transactions.transactions disable trigger user');
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
    await session.query(statement, values);
    await session.query('commit');
  } finally {
    await session.end();
  }
  // Each `alter table` was the transaction's own: committed with it, the guards stay off until put back.
  const restore = await database.connect('owner');
  try {
    if (table === 'instructions') await restore.query('alter table instructions.instructions enable trigger user');
    else await restore.query('alter table transactions.transactions enable trigger user');
  } finally {
    await restore.end();
  }
};

describe('B3 the instruction (one a request, made once)', () => {
  it('is made, signed with its intent’s hash, entered in the directory, and read back through its seal', async () => {
    const world = await approvedRequest();
    const { instruction } = await handedOff(world);

    const read = await withSignedStates(app, world.orgId, services(), (tx, states) =>
      instructionOf(tx, states, { orgId: world.orgId, id: instruction.id }),
    );
    expect(read).toEqual({
      outcome: 'found',
      instruction: {
        ...instruction,
        orgId: undefined,
        intentHash: intentHashOf(instruction),
        createdAt: AT,
      },
    });
    const byRequest = await withSignedStates(app, world.orgId, services(), (tx, states) =>
      instructionOfRequest(tx, states, { orgId: world.orgId, spendRequestId: world.request }),
    );
    expect(byRequest).toMatchObject({ outcome: 'found', instruction: { id: instruction.id } });
    // Its signed event names the request it pays and the intent's hash, for the audit log and the evidence.
    const made = await withTenant(app, world.orgId, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'details'])
        .where('subject_type', '=', 'instruction')
        .where('subject_id', '=', instruction.id)
        .execute(),
    );
    expect(made.map(({ action, details }) => ({ action, details: JSON.parse(details) as unknown }))).toEqual([
      {
        action: 'instruction.made',
        details: expect.objectContaining({
          spendRequestId: world.request.toLowerCase(),
          intentHash: intentHashOf(instruction),
        }) as unknown,
      },
    ]);
    expect(await organizationOfInstruction(app, instruction.id)).toBe(world.orgId);
    expect(await organizationOfInstruction(app, ids.next())).toBeUndefined();
  });

  it('is one a request: a second, whoever makes it, is refused by the table’s key', async () => {
    const world = await approvedRequest();
    await handedOff(world);

    await expect(handedOff(world)).rejects.toMatchObject({ constraint: 'one_instruction_a_request' });
  });

  it('hashes every field, and no two fields’ texts run together alike', () => {
    const base = instructionFor({
      orgId: ids.next(),
      request: ids.next(),
      source: ids.next(),
      supplierVersion: ids.next(),
    });
    const hash = intentHashOf(base);
    const changes: Partial<NewInstruction>[] = [
      { orgId: ids.next() },
      { id: ids.next() },
      { spendRequestId: ids.next() },
      { routeReason: 'another_reason' },
      { fundingSourceId: ids.next() },
      { partner: 'other' },
      { partnerLegalEntityId: 'OTHER-LEI' },
      { partnerLicenceRef: 'OTHER-LICENCE' },
      { accountConsentId: 'fake-consent-2' },
      { beneficiaryRef: 'fake-payee-2' },
      { supplierVersionId: ids.next() },
      { amountMinor: 100_001n },
      { currency: 'USD' },
      { paymentReference: 'INV-2' },
    ];
    for (const changed of changes) expect(intentHashOf({ ...base, ...changed })).not.toBe(hash);
    // The same texts split differently between two fields are another intent.
    expect(intentHashOf({ ...base, partnerLegalEntityId: 'AB', partnerLicenceRef: 'C' })).not.toBe(
      intentHashOf({ ...base, partnerLegalEntityId: 'A', partnerLicenceRef: 'BC' }),
    );
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is read as tampered once changed past the app (FX-TAMPER), and its row refuses the app any change once made', async () => {
    const world = await approvedRequest();
    const { instruction } = await handedOff(world);

    await expect(
      withTenant(app, world.orgId, (tx) =>
        tx
          .updateTable('instructions.instructions')
          .set({ beneficiary_ref: 'attacker' })
          .where('id', '=', instruction.id)
          .execute(),
      ),
    ).rejects.toMatchObject({ constraint: 'made_once' });
    await owner(
      world.orgId,
      'instructions',
      'update instructions.instructions set beneficiary_ref = $2 where id = $1',
      [instruction.id, 'attacker'],
    );

    const read = await withSignedStates(app, world.orgId, services(), (tx, states) =>
      instructionOf(tx, states, { orgId: world.orgId, id: instruction.id }),
    );
    expect(read.outcome).toBe('tampered');
  });

  it('is no other organisation’s: none by its ID, none by its request', async () => {
    const world = await approvedRequest();
    const other = await approvedRequest();
    const { instruction } = await handedOff(world);

    const seen = await withSignedStates(app, other.orgId, services(), async (tx, states) => [
      (await instructionOf(tx, states, { orgId: other.orgId, id: instruction.id })).outcome,
      (await instructionOfRequest(tx, states, { orgId: other.orgId, spendRequestId: world.request })).outcome,
    ]);
    expect(seen).toEqual(['missing', 'missing']);
  });
});

describe('B3 the transaction (PRD §4.3)', () => {
  const move = (orgId: string, id: string, event: Parameters<typeof moveTransaction>[3], facts = NO_FACTS) =>
    withSignedStates(app, orgId, services(), (tx, states) =>
      moveTransaction(tx, states, { orgId, id }, event, facts, { actor: ACTOR, details: { via: 'test' } }),
    );
  const read = (orgId: string, id: string) =>
    withSignedStates(app, orgId, services(), (tx, states) => transactionOf(tx, states, { orgId, id }, 'share'));
  const eventsOf = (orgId: string, id: string) =>
    withTenant(app, orgId, (tx) =>
      tx
        .selectFrom('audit.events')
        .select('action')
        .where('subject_type', '=', 'transaction')
        .where('subject_id', '=', id)
        .orderBy('seq')
        .execute(),
    );

  it('is born SUBMISSION_PENDING with its instruction, and moves by its machine with the partner’s facts beside', async () => {
    const world = await approvedRequest();
    const { instruction, transactionId } = await handedOff(world);
    expect(await read(world.orgId, transactionId)).toMatchObject({
      outcome: 'found',
      transaction: { status: 'SUBMISSION_PENDING', instructionId: instruction.id, providerStatus: null },
    });

    const pending: ProviderFacts = {
      providerStatus: 'Pending',
      paymentInstructionRef: 'fake-payment-1',
      rejectCode: null,
      providerChangedAt: AT,
    };
    expect(await move(world.orgId, transactionId, 'submitted', pending)).toEqual({
      outcome: 'moved',
      from: 'SUBMISSION_PENDING',
      to: 'SUBMITTED',
    });
    // The same facts again note nothing new.
    expect(await move(world.orgId, transactionId, 'processing', pending)).toMatchObject({ to: 'PROCESSING' });
    const credited = {
      ...pending,
      providerStatus: 'AcceptedCreditSettlementCompleted',
      providerChangedAt: new Date(AT.getTime() + 120_000),
    };
    expect(await move(world.orgId, transactionId, 'succeed', credited)).toMatchObject({ to: 'SUCCEEDED' });

    expect(await read(world.orgId, transactionId)).toMatchObject({
      outcome: 'found',
      transaction: { status: 'SUCCEEDED', ...credited },
    });
  });

  it('refuses a move its machine doesn’t allow, changing nothing: never FAILED after SUCCEEDED, never back from FAILED', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);
    await move(world.orgId, transactionId, 'fail', { ...NO_FACTS, rejectCode: 'AANI.AM04' });

    expect(await move(world.orgId, transactionId, 'succeed')).toEqual({ outcome: 'refused', from: 'FAILED' });
    expect(await move(world.orgId, transactionId, 'lose_track')).toEqual({ outcome: 'refused', from: 'FAILED' });
    expect(await read(world.orgId, transactionId)).toMatchObject({
      transaction: { status: 'FAILED', rejectCode: 'AANI.AM04' },
    });
  });

  it('resolves an UNKNOWN only by evidence, and reverses a success only by the partner’s word', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);

    expect(await move(world.orgId, transactionId, 'lose_track')).toMatchObject({ to: 'UNKNOWN' });
    expect(await move(world.orgId, transactionId, 'succeed')).toMatchObject({ from: 'UNKNOWN', to: 'SUCCEEDED' });
    expect(await move(world.orgId, transactionId, 'reverse')).toMatchObject({ to: 'REVERSED' });
  });

  it('is read as tampered once its status is changed past the app; the guard refuses the app a move not listed', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);

    await expect(
      withTenant(app, world.orgId, (tx) =>
        tx
          .updateTable('transactions.transactions')
          .set({ status: 'SUCCEEDED' })
          .where('id', '=', transactionId)
          .execute(),
      ),
    ).rejects.toMatchObject({ constraint: 'status_guard' });
    await owner(
      world.orgId,
      'transactions',
      "update transactions.transactions set status = 'SUCCEEDED' where id = $1",
      [transactionId],
    );

    expect((await read(world.orgId, transactionId)).outcome).toBe('tampered');
    expect((await move(world.orgId, transactionId, 'reverse')).outcome).toBe('tampered');
  });

  it('keeps the facts given before when a later move gives none, and notes the same facts nothing new', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);
    const pending: ProviderFacts = {
      providerStatus: 'Pending',
      paymentInstructionRef: 'fake-payment-1',
      rejectCode: null,
      providerChangedAt: AT,
    };
    await move(world.orgId, transactionId, 'submitted', pending);
    await move(world.orgId, transactionId, 'processing', pending);
    await move(world.orgId, transactionId, 'lose_track');

    expect(await read(world.orgId, transactionId)).toMatchObject({ transaction: { status: 'UNKNOWN', ...pending } });
    const actions = (await eventsOf(world.orgId, transactionId)).map(({ action }) => action);
    expect(actions).toEqual([
      'transaction.opened',
      'transaction.provider_noted',
      'transaction.submitted',
      'transaction.processing',
      'transaction.lose_track',
    ]);
  });

  it('keeps the partner’s answer when its machine refuses the move, and notes facts with no move at all', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);
    await move(world.orgId, transactionId, 'submitted', { ...NO_FACTS, providerStatus: 'Pending' });
    await move(world.orgId, transactionId, 'processing');

    // Under way again, later: refused as a move, kept as evidence.
    const later = {
      ...NO_FACTS,
      providerStatus: 'AcceptedSettlementCompleted',
      providerChangedAt: new Date(AT.getTime() + 60_000),
    };
    expect(await move(world.orgId, transactionId, 'processing', later)).toEqual({
      outcome: 'refused',
      from: 'PROCESSING',
    });
    expect(await read(world.orgId, transactionId)).toMatchObject({ transaction: { status: 'PROCESSING', ...later } });

    const latest = { ...later, providerChangedAt: new Date(AT.getTime() + 90_000) };
    expect(
      await withSignedStates(app, world.orgId, services(), (tx, states) =>
        noteTransactionFacts(tx, states, { orgId: world.orgId, id: transactionId }, latest, {
          actor: ACTOR,
          details: {},
        }),
      ),
    ).toEqual({ outcome: 'noted' });
    expect(await read(world.orgId, transactionId)).toMatchObject({
      transaction: { providerChangedAt: latest.providerChangedAt },
    });
    expect(
      await withSignedStates(app, world.orgId, services(), (tx, states) =>
        noteTransactionFacts(tx, states, { orgId: world.orgId, id: ids.next() }, latest, { actor: ACTOR, details: {} }),
      ),
    ).toEqual({ outcome: 'missing' });
  });

  it('never lets an older status replace a newer one: a late answer after a lookup keeps the newer word (E1a)', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);
    const credited: ProviderFacts = {
      providerStatus: 'AcceptedCreditSettlementCompleted',
      paymentInstructionRef: null,
      rejectCode: null,
      providerChangedAt: new Date(AT.getTime() + 120_000),
    };
    await move(world.orgId, transactionId, 'submitted', credited);
    await move(world.orgId, transactionId, 'succeed', credited);

    // The hand-off's own answer, from before: its reference is new and kept, its older status isn't.
    const late: ProviderFacts = {
      providerStatus: 'Pending',
      paymentInstructionRef: 'fake-payment-1',
      rejectCode: 'AANI.XX00',
      providerChangedAt: AT,
    };
    expect(await move(world.orgId, transactionId, 'submitted', late)).toEqual({
      outcome: 'refused',
      from: 'SUCCEEDED',
    });
    expect(await read(world.orgId, transactionId)).toMatchObject({
      transaction: { status: 'SUCCEEDED', ...credited, paymentInstructionRef: 'fake-payment-1' },
    });

    // One as new as the kept one replaces it (the bank's newest word at the same moment).
    const same = { ...late, providerStatus: 'Rejected', providerChangedAt: credited.providerChangedAt };
    await move(world.orgId, transactionId, 'reverse', same);
    expect(await read(world.orgId, transactionId)).toMatchObject({
      transaction: { providerStatus: 'Rejected', rejectCode: 'AANI.XX00' },
    });
  });

  it('moves SUBMISSION_PENDING to SUBMITTED to SUCCEEDED in one transaction (ADR-007 §13)', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);
    const credited = {
      ...NO_FACTS,
      providerStatus: 'AcceptedCreditSettlementCompleted',
      paymentInstructionRef: 'fake-payment-9',
    };

    await withSignedStates(app, world.orgId, services(), async (tx, states) => {
      const key = { orgId: world.orgId, id: transactionId };
      await moveTransaction(tx, states, key, 'submitted', credited, { actor: ACTOR, details: {} });
      await moveTransaction(tx, states, key, 'succeed', credited, { actor: ACTOR, details: {} });
    });

    expect(await read(world.orgId, transactionId)).toMatchObject({ transaction: { status: 'SUCCEEDED', ...credited } });
  });

  it('fails only with proof: a reject code, or an evidence reference a person attached (ADR-007 §9–§10)', async () => {
    const world = await approvedRequest();
    const { transactionId } = await handedOff(world);

    await expect(move(world.orgId, transactionId, 'fail')).rejects.toThrow(RangeError);
    await move(world.orgId, transactionId, 'lose_track');
    expect(
      await withSignedStates(app, world.orgId, services(), (tx, states) =>
        moveTransaction(tx, states, { orgId: world.orgId, id: transactionId }, 'fail', NO_FACTS, {
          actor: ACTOR,
          details: { evidenceRef: 'PARTNER-CASE-77' },
        }),
      ),
    ).toMatchObject({ outcome: 'moved', to: 'FAILED' });
  });

  it('is one an instruction, its instruction and opening fixed: the database refuses the app either change', async () => {
    const world = await approvedRequest();
    const { instruction, transactionId } = await handedOff(world);

    await expect(
      withSignedStates(app, world.orgId, services(), (tx, states) =>
        openTransaction(
          tx,
          states,
          { orgId: world.orgId, id: ids.next(), instructionId: instruction.id, createdAt: AT },
          { actor: ACTOR, details: {} },
        ),
      ),
    ).rejects.toMatchObject({ constraint: 'one_transaction_an_instruction' });
    await expect(
      withTenant(app, world.orgId, (tx) =>
        tx
          .updateTable('transactions.transactions')
          .set({ created_at: new Date(AT.getTime() + 1) })
          .where('id', '=', transactionId)
          .execute(),
      ),
    ).rejects.toMatchObject({ constraint: 'fixed_at_creation' });
  });

  it('a move on a transaction that isn’t there is missing', async () => {
    const world = await approvedRequest();
    expect(await move(world.orgId, ids.next(), 'submitted')).toEqual({ outcome: 'missing' });
  });
});
