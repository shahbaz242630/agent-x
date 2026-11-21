// AT13 (R-15) on the organisation's policy, as the database's owner: agentx_owner, holding none of the app's keys,
// inside one organisation through @agentx/testing's tamperAsOwner. A policy widened back by deleting its newest change's
// event below the anchor (older than the chain's last 1,000, which no check each run reads) and putting its row back
// as it was before, every seal true: without the signed states' digest it reads as the wider policy; held to the digest
// the anchor check's walk kept, it is refused at decision time, the alarm raised and the organisation held.
import { CHAIN_START, createDigestLog, type DigestLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import { type AuditTables, checkStatesWith, createAuditTrail, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { PolicyRules } from '../domain/policy.ts';
import { POLICIES } from './mandates.ts';
import { policyOf, setPolicy } from './policies.ts';
import type { MandatesTables } from './tables.ts';

type Tables = MandatesTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x13_0000);
const clock = new FixedClock(new Date('2026-11-21T09:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let capture: LogCapture;
let owner: OwnerTamper;
let org: string;

const services = () => ({ keys, ids, logger: testLogger(capture) });
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Rules with a monthly cap of `dirhams`. */
const cappedAt = (dirhams: bigint): PolicyRules => ({
  currency: 'AED',
  perOrderCap: null,
  monthlyCap: money(dirhams * 100n, 'AED'),
  approvalThreshold: null,
  supplierIds: null,
});

/** The organisation's policy set to `rules`, as the use case sets it: read for change, then moved on. */
const policySet = (rules: PolicyRules) =>
  withSignedStates(app, org, { keys, ids, logger: testLogger() }, async (tx, states) => {
    const read = await policyOf(tx, states, { orgId: org, id: org }, 'change');
    await setPolicy(tx, states, {
      orgId: org,
      existing: read.outcome === 'found' ? read : null,
      scope: 'organization',
      mandateId: null,
      versionId: ids.next(),
      rules,
      madeBy: ids.next(),
      madeAt: clock.now(),
      actor: OPERATOR,
      details: {},
    });
  });

/** The policy as a decision reads it. */
const policyNow = () =>
  withSignedStates(app, org, services(), (tx, states) => policyOf(tx, states, { orgId: org, id: org }, 'share'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: testLogger() }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, POLICIES, org);
});

afterEach(async () => {
  await owner.end();
});

describe(`AT13 an organisation's policy change deleted below the anchor, its row rolled back (R-15; Postgres ${server.version})`, () => {
  /**
   * A cap of 50,000 lowered to 1,000; the anchor check's walk kept in a digest; then the lowering's event deleted past
   * the app and the row put back at the wider version.
   */
  async function widenedBack(): Promise<{ digest: DigestLog; wider: string }> {
    await policySet(cappedAt(50_000n));
    const before = await owner.saveRow(org);
    const wider = await policyNow();
    if (wider.outcome !== 'found') throw new Error('the policy should read');
    await policySet(cappedAt(1000n));
    const step = await createAuditTrail({ keys, ids }).checkFromAnchor(app, org, CHAIN_START);
    if (!step.ok || step.signed === undefined) throw new Error('The chain should have checked out');
    const digest = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 1024 * 1024,
    });
    digest.record({ kind: 'organisation', orgId: org }, step.signed, clock.now(), { from: 0n, to: step });
    await owner.query("delete from audit.events where org_id = $1 and subject_id = $2 and action = 'policy.changed'", [
      org,
      org,
    ]);
    await owner.restoreRow(before);
    return { digest, wider: wider.policy.currentVersionId };
  }

  it('the positive control: without the digest, the policy reads as the wider version again', async () => {
    const { wider } = await widenedBack();
    expect(await policyNow()).toMatchObject({ outcome: 'found', policy: { currentVersionId: wider } });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('held to the digest: refused at decision time, the alarm at the walk’s place, and the organisation held', async () => {
    const { digest } = await widenedBack();
    checkStatesWith(digest);
    try {
      expect(await policyNow()).toEqual({ outcome: 'tampered', sign: 'log' });
    } finally {
      checkStatesWith(undefined);
    }
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ check: 'state', reason: 'log', subjectType: 'policy', objectId: org, orgId: org }),
    ]);
    expect(
      await withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none')),
    ).toMatchObject({ outcome: 'held' });
  });
});
