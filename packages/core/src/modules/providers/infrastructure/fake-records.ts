// Where the fake partner keeps its records (D2-1): in memory for the unit
// tests, and in the database (0028) wherever it must outlive a restart and be
// the same partner to every process: on staging, the API and the test steps
// playing the business at its bank. Both pass the same contract tests.
//
// Every record is one organisation's, reached only inside `within` for it,
// which runs its work as one atomic step: in the database, withTenant's
// transaction, each record read locked until it ends (each statement bounded,
// so a step held open fails rather than stalls the rest); in memory, one step
// at a time. So two calls acting on the same record never both act on what
// the other hasn't yet written. A record not there yet can't be locked: two
// calls adding it at once both find none, and the second's `add` waits for the
// first's step, then adds nothing and says so, and the caller reads what the
// first added.
import { limitStatements, withTenant } from '@agentx/platform/db';
import type { Kysely, Transaction } from 'kysely';

import type { ConsentControls, PayeeNameCheck } from '../domain/rail.ts';
import type { ConsentStatus } from '../domain/uae-consent.ts';

/** A link's session at the partner (ref: our link ID; alias: the session's reference). */
interface LinkBody {
  readonly expiresAt: string;
  readonly outcome: 'open' | 'rejected' | { readonly externalRef: string };
}

/** A source and its current consent (ref: the partner's source reference; alias: the consent's ID). */
export interface SourceBody {
  /** The sandbox account's ID at the fake bank: never its number. */
  readonly accountId: string;
  readonly replacesConsentId: string | null;
  readonly status: ConsentStatus;
  readonly statusChangedAt: string;
  readonly expiresAt: string;
  readonly controls: {
    readonly currency: string;
    readonly period: ConsentControls['period'];
    /** Minor units, as decimal text: JSON has no bigint. */
    readonly maxPaymentMinor: string;
    readonly maxPeriodMinor: string;
    readonly maxPeriodPayments: number;
  };
}

/** A payee registered, as the partner holds it: masked parts alone. */
export interface BeneficiaryBody {
  readonly beneficiaryRef: string;
  readonly payeeIdentity: string | null;
  readonly nameCheck: PayeeNameCheck;
  readonly maskedName: string | null;
  readonly hint: string;
  readonly registeredAt: string;
}

/** A payee registration (ref: our registration ID; alias: its hosted form's reference, none for a pass-through). */
export interface RegistrationBody {
  readonly form: { readonly formRef: string; readonly expiresAt: string } | null;
  readonly outcome: 'waiting' | 'invalid_details' | { readonly beneficiary: BeneficiaryBody };
}

interface FakeBodies {
  readonly link: LinkBody;
  readonly source: SourceBody;
  readonly registration: RegistrationBody;
}

type FakeRecordKind = keyof FakeBodies;

export interface FakeRecord<K extends FakeRecordKind> {
  readonly ref: string;
  /** Every link and source has one; a registration only for a hosted form. */
  readonly alias: K extends 'registration' ? string | null : string;
  readonly body: FakeBodies[K];
}

/** One organisation's records, inside one atomic step. */
export interface FakeRecords {
  readonly organizationId: string;
  get<K extends FakeRecordKind>(kind: K, ref: string): Promise<FakeRecord<K> | undefined>;
  byAlias<K extends FakeRecordKind>(kind: K, alias: string): Promise<FakeRecord<K> | undefined>;
  /**
   * Adds the record; false, adding nothing, when one of its kind and
   * reference is there already. Another of its kind holding the same alias
   * is refused.
   */
  add<K extends FakeRecordKind>(kind: K, record: FakeRecord<K>): Promise<boolean>;
  /** Replaces the record of its kind and reference; refused when there is none, or another holds its alias. */
  update<K extends FakeRecordKind>(kind: K, record: FakeRecord<K>): Promise<void>;
}

export interface FakePartnerStore {
  within<T>(organizationId: string, work: (records: FakeRecords) => Promise<T>): Promise<T>;
}

/** A copy through JSON, as the database would give back: what the fake holds is never the caller's object. */
const copied = <T>(value: T): T => (value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T));

const NO_SUCH_RECORD = 'The fake partner holds no such record';

/** The records in memory, for the unit tests: one step at a time, as the database's locks would have it. */
export function createMemoryRecords(): FakePartnerStore {
  const records = new Map<string, FakeRecord<FakeRecordKind>>();
  let queue: Promise<unknown> = Promise.resolve();
  const key = (organizationId: string, kind: FakeRecordKind, ref: string): string => `${organizationId} ${kind} ${ref}`;

  const of = (organizationId: string): FakeRecords => {
    const withAlias = (kind: FakeRecordKind, alias: string) => {
      const prefix = key(organizationId, kind, '');
      return [...records].find(([each, record]) => each.startsWith(prefix) && record.alias === alias)?.[1];
    };
    /** Sets the record, as the table's unique alias allows: never two of a kind with one alias. */
    const set = (kind: FakeRecordKind, record: FakeRecord<FakeRecordKind>): Promise<void> => {
      const holder = record.alias === null ? undefined : withAlias(kind, record.alias);
      if (holder !== undefined && holder.ref !== record.ref) {
        return Promise.reject(new Error('Another record of the fake partner holds that alias'));
      }
      records.set(key(organizationId, kind, record.ref), copied(record));
      return Promise.resolve();
    };
    return {
      organizationId,
      get: <K extends FakeRecordKind>(kind: K, ref: string) =>
        Promise.resolve(copied(records.get(key(organizationId, kind, ref)) as FakeRecord<K> | undefined)),
      byAlias: <K extends FakeRecordKind>(kind: K, alias: string) =>
        Promise.resolve(copied(withAlias(kind, alias) as FakeRecord<K> | undefined)),
      add: async (kind, record) => {
        if (records.has(key(organizationId, kind, record.ref))) return false;
        await set(kind, record);
        return true;
      },
      update: (kind, record) =>
        records.has(key(organizationId, kind, record.ref))
          ? set(kind, record)
          : Promise.reject(new Error(NO_SUCH_RECORD)),
    };
  };

  return {
    within: (organizationId, work) => {
      const step = queue.then(() => work(of(organizationId)));
      queue = step.catch(() => undefined);
      return step;
    },
  };
}

/** The fake partner's table (db/migrations/0028_fake_partner.sql), as Kysely sees it. */
export interface FakePartnerTables {
  'fake_partner.records': {
    org_id: string;
    kind: string;
    ref: string;
    alias: string | null;
    body: unknown;
  };
}

/** The records in the database (0028), each organisation's behind the tenant walls. */
export function createDatabaseRecords(db: Kysely<FakePartnerTables>): FakePartnerStore {
  const of = (tx: Transaction<FakePartnerTables>, organizationId: string): FakeRecords => {
    const read = async <K extends FakeRecordKind>(
      kind: K,
      column: 'ref' | 'alias',
      value: string,
    ): Promise<FakeRecord<K> | undefined> => {
      const row = await tx
        .selectFrom('fake_partner.records')
        .select(['ref', 'alias', 'body'])
        .where('kind', '=', kind)
        .where(column, '=', value)
        .forUpdate()
        .executeTakeFirst();
      // The row is the fake's own, written only by `add` and `update` below.
      return row as FakeRecord<K> | undefined;
    };
    return {
      organizationId,
      get: (kind, ref) => read(kind, 'ref', ref),
      byAlias: (kind, alias) => read(kind, 'alias', alias),
      // Another call adding the same record at once waits for this one's
      // transaction, then adds nothing: the caller reads what was added.
      add: async (kind, { ref, alias, body }) => {
        const added = await tx
          .insertInto('fake_partner.records')
          .values({ org_id: organizationId, kind, ref, alias, body: JSON.stringify(body) })
          .onConflict((conflict) => conflict.columns(['org_id', 'kind', 'ref']).doNothing())
          .executeTakeFirst();
        return added.numInsertedOrUpdatedRows === 1n;
      },
      update: async (kind, { ref, alias, body }) => {
        const updated = await tx
          .updateTable('fake_partner.records')
          .set({ alias, body: JSON.stringify(body) })
          .where('kind', '=', kind)
          .where('ref', '=', ref)
          .executeTakeFirst();
        if (updated.numUpdatedRows !== 1n) throw new Error(NO_SUCH_RECORD);
      },
    };
  };
  return {
    within: (organizationId, work) =>
      withTenant(db, organizationId, async (tx) => {
        await limitStatements(tx);
        return work(of(tx, organizationId));
      }),
  };
}
