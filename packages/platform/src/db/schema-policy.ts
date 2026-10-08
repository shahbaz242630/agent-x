// What our schema is allowed to look like (ADR-005 §6, §8, §9): which tables
// may stand outside the tenant walls and what the app may do to them, what it
// may do in the audit trails' schemas, and the foreign keys that must stay.
//
// **It lives in the product, not in tooling, because two readers need it and
// they must never hold different lists** (the A3c-2 lesson):
//
// - CI-06 checks a freshly migrated database against it on every run
//   (tooling/checks/database-schema.db.test.ts, through @agentx/testing's
//   schemaProblems), as the migration role, on Postgres 16 and 18;
// - the live schema guard checks the **running** database against it, as the
//   app role, at start-up and on every anchor check (A3e-1b). The database is
//   what an owner-level attacker controls, so the expectation has to travel in
//   the image CI signs and the deploy verifies — never in the database itself.
//
// A table is listed under `globalTables` only with a reason and its exact
// columns, so a new global table, or a new column on one, is always a reviewed
// change to this file (SEC-TEN-08). An entry for a table that no longer exists
// fails CI-06, so the list can't go stale; the same holds for the append-only
// exceptions, the fill-in tables and the required foreign keys.

import { IDEMPOTENCY_RETENTION_DAYS } from './idempotency.ts';

/** The rights on a table's rows the app role can be allowed. */
type RowRight = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

/** A table with no org_id and no row-level security, allowed by name (ADR-005 §6). */
interface GlobalTable {
  /** Why it can't be a tenant table. */
  readonly reason: string;
  /** Every column it has, exactly: a new column is a reviewed entry (SEC-TEN-08). */
  readonly columns: readonly string[];
  /**
   * Every right the app role may hold on it, on the whole table or any of its
   * columns: nothing it needn't do, since no tenant wall stands behind a
   * global table (B1d-1). Named for every global table outside the
   * append-only schemas, and for none inside them, which their own rule holds
   * (CI-06 checks both).
   */
  readonly appMay?: readonly RowRight[];
  /**
   * The only columns the app may UPDATE, each granted on its own (B2-1): a
   * table the app changes in part only, such as a session's cookie hash, and
   * never in who or what it is about. UPDATE is then left out of `appMay`,
   * and a grant of UPDATE on the whole table, or on any other column, is a
   * problem to CI-06 and the live guard alike.
   */
  readonly appMayUpdate?: readonly string[];
}

/**
 * A foreign key the running database must still hold, validated (B1d-1): one a
 * check reaching across organisations rests on, which the owner could drop or
 * switch off without touching a row.
 */
interface RequiredForeignKey {
  /** Why it matters: what could happen without it. */
  readonly reason: string;
  /** The table it runs from, by schema-qualified name as Postgres quotes it. */
  readonly table: string;
  /** Its columns, in order. */
  readonly columns: readonly string[];
  /** The table it points at, named the same way. */
  readonly references: string;
  /** The columns it points at, in the same order. */
  readonly referencedColumns: readonly string[];
}

/** A tenant table the app adds rows to and reads, and changes only in the columns named. */
interface FillInTable {
  /** Why the app needs no more: what a row deleted, or another column changed, would allow. */
  readonly reason: string;
  /** Exactly the columns the app is granted UPDATE on, each on its own (CI-06 checks it); none: rows are only added. */
  readonly columns: readonly string[];
  /**
   * When the app may also delete a row (B1e): once its `column` is `days` whole
   * days old, and never before. The column is a timestamptz NOT NULL the app
   * can't change; a restrictive DELETE policy named `retention` holds the rule,
   * reading `column < now() - make_interval(days => days)` exactly (CI-06 and
   * the live guard check both). Without it, the app never deletes.
   */
  readonly sweptAfter?: { readonly column: string; readonly days: number };
}

/**
 * A unique index that holds only where its condition does (E2-1a): one the
 * policy lists exactly, since any other partial key enforces nothing outside
 * its condition and is refused by CI-06 and the live guard alike.
 */
interface PartialUniqueIndex {
  /** Why it is partial, and what it still holds. */
  readonly reason: string;
  /** The table it is on, by schema-qualified name as Postgres quotes it. */
  readonly table: string;
  /** Its name. */
  readonly name: string;
  /** Its key columns, in order. */
  readonly columns: readonly string[];
  /**
   * Its condition exactly as Postgres prints it (`pg_get_expr` of `indpred`),
   * brackets and all. Name only columns and pg_catalog's own: a name from our
   * schemas prints qualified for CI-06 but may not on the app's search path,
   * and the live guard would then raise a false alarm.
   */
  readonly predicate: string;
}

export interface SchemaPolicy {
  /**
   * The global tables, by schema-qualified name as Postgres quotes it
   * (`schema.table`). Every other table is a tenant table.
   */
  readonly globalTables: Readonly<Record<string, GlobalTable>>;
  /** Schemas whose tables the app role may only add to and read, such as the audit trail (SEC-EVD-01). */
  readonly appendOnlySchemas: readonly string[];
  /**
   * Tables in those schemas that the app may also change, by name, each with
   * its reason: a row the app locks and moves on, such as a chain head.
   */
  readonly appendOnlyExceptions: Readonly<Record<string, string>>;
  /**
   * Tenant tables outside those schemas that the app may add rows to and read,
   * and change only in the columns listed, never DELETE (but past a retention
   * its entry names, `sweptAfter`), by schema-qualified
   * name as Postgres quotes it: a row filled in once after it is added, such as
   * an idempotency key's result. Any other tenant table allows every row right.
   */
  readonly fillInTables: Readonly<Record<string, FillInTable>>;
  /**
   * Foreign keys that must be there, validated, with their
   * reasons. CI-06 checks each against the migrations; the live schema guard
   * checks the running database still holds it.
   */
  readonly requiredForeignKeys: readonly RequiredForeignKey[];
  /**
   * The only unique indexes that may be partial, each with its reason: its
   * table, name, key columns and condition must all be as listed (E2-1a).
   */
  readonly partialUniqueIndexes: readonly PartialUniqueIndex[];
}

export const SCHEMA_POLICY: SchemaPolicy = {
  globalTables: {
    'directory.orgs': {
      reason:
        "The directory's list of organisations (ADR-005 §6): IDs only, read by work that runs across organisations (the anchor check, the retention sweeps) before it works inside each one's withTenant",
      columns: ['org_id'],
      // Added with its organisation and read; an entry changed or deleted
      // would be an organisation no anchor check or sweep reaches.
      appMay: ['SELECT', 'INSERT'],
    },
    'directory.members': {
      reason:
        "The directory's list of who belongs where (ADR-005 §6, B4-1): IDs only, a person's organisations and their membership in each, found at sign-in before any organisation is known; the membership itself is read and verified inside that organisation's withTenant",
      columns: ['user_id', 'org_id', 'membership_id'],
      // Added with its membership and read; an entry changed could point a
      // person at another's membership (which its signed state then refuses),
      // and one deleted would hide an organisation from its own member.
      appMay: ['SELECT', 'INSERT'],
    },
    'directory.invites': {
      reason:
        "The directory's list of invitation tokens (ADR-005 §6, B4-3): a token's SHA-256, never the token, with its organisation and invitation, found on accepting before any organisation is known; the invitation itself is read and verified inside that organisation's withTenant",
      columns: ['token_hash', 'org_id', 'invitation_id'],
      // Added as its invitation opens, and read; an entry changed could point
      // a token at another invitation (which its email check then refuses),
      // and one deleted would leave an open invitation no one can accept.
      appMay: ['SELECT', 'INSERT'],
    },
    'directory.agent_keys': {
      reason:
        "The directory's list of agent keys (ADR-005 §6, ADR-011 §1, C1-1): a key's ID and its organisation, found when a request carries the key, before any organisation is known; the key itself is read and verified inside that organisation's withTenant",
      columns: ['key_id', 'org_id'],
      // Added as its key is issued, and read; an entry changed would place a
      // key in an organisation that has no such key (which then finds none),
      // and one deleted would leave a key no request can be placed with.
      appMay: ['SELECT', 'INSERT'],
    },
    'mandates.allowed_currencies': {
      reason:
        "The deployment's currencies (ADR-006 §1, ADR-010; Phase 2 B1): AED in the Pilot, the same for every organisation, which a mandate version's currency must be one of",
      columns: ['code'],
      // Read only: a currency is added by a migration, never by the app.
      appMay: ['SELECT'],
    },
    'identity.session_emails': {
      reason:
        "A session's verified email address (ADR-003 §5, B4-4a), encrypted, for an invitation to be matched against; it belongs to the person's session, which belongs to no organisation, and goes with it",
      columns: ['session_id', 'email_ciphertext', 'email_key_version'],
      // Added as the session opens, and read; it goes with its session (the
      // key's cascade). A changed address could accept another's invitation.
      appMay: ['SELECT', 'INSERT'],
    },
    'identity.users': {
      reason:
        "The people who sign in (ADR-003 §5, ADR-005 §6), by the login service's issuer and subject: a person can belong to several organisations, and is found at sign-in before any is known",
      columns: ['id', 'issuer', 'subject', 'created_at'],
      // Made at the first sign-in and read; a user changed or deleted would
      // move or orphan every membership and event pointing at them.
      appMay: ['SELECT', 'INSERT'],
    },
    'identity.sessions': {
      reason:
        "The console's server-side sessions (ADR-003 §5-§7): opened at sign-in, before any organisation is known, and a person's sessions are ended together across all of theirs",
      columns: [
        'id',
        'user_id',
        'cookie_hash',
        'idp_session_id',
        'auth_time',
        'amr',
        'created_at',
        'last_seen_at',
        'ends_at',
      ],
      // Opened, read and ended; changed only in its cookie ID (rotated) and
      // its last-seen time, never moved to another person, nor what it
      // proved or when it ends.
      appMay: ['SELECT', 'INSERT', 'DELETE'],
      appMayUpdate: ['cookie_hash', 'last_seen_at'],
    },
    'identity.login_flows': {
      reason:
        "The sign-in flows under way (ADR-003 §5, B2-3a): each browser's state, nonce and PKCE verifier until it returns from the login service, before anyone is known",
      columns: [
        'cookie_hash',
        'state',
        'nonce',
        'verifier',
        'return_to',
        'created_at',
        'ends_at',
        'step_up_challenge_id',
      ],
      // Added, and taken once (deleted as it is read); never changed.
      appMay: ['SELECT', 'INSERT', 'DELETE'],
    },
    'identity.step_up_challenges': {
      reason:
        "Step-up challenges (ADR-003 §8-§9, B3-1): a person's fresh sign-in bound to one pending change in their own session, which belongs to no organisation",
      columns: [
        'id',
        'session_id',
        'user_id',
        'action',
        'change_hash',
        'nonce',
        'created_at',
        'ends_at',
        'verified_at',
        'auth_time',
        'amr',
        'idp_session_id',
        'id_token_hash',
      ],
      // Added, read and consumed (deleted as it is read); changed only to
      // record its evidence, never in what it is for or whose it is.
      appMay: ['SELECT', 'INSERT', 'DELETE'],
      appMayUpdate: ['verified_at', 'auth_time', 'amr', 'idp_session_id', 'id_token_hash'],
    },
    'notifications.outbox': {
      reason:
        "Notices waiting to be sent (ADR-003 §10, ADR-005 §8's job queue; B5-1a): the sender takes the due ones across every organisation, each row naming its own",
      columns: [
        'id',
        'org_id',
        'recipient_user_id',
        'kind',
        'membership_id',
        'role',
        'created_at',
        'attempts',
        'next_attempt_at',
        'sent_at',
        'given_up_at',
        'last_failure',
        // B6-1b (0023): a registered contact, or all of them, as the recipient; what it's about.
        'recipient_contact_id',
        'to_contacts',
        'about_id',
      ],
      // Added, read, and deleted once done and past its retention; changed
      // only in its tries and outcome, never in whom or what it tells of.
      appMay: ['SELECT', 'INSERT', 'DELETE'],
      appMayUpdate: ['attempts', 'next_attempt_at', 'sent_at', 'given_up_at', 'last_failure'],
    },
    'security.events': {
      reason:
        'Failed sign-ins and rate-limit hits with the client IP (ADR-005 §6, ADR-011 §7): they happen before any organisation is known, and the address is kept in-country, here alone',
      columns: ['id', 'kind', 'reason', 'ip', 'user_id', 'window_start', 'count', 'created_at'],
      // Added, read, and deleted once past the retention the config names;
      // never changed, so a count once written stands.
      appMay: ['SELECT', 'INSERT', 'DELETE'],
    },
    'migrations.applied': {
      reason:
        'The migration ledger (runMigrations): one row per applied file, written only by the migration role at deploy time, never by the app',
      columns: ['name', 'checksum', 'applied_at'],
      appMay: [],
    },
    'platform_controls.audit_events': {
      reason:
        "The platform's own audit chain (ADR-011 §3, ADR-014 §8): events of no organisation, such as each start's config hash (SEC-OPS-05). Append-only for the app",
      columns: [
        'seq',
        'id',
        'recorded_at',
        'actor_type',
        'actor_id',
        'action',
        'details',
        'prev_hash',
        'hash',
        'mac',
        'mac_key_version',
      ],
    },
    'platform_controls.audit_head': {
      reason: "The platform audit chain's one head row, which the app locks and moves on with every event",
      columns: ['only_row', 'seq', 'hash', 'mac', 'mac_key_version'],
    },
  },
  // The audit trails' schemas (ADR-004 §4): the app role may only add audit rows and read them (ADR-005 §9).
  appendOnlySchemas: ['audit', 'platform_controls'],
  appendOnlyExceptions: {
    'audit.heads':
      "Each organisation's chain head: the app locks it and moves it on with every event it records (ADR-006 §6, ADR-011 §3)",
    'platform_controls.audit_head':
      "The platform chain's head: the app locks it and moves it on with every event it records (ADR-006 §6, ADR-011 §3)",
  },
  fillInTables: {
    'idempotency.keys': {
      reason:
        "Each write's idempotency key (ADR-007 §4): the app adds the key and fills in the write's result. A key deleted before its retention, or its namespace or hash changed, would let a retry do the write again",
      columns: ['result_status', 'result_id'],
      // The retention sweep (B1e, 0009); ADR-014 §3's default.
      sweptAfter: { column: 'created_at', days: IDEMPOTENCY_RETENTION_DAYS },
    },
    // The S68 audit: these three were held to no narrower rights than any tenant table's, so a wider
    // grant a later migration slipped in went unseen by CI-06 and the live guard alike.
    'identity.factor_reset_confirmations': {
      reason:
        "A contact's confirmation of a reset (0025): added once, never changed or deleted. One deleted would drop a confirmation a reset counts; one changed would put it down to another contact",
      columns: [],
    },
    'funding_sources.links': {
      reason:
        "A link Agent X started with the partner (0029): the app settles it once, from the partner's own answer. A link deleted would hide a start from the day's budget; its session, partner or starter changed would point it at another's",
      columns: ['outcome', 'source_id', 'settled_at'],
    },
    'fake_partner.records': {
      reason:
        "The fake partner's own records on staging (0028): it moves a link's or a payee's state and keeps an alias; never a record deleted, nor its reference or organisation changed",
      columns: ['alias', 'body'],
    },
    'spend_requests.order_claims': {
      reason:
        "An order's claim (ADR-006 §11, 0039): the app adds it and only ever releases it, once its request or payment ends. A claim deleted, or its order, supplier or payee changed, would let the same order be paid twice",
      columns: ['released_at'],
    },
  },
  requiredForeignKeys: [
    {
      reason:
        "An organisation's row points at its directory entry (0008), so no organisation exists that the directory's list leaves out, and so none that the anchor check of every chain never reaches",
      table: 'organizations.organizations',
      columns: ['org_id'],
      references: 'directory.orgs',
      referencedColumns: ['org_id'],
    },
  ],
  partialUniqueIndexes: [
    {
      reason:
        "One supplier per payee key in an organisation, suspended suppliers included (0033, partner S71). Partial so payee_key is never a key column: Postgres counts only a full unique index's columns as keys, and a full one would turn the signed state's no-key write of the key into a key update (ADR-006 §6)",
      table: 'suppliers.suppliers',
      name: 'one_supplier_a_payee',
      columns: ['org_id', 'payee_key'],
      // As Postgres prints `WHERE payee_key IS NOT NULL` (ruleutils puts a NullTest in brackets), on 16 to 18.
      predicate: '(payee_key IS NOT NULL)',
    },
    {
      reason:
        "One open mandate an agent (PRD §3, the Pilot; 0035): waiting, ACTIVE or SUSPENDED, so a second can't be drafted while one is open. Partial so the status is never a key column, and a status change stays a no-key write (ADR-006 §6)",
      table: 'mandates.mandates',
      name: 'one_open_mandate_an_agent',
      columns: ['org_id', 'agent_id'],
      // As Postgres prints `WHERE status IN ('PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED')`.
      predicate: "(status = ANY (ARRAY['PENDING_ACCEPTANCE'::text, 'ACTIVE'::text, 'SUSPENDED'::text]))",
    },
    {
      reason:
        'One open claim an order by its supplier (ADR-006 §11, PRD §3.2; 0039): a second request for the same order waits on the first and is refused. Partial so a released claim (its request denied, cancelled or expired, its payment failed) no longer holds the order, and released_at is never a key column: a release stays a no-key write (ADR-006 §6)',
      table: 'spend_requests.order_claims',
      name: 'one_open_claim_a_supplier_order',
      columns: ['org_id', 'supplier_id', 'order_reference'],
      predicate: '(released_at IS NULL)',
    },
    {
      reason:
        "One open claim an order by its payee where the supplier has a payee key (ADR-014 §3; 0039): the same invoice to a supplier re-created with the same account. Partial as the supplier's claim is, and for claims with no payee key, which the supplier's alone holds",
      table: 'spend_requests.order_claims',
      name: 'one_open_claim_a_payee_order',
      columns: ['org_id', 'payee_key', 'order_reference'],
      predicate: '((released_at IS NULL) AND (payee_key IS NOT NULL))',
    },
  ],
};
