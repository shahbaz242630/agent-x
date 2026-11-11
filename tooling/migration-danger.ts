// S185: no migration destroys data or switches a guard off unless it is named here.
//
// **Why.** Migrations run by themselves on every release, as the database's owner
// (deploy/azure/release.ts), so a destructive statement in one reaches staging and,
// later, production with no person reading it first. An agent once wrote restore
// steps that would have deleted the live server; this keeps the same kind of slip
// out of the migrations. migration-order.ts polices triggers and routine bodies;
// this polices what is destroyed.
//
// **The rule.** A migration may not drop a table, foreign table, sequence, schema,
// database, column or what a role owns; truncate; delete from, update or merge into
// an `audit.` or `security.` table, change one of their columns' types, or make,
// alter or drop a policy on one; switch a trigger or row-level security off; set
// the session's search_path; or run SQL it builds (EXECUTE). Nor may it hide any of
// these in a function or DO body, or give a body as a plain string this reader
// can't look into. A migration this reader can't parse whole is refused too. The
// only way past is EXCEPTIONS, below: a migration number, the rule and why, each
// one of them proved to still match (a stale one fails the check).
//
// db/bootstrap's SQL, which db-setup runs as the owner on staging, is held to the
// same rules, its exceptions named `bootstrap/<file>`.
//
// tooling/checks/migration-danger.test.ts holds every migration to this. The SQL is
// read with migration-order.ts's reader: comments are gone, strings are blanked and
// quoted names unquoted (lower-cased, so `"Audit"` is read as audit: refused, never
// passed), and each dollar-quoted body is read again as SQL of its own. Nothing here
// imports a package.
import { IDENTIFIER_CHAR, type Migration, pastQuoted, statements } from './migration-order.ts';

/** What a migration may not do, each by a short name an exception gives. */
type DangerRule =
  | 'drop'
  | 'drop-column'
  | 'truncate'
  | 'guarded-write'
  | 'guarded-type'
  | 'guarded-policy'
  | 'search-path'
  | 'trigger-off'
  | 'row-security-off'
  | 'dynamic-sql'
  | 'string-body'
  | 'unreadable';

/** One migration let through one rule, and why. */
export interface DangerException {
  readonly migration: string;
  readonly rule: DangerRule;
  readonly reason: string;
}

/**
 * The migrations let through, each for one rule only. Every other rule still holds for them. The check proves each
 * entry still matches a statement its migration holds, so none can outlive what it was written for.
 */
export const EXCEPTIONS: readonly DangerException[] = [
  {
    migration: '0002',
    rule: 'guarded-policy',
    reason:
      'tenant_isolation made with audit.events and audit.heads, the tables it walls, in the migration that builds them (Phase 1)',
  },
  {
    migration: '0079',
    rule: 'guarded-policy',
    reason:
      'tenant_isolation made with audit.operator_signatures and operator_signing_starts, the tables it walls, in the migration that builds them (PL-57)',
  },
  {
    migration: '0054',
    rule: 'row-security-off',
    reason:
      "NO FORCE on limit_reservations.agent_zones for one fill (id = agent_id) and FORCE again, in the migration's own transaction (Phase 4 G3b)",
  },
  {
    migration: '0067',
    rule: 'row-security-off',
    reason:
      "NO FORCE on spend_requests.requests and order_claims for one fill of order_reference and FORCE again, in the migration's own transaction (Phase 4)",
  },
  {
    migration: '0079',
    rule: 'row-security-off',
    reason:
      "NO FORCE on audit.heads for one read filling operator_signing_starts and FORCE again, in the migration's own transaction (PL-57)",
  },
  {
    migration: '0067',
    rule: 'drop-column',
    reason:
      "spend_requests.requests.order_key, a generated column made again over the full fold (an expression can't change on 16): computed, no data of its own lost (Phase 4, released before this rule)",
  },
];

/** The schemas whose rows are evidence: never deleted, changed or merged by a migration. */
const GUARDED = String.raw`(?:only )?(?:audit|security) ?\.`;
/** The head of an ALTER TABLE on an evidence table. */
const ALTER_GUARDED = String.raw`^alter table (?:if exists )?${GUARDED}`;

const RULES: readonly (readonly [DangerRule, RegExp, string])[] = [
  [
    'drop',
    /\bdrop (?:table|foreign table|sequence|schema|database|owned)\b/,
    'drops a table, foreign table, sequence, schema, database or what a role owns',
  ],
  // In ALTER TABLE, any DROP but a constraint, default, NOT NULL, identity or generation drops a column (COLUMN is optional).
  [
    'drop-column',
    /^alter (?:foreign )?table .*\bdrop (?!constraint\b|default\b|not null\b|identity\b|expression\b)/,
    'drops a column',
  ],
  // Not a trigger's event or a grant's privilege (`or truncate on`, `truncate, select`): a TRUNCATE statement.
  ['truncate', /\btruncate (?!on\b|or\b)(?:table |only )*["a-z_]/, 'truncates a table'],
  [
    'guarded-write',
    new RegExp(String.raw`\b(?:delete from|update|merge into) ${GUARDED}`),
    'deletes, updates or merges rows of an audit. or security. table',
  ],
  [
    'guarded-type',
    new RegExp(String.raw`${ALTER_GUARDED}.*\balter (?:column )?\S+ (?:set data )?type\b`),
    "changes the type of an audit. or security. table's column",
  ],
  [
    'guarded-policy',
    new RegExp(String.raw`^(?:create|alter|drop) policy\b.* on ${GUARDED}`),
    'makes, alters or drops a policy on an audit. or security. table',
  ],
  // The session's search_path, which outlives the statement; SET LOCAL and a function's own SET are the transaction's.
  ['search-path', /(?:^|\bbegin )set (?:session )?search_path\b/, "sets the session's search_path"],
  [
    'trigger-off',
    /\bdisable trigger\b|\bsession_replication_role\b/,
    'switches a trigger off (DISABLE TRIGGER, session_replication_role)',
  ],
  [
    'row-security-off',
    /\b(?:disable|no force) row level security\b|\brow_security\b/,
    'switches row-level security off',
  ],
  // EXECUTE as a grant's privilege or a trigger's action is no dynamic SQL.
  ['dynamic-sql', /\bexecute\b(?! (?:on|function|procedure)\b)/, 'runs SQL it builds (EXECUTE)'],
];

/** A function, procedure or DO whose body is a plain string: what it runs can't be read here. */
const STRING_BODY = /^(?:create (?:or replace )?(?:function|procedure)\b.*\bas ''|do (?:language [a-z_]+ )?'')/;

/** A statement's words with every string blanked and every quoted name unquoted and lower-cased. */
export function plainOf(words: string): string {
  let plain = '';
  let at = 0;
  while (at < words.length) {
    const char = words[at] ?? '';
    if (char === "'" || char === '"') {
      const escaped = char === "'" && words[at - 1] === 'e' && !IDENTIFIER_CHAR.test(words[at - 2] ?? '');
      const past = pastQuoted(words, at, char, escaped);
      plain +=
        char === "'"
          ? "''"
          : words
              .slice(at + 1, past - 1)
              .replaceAll('""', '"')
              .toLowerCase();
      at = past;
    } else {
      plain += char;
      at += 1;
    }
  }
  return plain;
}

/** Each rule one stretch of SQL breaks, its bodies read in turn, as `rule: what`. */
function brokenIn(sql: string): { rule: DangerRule; what: string }[] {
  let read;
  try {
    read = statements(sql);
  } catch (error) {
    return [{ rule: 'unreadable', what: `can't be read whole (${(error as Error).message})` }];
  }
  return read.flatMap(({ words, bodies }) => {
    let plain;
    try {
      plain = plainOf(words);
    } catch (error) {
      return [{ rule: 'unreadable' as const, what: `can't be read whole (${(error as Error).message})` }];
    }
    // A Unicode-escaped name or string (U&"…") can spell anything: refused, not decoded.
    const own = /\bu ?&/.test(plain)
      ? [{ rule: 'unreadable' as const, what: 'names something in Unicode escapes (U&)' }]
      : RULES.filter(([, pattern]) => pattern.test(plain)).map(([rule, , what]) => ({ rule, what }));
    const stringBody = STRING_BODY.test(plain)
      ? [{ rule: 'string-body' as const, what: 'gives a function or DO body as a plain string' }]
      : [];
    return [...own, ...stringBody, ...bodies.flatMap((body) => brokenIn(body))];
  });
}

/** Whether an exception names a file: `0067` names `0067_words.sql` alone, `bootstrap/roles` names `bootstrap/roles.sql`. */
const isNamed = (one: DangerException, name: string): boolean =>
  name.startsWith(`${one.migration}_`) || name === `${one.migration}.sql`;

/**
 * Each refusal for the migrations given, as `NNNN_name.sql rule: what`, and each exception that no longer matches
 * anything it names. Empty when every migration keeps the rule.
 */
export function dangerRefusals(
  migrations: readonly Migration[],
  exceptions: readonly DangerException[] = EXCEPTIONS,
): string[] {
  const used = new Set<DangerException>();
  const refused = migrations.flatMap(({ name, sql }) => {
    const broken = brokenIn(sql);
    const seen = new Set<string>();
    return broken.flatMap(({ rule, what }) => {
      const excused = exceptions.find((one) => one.rule === rule && isNamed(one, name));
      if (excused !== undefined) {
        used.add(excused);
        return [];
      }
      const said = `${name} ${rule}: ${what}`;
      if (seen.has(said)) return [];
      seen.add(said);
      return [said];
    });
  });
  const stale = exceptions
    .filter((one) => !used.has(one) && migrations.some(({ name }) => isNamed(one, name)))
    .map((one) => `exception ${one.migration} ${one.rule} matches nothing its migration holds: take it out`);
  const orphan = exceptions
    .filter((one) => !migrations.some(({ name }) => isNamed(one, name)))
    .map((one) => `exception ${one.migration} ${one.rule} names no migration: take it out`);
  return [...refused, ...stale, ...orphan];
}
