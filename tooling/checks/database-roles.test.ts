// The owner role's name is written in two places that can't import each other:
// `db/bootstrap/roles.sql`, which creates it, and the live schema check, which
// compares every object's owner against it (A3e-1b). A rename in the SQL alone
// would leave the guard comparing against a role that no longer exists — every
// table would look like it had changed hands, and every start would be refused.
//
// The SQL is the source of truth, so it is read here rather than restated.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { OWNER_ROLE } from '../../packages/core/src/schema-check.ts';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const roles = (): string => readFileSync(path.join(ROOT, 'db', 'bootstrap', 'roles.sql'), 'utf8');

describe('the owner role the schema check compares against', () => {
  it('is the role db/bootstrap/roles.sql creates', () => {
    expect(roles()).toContain(`CREATE ROLE ${OWNER_ROLE}`);
  });

  it('is the role that owns the app database', () => {
    // database.sql hands the database to it; if that ever named another role,
    // the guard would be checking the wrong owner.
    const database = readFileSync(path.join(ROOT, 'db', 'bootstrap', 'database.sql'), 'utf8');
    expect(database).toContain(OWNER_ROLE);
  });

  it('is no superuser and cannot create roles or databases, which is what makes the guard necessary', () => {
    // The whole of A3e rests on this: the owner is powerful over our tables and
    // powerless over the server. If it ever gained SUPERUSER the guard would be
    // arguing with someone who could switch it off.
    expect(roles()).toMatch(new RegExp(`CREATE ROLE ${OWNER_ROLE}\\s+LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE`));
  });
});
