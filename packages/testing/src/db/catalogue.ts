// Reading Postgres's own catalogues, for the checks that judge a migrated
// schema: CI-06's tenant walls (schema-checks.ts) and A3c's authority tables
// (authority-checks.ts). Both connect the same way and run fixed query texts,
// so the connection and the query step are here rather than in each of them,
// where a new Postgres version would have to be followed twice.
//
// The connection is the migration role's, the one that applied the migrations,
// with only pg_catalog on the search path. That has two effects the checks
// rest on: every name from our schemas is printed with its schema (so a
// planted look-alike can be told from Postgres's own), and no function or
// operator planted in another schema can stand in for one of Postgres's.
//
// Nothing here writes: a check may open a transaction to build a reference
// object and roll it back, but it leaves the database as it was.
import pg from 'pg';

import type { TestDatabase } from './test-database.ts';

/** A connection as the migration role, with pg_catalog alone on the search path. Close it with `end()`. */
export async function openCatalogue(database: TestDatabase): Promise<pg.Client> {
  const client = new pg.Client({ ...database.connection('owner'), ssl: false, options: '-c search_path=pg_catalog' });
  await client.connect();
  return client;
}

/** The rows of one of the checks' fixed query texts, with its parameters bound. */
export async function catalogueRows<Row extends object>(
  client: pg.Client,
  text: string,
  values: readonly unknown[],
): Promise<Row[]> {
  // eslint-disable-next-line agentx/no-string-built-sql -- Passes on the callers' fixed query texts; the rule checks each where it is written.
  return (await client.query<Row>(text, [...values])).rows;
}
