// The zod schemas the API's OpenAPI document names or describes (SEC-WEB-06).
// A registry of the API's own, not zod's global one: the document then holds
// only what the API registered here, and a module loaded afresh (as each test
// file does) gets a fresh registry rather than a clash over a name in use.
import { z } from 'zod';

export interface SchemaMeta {
  /** Makes the schema a named component of the document, referred to by that name. */
  readonly id?: string | undefined;
  /** Its public description, in the document. */
  readonly description?: string | undefined;
  readonly [key: string]: unknown;
}

export const API_SCHEMAS = z.registry<SchemaMeta>();
