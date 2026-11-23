/**
 * The Postgres versions every database test runs against: the oldest and the
 * newest we support (ADR-001, ADR-010). Each image is pinned by its digest, so
 * a changed image can't slip in under the same tag. The weekly update check
 * moves them to the newest patch release. Each Vitest project is named after
 * its version (db-pg16, db-pg18).
 */
export const POSTGRES_IMAGES: Readonly<Record<string, string>> = {
  'db-pg16': 'postgres:16.16-trixie@sha256:3950ad7c3148ca2175ef1b6c36c9efbf78957ae8fbe8b3a5d7c35af50500382f',
  'db-pg18': 'postgres:18.7-trixie@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a',
};
