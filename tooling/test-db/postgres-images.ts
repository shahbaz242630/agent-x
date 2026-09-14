/**
 * The Postgres versions every database test runs against: the oldest and the
 * newest we support (ADR-001, ADR-010). Each image is pinned by its digest, so
 * a changed image can't slip in under the same tag. The weekly update check
 * moves them to the newest patch release. Each Vitest project is named after
 * its version (db-pg16, db-pg18).
 */
export const POSTGRES_IMAGES: Readonly<Record<string, string>> = {
  'db-pg16': 'postgres:16.15-trixie@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94',
  'db-pg18': 'postgres:18.6-trixie@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280',
};
