/**
 * The Postgres versions every database test runs against: the oldest and the
 * newest we support (ADR-001, ADR-010). Each image is pinned by its digest, so
 * a changed image can't slip in under the same tag. The weekly update check
 * moves them to the newest patch release. Each Vitest project is named after
 * its version (db-pg16, db-pg18).
 */
export const POSTGRES_IMAGES: Readonly<Record<string, string>> = {
  'db-pg16': 'postgres:16.15-trixie@sha256:f9a7b9ebf6f56201f949db745e47bc423c0f0f8294bafe991cc10bf74b029657',
  'db-pg18': 'postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42',
};
