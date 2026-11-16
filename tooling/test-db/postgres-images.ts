/**
 * The Postgres versions every database test runs against: the oldest and the
 * newest we support (ADR-001, ADR-010). Each image is pinned by its digest, so
 * a changed image can't slip in under the same tag. The weekly update check
 * moves them to the newest patch release. Each Vitest project is named after
 * its version (db-pg16, db-pg18).
 */
export const POSTGRES_IMAGES: Readonly<Record<string, string>> = {
  'db-pg16': 'postgres:16.16-trixie@sha256:dd2bf3ce2dc83a81674cf7f217fcfd8a5009a4b325dda5b843bfee82a06cff6f',
  'db-pg18': 'postgres:18.7-trixie@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc',
};
