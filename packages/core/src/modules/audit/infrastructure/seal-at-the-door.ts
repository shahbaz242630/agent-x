// A signed row and its seal, read where no lock can be taken (AG1, PL-67):
// a key's check at the door, a read alone outside its organisation's share,
// which may refuse on what it reads but never grants. Whether the row agrees
// with its object's newest signed event, its pointer, version and seal (one
// local HMAC): a row that doesn't is left to the full, sealed read, which
// raises the alarm and the hold, so the door never refuses one silently. Not
// verifiedState: no chain, head or event MAC is judged here, so agreeing is
// only "nothing to report", never a state to decide on.
import { stateSealIn, stateSealMatches } from '@agentx/platform/audit-chain';
import {
  type SignedRow,
  signedRowAsRead,
  type SignedRowKey,
  signedRowUnlocked,
  type SignedStateTable,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type RawBuilder, sql } from 'kysely';

import { detailsObject, HAS_STATE_SEAL } from './audit-trail.ts';

/** One statement, not run: the row with no lock, and beside it its object's newest signed event's ID, version and details. */
export function sealedRowRead(table: SignedStateTable, key: SignedRowKey): RawBuilder<Record<string, unknown>> {
  return sql<Record<string, unknown>>`
    with ${signedRowUnlocked(table, key)}
    select r.*, e.id::text as sealed_event_id, e.subject_version as sealed_version, e.details as sealed_details
    from row_read r
    left join lateral (
      select s.id, s.subject_version, s.details from audit.events s
      where s.org_id = r.org_id and s.subject_type = ${table.subject} and s.subject_id = r.id
        and pg_catalog.strpos(s.details, ${HAS_STATE_SEAL}) > 0
      order by s.seq desc limit 1
    ) as e on true
  `;
}

/** The row sealedRowRead read, and whether it agrees with its newest signed event. */
export interface SealedRowAsRead {
  readonly row: SignedRow;
  readonly agrees: boolean;
}

/**
 * sealedRowRead's rows judged: the row as readSignedRow judges one, and whether its pointer, version and fields match
 * the newest signed event's seal. Exactly one HMAC whatever is found (a row missing or unreadable is checked against a
 * seal of zeros), so how long it takes tells nothing of what was there.
 */
export function sealedRowJudged(
  keys: KeyProvider,
  table: SignedStateTable,
  key: SignedRowKey,
  rows: readonly Readonly<Record<string, unknown>>[],
): SealedRowAsRead {
  const row = signedRowAsRead(table, rows);
  const [first] = rows;
  const details = detailsObject(first?.sealed_details);
  const seal = details === undefined ? undefined : stateSealIn(details);
  const found = row.outcome === 'found' ? row : undefined;
  const sealOf = seal === undefined || seal === 'malformed' ? undefined : seal;
  const version = found?.version ?? 1;
  const facts = {
    orgId: key.orgId,
    subject: { type: table.subject, id: key.id, version },
    fields: found?.fields ?? table.fields.map(({ column }) => [column, null] as const),
  };
  const auditMac = keys.describe().find(({ purpose }) => purpose === 'audit-mac')?.current ?? 1;
  const matches = stateSealMatches(keys, facts, sealOf ?? { fingerprint: Buffer.alloc(32), keyVersion: auditMac });
  const sealedEventId = typeof first?.sealed_event_id === 'string' ? first.sealed_event_id.toLowerCase() : null;
  const agrees =
    found !== undefined &&
    sealOf !== undefined &&
    matches &&
    sealedEventId !== null &&
    found.eventId === sealedEventId &&
    found.version === first?.sealed_version;
  return { row, agrees };
}
