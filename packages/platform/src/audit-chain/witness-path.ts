// Whether a walk of a chain passed through every head a copy witnessed (TR-1, witness-log.ts): the anchor check's walk
// from the anchor (and the platform chain's whole walk) re-hashes every event to the head, so the hash it read at a
// witnessed place is the chain's own there, linked to the anchor, never a row put back beside a cut branch (a row read
// on its own can be: the owner cuts to 100, a stale copy writes 101'–106', and the original row 105 goes back at 105).
//
// The heads are asked before the walk's first statement, so each was committed before it: a head above where the walk
// ended its reach (`to`, the head it read) is the chain cut back below it, and one at a place the walk read with another
// hash is a fork. A head at or below where the walk began, or past where a capped step stopped short of `to`, is not
// this walk's to judge: it stays held, for the next. A fingerprint of a head the witness log let go for memory (its
// place and its hash's first 16 bytes) is held to as a head, by those bytes (TR-3), as is a head released.
import type { ChainReport, StoredEntry } from './chain.ts';
import { hashHolds, type HeadSeen } from './digest-log.ts';
import type { ChainReader } from './store.ts';

/**
 * The walk's own reads, each event's hash kept where it is at a witnessed place, and where `recent` is given, every
 * event recorded from its `since` on (the anchor check holds a head landing late to them): no read of their own.
 */
export function watchingPlaces<Reader extends Pick<ChainReader, 'events'>>(
  reader: Reader,
  heads: readonly HeadSeen[],
  found: Map<bigint, Buffer>,
  recent?: { readonly since: Date; readonly found: Map<bigint, Buffer> },
): Reader {
  if (heads.length === 0 && recent === undefined) return reader;
  const places = new Set(heads.map(({ seq }) => seq));
  const since = recent?.since.getTime();
  return {
    ...reader,
    async events(after: bigint, upTo: bigint, limit: number): Promise<readonly (StoredEntry | undefined)[]> {
      const batch = await reader.events(after, upTo, limit);
      for (const entry of batch) {
        if (entry === undefined) continue;
        if (places.has(entry.seq)) found.set(entry.seq, entry.hash);
        if (since !== undefined && entry.recordedAt.getTime() >= since) recent?.found.set(entry.seq, entry.hash);
      }
      return batch;
    },
  };
}

/**
 * A walk's report held to the witnessed heads: as it was where it fails already or every head it can judge is on its
 * path, else refused (`cut_back`, at the highest head missed). `from` where it began; `to`, a step's goal (its head),
 * where it was capped short of it.
 */
export function heldToWitnessed<Report extends ChainReport & { readonly to?: bigint }>(
  report: Report,
  heads: readonly HeadSeen[],
  found: ReadonlyMap<bigint, Buffer>,
  from: bigint,
): Report | Extract<ChainReport, { readonly ok: false }> {
  if (!report.ok || heads.length === 0) return report;
  const reached = report.seq;
  const goal = report.to ?? reached;
  const missed = heads
    .filter(({ seq, hash }) => {
      if (seq > goal) return true;
      if (seq <= from || seq > reached) return false;
      const there = seq === reached ? report.hash : found.get(seq);
      // A compact head (TR-3: a fingerprint, or a head released) carries its hash's first bytes alone: those compared.
      return !hashHolds(there, hash);
    })
    .map(({ seq }) => seq);
  if (missed.length === 0) return report;
  const seq = missed.reduce((one, other) => (other > one ? other : one));
  return { ok: false, problem: { reason: 'cut_back', seq } };
}
