// The signed states' digest (AT13, R-15; decisions 1 and 2b): for each chain, every signed object's newest signed event,
// by place, as the anchor check's walk found it under an anchor. A decision's read of a signed state finds the newest
// signed event in the database itself (latestSignedState); someone with the database's keys can delete or move an
// object's newest events once they are older than the last 1,000 of the chain, and roll its row back to an older
// genuine version, and every seal left reads true. The digest, held apart from the database, knows where the newest one
// was: a read finding an older one, or none, is the tamper sign, at decision time (audit-trail.ts).
//
// Held compactly, one table a chain: each object as 8 bytes of a SHA-256 of its type and ID, and its place, 16 bytes a
// slot, at most four slots in three used. Two objects of one chain sharing 8 bytes would hold the higher place of the
// two: a false refusal of the lower one, never a pass, about one chance in 40 million for a chain of a million objects.
// Places only ever rise: a fact once known stays true until a rebase (rebase.ts) sets the chain's whole digest aside.
import { createHash } from 'node:crypto';

/** An object's key in a digest: its subject type and ID as the chain's events name them, the ID in lower case. */
export const subjectKey = (type: string, id: string): string => `${type}\n${id.toLowerCase()}`;

/** What a walk saw: each signed object's newest signed event's place, by subjectKey. */
export type SignedSeen = ReadonlyMap<string, bigint>;

/** A file line's entry: the object's 8 bytes, then its place, 8 bytes, both big-endian. */
export const ENTRY_BYTES = 16;

/** The smallest table a chain gets, in slots: a power of two. */
const FIRST_SLOTS = 8;

/** A slot's value; one past the table, which no slot is, as empty. */
export const valueAt = (array: Float64Array | Uint32Array, index: number): number => array[index] ?? 0;

/** A hash's first 8 bytes as two 32-bit halves, never both 0 (an empty slot). */
export function halvesOf(hash: Buffer): readonly [number, number] {
  const high = hash.readUInt32BE(0);
  const low = hash.readUInt32BE(4);
  return high === 0 && low === 0 ? [0, 1] : [high, low];
}

/** The fingerprint of an object's key. */
export const fingerprintOf = (key: string): readonly [number, number] =>
  halvesOf(createHash('sha256').update(key, 'utf8').digest());

/** A place as a slot holds it: every place a chain can reach is a safe integer. */
export function placeOf(seq: bigint): number {
  if (seq < 1n || seq > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('A signed event is at a place from 1');
  return Number(seq);
}

/**
 * One chain's digest: each object's fingerprint and its newest signed place, in an open-addressed table, so it costs
 * 16 bytes a slot whatever the objects' names. `bornAt` is when the oldest fact it holds was signed into the store (a
 * line's time): a rebase after it sets the whole table aside, as it can't tell which facts came after.
 */
export class ChainDigest {
  bornAt: number;
  #halves: Uint32Array;
  #places: Float64Array;
  #size = 0;

  constructor(bornAt: number, slots = FIRST_SLOTS) {
    this.bornAt = bornAt;
    this.#halves = new Uint32Array(slots * 2);
    this.#places = new Float64Array(slots);
  }

  get size(): number {
    return this.#size;
  }

  /** What the table's buffers take. */
  get bytes(): number {
    return this.#halves.byteLength + this.#places.byteLength;
  }

  /** Where the fingerprint sits, or the empty slot it would take. */
  #slotOf(high: number, low: number): number {
    const mask = this.#places.length - 1;
    // The halves are a hash already: the low one spreads the slots.
    let slot = low & mask;
    for (;;) {
      const at = slot * 2;
      const [h, l] = [valueAt(this.#halves, at), valueAt(this.#halves, at + 1)];
      if ((h === 0 && l === 0) || (h === high && l === low)) return slot;
      slot = (slot + 1) & mask;
    }
  }

  /** The object's newest signed place, if this table knows it. */
  get(high: number, low: number): number | undefined {
    const slot = this.#slotOf(high, low);
    const place = valueAt(this.#places, slot);
    return place === 0 ? undefined : place;
  }

  /** Keeps the place where it is higher than the one known: whether it moved. */
  put(high: number, low: number, place: number): boolean {
    if ((this.#size + 1) * 4 > this.#places.length * 3) this.#grow();
    const slot = this.#slotOf(high, low);
    const known = valueAt(this.#places, slot);
    if (known >= place) return false;
    if (known === 0) {
      this.#size += 1;
      this.#halves[slot * 2] = high;
      this.#halves[slot * 2 + 1] = low;
    }
    this.#places[slot] = place;
    return true;
  }

  /** Every object held: its halves and place. */
  *entries(): Generator<readonly [number, number, number]> {
    for (let slot = 0; slot < this.#places.length; slot += 1) {
      const place = valueAt(this.#places, slot);
      if (place !== 0) yield [valueAt(this.#halves, slot * 2), valueAt(this.#halves, slot * 2 + 1), place];
    }
  }

  #grow(): void {
    const old = [...this.entries()];
    this.#halves = new Uint32Array(this.#places.length * 4);
    this.#places = new Float64Array(this.#places.length * 2);
    this.#size = 0;
    for (const [high, low, place] of old) this.put(high, low, place);
  }
}

/** Entries as a file line carries them: 16 bytes each. */
export function packEntries(entries: Iterable<readonly [number, number, number]>, count: number): Buffer {
  const packed = Buffer.alloc(count * ENTRY_BYTES);
  let at = 0;
  for (const [high, low, place] of entries) {
    packed.writeUInt32BE(high, at);
    packed.writeUInt32BE(low, at + 4);
    packed.writeBigUInt64BE(BigInt(place), at + 8);
    at += ENTRY_BYTES;
  }
  if (at !== packed.length) throw new RangeError('As many entries packed as counted');
  return packed;
}

/** A line's entries, or nothing if they can't be ours: a length not of whole entries, an empty slot, or a place off. */
export function unpackEntries(packed: Buffer): readonly (readonly [number, number, number])[] | undefined {
  if (packed.length === 0 || packed.length % ENTRY_BYTES !== 0) return undefined;
  const entries: (readonly [number, number, number])[] = [];
  for (let at = 0; at < packed.length; at += ENTRY_BYTES) {
    const high = packed.readUInt32BE(at);
    const low = packed.readUInt32BE(at + 4);
    const place = packed.readBigUInt64BE(at + 8);
    if ((high === 0 && low === 0) || place < 1n || place > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
    entries.push([high, low, Number(place)]);
  }
  return entries;
}
