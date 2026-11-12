/**
 * Golden: chains' names and their shards in the anchors' store (PL-65), the first byte of the SHA-256 of the name. Both
 * shards.ts's shardOf and the database's generated column (0082) are held to these, so the two can never part.
 */
export const ANCHOR_SHARD_VECTORS: readonly (readonly [chain: string, shard: number])[] = [
  ['platform', 210],
  ['organisation:0199a0f0-0000-7000-8000-000000000001', 150],
  ['organisation:0199a0f0-0000-7000-8000-000000000002', 213],
  ['organisation:00000000-0000-7000-8000-000000000000', 16],
  ['organisation:ffffffff-ffff-7fff-bfff-ffffffffffff', 226],
];
