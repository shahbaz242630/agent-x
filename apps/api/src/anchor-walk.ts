// The anchors' store walked shard by shard (PL-65 PR4). Where the anchor log lets shards go past its memory budget (PR3),
// work taken in any other order reads a shard back for one chain, lets it go for another's, and reads it back again: past
// the budget, every chain a read of the store. So the anchor check's turns, the rotation's days and its full pass each
// take their organisations a shard at a time, each shard's together: each shard read back at most once a pass. And as
// the walk leaves a shard it tells the log (`walkedPast`), which then lets that shard go before any other, the one passed
// last first. A walk that repeats wants next the shard it passed longest ago, which least-recently-used would let go
// first; this way what the budget holds at a round's end is still held when the next round reaches it, and a round reads
// back about the shards that don't fit, not nearly all of them.
//
// The walk's place is its own order, kept as each kind of work keeps its place today (the check's turns, the pass's
// round, between runs in a process), and after a restart made again from what the store itself says: the shards whose
// chains waited longest first, by the signed times of their anchors or passes (`age`). So it needs no cursor written
// anywhere, and nothing anyone can change but the `audit-anchor` key's holder moves it: a shard reached late one round
// waits less next, and one never reached comes first. It only ever orders work, and never decides a verdict.
import { shardOf } from '@agentx/platform/audit-chain';

/** An organisation's chain's shard in the anchors' store: as the database's generated column (0082) gives it too. */
export const shardOfOrganisation = (orgId: string): number => shardOf(`organisation:${orgId}`);

/**
 * `items` a shard at a time: the shards by the oldest of their own (`age`, the smallest first, then by number), and in
 * each the oldest first, ties as given. Each one's shard worked out once (a hash), never in the sort.
 */
export function shardWalk<T>(items: readonly T[], orgIdOf: (item: T) => string, age: (item: T) => number): T[] {
  const groups = new Map<number, { oldest: number; readonly members: { readonly item: T; readonly age: number }[] }>();
  for (const item of items) {
    const shard = shardOfOrganisation(orgIdOf(item));
    const member = { item, age: age(item) };
    const group = groups.get(shard);
    if (group === undefined) groups.set(shard, { oldest: member.age, members: [member] });
    else {
      group.oldest = Math.min(group.oldest, member.age);
      group.members.push(member);
    }
  }
  return [...groups]
    .toSorted(([shard, group], [otherShard, other]) => group.oldest - other.oldest || shard - otherShard)
    .flatMap(([, { members }]) => members.toSorted((one, other) => one.age - other.age).map(({ item }) => item));
}
