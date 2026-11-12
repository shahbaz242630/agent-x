// The anchors' store walked a shard at a time (PL-65 PR4): the order every walker takes its organisations in.
import { shardOf } from '@agentx/platform/audit-chain';
import { ANCHOR_SHARD_VECTORS } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { shardOfOrganisation, shardWalk } from './anchor-walk.ts';

const org = (index: number): string => `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`;
const itself = (orgId: string): string => orgId;

/** Organisations in one shard and in two others, found by trying IDs in turn. */
function inShards(): { readonly a: string[]; readonly b: string[]; readonly c: string[] } {
  const byShard = new Map<number, string[]>();
  // Some 256 shards: a few thousand IDs fill three of them three deep.
  for (let index = 0; index < 5000; index += 1) {
    const orgId = org(index);
    const shard = shardOfOrganisation(orgId);
    byShard.set(shard, [...(byShard.get(shard) ?? []), orgId]);
  }
  const [a = [], b = [], c = []] = [...byShard.entries()]
    .filter(([, ids]) => ids.length >= 3)
    .toSorted(([one], [other]) => one - other)
    .map(([, ids]) => ids.slice(0, 3));
  return { a, b, c };
}

describe('the shard walk (PL-65 PR4)', () => {
  it('names an organisation’s shard as its chain’s, as shards.ts and the database do', () => {
    for (const [chain, shard] of ANCHOR_SHARD_VECTORS) {
      if (chain.startsWith('organisation:'))
        expect(shardOfOrganisation(chain.slice('organisation:'.length))).toBe(shard);
    }
    expect(shardOfOrganisation(org(7))).toBe(shardOf(`organisation:${org(7)}`));
  });

  it('takes each shard’s together, the shards by the oldest in each, and in each the oldest first', () => {
    const { a, b, c } = inShards();
    const age = new Map<string, number>([
      // The oldest of all in b, the shard in the middle by number: b goes first, then c (its oldest before a's).
      [b[2] ?? '', 1],
      [b[0] ?? '', 50],
      [b[1] ?? '', 40],
      [c[0] ?? '', 10],
      [c[1] ?? '', 90],
      [c[2] ?? '', 20],
      [a[0] ?? '', 30],
      [a[1] ?? '', 30],
      [a[2] ?? '', 15],
    ]);
    const mixed = [a[0], c[1], b[0], a[1], c[0], b[1], a[2], c[2], b[2]].map((orgId) => orgId ?? '');
    expect(shardWalk(mixed, itself, (orgId) => age.get(orgId) ?? 0)).toEqual([
      b[2],
      b[1],
      b[0],
      c[0],
      c[2],
      c[1],
      a[2],
      a[0],
      a[1],
    ]);
  });

  it('shards as old as each other go by number, and ties within one stay as given', () => {
    const { a, b, c } = inShards();
    const mixed = [c[2], b[1], a[1], c[0], a[0], b[0]].map((orgId) => orgId ?? '');
    expect(shardWalk(mixed, itself, () => 0)).toEqual([a[1], a[0], b[1], b[0], c[2], c[0]]);
  });

  it('walks any items by the organisation each names, and nothing for nothing', () => {
    const { a, b } = inShards();
    const days = [
      { orgId: b[0] ?? '', dueAt: 5 },
      { orgId: a[0] ?? '', dueAt: 9 },
      { orgId: b[1] ?? '', dueAt: 7 },
    ];
    expect(
      shardWalk(
        days,
        (day) => day.orgId,
        (day) => day.dueAt,
      ).map((day) => day.orgId),
    ).toEqual([b[0], b[1], a[0]]);
    expect(shardWalk([], itself, () => 0)).toEqual([]);
  });
});
