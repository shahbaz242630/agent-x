// The restore drill's check (S78; SEC-AV-06, SEC-DATA-06): a point-in-time
// copy of the database holds our data whole. Run from the operator's job,
// inside the network, against the drill's copy and the live server, both
// read-only and as the app's own role.
//
// 1. On the copy, every chain is checked whole from its start: the platform's,
//    and each organisation's the directory lists. Every organisation the
//    platform chain records as created must be listed: the anchor check's
//    rule, one way only, as there (an organisation is recorded and listed in
//    one transaction, and the platform chain's seals are what a listing
//    without a record would have to get past).
// 2. On the live server, each of those chains is checked again with the copy's
//    head as its anchor: it passes only if the live chain is the copy's grown
//    on, so the copy is a true earlier state of it, not merely a sound chain.
//
// It writes nothing, and can't: both connections are read-only from their
// first packet, and each is asked to prove it before anything is read. It
// never raises the integrity alarm (`audit.integrity_failed` pages someone,
// and a broken copy is the drill's finding, not an incident): every problem
// is the run's own line, and the job's exit code.
import { createAuditTrail } from '@agentx/core/modules/audit';
import { listedOrganizations } from '@agentx/core/modules/directory';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { AnchorPoint, ChainReport } from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import type { OperatorTables } from './create-organization.ts';

export interface RestoreCheckReport {
  /** Chains checked on the copy, and how many of those held on both sides. */
  readonly chainsChecked: number;
  readonly chainsHeld: number;
  /** The platform chain's head on each side, where it was read: how far the live server is past the copy. */
  readonly platformCopySeq: bigint | null;
  readonly platformLiveSeq: bigint | null;
  /** Organisations the copy lists, and the live server lists past them (made since the restore point). */
  readonly copyOrganizations: number;
  readonly newSinceCopy: number;
  /** Everything wrong, each naming its chain and reason; none means the copy holds. */
  readonly problems: readonly string[];
}

export interface RestoreCheckSides {
  readonly copy: Database<OperatorTables>;
  readonly live: Database<OperatorTables>;
  readonly keys: KeyProvider;
}

/** What stopped a read: the database's error code alone, never its message, which could hold data. */
function unreadable(error: unknown): string {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'error';
  return `unreadable (${code})`;
}

/** The check of one chain as a head, or its problem in words. */
async function reportOf(verify: () => Promise<ChainReport>): Promise<AnchorPoint | string> {
  try {
    const report = await verify();
    return report.ok
      ? { seq: report.seq, hash: report.hash }
      : `${report.problem.reason} at ${String(report.problem.seq)}`;
  } catch (error) {
    return unreadable(error);
  }
}

/** Checks the copy, then the live server against it: never throws for what it finds. */
export async function checkRestoredCopy({ copy, live, keys }: RestoreCheckSides): Promise<RestoreCheckReport> {
  // The IDs are never used: nothing is written. The trail and the chain need a source all the same.
  const platform = createPlatformChain({ keys, ids: uuidV7Ids });
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  const problems: string[] = [];
  let chainsChecked = 0;
  let chainsHeld = 0;

  /** One chain on both sides: its heads when it held on both, nothing when it didn't (a problem said). */
  const both = async (
    chain: string,
    verify: (database: Database<OperatorTables>, anchor: AnchorPoint | undefined) => Promise<ChainReport>,
  ): Promise<{ readonly copySeq: bigint; readonly liveSeq: bigint } | undefined> => {
    chainsChecked += 1;
    const onCopy = await reportOf(() => verify(copy, undefined));
    if (typeof onCopy === 'string') {
      problems.push(`${chain} on the copy: ${onCopy}`);
      return undefined;
    }
    const onLive = await reportOf(() => verify(live, onCopy));
    if (typeof onLive === 'string') {
      problems.push(`${chain} on the live server, from the copy's head: ${onLive}`);
      return undefined;
    }
    chainsHeld += 1;
    return { copySeq: onCopy.seq, liveSeq: onLive.seq };
  };

  const heads = await both('platform', (database, anchor) => platform.verifyAlone(database, anchor));
  let lists: readonly [string[], string[], string[]];
  try {
    lists = await Promise.all([
      listedOrganizations(copy),
      platform.createdOrganizations(copy),
      listedOrganizations(live),
    ]);
  } catch (error) {
    problems.push(`the organisations' lists: ${unreadable(error)}`);
    lists = [[], [], []];
  }
  const [listed, recorded, liveListed] = lists;
  const onList = new Set(listed);
  const onLive = new Set(liveListed);
  for (const orgId of recorded) {
    if (!onList.has(orgId)) problems.push(`organisation ${orgId}: recorded as created on the copy, but not listed`);
  }
  for (const orgId of listed) {
    await both(`organisation ${orgId}`, (database, anchor) => trail.verifyAlone(database, orgId, anchor));
    if (!onLive.has(orgId)) problems.push(`organisation ${orgId}: on the copy, but not listed live`);
  }
  return {
    chainsChecked,
    chainsHeld,
    platformCopySeq: heads?.copySeq ?? null,
    platformLiveSeq: heads?.liveSeq ?? null,
    copyOrganizations: listed.length,
    newSinceCopy: liveListed.filter((orgId) => !onList.has(orgId)).length,
    problems,
  };
}
