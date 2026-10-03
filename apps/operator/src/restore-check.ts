// The restore drill's check (S78; SEC-AV-06, SEC-DATA-06): a point-in-time
// copy of the database holds our data whole. Run from the operator's job,
// inside the network, against the drill's copy and the live server, both
// read-only and as the app's own role.
//
// 1. On the copy, every chain is checked whole from its start: the platform's,
//    and each organisation's the directory lists. Every organisation the
//    platform chain records as created must be listed (the anchor check's
//    rule).
// 2. On the live server, each of those chains is checked again with the copy's
//    head as its anchor: it passes only if the live chain is the copy's grown
//    on, so the copy is a true earlier state of it, not merely a sound chain.
//
// It writes nothing, and can't: both connections are read-only from their
// first packet, and each is asked to prove it before anything is read. It
// never raises the integrity alarm (`audit.integrity_failed` pages someone,
// and a broken copy is the drill's finding, not an incident): every problem
// is the run's own line, and the job's exit code.
import { type OperatorTables } from './create-organization.ts';

import { listedOrganizations } from '@agentx/core/modules/directory';
import { createAuditTrail } from '@agentx/core/modules/audit';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { AnchorPoint, ChainReport } from '@agentx/platform/audit-chain';
import { type Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

/** One chain's head on the copy and on the live server, or why it fell short. */
interface ChainOutcome {
  readonly chain: string;
  readonly copySeq?: bigint;
  readonly liveSeq?: bigint;
  readonly problem?: string;
}

export interface RestoreCheckReport {
  readonly chains: readonly ChainOutcome[];
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

/** A chain's report as a head, or its problem in words: never an error's message, which could hold data. */
function headOf(report: ChainReport): AnchorPoint | string {
  return report.ok
    ? { seq: report.seq, hash: report.hash }
    : `${report.problem.reason} at ${String(report.problem.seq)}`;
}

/** The check of one chain, or what stopped it: the database's error code alone. */
async function reportOf(verify: () => Promise<ChainReport>): Promise<AnchorPoint | string> {
  try {
    return headOf(await verify());
  } catch (error) {
    const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'error';
    return `unreadable (${code})`;
  }
}

/** Checks the copy, then the live server against it: never throws for what it finds. */
export async function checkRestoredCopy({ copy, live, keys }: RestoreCheckSides): Promise<RestoreCheckReport> {
  // The IDs are never used: nothing is written. The trail and the chain need a source all the same.
  const platform = createPlatformChain({ keys, ids: uuidV7Ids });
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  const problems: string[] = [];
  const chains: ChainOutcome[] = [];

  const both = async (
    chain: string,
    verify: (database: Database<OperatorTables>, anchor: AnchorPoint | undefined) => Promise<ChainReport>,
  ): Promise<void> => {
    const onCopy = await reportOf(() => verify(copy, undefined));
    if (typeof onCopy === 'string') {
      problems.push(`${chain} on the copy: ${onCopy}`);
      chains.push({ chain, problem: onCopy });
      return;
    }
    const onLive = await reportOf(() => verify(live, onCopy));
    if (typeof onLive === 'string') {
      problems.push(`${chain} on the live server, from the copy's head: ${onLive}`);
      chains.push({ chain, copySeq: onCopy.seq, problem: onLive });
      return;
    }
    chains.push({ chain, copySeq: onCopy.seq, liveSeq: onLive.seq });
  };

  await both('platform', (database, anchor) => platform.verifyAlone(database, anchor));
  const [listed, recorded, liveListed] = await Promise.all([
    listedOrganizations(copy),
    platform.createdOrganizations(copy),
    listedOrganizations(live),
  ]);
  const onList = new Set(listed);
  for (const orgId of recorded) {
    if (!onList.has(orgId)) problems.push(`organisation ${orgId}: recorded as created on the copy, but not listed`);
  }
  for (const orgId of listed) {
    await both(`organisation ${orgId}`, (database, anchor) => trail.verifyAlone(database, orgId, anchor));
  }
  const missingLive = listed.filter((orgId) => !liveListed.includes(orgId));
  for (const orgId of missingLive) problems.push(`organisation ${orgId}: on the copy, but not listed live`);
  return {
    chains,
    copyOrganizations: listed.length,
    newSinceCopy: liveListed.filter((orgId) => !onList.has(orgId)).length,
    problems,
  };
}
