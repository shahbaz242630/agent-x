// The API process. Run it with `node apps/api/src/main.ts`. One image and one
// start command; `AGENTX_ROLE` says which side of the work this process does
// (4D2e D):
// - `all`, the default: the server and every job, as one process
// - `web`: the server, with what every process runs for itself
// - `jobs`: the jobs, with no server
// Whichever has the jobs runs them only while it holds their lease (background.ts).
// Each first does what boot.ts says, then its own work, then stops as it says.
import { jobsBeating } from '@agentx/core/modules/platform-controls';
import type { FastifyInstance } from 'fastify';

import type { Leadership } from './background.ts';
import {
  boot,
  type ApiProcess,
  type Booted,
  leadershipOf,
  onStopSignals,
  type RunOptions,
  sharedParts,
  type SharedParts,
} from './boot.ts';
import { HEARTBEAT_STALE_MS } from './handoff.ts';
import { type HealthCheck, heartbeatChecks, sharedHeartbeat } from './health.ts';
import { eachProcessJobs, oneCopyJobs } from './job-list.ts';
import { keepAlive, startJobs } from './start-jobs.ts';
import { startWeb } from './start-web.ts';

export type { ApiProcess } from './boot.ts';

/**
 * /health's checks. Where this process leads, its own hand-off and payment checks
 * say, with no trip. Where it doesn't (`web`, or a follower in a deploy's overlap),
 * the lease's heartbeat says. Only where the partner's rail is built: no jobs beat otherwise.
 */
function healthChecksOf(
  { database }: Booted,
  { rail }: SharedParts,
  leadership: Leadership | undefined,
  oneCopy: ReturnType<typeof oneCopyJobs> | undefined,
): HealthCheck[] {
  if (rail === undefined) return [];
  const leading = (): boolean => leadership?.leading() ?? false;
  const whileLeading = (job: { beating(): boolean } | undefined) =>
    job && { beating: () => !leading() || job.beating() };
  return [
    ...heartbeatChecks({
      handoff: whileLeading(oneCopy?.handoff),
      payment_checks: whileLeading(oneCopy?.paymentChecks),
    }),
    sharedHeartbeat(() => jobsBeating(database, HEARTBEAT_STALE_MS / 1000), leading),
  ];
}

/**
 * Starts the role's work and returns its server, or nothing where it has none
 * (`jobs`), or nothing with a failed exit code when it can't start.
 */
export async function runApi(host: ApiProcess, options: RunOptions): Promise<FastifyInstance | undefined> {
  const booted = await boot(host, options);
  if (booted === undefined) return undefined;
  const { role } = booted.config;
  const leadership = leadershipOf(booted);
  const parts = sharedParts(booted, leadership);
  const oneCopy = leadership && oneCopyJobs(booted, parts, leadership);
  const firstZonePass = async (): Promise<void> => {
    await oneCopy?.zoneSealing.run();
  };

  let server: FastifyInstance | undefined;
  if (role === 'jobs') {
    await firstZonePass();
  } else {
    server = await startWeb(booted, parts, healthChecksOf(booted, parts, leadership, oneCopy), firstZonePass);
    if (server === undefined) return undefined;
  }

  // One try at the lease before the jobs start, so a process alone runs them at once, as it always has.
  await leadership?.start(() => oneCopy?.handoff?.beating() === true && oneCopy.paymentChecks?.beating() === true);
  const jobs = startJobs([...(oneCopy?.jobs ?? []), ...eachProcessJobs(booted, parts)]);
  const holding = role === 'jobs' ? keepAlive() : undefined;
  onStopSignals(
    booted,
    server,
    {
      stop: async () => {
        // The lease last: another copy takes over only once this one's runs have ended.
        await jobs.stop();
        await leadership?.stop();
        holding?.stop();
      },
    },
    parts.recorder,
  );
  return server;
}

// Only when Node runs this file itself. That's a real process, which in-process
// coverage can't see: tooling/checks/api-process.db.test.ts runs it.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runApi(process, {});
