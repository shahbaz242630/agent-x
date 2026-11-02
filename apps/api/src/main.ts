// The API process. Run it with `node apps/api/src/main.ts`. One image and one
// start command; `AGENTX_ROLE` says which side of the work this process does
// (4D2e D):
// - `all`, the default: the server and every job, as one process
// - `web`: the server, with what every process runs for itself
// - `jobs`: the jobs, with no server
// Each first does what boot.ts says, then its own work, then stops as it says.
import type { FastifyInstance } from 'fastify';

import { boot, type ApiProcess, onStopSignals, type RunOptions, sharedParts } from './boot.ts';
import { heartbeatChecks } from './health.ts';
import { eachProcessJobs, oneCopyJobs } from './job-list.ts';
import { keepAlive, startJobs } from './start-jobs.ts';
import { startWeb } from './start-web.ts';

export type { ApiProcess } from './boot.ts';

/**
 * Starts the role's work and returns its server, or nothing where it has none
 * (`jobs`), or nothing with a failed exit code when it can't start.
 */
export async function runApi(host: ApiProcess, options: RunOptions): Promise<FastifyInstance | undefined> {
  const booted = await boot(host, options);
  if (booted === undefined) return undefined;
  const { role } = booted.config;
  const parts = sharedParts(booted);
  const oneCopy = role === 'web' ? undefined : oneCopyJobs(booted, parts);
  const firstZonePass = async (): Promise<void> => {
    await oneCopy?.zoneSealing.run();
  };

  let server: FastifyInstance | undefined;
  if (role === 'jobs') {
    await firstZonePass();
  } else {
    server = await startWeb(
      booted,
      parts,
      heartbeatChecks({ handoff: oneCopy?.handoff, payment_checks: oneCopy?.paymentChecks }),
      firstZonePass,
    );
    if (server === undefined) return undefined;
  }

  const jobs = startJobs([...(oneCopy?.jobs ?? []), ...eachProcessJobs(booted, parts)]);
  const holding = role === 'jobs' ? keepAlive() : undefined;
  onStopSignals(
    booted,
    server,
    {
      stop: async () => {
        await jobs.stop();
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
