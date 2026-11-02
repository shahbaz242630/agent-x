// Starts the API's jobs (job-list.ts), in the list's order, each on a timer of
// its own, and stops them together. A process that has no server has nothing
// else to keep it alive: every job's timer lets the process end (background.ts).
import type { Job } from './job-list.ts';

/** Long enough never to matter: it only has to be there. */
const KEEP_ALIVE_EVERY_MS = 2 ** 30;

export function startJobs(jobs: readonly Job[]): { stop(): Promise<void> } {
  const handles = jobs.map((job) => job.start());
  return {
    stop: async () => {
      await Promise.all(handles.map((handle) => handle.stop()));
    },
  };
}

/** Holds a process with no server open until it stops. */
export function keepAlive(everyMs = KEEP_ALIVE_EVERY_MS): { stop(): void } {
  const timer = setInterval(() => undefined, everyMs);
  return {
    stop: () => {
      clearInterval(timer);
    },
  };
}
