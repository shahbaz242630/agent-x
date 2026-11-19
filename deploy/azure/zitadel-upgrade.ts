// Zitadel upgrades (AZ29, S190 #642 review). `zitadel start` runs no
// migrations: a new version's `zitadel setup` must have run before Zitadel and
// its login pages start on it. `apps` changes the setup job and the two apps in
// one deployment, so the apps rolled first and, until someone ran the setup job
// by hand, sign-up and creating organisations, projects or apps failed.
//
// So when the image staging.apps.bicepparam pins differs from the one the
// Zitadel app runs, `apps` (deploy.ts) runs the setup first: the pinned image
// put on the setup job alone, by a minimal PATCH of its one container, as CI's
// release puts ours on the migration job (never `az containerapp update`); the
// job run and waited for (jobs.ts); and only once it has succeeded is the
// deployment sent, which rolls the apps. The old version keeps serving on the
// set-up database meanwhile, as Zitadel's own upgrade order has it.
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { ARM, type Az, RESOURCE_GROUP, text } from './deploy.ts';
import { JOBS_API, jobName, type JobSteps, start, waitFor } from './jobs.ts';

/** The image every Zitadel server container is (policy.ts ZITADEL_SERVER_IMAGE), a tag and a digest after it. */
const ZITADEL_SERVER = 'ghcr.io/zitadel/zitadel:';

/** Where the version a deployment sends is pinned (tooling/checks/images.test.ts keeps it the compose stack's). */
const APPS_PARAMS = path.join(import.meta.dirname, 'staging.apps.bicepparam');

/** The Zitadel image `apps` sends: staging.apps.bicepparam's zitadelImage, as written there. */
export function pinnedZitadelImage(params: string = readFileSync(APPS_PARAMS, 'utf8')): string {
  const found = /^param zitadelImage = '([^']+)'$/m.exec(params)?.[1];
  if (!found?.startsWith(ZITADEL_SERVER)) {
    throw new Error(
      "staging.apps.bicepparam pins no Zitadel image (param zitadelImage = 'ghcr.io/zitadel/zitadel:…').",
    );
  }
  return found;
}

/** How long Azure may take to settle the setup job's PATCH before the run gives up, and how often it looks. */
const SETTLE_MS = 600_000;

const workloadUrl = (subscription: string, kind: 'containerApps' | 'jobs', name: string): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/${kind}/${name}?api-version=${JOBS_API}`;

/** One GET through Resource Manager, or undefined for a resource that isn't there (a first deploy). */
function got(az: Az, url: string): Record<string, unknown> | undefined {
  const done = az.run(['rest', '--method', 'get', '--url', url]);
  if (done.status !== 0) {
    if (/\(ResourceNotFound\)|\bNot ?Found\b/i.test(done.stderr)) return undefined;
    throw new Error(
      `Azure didn't answer a read of ${url.split('?')[0]?.split('/').at(-1) ?? 'it'}:\n${done.stderr.trim()}`,
    );
  }
  return JSON.parse(done.stdout) as Record<string, unknown>;
}

/** A resource's one container, as Azure gives it, or undefined when it holds any other number. */
function onlyContainer(resource: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  const containers = (resource?.properties as { template?: { containers?: unknown } } | undefined)?.template
    ?.containers;
  return Array.isArray(containers) && containers.length === 1 ? (containers[0] as Record<string, unknown>) : undefined;
}

/** The image Zitadel's app runs, or undefined where there is no app yet: a first deploy, whose jobs run after it. */
export function runningZitadelImage(az: Az, subscription: string): string | undefined {
  const app = got(az, workloadUrl(subscription, 'containerApps', 'ca-agentx-stg-zitadel'));
  if (app === undefined) return undefined;
  const image = text(onlyContainer(app)?.image);
  if (!image.startsWith(ZITADEL_SERVER)) {
    throw new Error(
      "ca-agentx-stg-zitadel doesn't run one Zitadel container, so whether Zitadel moves can't be told: nothing was deployed.",
    );
  }
  return image;
}

/**
 * The setup job's one container with `image` in place, everything else as Azure holds it (its command, arguments,
 * settings by name or secret reference, mounts and size), or an error for a job that isn't the Zitadel setup.
 */
function withImage(job: Record<string, unknown> | undefined, image: string): Record<string, unknown> {
  const container = onlyContainer(job);
  const name = jobName('zitadel-setup');
  if (job === undefined)
    throw new Error(`${name} isn't there, so Zitadel's setup can't run first: nothing was deployed.`);
  if (container?.name !== 'zitadel-setup' || !text(container.image).startsWith(ZITADEL_SERVER)) {
    throw new Error(
      `${name} isn't the Zitadel setup this tool knows (one container, zitadel-setup, Zitadel's image): nothing was changed.`,
    );
  }
  return { ...container, image };
}

/** The setup job's time limit, in seconds, which its run is waited for against. */
function limitOf(job: Record<string, unknown>): number {
  const seconds = (job.properties as { configuration?: { replicaTimeout?: unknown } } | undefined)?.configuration
    ?.replicaTimeout;
  if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds <= 0) {
    throw new Error(`Azure gave no time limit for ${jobName('zitadel-setup')}, so how long to wait is unknown.`);
  }
  return seconds;
}

/** Waits until Azure holds the setup job with `image`, marked Succeeded: just after the PATCH it may show the old. */
async function settled(steps: JobSteps, url: string, image: string): Promise<Record<string, unknown>> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    const job = got(steps.az, url);
    const state = text((job?.properties as { provisioningState?: unknown } | undefined)?.provisioningState);
    const taken = text(onlyContainer(job)?.image) === image;
    if (job !== undefined && taken && state === 'Succeeded') return job;
    if (taken && (state === 'Failed' || state === 'Canceled')) {
      throw new Error(`Azure's update of ${jobName('zitadel-setup')} ended ${state}: nothing was deployed.`);
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `Azure hadn't settled ${jobName('zitadel-setup')}'s new image after 10 minutes (${state || 'no state'}): nothing was deployed.`,
      );
    }
    await steps.sleep(15_000);
  }
}

/**
 * Zitadel's setup at `image`, run to success before the apps roll: the setup job given the image (a PATCH of its
 * one container, sent only when it holds another), started once no run of it is going, and waited for. Anything but
 * success throws, saying what it left: the apps untouched, on the version they ran.
 */
export async function runSetupFirst(steps: JobSteps, subscription: string, image: string, from: string): Promise<void> {
  const name = jobName('zitadel-setup');
  const url = workloadUrl(subscription, 'jobs', name);
  const job = got(steps.az, url);
  const container = withImage(job, image);
  if (text(onlyContainer(job)?.image) === image) {
    steps.say(`${name} already holds ${image}.`);
  } else {
    const done = steps.az.run([
      'rest',
      '--method',
      'patch',
      '--url',
      url,
      '--body',
      JSON.stringify({ properties: { template: { containers: [container] } } }),
    ]);
    if (done.status !== 0) {
      throw new Error(
        `Azure refused ${name}'s new image, so nothing was run or deployed. The resource group's activity log has why.`,
      );
    }
    steps.say(`Updating ${name} to ${image}...`);
  }
  const limit = limitOf(await settled(steps, url, image));
  const left = `${name} holds ${image}; Zitadel and its login pages still run ${from}, and apps was not sent`;
  const target = { subscription, job: 'zitadel-setup' } as const;
  const run = start(steps, target);
  const ended = await waitFor(steps, target, run, limit);
  if (ended?.status !== 'Succeeded') {
    const how = ended === undefined ? "hadn't ended in time" : 'ended ' + ended.status;
    throw new Error(
      `${run} ${how}: ${left}. Read its log: node deploy/azure/jobs.ts wait zitadel-setup ${run}; a setup that died mid-step needs jobs.ts cleanup first (Azure.md, "Running the jobs"). Then run apps again.`,
    );
  }
  steps.say(`${run} succeeded: Zitadel's database is set up for ${image}.`);
}
