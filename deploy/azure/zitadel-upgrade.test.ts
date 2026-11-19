import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { pinnedZitadelImage, runningZitadelImage, runSetupFirst } from './zitadel-upgrade.ts';

const SUB = '00000000-0000-0000-0000-000000000001';
const OLD = `ghcr.io/zitadel/zitadel:v4.19.5@sha256:${'a'.repeat(64)}`;
const NEW = `ghcr.io/zitadel/zitadel:v4.20.3@sha256:${'b'.repeat(64)}`;
const RUN = 'job-agentx-stg-zitadel-setup-x7k2p';

const ok = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
const refused = (stderr: string): AzResult => ({ status: 1, stdout: '', stderr });

/** The setup job as Azure holds it: one container, its mounts and settings, the image given. */
const setupJob = (image: string, state = 'Succeeded') => ({
  properties: {
    provisioningState: state,
    configuration: { replicaTimeout: 1800 },
    template: {
      containers: [
        {
          name: 'zitadel-setup',
          image,
          command: ['/app/zitadel'],
          args: ['setup', '--masterkeyFile', '/mnt/secrets/zitadel-masterkey'],
          env: [{ name: 'ZITADEL_DATABASE_POSTGRES_USER_PASSWORD', secretRef: 'db-zitadel-password' }],
          volumeMounts: [{ volumeName: 'secrets', mountPath: '/mnt/secrets' }],
          resources: { cpu: 0.5, memory: '1Gi' },
        },
      ],
    },
  },
});

/** The job commands jobs.ts sends through the CLI: no run going, a start, and the run ending as `ends`. */
function jobCommand(args: readonly string[], ends = 'Succeeded'): AzResult | undefined {
  const words = args.slice(0, 4).join(' ');
  if (words === 'containerapp job execution list') return ok([]);
  if (words.startsWith('containerapp job start')) return ok({ name: RUN });
  if (words !== 'containerapp job execution show') return undefined;
  return ok({ properties: { status: ends, startTime: '2026-11-19T08:00:00Z', endTime: '2026-11-19T08:03:00Z' } });
}

/** Zitadel's app as Azure gives it, running `image`; none (a first deploy) for null. */
const zitadelApp = (image: string | null | undefined): AzResult =>
  image === null
    ? refused('(ResourceNotFound) The Resource was not found.')
    : ok({ properties: { template: { containers: [{ name: 'zitadel', image: image ?? OLD }] } } });

/** A CLI over one setup job: the app's image, how the run ends, and every call in order. */
function cli(options: { app?: string | null; job?: string; ends?: string; patchRefused?: boolean } = {}) {
  const calls: string[] = [];
  const bodies: unknown[] = [];
  let jobImage = options.job ?? OLD;
  let reads = 0;
  const az: Az = {
    interactive: () => 0,
    run: (args) => {
      const url = args[args.indexOf('--url') + 1] ?? '';
      const method = args[0] === 'rest' ? args[2] : undefined;
      calls.push(
        method === undefined ? args.slice(0, 4).join(' ') : `${method} ${url.split('?')[0]?.split('/').at(-1)}`,
      );
      if (method === 'get' && url.includes('/containerApps/')) return zitadelApp(options.app);
      if (method === 'get') {
        reads += 1;
        // Just after the PATCH, Azure still shows the job as it was, marked Succeeded; then the new image settling.
        if (reads === 2 && bodies.length > 0) return ok(setupJob(options.job ?? OLD));
        return ok(setupJob(jobImage, reads === 3 ? 'InProgress' : 'Succeeded'));
      }
      if (method === 'patch') {
        if (options.patchRefused === true) return refused('(Conflict) refused');
        bodies.push(JSON.parse(args[args.indexOf('--body') + 1] ?? '{}'));
        const sent = (bodies.at(-1) as ReturnType<typeof setupJob>).properties.template.containers[0];
        jobImage = sent?.image ?? jobImage;
        return ok({});
      }
      const command = jobCommand(args, options.ends);
      if (command !== undefined) return command;
      return refused(`unexpected ${args.join(' ')}`);
    },
  };
  const said: string[] = [];
  const steps = {
    az,
    say: (line: string) => said.push(line),
    now: () => new Date('2026-11-19T08:00:00Z'),
    sleep: () => Promise.resolve(),
  };
  return { steps, calls, bodies, said };
}

describe('Zitadel upgrades: its setup before its apps (AZ29)', () => {
  it('reads the pinned image from the apps parameters, the same one the compose stack runs', () => {
    const params = readFileSync(new URL('./staging.apps.bicepparam', import.meta.url), 'utf8');
    expect(pinnedZitadelImage()).toBe(/^param zitadelImage = '([^']+)'$/m.exec(params)?.[1]);
    expect(pinnedZitadelImage()).toMatch(/^ghcr\.io\/zitadel\/zitadel:v4\.[0-9.]+@sha256:[0-9a-f]{64}$/);
    expect(() => pinnedZitadelImage("param zitadelImage = 'ghcr.io/someone/else:v1'")).toThrow(/pins no Zitadel image/);
    expect(() => pinnedZitadelImage('')).toThrow(/pins no Zitadel image/);
  });

  it("reads what Zitadel's app runs, nothing for a first deploy, and refuses an app that isn't Zitadel's", () => {
    expect(runningZitadelImage(cli({ app: OLD }).steps.az, SUB)).toBe(OLD);
    expect(runningZitadelImage(cli({ app: null }).steps.az, SUB)).toBeUndefined();
    expect(() => runningZitadelImage(cli({ app: 'ghcr.io/someone/else:v1' }).steps.az, SUB)).toThrow(
      /doesn't run one Zitadel container/,
    );
  });

  it('puts the new image on the setup job alone, waits for Azure to hold it, then runs it and waits for success', async () => {
    const { steps, calls, bodies, said } = cli();
    await runSetupFirst(steps, SUB, NEW, OLD);
    expect(calls).toEqual([
      'get job-agentx-stg-zitadel-setup',
      'patch job-agentx-stg-zitadel-setup',
      // The old image still shown, Succeeded; the new one settling; then held.
      'get job-agentx-stg-zitadel-setup',
      'get job-agentx-stg-zitadel-setup',
      'get job-agentx-stg-zitadel-setup',
      'containerapp job execution list',
      'containerapp job start --subscription',
      'containerapp job execution show',
    ]);
    // Only the image changes: its command, arguments, settings by reference and mounts go back as Azure held them.
    expect(bodies).toEqual([
      { properties: { template: { containers: [{ ...setupJob(NEW).properties.template.containers[0] }] } } },
    ]);
    expect(said.at(-1)).toBe(`${RUN} succeeded: Zitadel's database is set up for ${NEW}.`);
  });

  it('sends no PATCH to a job already holding the image, and still runs it', async () => {
    const { steps, calls } = cli({ job: NEW });
    await runSetupFirst(steps, SUB, NEW, OLD);
    expect(calls.filter((call) => call.startsWith('patch'))).toEqual([]);
    expect(calls).toContain('containerapp job start --subscription');
  });

  it('throws, saying what it left and what next, when the run fails, and changes nothing when the PATCH is refused', async () => {
    const failed = cli({ ends: 'Failed' });
    await expect(runSetupFirst(failed.steps, SUB, NEW, OLD)).rejects.toThrow(
      `${RUN} ended Failed: job-agentx-stg-zitadel-setup holds ${NEW}; Zitadel and its login pages still run ${OLD}, and apps was not sent. Read its log: node deploy/azure/jobs.ts wait zitadel-setup ${RUN}`,
    );
    const refusedPatch = cli({ patchRefused: true });
    await expect(runSetupFirst(refusedPatch.steps, SUB, NEW, OLD)).rejects.toThrow(
      /refused .*nothing was run or deployed/,
    );
    expect(refusedPatch.calls.some((call) => call.includes('start'))).toBe(false);
  });

  it("refuses a setup job that isn't the Zitadel setup it knows, before changing anything", async () => {
    const strange = cli();
    const run = strange.steps.az.run.bind(strange.steps.az);
    strange.steps.az.run = (args) => {
      if (args[2] === 'get' && String(args[args.indexOf('--url') + 1]).includes('/jobs/')) {
        return ok({ properties: { template: { containers: [{ name: 'other', image: NEW }] } } });
      }
      return run(args);
    };
    await expect(runSetupFirst(strange.steps, SUB, NEW, OLD)).rejects.toThrow(
      /isn't the Zitadel setup this tool knows/,
    );
    expect(strange.calls.some((call) => call.startsWith('patch'))).toBe(false);
  });
});
