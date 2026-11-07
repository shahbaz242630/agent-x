// The load jobs' shared steps (load-jobs.ts) where load.test.ts and the Stage G
// tests don't reach: a job still taking a change, a change Azure ended as
// failed, a job with no time limit, a Stage G job's script. A stand-in CLI.
import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { limitOf, readLoadJob, runWith } from './load-jobs.ts';

const SUBSCRIPTION = '6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';
const LOAD_IMAGE = `ghcr.io/shahbaz242630/agent-x-load@sha256:${'c'.repeat(64)}`;

const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/** A load-step job whose state moves through `states`, one a reading, its change time moving on after a patch. */
class FakeJob implements Az {
  readings = 0;
  patched = 0;
  readonly states: readonly string[];
  readonly limit: unknown;
  readonly script: string;

  constructor(states: readonly string[], limit: unknown = 900, script = 'tooling/load/stageg-job.ts') {
    this.states = states;
    this.limit = limit;
    this.script = script;
  }

  interactive(): number | null {
    throw new Error('never interactive');
  }

  run(args: readonly string[]): AzResult {
    if (args.includes('patch')) {
      this.patched += 1;
      return json({});
    }
    const state = this.states[Math.min(this.readings, this.states.length - 1)] ?? 'Succeeded';
    this.readings += 1;
    return json({
      properties: {
        provisioningState: state,
        configuration: {
          replicaTimeout: this.limit,
          secrets: [{ name: 'load-request' }, { name: 'k', keyVaultUrl: 'https://kv/k', identity: 'id' }],
        },
        template: { containers: [{ image: LOAD_IMAGE, command: ['node', this.script], args: ['step'] }] },
      },
      systemData: { lastModifiedAt: `2026-11-06T10:00:0${String(this.patched)}Z` },
    });
  }
}

const stepsOn = (az: Az) => {
  let clock = 0;
  return {
    az,
    say: () => undefined,
    now: () => {
      clock += 1000;
      return new Date(clock);
    },
    sleep: (ms: number) => {
      clock += ms;
      return Promise.resolve();
    },
  };
};

describe('the load jobs', () => {
  it("knows Stage G's jobs by their own script, and refuses one running another", () => {
    expect(readLoadJob(stepsOn(new FakeJob(['Succeeded'])), SUBSCRIPTION, 'load-step').state).toBe('Succeeded');
    expect(() =>
      readLoadJob(stepsOn(new FakeJob(['Succeeded'], 900, 'tooling/load/job.ts')), SUBSCRIPTION, 'load-step'),
    ).toThrow('it must run node tooling/load/stageg-job.ts step');
  });

  it('refuses a job with no time limit', () => {
    expect(() => limitOf(new FakeJob(['Succeeded'], 'none'), SUBSCRIPTION, 'load-step')).toThrow(
      'Azure gave no time limit for job-agentx-stg-load-step.',
    );
  });

  it('waits out a change still going before writing, and says when Azure ends a change failed', async () => {
    const az = new FakeJob(['InProgress', 'InProgress', 'Succeeded', 'Failed']);
    await expect(
      runWith(stepsOn(az), SUBSCRIPTION, 'load-step', { request: { runId: 'r' }, lastEvent: 'x', ifStuck: 'wait.' }),
    ).rejects.toThrow("Azure's change for the run's request on job-agentx-stg-load-step ended Failed.");
    expect(az.patched).toBeGreaterThan(0);
  });

  it('gives up on a change still going after 10 minutes', async () => {
    const az = new FakeJob(['InProgress']);
    await expect(
      runWith(stepsOn(az), SUBSCRIPTION, 'load-step', { request: { runId: 'r' }, lastEvent: 'x', ifStuck: 'wait.' }),
    ).rejects.toThrow('job-agentx-stg-load-step was still taking a change after 10 minutes.');
  });
});
