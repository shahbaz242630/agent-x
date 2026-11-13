// The prune of old image versions (0e G4-5; partner, S25: the 5 newest images
// kept, and the one staging runs). What keeps it safe is held here: it runs
// only on a push to main, in the release workflow (AZ2d), only after the release has gone green (staging then
// runs this run's image or a later commit's, and the prune keeps both, read
// from the whole history), one at a time, and it removes versions (G4-5b) with
// no power to sign and no code but ours.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { RELEASE_WORKFLOW } from '../../deploy/image/published.ts';

interface Step {
  name?: string;
  uses?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}

interface Job {
  if?: string;
  needs?: string[] | string;
  'timeout-minutes'?: number;
  environment?: unknown;
  concurrency?: unknown;
  permissions?: Record<string, string>;
  steps?: Step[];
}

const { jobs } = parse(readFileSync(RELEASE_WORKFLOW, 'utf8')) as { jobs: Record<string, Job> };
const prune = jobs['image-prune'];
if (prune === undefined) throw new Error(`${RELEASE_WORKFLOW} has no image-prune job`);
const steps = prune.steps ?? [];

describe('the image prune job', () => {
  it('runs only on a push to main, after the release, with the digest CI’s image jobs left', () => {
    expect(prune.if).toBe("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    expect([prune.needs ?? []].flat().sort()).toEqual(['ci-image', 'release']);
    expect(prune.environment).toBeUndefined();
  });

  it('runs one prune at a time and never cancels one that has started', () => {
    expect(prune.concurrency).toEqual({ group: 'image-prune', 'cancel-in-progress': false });
  });

  it('may read the code and remove package versions, and ask for no signing token', () => {
    expect(prune.permissions).toEqual({ contents: 'read', packages: 'write' });
  });

  it('has time for a run’s 200 removals, one a second', () => {
    expect(prune['timeout-minutes']).toBe(15);
  });

  it('runs the prune alone, with the job token and the published digest, and nothing from outside', () => {
    expect(steps.map((step) => step.uses?.replace(/@.*/, '') ?? 'run')).toEqual([
      'actions/checkout',
      'actions/setup-node',
      'run',
    ]);
    // The whole history: the prune keeps every image of a commit after this one, and would
    // keep every image in a shallow clone, which knows none.
    expect(steps[0]?.with).toEqual({ 'persist-credentials': false, 'fetch-depth': 0 });
    expect(steps[1]?.with?.['check-latest']).toBe(false);
    expect(steps[2]).toEqual({
      name: 'Prune old image versions',
      env: {
        GITHUB_TOKEN: '${{ secrets.GITHUB_TOKEN }}',
        COMMIT: '${{ github.sha }}',
        DIGEST: '${{ needs.ci-image.outputs.digest }}',
      },
      run: 'node deploy/image/prune.ts prune "${COMMIT}" "${DIGEST}"',
    });
  });
});

describe('AZ9: the check that kept images still verify after the prune', () => {
  const kept = jobs['image-kept-verify'];
  if (kept === undefined) throw new Error(`${RELEASE_WORKFLOW} has no image-kept-verify job`);
  const keptSteps = kept.steps ?? [];

  it('runs on a push to main, after the prune, and can only read', () => {
    expect(kept.if).toBe("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    expect([kept.needs ?? []].flat().sort()).toEqual(['ci-image', 'image-prune']);
    expect(kept.permissions).toEqual({ contents: 'read', packages: 'read' });
    expect(kept.environment).toBeUndefined();
  });

  it('checks with the pinned cosign and the prune tool alone, logging in nowhere', () => {
    expect(keptSteps.map((step) => step.uses?.replace(/@.*/, '') ?? 'run')).toEqual([
      'actions/checkout',
      'actions/setup-node',
      'run',
      'run',
    ]);
    expect(keptSteps[0]?.with).toEqual({ 'persist-credentials': false, 'fetch-depth': 0 });
    expect(keptSteps[2]?.run).toBe('node tooling/cosign/install.ts');
    expect(keptSteps[3]).toEqual({
      name: "Check every kept image up to this run's",
      env: {
        GITHUB_TOKEN: '${{ secrets.GITHUB_TOKEN }}',
        COMMIT: '${{ github.sha }}',
        DIGEST: '${{ needs.ci-image.outputs.digest }}',
      },
      run: 'node deploy/image/prune.ts verify-kept "${COMMIT}" "${DIGEST}"',
    });
  });

  it('holds nothing back: no job waits on it', () => {
    expect(Object.values(jobs).filter((other) => [other.needs ?? []].flat().includes('image-kept-verify'))).toEqual([]);
  });
});
