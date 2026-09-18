// CI's release to staging (G4; ADR-002 "Deploying"): the one job that signs in
// to Azure. What keeps it narrow is held here: it runs only on a push to main,
// after the image is published and attested, in GitHub's `staging` environment
// (the only subject Azure trusts, and only main may use it), one at a time,
// with no permission but reading the code and asking for Azure's token, and
// with nothing of Azure's printed. For now it only checks (G4-4a).
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { SIGNING_WORKFLOW } from '../../deploy/image/verify.ts';

interface Step {
  name?: string;
  uses?: string;
  run?: string;
  if?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}

interface Job {
  name?: string;
  if?: string;
  needs?: string[] | string;
  'runs-on'?: string;
  'timeout-minutes'?: number;
  environment?: unknown;
  concurrency?: unknown;
  permissions?: Record<string, string>;
  steps?: Step[];
}

const WORKFLOW_DIR = '.github/workflows';
const workflows = readdirSync(WORKFLOW_DIR)
  .filter((file) => /\.ya?ml$/.test(file))
  .map((file) => ({
    file: path.posix.join(WORKFLOW_DIR, file),
    text: readFileSync(path.join(WORKFLOW_DIR, file), 'utf8'),
  }))
  .map(({ file, text }) => ({ file, text, jobs: (parse(text) as { jobs: Record<string, Job> }).jobs }));

const ci = workflows.find(({ file }) => file === SIGNING_WORKFLOW);
if (ci === undefined) throw new Error(`${SIGNING_WORKFLOW} is missing`);
const release = ci.jobs.release;
if (release === undefined) throw new Error(`${SIGNING_WORKFLOW} has no release job`);
const steps = release.steps ?? [];

const AZURE_LOGIN = /^azure\/login@[0-9a-f]{40}$/;

describe('the release job', () => {
  it('is the only job anywhere that names an environment or signs in to Azure', () => {
    const naming = workflows.flatMap(({ file, jobs }) =>
      Object.entries(jobs)
        .filter(([, job]) => job.environment !== undefined)
        .map(([name]) => `${file}: ${name}`),
    );
    expect(naming).toEqual([`${SIGNING_WORKFLOW}: release`]);
    const signingIn = workflows.flatMap(({ file, jobs }) =>
      Object.entries(jobs)
        .filter(([, job]) => (job.steps ?? []).some((step) => step.uses?.startsWith('azure/') === true))
        .map(([name]) => `${file}: ${name}`),
    );
    expect(signingIn).toEqual([`${SIGNING_WORKFLOW}: release`]);
  });

  it('runs only on a push to main, after the image is published and attested, in the staging environment', () => {
    expect(release.if).toBe("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    expect([release.needs ?? []].flat().sort()).toEqual(['image-attest', 'image-publish']);
    // Azure trusts a job in this environment, which only main may use (the handoff: read back S23).
    expect(release.environment).toBe('staging');
  });

  it('runs one release at a time and never cancels one that has started', () => {
    expect(release.concurrency).toEqual({ group: 'release-staging', 'cancel-in-progress': false });
  });

  it('may read the code and ask for Azure’s token, and nothing else', () => {
    expect(release.permissions).toEqual({ contents: 'read', 'id-token': 'write' });
  });

  it('is started by nothing that runs code a pull request controls with the trusted context', () => {
    // pull_request_target, workflow_run and issue_comment run on main's ref with its secrets and environments.
    for (const { file, text } of workflows) {
      expect({ file, trigger: /\b(?:pull_request_target|workflow_run|issue_comment)\b/.test(text) }).toEqual({
        file,
        trigger: false,
      });
    }
  });

  it('checks out the whole history without keeping credentials, and masks the three IDs before signing in', () => {
    const [checkout] = steps;
    expect(checkout?.with).toEqual({ 'persist-credentials': false, 'fetch-depth': 0 });
    const masking = steps.findIndex((step) => step.run?.includes('::add-mask::') === true);
    const signingIn = steps.findIndex((step) => AZURE_LOGIN.test(step.uses ?? ''));
    expect(masking).toBeGreaterThan(0);
    expect(signingIn).toBeGreaterThan(masking);
    expect(steps[masking]?.env).toEqual({
      CLIENT: '${{ vars.AZURE_CLIENT_ID }}',
      TENANT: '${{ vars.AZURE_TENANT_ID }}',
      SUBSCRIPTION: '${{ vars.AZURE_SUBSCRIPTION_ID }}',
    });
  });

  it('signs in by OIDC alone, with the environment’s three IDs and no stored credential', () => {
    const logins = steps.filter((step) => step.uses?.startsWith('azure/login@') === true);
    expect(logins).toHaveLength(1);
    expect(logins[0]?.uses).toMatch(AZURE_LOGIN);
    expect(logins[0]?.with).toEqual({
      'client-id': '${{ vars.AZURE_CLIENT_ID }}',
      'tenant-id': '${{ vars.AZURE_TENANT_ID }}',
      'subscription-id': '${{ vars.AZURE_SUBSCRIPTION_ID }}',
    });
    // No secret anywhere in the job: a client secret or certificate would be a credential to leak.
    expect(JSON.stringify(release)).not.toMatch(/secrets\./);
  });

  it('checks the commit it runs for, with the digest the image job published, and signs out whatever happens', () => {
    const checking = steps.filter((step) => step.run?.startsWith('node deploy/azure/release.ts ') === true);
    expect(checking).toEqual([
      {
        name: 'What a release of this commit would do (reads only)',
        env: { COMMIT: '${{ github.sha }}', DIGEST: '${{ needs.image-publish.outputs.digest }}' },
        run: 'node deploy/azure/release.ts check "${COMMIT}" "${DIGEST}"',
      },
    ]);
    expect(steps.at(-1)).toMatchObject({ if: 'always()', run: 'az account clear' });
  });

  it('has an end', () => {
    expect(release['timeout-minutes']).toBe(15);
  });
});
