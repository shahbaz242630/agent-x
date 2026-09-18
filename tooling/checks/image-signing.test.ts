// SEC-SC-02's second half (ADR-002 Amendment E2): the image is published and
// signed only by CI's image jobs, only from main after every other check has
// passed, where the deploy check (deploy/image/verify.ts) looks, and each of
// that check's refusals is proven against the real image on every publish.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import {
  EXIT,
  IMAGE_REPOSITORY,
  SIGNER_IDENTITY,
  SIGNING_WORKFLOW,
  SOURCE_REPOSITORY,
} from '../../deploy/image/verify.ts';

interface Step {
  name?: string;
  uses?: string;
  run?: string;
  if?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
}

interface Job {
  if?: string;
  needs?: string[] | string;
  permissions?: Record<string, string>;
  env?: Record<string, string>;
  steps?: Step[];
}

interface Workflow {
  jobs: Record<string, Job>;
}

const WORKFLOW_DIR = '.github/workflows';
const workflows = readdirSync(WORKFLOW_DIR)
  .filter((file) => /\.ya?ml$/.test(file))
  .map((file) => ({
    file: path.posix.join(WORKFLOW_DIR, file),
    workflow: parse(readFileSync(path.join(WORKFLOW_DIR, file), 'utf8')) as Workflow,
  }));

const ci = workflows.find(({ file }) => file === SIGNING_WORKFLOW)?.workflow;
if (ci === undefined) throw new Error(`${SIGNING_WORKFLOW} is missing`);
const jobs = ci.jobs;

const IMAGE_JOBS = ['image-publish', 'image-sbom', 'image-attest'];
const MAIN_PUSH_ONLY = "github.event_name == 'push' && github.ref == 'refs/heads/main'";

const job = (name: string): Job => {
  const found = jobs[name];
  if (found === undefined) throw new Error(`${SIGNING_WORKFLOW} has no job ${name}`);
  return found;
};
const steps = (name: string): Step[] => job(name).steps ?? [];
const indexOf = (name: string, found: (step: Step) => boolean): number => {
  const index = steps(name).findIndex(found);
  if (index < 0) throw new Error(`${name} has no such step`);
  return index;
};
const expecting = (code: number) => (step: Step) => step.env?.EXPECTED_EXIT === String(code);
const running = (command: string) => (step: Step) => step.run?.includes(command) === true;

describe('SEC-SC-02 the image is signed only by CI on main, and verified before deploy', () => {
  it('lets only the publishing and attesting jobs push packages or ask for a signing token', () => {
    const holding = (scope: string) =>
      workflows.flatMap(({ file, workflow }) =>
        Object.entries(workflow.jobs)
          .filter(([, candidate]) => candidate.permissions?.[scope] === 'write')
          .map(([name]) => `${file}: ${name}`),
      );
    expect(holding('packages').sort()).toEqual([
      `${SIGNING_WORKFLOW}: image-attest`,
      `${SIGNING_WORKFLOW}: image-publish`,
    ]);
    // The release job asks for a token too, but Azure's (release-job.test.ts): it pushes nothing and signs nothing.
    expect(holding('id-token').sort()).toEqual([
      `${SIGNING_WORKFLOW}: image-attest`,
      `${SIGNING_WORKFLOW}: image-publish`,
      `${SIGNING_WORKFLOW}: release`,
    ]);
    // It checks the image with the pinned cosign (release.ts), and never signs, attests or pushes one.
    expect(
      steps('release').some((step) =>
        /cosign (?:sign|attest)|cosign-installer|docker (?:push|login)/.test(`${step.uses ?? ''} ${step.run ?? ''}`),
      ),
    ).toBe(false);
  });

  it('gives every push its own run, so no merged commit is left without a signed image', () => {
    // GitHub cancels all but one waiting run in a concurrency group, whatever cancel-in-progress says.
    const { concurrency } = parse(readFileSync(SIGNING_WORKFLOW, 'utf8')) as {
      concurrency?: { group?: string; 'cancel-in-progress'?: string };
    };
    expect(concurrency?.group).toBe("ci-${{ github.event_name == 'pull_request' && github.ref || github.sha }}");
    expect(concurrency?.['cancel-in-progress']).toBe("${{ github.event_name == 'pull_request' }}");
  });

  it('runs the image jobs only on a push to main', () => {
    for (const name of IMAGE_JOBS) expect(job(name).if).toBe(MAIN_PUSH_ONLY);
  });

  it('publishes nothing until every other job on a push has passed, and releases only what it published', () => {
    // The release job comes after the image jobs, releasing what they published (release-job.test.ts),
    // and the prune after the release (image-prune.test.ts).
    const others = Object.entries(jobs)
      .filter(
        ([name, candidate]) =>
          !IMAGE_JOBS.includes(name) &&
          !['release', 'image-prune'].includes(name) &&
          candidate.if !== "github.event_name == 'pull_request'",
      )
      .map(([name]) => name);
    expect(others.length).toBeGreaterThanOrEqual(5);
    expect([job('image-publish').needs ?? []].flat().sort()).toEqual(others.sort());
    expect([job('image-sbom').needs ?? []].flat()).toEqual(['image-publish']);
    expect([job('image-attest').needs ?? []].flat().sort()).toEqual(['image-publish', 'image-sbom']);
    expect([job('release').needs ?? []].flat().sort()).toEqual(['image-attest', 'image-publish']);
  });

  it('keeps the SBOM scanner, outside code, in a job that can only read the image', () => {
    expect(job('image-sbom').permissions).toEqual({ packages: 'read' });
  });

  it('gives the scanner no registry login: the image is pulled, and the login ended, before it runs', () => {
    const pull = indexOf('image-sbom', running('docker pull'));
    const scan = indexOf('image-sbom', (step) => step.uses?.startsWith('anchore/sbom-action@') === true);
    expect(pull).toBeLessThan(scan);
    expect(steps('image-sbom')[pull]?.run).toMatch(/^trap 'docker logout ghcr\.io' EXIT\n/);
    expect(Object.keys(steps('image-sbom')[scan]?.with ?? {}).filter((input) => input.startsWith('registry-'))).toEqual(
      [],
    );
  });

  it('installs cosign 3.1.3 or later wherever it runs (GHSA-fx35-mq7g-6g98)', () => {
    const installs = workflows.flatMap(({ workflow }) =>
      Object.values(workflow.jobs).flatMap((candidate) =>
        (candidate.steps ?? []).filter((step) => step.uses?.startsWith('sigstore/cosign-installer@') === true),
      ),
    );
    expect(installs).toHaveLength(2);
    for (const step of installs) {
      const [major = 0, minor = 0, patch = 0] = (step.with?.['cosign-release'] ?? '')
        .replace(/^v/, '')
        .split('.')
        .map(Number);
      expect(step.with?.['cosign-release']).toMatch(/^v\d+\.\d+\.\d+$/);
      expect(major * 1_000_000 + minor * 1_000 + patch).toBeGreaterThanOrEqual(3_001_003);
    }
  });

  it('publishes where the deploy check looks, signs as the identity it expects, and links the package to the repository', () => {
    expect(job('image-publish').env?.IMAGE).toBe(IMAGE_REPOSITORY);
    expect(job('image-attest').env?.IMAGE).toBe(IMAGE_REPOSITORY);
    const scan = steps('image-sbom').find((step) => step.uses?.startsWith('anchore/sbom-action@') === true);
    expect(scan?.with?.image).toBe(`${IMAGE_REPOSITORY}@\${{ needs.image-publish.outputs.digest }}`);
    expect(SIGNER_IDENTITY).toBe(`https://github.com/${SOURCE_REPOSITORY}/${SIGNING_WORKFLOW}@refs/heads/main`);
    expect(readFileSync('Dockerfile', 'utf8')).toContain(
      `org.opencontainers.image.source="https://github.com/${SOURCE_REPOSITORY}"`,
    );
  });

  it('signs and attests the image by its digest, never by a tag', () => {
    const signing = steps('image-publish').filter(running('cosign sign '));
    const attesting = steps('image-attest').filter(running('cosign attest '));
    expect(signing).toHaveLength(1);
    expect(attesting).toHaveLength(1);
    expect(signing[0]?.run).toMatch(/cosign sign --yes "\$\{IMAGE\}@\$\{DIGEST\}"$/);
    expect(signing[0]?.env?.DIGEST).toBe('${{ steps.push.outputs.digest }}');
    expect(attesting[0]?.run).toMatch(
      /cosign attest --yes --type cyclonedx --predicate "\$\{files\[0\]\}" "\$\{IMAGE\}@\$\{DIGEST\}"\n?$/,
    );
    expect(attesting[0]?.env?.DIGEST).toBe('${{ needs.image-publish.outputs.digest }}');
  });

  it('signs the digest this push uploaded, read from the local image, never from the movable tag', () => {
    const push = steps('image-publish').find((step) => step.name === 'Push');
    expect(push?.run).toContain(
      'docker image inspect "${IMAGE}:${COMMIT}" --format \'{{range .RepoDigests}}{{.}} {{end}}\'',
    );
    expect(push?.run).toContain('if [ "${#digests[@]}" -ne 1 ]; then');
    expect(push?.run).toContain('docker buildx imagetools inspect "${IMAGE}@${digest}"');
    expect(push?.run).not.toContain('imagetools inspect "${IMAGE}:${COMMIT}"');
  });

  it('tries the push three times before failing, since the registry sometimes refuses one ("unknown blob")', () => {
    const run = steps('image-publish').find((step) => step.name === 'Push')?.run ?? '';
    expect(run.match(/docker push /g)).toHaveLength(1);
    expect(run).toContain(
      'pushed=false\nfor attempt in 1 2 3; do\n  if docker push --quiet "${IMAGE}:${COMMIT}"; then\n    pushed=true\n    break\n  fi\n',
    );
    expect(run).toContain(
      'if [ "${pushed}" != true ]; then\n  echo "::error::Pushing ${IMAGE}:${COMMIT} failed 3 times."\n  exit 1\nfi\n',
    );
    expect(run.indexOf('docker push ')).toBeLessThan(run.indexOf('docker image inspect'));
  });

  it("uses the runner image's own Node, not a same-day download, in the jobs that can sign", () => {
    for (const name of ['image-publish', 'image-attest']) {
      const setupNode = steps(name).find((step) => step.uses?.startsWith('actions/setup-node@') === true);
      expect(setupNode?.with?.['check-latest']).toBe(false);
    }
  });

  it('proves each refusal against the real image, in order: unsigned, then no SBOM, then another commit', () => {
    const unsigned = indexOf('image-publish', expecting(EXIT.IMAGE_UNSIGNED));
    const sign = indexOf('image-publish', running('cosign sign '));
    const noSbom = indexOf('image-publish', expecting(EXIT.SBOM_MISSING));
    expect(unsigned).toBeLessThan(sign);
    expect(sign).toBeLessThan(noSbom);

    const attest = indexOf('image-attest', running('cosign attest '));
    const accepted = indexOf(
      'image-attest',
      (step) => running('node deploy/image/verify.ts')(step) && step.env?.EXPECTED_EXIT === undefined,
    );
    const otherCommit = indexOf('image-attest', expecting(EXIT.SIGNATURE_REFUSED));
    expect(attest).toBeLessThan(accepted);
    expect(accepted).toBeLessThan(otherCommit);
    expect(steps('image-attest')[accepted]?.env?.COMMIT).toBe('${{ github.sha }}');
    expect(steps('image-attest')[otherCommit]?.env?.COMMIT).toMatch(/^[0-9a-f]{40}$/);
  });

  it('runs every proof as the deploy check itself, with the exit code it expects', () => {
    const proofs = IMAGE_JOBS.flatMap(steps).filter((step) => step.env?.EXPECTED_EXIT !== undefined);
    expect(proofs).toHaveLength(3);
    for (const proof of proofs) {
      expect(proof.run).toContain('node deploy/image/verify.ts "${IMAGE}@${DIGEST}" "${COMMIT}" || status=$?');
      expect(proof.run).toContain('if [ "${status}" -ne "${EXPECTED_EXIT}" ]; then');
    }
  });

  it('logs out of the registry even when a step fails', () => {
    for (const name of ['image-publish', 'image-attest']) {
      expect(steps(name).at(-1)).toMatchObject({ if: 'always()', run: 'docker logout ghcr.io' });
    }
  });
});
