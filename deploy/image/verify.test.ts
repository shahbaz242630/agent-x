import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type Cosign,
  digestOf,
  EXIT,
  IMAGE_REPOSITORY,
  main,
  OIDC_ISSUER,
  type Run,
  runCosign,
  SBOM_PREDICATE_TYPE,
  sbomArgs,
  sbomOutputProblem,
  signatureArgs,
  signatureOutputProblem,
  SIGNER_IDENTITY,
  signerFlags,
  verifyImage,
} from './verify.ts';

const HEX = '3f'.repeat(32);
const DIGEST = `sha256:${HEX}`;
const IMAGE = `${IMAGE_REPOSITORY}@${DIGEST}`;
const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const OTHER_HEX = 'e0'.repeat(32);

/** One entry of `cosign verify`'s JSON, as cosign 3.1.3 prints it for a bundle. */
const verified = (type: string, digest = DIGEST): unknown => ({
  critical: { identity: { 'docker-reference': IMAGE }, image: { 'docker-manifest-digest': digest }, type },
  optional: {},
});
const SIGNATURE = 'https://sigstore.dev/cosign/sign/v1';

/** One line of `cosign verify-attestation`'s output: a DSSE envelope around an in-toto statement. */
const envelope = (statement: unknown, payloadType = 'application/vnd.in-toto+json'): string =>
  JSON.stringify({
    payloadType,
    payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
    signatures: [{ keyid: '', sig: 'c2lnbmF0dXJl' }],
  });
const sbomStatement = (hex = HEX, predicateType = SBOM_PREDICATE_TYPE): unknown => ({
  _type: 'https://in-toto.io/Statement/v0.1',
  subject: [{ name: IMAGE_REPOSITORY, digest: { sha256: hex } }],
  predicateType,
  predicate: { bomFormat: 'CycloneDX', specVersion: '1.7', components: [] },
});

const ok = (stdout: string): Run => ({ status: 0, stdout, stderr: 'Verification for …\n' });
const failed = (status: number, message: string): Run => ({
  status,
  stdout: '',
  stderr: `Error: ${message}\nerror during command execution: ${message}\n`,
});

const GOOD_SIGNATURE = ok(JSON.stringify([verified(SIGNATURE), verified(SBOM_PREDICATE_TYPE)]));
const GOOD_SBOM = ok(`${envelope(sbomStatement())}\n`);

/** A stand-in for cosign that answers each subcommand and records every call. */
function fakeCosign(answers: { verify?: Run; attestation?: Run }): Cosign & { calls: string[][] } {
  const calls: string[][] = [];
  const cosign = (args: readonly string[]): Run => {
    calls.push([...args]);
    const answer = args[0] === 'verify' ? answers.verify : answers.attestation;
    if (answer === undefined) throw new Error(`unexpected cosign ${args[0] ?? ''}`);
    return answer;
  };
  return Object.assign(cosign, { calls });
}

describe('SEC-SC-02 verify-before-deploy: only our signed image, by digest, at this commit', () => {
  describe('the image must be ours and named by its digest', () => {
    it('accepts our repository at a sha256 digest', () => {
      expect(digestOf(IMAGE)).toBe(DIGEST);
    });

    it.each([
      ['a tag', `${IMAGE_REPOSITORY}:${COMMIT}`],
      ['a tag and a digest', `${IMAGE_REPOSITORY}:latest@${DIGEST}`],
      ['another owner', `ghcr.io/someone-else/agent-x@${DIGEST}`],
      ['a longer name', `${IMAGE_REPOSITORY}-evil@${DIGEST}`],
      ['a path below ours', `${IMAGE_REPOSITORY}/sub@${DIGEST}`],
      ['another registry', `docker.io/shahbaz242630/agent-x@${DIGEST}`],
      ['upper-case hex', `${IMAGE_REPOSITORY}@sha256:${HEX.toUpperCase()}`],
      ['63 hex digits', `${IMAGE_REPOSITORY}@sha256:${HEX.slice(1)}`],
      ['another algorithm', `${IMAGE_REPOSITORY}@sha512:${HEX}${HEX}`],
      ['a trailing newline', `${IMAGE}\n`],
      ['nothing', ''],
    ])('refuses %s', (_case, image) => {
      expect(digestOf(image)).toBeUndefined();
    });
  });

  describe('every check pins the signer: CI on main, pushed, at this commit', () => {
    it('names the workflow file and branch that sign, and GitHub as the issuer', () => {
      expect(SIGNER_IDENTITY).toBe('https://github.com/shahbaz242630/agent-x/.github/workflows/ci.yml@refs/heads/main');
      expect(OIDC_ISSUER).toBe('https://token.actions.githubusercontent.com');
    });

    it('asks cosign for every claim, the commit included', () => {
      expect(signerFlags(COMMIT)).toEqual([
        '--certificate-identity',
        SIGNER_IDENTITY,
        '--certificate-oidc-issuer',
        OIDC_ISSUER,
        '--certificate-github-workflow-repository',
        'shahbaz242630/agent-x',
        '--certificate-github-workflow-ref',
        'refs/heads/main',
        '--certificate-github-workflow-trigger',
        'push',
        '--certificate-github-workflow-sha',
        COMMIT,
      ]);
    });

    it('verifies the signature and the CycloneDX attestation with those claims, on the digest', () => {
      expect(signatureArgs(IMAGE, COMMIT)).toEqual(['verify', ...signerFlags(COMMIT), IMAGE]);
      expect(sbomArgs(IMAGE, COMMIT)).toEqual([
        'verify-attestation',
        '--type',
        'cyclonedx',
        ...signerFlags(COMMIT),
        IMAGE,
      ]);
    });
  });

  describe("cosign's signature output must show a signature over this digest", () => {
    it('accepts a signature, alone or listed with the SBOM', () => {
      expect(signatureOutputProblem(JSON.stringify([verified(SIGNATURE)]), DIGEST)).toBeUndefined();
      expect(signatureOutputProblem(GOOD_SIGNATURE.stdout, DIGEST)).toBeUndefined();
    });

    it.each([
      ['no JSON', 'Verification for …', 'cosign printed no JSON'],
      ['an empty list', '[]', 'cosign listed nothing it verified'],
      ['an object', JSON.stringify(verified(SIGNATURE)), 'cosign listed nothing it verified'],
      [
        'only an attestation',
        JSON.stringify([verified(SBOM_PREDICATE_TYPE)]),
        'cosign verified attestations but no signature',
      ],
      [
        'something over another digest',
        JSON.stringify([verified(SIGNATURE), verified(SIGNATURE, `sha256:${OTHER_HEX}`)]),
        `cosign listed something not over ${DIGEST}`,
      ],
      [
        'an entry without claims',
        JSON.stringify([verified(SIGNATURE), {}]),
        `cosign listed something not over ${DIGEST}`,
      ],
      ['a non-object entry', JSON.stringify([verified(SIGNATURE), 'x']), `cosign listed something not over ${DIGEST}`],
    ])('refuses %s', (_case, stdout, problem) => {
      expect(signatureOutputProblem(stdout, DIGEST)).toBe(problem);
    });
  });

  describe("cosign's attestation output must be CycloneDX SBOMs about this digest", () => {
    it('accepts one SBOM, or several, ignoring blank lines', () => {
      expect(sbomOutputProblem(GOOD_SBOM.stdout, DIGEST)).toBeUndefined();
      expect(
        sbomOutputProblem(`\n${envelope(sbomStatement())}\n\n${envelope(sbomStatement())}\n`, DIGEST),
      ).toBeUndefined();
    });

    it('accepts a statement that names several subjects, this digest among them', () => {
      const statement = {
        ...(sbomStatement() as object),
        subject: [{ digest: { sha256: OTHER_HEX } }, { digest: { sha256: HEX } }],
      };
      expect(sbomOutputProblem(envelope(statement), DIGEST)).toBeUndefined();
    });

    it.each([
      ['no output', '\n', 'cosign printed no attestation'],
      ['a line that is not JSON', 'Verification for …', 'an attestation is not readable JSON'],
      [
        'a payload that is not JSON',
        JSON.stringify({ payloadType: 'application/vnd.in-toto+json', payload: 'bm90IGpzb24=' }),
        'an attestation is not readable JSON',
      ],
      ['another payload type', envelope(sbomStatement(), 'text/plain'), 'an attestation is not an in-toto envelope'],
      [
        'a payload that is not a string',
        JSON.stringify({ payloadType: 'application/vnd.in-toto+json', payload: 1 }),
        'an attestation is not an in-toto envelope',
      ],
      ['an envelope that is a list', '[]', 'an attestation is not an in-toto envelope'],
      [
        'an SPDX SBOM',
        envelope(sbomStatement(HEX, 'https://spdx.dev/Document')),
        'an attestation is not a CycloneDX SBOM',
      ],
      ['a statement that is a list', envelope([]), 'an attestation is not a CycloneDX SBOM'],
      ['an SBOM of another image', envelope(sbomStatement(OTHER_HEX)), `an SBOM is not about ${DIGEST}`],
      ['an SBOM with no subject', envelope({ predicateType: SBOM_PREDICATE_TYPE }), `an SBOM is not about ${DIGEST}`],
      [
        'a subject without a digest',
        envelope({ predicateType: SBOM_PREDICATE_TYPE, subject: [{ name: 'x' }] }),
        `an SBOM is not about ${DIGEST}`,
      ],
      [
        'one good line and one bad',
        `${envelope(sbomStatement())}\n${envelope(sbomStatement(OTHER_HEX))}`,
        `an SBOM is not about ${DIGEST}`,
      ],
    ])('refuses %s', (_case, stdout, problem) => {
      expect(sbomOutputProblem(stdout, DIGEST)).toBe(problem);
    });
  });

  describe('each outcome, checking the signature before the SBOM', () => {
    it('verifies a signed image with its SBOM, asking cosign exactly the pinned questions', () => {
      const cosign = fakeCosign({ verify: GOOD_SIGNATURE, attestation: GOOD_SBOM });
      expect(verifyImage(IMAGE, COMMIT, cosign)).toEqual({ verified: true });
      expect(cosign.calls).toEqual([signatureArgs(IMAGE, COMMIT), sbomArgs(IMAGE, COMMIT)]);
    });

    it('refuses a bad image or commit without running cosign', () => {
      const cosign = fakeCosign({});
      expect(verifyImage(`${IMAGE_REPOSITORY}:latest`, COMMIT, cosign)).toEqual({
        verified: false,
        reason: 'INPUT_INVALID',
        detail: `not ${IMAGE_REPOSITORY}@sha256:<64 hex digits>`,
      });
      for (const commit of [COMMIT.toUpperCase(), COMMIT.slice(1), `${COMMIT}0`, '']) {
        expect(verifyImage(IMAGE, commit, cosign)).toEqual({
          verified: false,
          reason: 'INPUT_INVALID',
          detail: 'the commit must be 40 lower-case hex digits',
        });
      }
      expect(cosign.calls).toEqual([]);
    });

    it("calls an image with no signature unsigned, from cosign's own exit code", () => {
      const cosign = fakeCosign({ verify: failed(10, 'no signatures found') });
      expect(verifyImage(IMAGE, COMMIT, cosign)).toEqual({
        verified: false,
        reason: 'IMAGE_UNSIGNED',
        detail: 'error during command execution: no signatures found',
      });
      expect(cosign.calls).toHaveLength(1);
    });

    it('refuses a signature from anyone else, or one that cosign could not check', () => {
      const mismatch = 'no matching attestations: expected GithubWorkflowSHA to be "x", got "y"';
      expect(verifyImage(IMAGE, COMMIT, fakeCosign({ verify: failed(1, mismatch) }))).toEqual({
        verified: false,
        reason: 'SIGNATURE_REFUSED',
        detail: `error during command execution: ${mismatch}`,
      });
      const missing: Run = { status: null, stdout: '', stderr: 'cosign could not run: spawn cosign ENOENT' };
      expect(verifyImage(IMAGE, COMMIT, fakeCosign({ verify: missing }))).toEqual({
        verified: false,
        reason: 'SIGNATURE_REFUSED',
        detail: 'cosign could not run: spawn cosign ENOENT',
      });
      expect(verifyImage(IMAGE, COMMIT, fakeCosign({ verify: { status: 1, stdout: '', stderr: '' } }))).toEqual({
        verified: false,
        reason: 'SIGNATURE_REFUSED',
        detail: 'no message',
      });
    });

    it('refuses when cosign passes but its output shows no signature', () => {
      const cosign = fakeCosign({ verify: ok(JSON.stringify([verified(SBOM_PREDICATE_TYPE)])) });
      expect(verifyImage(IMAGE, COMMIT, cosign)).toEqual({
        verified: false,
        reason: 'SIGNATURE_REFUSED',
        detail: 'cosign verified attestations but no signature',
      });
      expect(cosign.calls).toHaveLength(1);
    });

    it('calls a signed image with no SBOM attestation missing its SBOM', () => {
      const message = `none of the attestations matched the predicate type: cyclonedx, found: ${SIGNATURE}`;
      expect(
        verifyImage(IMAGE, COMMIT, fakeCosign({ verify: GOOD_SIGNATURE, attestation: failed(1, message) })),
      ).toEqual({ verified: false, reason: 'SBOM_MISSING', detail: `error during command execution: ${message}` });
    });

    it('refuses an SBOM attestation from anyone else, or not about this image', () => {
      const mismatch = 'no matching attestations: failed to verify certificate identity';
      expect(
        verifyImage(IMAGE, COMMIT, fakeCosign({ verify: GOOD_SIGNATURE, attestation: failed(1, mismatch) })),
      ).toEqual({
        verified: false,
        reason: 'SBOM_REFUSED',
        detail: `error during command execution: ${mismatch}`,
      });
      const elsewhere = ok(envelope(sbomStatement(OTHER_HEX)));
      expect(verifyImage(IMAGE, COMMIT, fakeCosign({ verify: GOOD_SIGNATURE, attestation: elsewhere }))).toEqual({
        verified: false,
        reason: 'SBOM_REFUSED',
        detail: `an SBOM is not about ${DIGEST}`,
      });
    });
  });

  describe('the command', () => {
    const run = (argv: string[], cosign: Cosign): { code: number; lines: string[] } => {
      const lines: string[] = [];
      const code = main(argv, cosign, (line: string) => lines.push(line));
      return { code, lines };
    };

    it('gives each outcome its own exit code, so CI can prove each refusal', () => {
      const codes = Object.values(EXIT);
      expect(EXIT.VERIFIED).toBe(0);
      expect(new Set(codes).size).toBe(codes.length);
      // 1 is what a crash or an uncaught error exits with; no outcome shares it.
      expect(codes).not.toContain(1);
    });

    it('prints what it verified and exits 0', () => {
      expect(run([IMAGE, COMMIT], fakeCosign({ verify: GOOD_SIGNATURE, attestation: GOOD_SBOM }))).toEqual({
        code: 0,
        lines: [`Verified ${IMAGE}: signed by ${SIGNER_IDENTITY} at commit ${COMMIT}, with its SBOM.`],
      });
    });

    it('prints the reason for a refusal and exits with its code', () => {
      expect(run([IMAGE, COMMIT], fakeCosign({ verify: failed(10, 'no signatures found') }))).toEqual({
        code: EXIT.IMAGE_UNSIGNED,
        lines: [`Refused ${IMAGE} (IMAGE_UNSIGNED): error during command execution: no signatures found`],
      });
    });

    it.each([[[]], [[IMAGE]], [[IMAGE, COMMIT, 'extra']]])('shows its usage for the arguments %j', (argv) => {
      const { code, lines } = run(argv, fakeCosign({}));
      expect(code).toBe(EXIT.INPUT_INVALID);
      expect(lines).toEqual([`Usage: node deploy/image/verify.ts ${IMAGE_REPOSITORY}@sha256:<64 hex> <40-hex commit>`]);
    });

    it('runs from the command line, and refuses when cosign is not installed', () => {
      const script = fileURLToPath(new URL('./verify.ts', import.meta.url));
      // No PATH at all, so cosign can't be found wherever this runs; SystemRoot keeps Windows' own start-up working.
      const env = process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? '' } : {};
      const usage = spawnSync(process.execPath, [script], { encoding: 'utf8', env });
      expect(usage.status).toBe(EXIT.INPUT_INVALID);
      expect(usage.stdout).toContain('Usage: node deploy/image/verify.ts');

      const refused = spawnSync(process.execPath, [script, IMAGE, COMMIT], { encoding: 'utf8', env });
      expect(refused.status).toBe(EXIT.SIGNATURE_REFUSED);
      expect(refused.stdout).toContain(`Refused ${IMAGE} (SIGNATURE_REFUSED): cosign could not run:`);
    });
  });

  describe('running cosign', () => {
    it('returns its exit code and both streams', () => {
      const script = "process.stdout.write('out'); process.stderr.write('err'); process.exit(7)";
      expect(runCosign(['-e', script], process.execPath)).toEqual({ status: 7, stdout: 'out', stderr: 'err' });
    });

    it('takes output as large as a real SBOM attestation (1.6 MB for this image), and more', () => {
      const script = "process.stdout.write('x'.repeat(8 * 1024 * 1024))";
      expect(runCosign(['-e', script], process.execPath).stdout).toHaveLength(8 * 1024 * 1024);
    });

    it('reports a command that cannot start as no status, so the check fails closed', () => {
      const run = runCosign(['version'], 'agentx-no-such-command');
      expect(run.status).toBeNull();
      expect(run.stdout).toBe('');
      expect(run.stderr).toMatch(/^cosign could not run: spawnSync agentx-no-such-command ENOENT/);
    });
  });
});
