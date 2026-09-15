// SEC-SC-02, the check before every deploy (ADR-002 Amendment E2). An image
// runs only if it is ours, named by its digest, signed by CI on main at the
// commit being deployed, and carries its SBOM, signed the same way. The
// signatures are keyless (Sigstore): each one's certificate names the
// workflow, branch, trigger and commit that made it, so nothing else can make
// one that passes. Run it as:
//
//   node deploy/image/verify.ts ghcr.io/shahbaz242630/agent-x@sha256:<64 hex> <commit>
//
// It needs cosign 3.1.3 or later on PATH. It exits with a code per outcome,
// so CI can prove each refusal on every publish (EXIT below).
import { spawnSync } from 'node:child_process';

/** Where CI publishes the image (ci.yml, the image-publish job). */
export const IMAGE_REPOSITORY = 'ghcr.io/shahbaz242630/agent-x';
export const SOURCE_REPOSITORY = 'shahbaz242630/agent-x';
/** The workflow whose main-branch runs sign; its certificate names it. */
export const SIGNING_WORKFLOW = '.github/workflows/ci.yml';
export const SIGNING_REF = 'refs/heads/main';
export const SIGNER_IDENTITY = `https://github.com/${SOURCE_REPOSITORY}/${SIGNING_WORKFLOW}@${SIGNING_REF}`;
export const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';

/** What cosign calls a signature, and the SBOM's in-toto predicate (`--type cyclonedx`). */
const SIGNATURE_TYPE = 'https://sigstore.dev/cosign/sign/v1';
export const SBOM_PREDICATE_TYPE = 'https://cyclonedx.org/bom';
const IN_TOTO_PAYLOAD = 'application/vnd.in-toto+json';

/** cosign's own exit code for an image with no signature at all (its errors package: ImageWithoutSignature). */
const COSIGN_IMAGE_WITHOUT_SIGNATURE = 10;
/** cosign's message when the image's attestations include none of the requested type. */
const NO_SBOM = 'none of the attestations matched the predicate type';

export const EXIT = {
  VERIFIED: 0,
  /** Not our repository by digest, or not a full commit. */
  INPUT_INVALID: 2,
  /** No signature at all. */
  IMAGE_UNSIGNED: 3,
  /** A signature, but not from CI on main at this commit, or one that can't be checked. */
  SIGNATURE_REFUSED: 4,
  /** Signed, but no SBOM attestation. */
  SBOM_MISSING: 5,
  /** An SBOM attestation that isn't ours, isn't for this image, or can't be checked. */
  SBOM_REFUSED: 6,
} as const;

export type Reason = Exclude<keyof typeof EXIT, 'VERIFIED'>;

export type Outcome =
  { readonly verified: true } | { readonly verified: false; readonly reason: Reason; readonly detail: string };

export interface Run {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export type Cosign = (args: readonly string[]) => Run;

const DIGEST_REFERENCE = /^(?<repository>[^@\s]+)@(?<digest>sha256:[0-9a-f]{64})$/g;
const COMMIT = /^[0-9a-f]{40}$/;

/** The digest of `repository@sha256:…` when the repository is ours, or nothing. */
export function digestOf(image: string): string | undefined {
  const match = [...image.matchAll(DIGEST_REFERENCE)][0]?.groups;
  return match?.repository === IMAGE_REPOSITORY ? match.digest : undefined;
}

/** The certificate claims every signature and attestation must carry. */
export function signerFlags(commit: string): string[] {
  return [
    '--certificate-identity',
    SIGNER_IDENTITY,
    '--certificate-oidc-issuer',
    OIDC_ISSUER,
    '--certificate-github-workflow-repository',
    SOURCE_REPOSITORY,
    '--certificate-github-workflow-ref',
    SIGNING_REF,
    '--certificate-github-workflow-trigger',
    'push',
    '--certificate-github-workflow-sha',
    commit,
  ];
}

export const signatureArgs = (image: string, commit: string): string[] => ['verify', ...signerFlags(commit), image];

export const sbomArgs = (image: string, commit: string): string[] => [
  'verify-attestation',
  '--type',
  'cyclonedx',
  ...signerFlags(commit),
  image,
];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Why `cosign verify`'s output doesn't show a signature over this digest, or
 * nothing. cosign lists every bundle it verified, and an SBOM attestation
 * counts as one, so a signature proper must be among them.
 */
export function signatureOutputProblem(stdout: string, digest: string): string | undefined {
  let entries: unknown;
  try {
    entries = JSON.parse(stdout);
  } catch {
    return 'cosign printed no JSON';
  }
  if (!Array.isArray(entries) || entries.length === 0) return 'cosign listed nothing it verified';
  const critical = entries.map((entry) => (isRecord(entry) && isRecord(entry.critical) ? entry.critical : {}));
  const over = (claim: Record<string, unknown>): unknown =>
    isRecord(claim.image) ? claim.image['docker-manifest-digest'] : undefined;
  if (critical.some((claim) => over(claim) !== digest)) return `cosign listed something not over ${digest}`;
  if (!critical.some((claim) => claim.type === SIGNATURE_TYPE)) return 'cosign verified attestations but no signature';
  return undefined;
}

/**
 * Why `cosign verify-attestation`'s output isn't one or more CycloneDX SBOM
 * statements about this digest, or nothing. Each line is a DSSE envelope
 * whose payload is the in-toto statement.
 */
export function sbomOutputProblem(stdout: string, digest: string): string | undefined {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
  if (lines.length === 0) return 'cosign printed no attestation';
  const hex = digest.slice('sha256:'.length);
  for (const line of lines) {
    let statement: unknown;
    try {
      const envelope: unknown = JSON.parse(line);
      if (!isRecord(envelope) || envelope.payloadType !== IN_TOTO_PAYLOAD || typeof envelope.payload !== 'string') {
        return 'an attestation is not an in-toto envelope';
      }
      statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
    } catch {
      return 'an attestation is not readable JSON';
    }
    if (!isRecord(statement) || statement.predicateType !== SBOM_PREDICATE_TYPE) {
      return 'an attestation is not a CycloneDX SBOM';
    }
    const subjects = Array.isArray(statement.subject) ? statement.subject : [];
    const names = (subject: unknown): unknown =>
      isRecord(subject) && isRecord(subject.digest) ? subject.digest.sha256 : undefined;
    if (!subjects.some((subject) => names(subject) === hex)) return `an SBOM is not about ${digest}`;
  }
  return undefined;
}

/** cosign's last message line, which says why it refused. */
function lastLine(text: string): string {
  const lines = text.split('\n').filter((line) => line.trim() !== '');
  return (lines.at(-1) ?? 'no message').trim().slice(0, 300);
}

const refuse = (reason: Reason, detail: string): Outcome => ({ verified: false, reason, detail });

/** Checks the signature first, then the SBOM: the first refusal is the answer. */
export function verifyImage(image: string, commit: string, cosign: Cosign): Outcome {
  const digest = digestOf(image);
  if (digest === undefined) return refuse('INPUT_INVALID', `not ${IMAGE_REPOSITORY}@sha256:<64 hex digits>`);
  if (!COMMIT.test(commit)) return refuse('INPUT_INVALID', 'the commit must be 40 lower-case hex digits');

  const signature = cosign(signatureArgs(image, commit));
  if (signature.status === COSIGN_IMAGE_WITHOUT_SIGNATURE) return refuse('IMAGE_UNSIGNED', lastLine(signature.stderr));
  if (signature.status !== 0) return refuse('SIGNATURE_REFUSED', lastLine(signature.stderr));
  const signatureProblem = signatureOutputProblem(signature.stdout, digest);
  if (signatureProblem !== undefined) return refuse('SIGNATURE_REFUSED', signatureProblem);

  const sbom = cosign(sbomArgs(image, commit));
  if (sbom.status !== 0)
    return refuse(sbom.stderr.includes(NO_SBOM) ? 'SBOM_MISSING' : 'SBOM_REFUSED', lastLine(sbom.stderr));
  const sbomProblem = sbomOutputProblem(sbom.stdout, digest);
  if (sbomProblem !== undefined) return refuse('SBOM_REFUSED', sbomProblem);

  return { verified: true };
}

/** Runs cosign with an argument list and no shell. The SBOM comes back whole, so the buffer is generous. */
export function runCosign(args: readonly string[], command = 'cosign'): Run {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 300_000,
    windowsHide: true,
  });
  if (result.error) return { status: null, stdout: '', stderr: `cosign could not run: ${result.error.message}` };
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const USAGE = `Usage: node deploy/image/verify.ts ${IMAGE_REPOSITORY}@sha256:<64 hex> <40-hex commit>`;

export function main(argv: readonly string[], cosign: Cosign = runCosign, log = console.log): number {
  const [image, commit, ...rest] = argv;
  if (image === undefined || commit === undefined || rest.length > 0) {
    log(USAGE);
    return EXIT.INPUT_INVALID;
  }
  const outcome = verifyImage(image, commit, cosign);
  if (outcome.verified) {
    log(`Verified ${image}: signed by ${SIGNER_IDENTITY} at commit ${commit}, with its SBOM.`);
    return EXIT.VERIFIED;
  }
  log(`Refused ${image} (${outcome.reason}): ${outcome.detail}`);
  return EXIT[outcome.reason];
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2));
