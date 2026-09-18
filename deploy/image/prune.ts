// Old image versions, pruned after each release to staging (0e G4-5). The
// partner set the limit (S25): the 5 newest images are kept, and the one
// staging runs is kept whatever its age.
//
//   node deploy/image/prune.ts plan <commit> <digest of its image>
//
// `plan` (G4-5a) reads the package and says what a prune would remove,
// changing nothing. CI runs it after each release that went green, with the
// commit the run is for and the digest its image job published, as the job's
// own token (GITHUB_TOKEN and GITHUB_ACTOR, which Actions sets; `packages:
// read`), in a checkout of the whole history.
//
// A green release leaves staging on this run's image, or on a later commit's
// when it was run again after a newer one (release.ts: "past"). So the prune
// never needs to know which: it keeps this run's image and every image of a
// commit after it, as well as the newest.
//
// How cosign 3 keeps an image's signature and SBOM on GitHub's registry, as
// read from the registry itself (S25): each is a small manifest, a Sigstore
// bundle whose `subject` is the image, and untagged. The registry has no
// referrers API, so cosign lists them in an index tagged `sha256-<image hex>`
// (OCI 1.1's fallback tag) and replaces that index whenever it adds one; the
// replaced one stays behind, untagged, read by nothing. So the package holds:
//   - each image, tagged with its commit
//   - its index, tagged `sha256-<hex>`
//   - untagged: the bundles, and the replaced indexes
// A version with any other tag stops the prune: it is refused, not guessed at.
//
// What is kept:
//   - the 5 newest images, this run's, and every image of a commit that isn't
//     in this commit's history (a later one, or one this clone doesn't know),
//     each with the index its tag names and every bundle that index lists.
//     verify.ts reads exactly those, so a kept image can still be deployed by
//     hand (a rollback)
//   - everything created at or after the oldest of the 5 newest images: a
//     merge running alongside may have pushed an image or a bundle that no
//     index lists yet
// Everything else goes, which also clears what an earlier prune left half
// done. This run's image must be in the package, tagged with its commit and
// with its index, or nothing is removed.
import { type History, realHistory } from '../azure/git.ts';
import { IMAGE_REPOSITORY } from './verify.ts';

/** The image's owner and package on GitHub, which make up IMAGE_REPOSITORY. */
export const OWNER = 'shahbaz242630';
export const PACKAGE = 'agent-x';
/** How many of the newest images are kept (partner, S25). */
export const KEEP = 5;

/**
 * Where the package's versions are listed, and its manifests read. Constants,
 * never read from a response or a file: an address that data could change
 * would be a different thing (CodeQL, PR #33).
 */
export const VERSIONS_API = `https://api.github.com/users/${OWNER}/packages/container/${PACKAGE}/versions`;
export const REGISTRY_TOKEN = `https://ghcr.io/token?service=ghcr.io&scope=repository:${OWNER}/${PACKAGE}:pull`;
export const MANIFESTS = `https://ghcr.io/v2/${OWNER}/${PACKAGE}/manifests`;

/** The package API's largest page; a shorter page is the last. */
export const PAGE_SIZE = 100;
/** An end to the listing whatever the API sends: 5,000 versions is far past any real package. */
export const MAX_PAGES = 50;

const INDEX_MEDIA_TYPE = 'application/vnd.oci.image.index.v1+json';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const INDEX_TAG = /^sha256-(?<hex>[0-9a-f]{64})$/;

export const EXIT = { PLANNED: 0, REFUSED: 1, USAGE: 2 } as const;

/** One version of the package, as the package API lists it. */
export interface Version {
  readonly id: number;
  readonly digest: string;
  /** When it was pushed, in milliseconds since 1970. */
  readonly created: number;
  readonly tags: readonly string[];
}

export type Kind =
  | { readonly kind: 'image'; readonly commit: string }
  | { readonly kind: 'index'; readonly of: string }
  | { readonly kind: 'untagged' };

/** What a version is, by its tags; a tag of any other shape is refused. */
export function kindOf(version: Version): Kind {
  const [tag, ...more] = version.tags;
  if (tag === undefined) return { kind: 'untagged' };
  if (more.length === 0) {
    if (COMMIT.test(tag)) return { kind: 'image', commit: tag };
    const hex = INDEX_TAG.exec(tag)?.groups?.hex;
    if (hex !== undefined) return { kind: 'index', of: `sha256:${hex}` };
  }
  throw new Error(`the version ${version.digest} has tags the prune doesn't know: ${version.tags.join(', ')}`);
}

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** One page of the package API's answer as versions, or an error saying what in it isn't one. */
export function versionsIn(page: unknown): Version[] {
  if (!Array.isArray(page)) throw new Error('the package API sent something other than a list of versions');
  return page.map((entry: unknown): Version => {
    const { id, name, created_at: createdAt, metadata } = isRecord(entry) ? entry : {};
    const container = isRecord(metadata) ? metadata.container : undefined;
    const tags = isRecord(container) ? container.tags : undefined;
    const created = typeof createdAt === 'string' ? Date.parse(createdAt) : Number.NaN;
    if (
      typeof id !== 'number' ||
      !Number.isSafeInteger(id) ||
      id <= 0 ||
      typeof name !== 'string' ||
      !DIGEST.test(name) ||
      !Number.isFinite(created) ||
      !Array.isArray(tags) ||
      !tags.every((tag) => typeof tag === 'string')
    ) {
      throw new Error('the package API sent a version without an id, a digest, a time and its tags');
    }
    return { id, digest: name, created, tags };
  });
}

/** An image in the package: a version tagged with its commit. */
export interface Image {
  readonly commit: string;
  readonly digest: string;
  readonly created: number;
  readonly id: number;
}

export interface Kept {
  /** The newest first, then the others kept, newest first. */
  readonly images: readonly Image[];
  /** When the oldest of the newest images was pushed: nothing from then on is removed. */
  readonly since: number;
}

/** The images among these versions, newest first (the later id first, pushed in the same millisecond). */
function imagesIn(versions: readonly Version[]): Image[] {
  return versions
    .flatMap((version): Image[] => {
      const kind = kindOf(version);
      if (kind.kind !== 'image') return [];
      return [{ commit: kind.commit, digest: version.digest, created: version.created, id: version.id }];
    })
    .sort((one, other) => other.created - one.created || other.id - one.id);
}

/** This run's image: the commit the run is for, and the digest its image job published. */
export interface Own {
  readonly commit: string;
  readonly digest: string;
}

/**
 * The images kept: the newest, this run's, and every image of a commit that
 * isn't in this run's history, which staging may run instead of this one.
 */
export function imagesToKeep(versions: readonly Version[], own: Own, history: Pick<History, 'isAncestor'>): Kept {
  const images = imagesIn(versions);
  const mine = images.find((image) => image.digest === own.digest);
  if (mine === undefined) throw new Error(`this run's image (${own.digest}) isn't in the package`);
  if (mine.commit !== own.commit) {
    throw new Error(`this run's image (${own.digest}) is tagged ${mine.commit}, not ${own.commit}`);
  }
  const newest = images.slice(0, KEEP);
  const oldest = newest.at(-1) ?? mine;
  const others = images.filter(
    (image) => !newest.includes(image) && (image === mine || !history.isAncestor(image.commit, own.commit)),
  );
  return { images: [...newest, ...others], since: oldest.created };
}

export interface Plan {
  readonly kept: Kept;
  readonly remove: readonly Version[];
  /** The images removed, newest first. */
  readonly removedImages: readonly Image[];
}

/**
 * What a prune removes, given the package and the bundles each kept image's
 * index lists (nothing for an image with no index yet).
 */
export function planPrune(
  versions: readonly Version[],
  kept: Kept,
  bundles: ReadonlyMap<string, readonly string[] | undefined>,
  own: string,
): Plan {
  if (bundles.get(own) === undefined) {
    throw new Error(`this run's image (${own}) has no index of its signature and SBOM`);
  }
  const keptDigests = new Set(kept.images.map((image) => image.digest));
  const held = new Set(keptDigests);
  for (const digest of keptDigests) for (const bundle of bundles.get(digest) ?? []) held.add(bundle);
  // Each kept image's index as the listing saw it tagged. One cosign writes
  // after the listing isn't in it, so it can't be removed either.
  for (const version of versions) {
    const kind = kindOf(version);
    if (kind.kind === 'index' && keptDigests.has(kind.of)) held.add(version.digest);
  }
  const remove = versions.filter((version) => !held.has(version.digest) && version.created < kept.since);
  return { kept, remove, removedImages: imagesIn(remove) };
}

/** Where the prune reads the package: GitHub's package API and its registry. */
export interface Package {
  readonly versions: () => Promise<Version[]>;
  /** The bundles an image's index lists, or nothing when it has no index. */
  readonly bundles: (image: string) => Promise<readonly string[] | undefined>;
}

/** Why a request failed, by its status alone: never the headers sent, which hold the token. */
const failed = (what: string, response: Response): Error =>
  new Error(`${what} answered ${String(response.status)} ${response.statusText}`.trim());

/** The bundles an index lists, or an error if it lists anything but manifests by digest. */
function bundlesIn(index: unknown, image: string): string[] {
  const manifests = isRecord(index) ? index.manifests : undefined;
  if (!Array.isArray(manifests)) throw new Error(`the index for ${image} lists no manifests`);
  return manifests.map((entry: unknown): string => {
    const digest = isRecord(entry) ? entry.digest : undefined;
    if (typeof digest !== 'string' || !DIGEST.test(digest)) {
      throw new Error(`the index for ${image} lists something other than a manifest by digest`);
    }
    return digest;
  });
}

/** The package as the job's own token reads it. */
export function realPackage(token: string, actor: string, http: typeof fetch = fetch): Package {
  let registryToken: Promise<string> | undefined;
  const pullToken = async (): Promise<string> => {
    // The exchange `docker login` makes with the same two, as image-sbom's pull does.
    const basic = Buffer.from(`${actor}:${token}`).toString('base64');
    const response = await http(REGISTRY_TOKEN, { headers: { authorization: `Basic ${basic}` } });
    if (!response.ok) throw failed("the registry's sign-in", response);
    const answer: unknown = await response.json();
    const pull = isRecord(answer) ? answer.token : undefined;
    if (typeof pull !== 'string' || pull === '') throw new Error("the registry's sign-in sent no token");
    return pull;
  };
  return {
    versions: async () => {
      // A version pushed while the pages are read can shift one onto the next page twice.
      const all = new Map<number, Version>();
      for (let page = 1; page <= MAX_PAGES; page += 1) {
        const response = await http(`${VERSIONS_API}?per_page=${String(PAGE_SIZE)}&page=${String(page)}`, {
          headers: {
            accept: 'application/vnd.github+json',
            authorization: `Bearer ${token}`,
            'x-github-api-version': '2022-11-28',
          },
        });
        if (!response.ok) throw failed('the package API', response);
        const versions = versionsIn(await response.json());
        for (const version of versions) all.set(version.id, version);
        if (versions.length < PAGE_SIZE) return [...all.values()];
      }
      throw new Error(`the package has more than ${String(MAX_PAGES * PAGE_SIZE)} versions; the prune stops there`);
    },
    bundles: async (image) => {
      if (!DIGEST.test(image)) throw new Error(`not an image digest: ${image}`);
      registryToken ??= pullToken();
      const response = await http(`${MANIFESTS}/sha256-${image.slice('sha256:'.length)}`, {
        headers: { accept: INDEX_MEDIA_TYPE, authorization: `Bearer ${await registryToken}` },
      });
      if (response.status === 404) return undefined;
      if (!response.ok) throw failed('the registry', response);
      if (response.headers.get('content-type') !== INDEX_MEDIA_TYPE) {
        throw new Error(`the registry's sha256-… tag for ${image} doesn't name an index`);
      }
      return bundlesIn(await response.json(), image);
    },
  };
}

const when = (created: number): string => new Date(created).toISOString().slice(0, 16).replace('T', ' ');

/** Reads the package, works out the prune and says it; removes nothing. */
export async function plan(
  own: Own,
  source: Package,
  history: Pick<History, 'isAncestor'>,
  say: (line: string) => void,
): Promise<Plan> {
  const versions = await source.versions();
  const kept = imagesToKeep(versions, own, history);
  const bundles = new Map<string, readonly string[] | undefined>();
  for (const image of kept.images) bundles.set(image.digest, await source.bundles(image.digest));
  const pruned = planPrune(versions, kept, bundles, own.digest);

  const kinds = versions.map((version) => kindOf(version).kind);
  const count = (kind: Kind['kind']): number => kinds.filter((found) => found === kind).length;
  say(
    `${IMAGE_REPOSITORY}: ${String(versions.length)} versions (${String(count('image'))} images, ` +
      `${String(count('index'))} signature indexes, ${String(count('untagged'))} untagged).`,
  );
  say(`Keeping ${String(kept.images.length)} images:`);
  for (const image of kept.images) {
    say(`  ${image.commit}  ${when(image.created)}${image.digest === own.digest ? '  (this run)' : ''}`);
  }
  say(
    `Would remove ${String(pruned.removedImages.length)} images and ` +
      `${String(pruned.remove.length - pruned.removedImages.length)} other versions ` +
      '(their signatures and SBOMs, and indexes nothing reads):',
  );
  for (const image of pruned.removedImages) say(`  ${image.commit}  ${when(image.created)}`);
  return pruned;
}

export const USAGE = 'Usage: node deploy/image/prune.ts plan <40-hex commit> <sha256 digest of its image>';

export async function main(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env,
  http: typeof fetch = fetch,
  history: Pick<History, 'isAncestor'> = realHistory(),
  say: (line: string) => void = console.log,
): Promise<number> {
  const [command, commit, digest, ...rest] = argv;
  if (
    command !== 'plan' ||
    commit === undefined ||
    !COMMIT.test(commit) ||
    digest === undefined ||
    !DIGEST.test(digest) ||
    rest.length > 0
  ) {
    say(USAGE);
    return EXIT.USAGE;
  }
  const { GITHUB_TOKEN: token, GITHUB_ACTOR: actor } = env;
  if (token === undefined || token === '' || actor === undefined || actor === '') {
    say('Refused: GITHUB_TOKEN and GITHUB_ACTOR must be set (Actions sets both). Nothing was removed.');
    return EXIT.REFUSED;
  }
  try {
    await plan({ commit, digest }, realPackage(token, actor, http), history, say);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(`Refused: ${error.message}. Nothing was removed.`);
    return EXIT.REFUSED;
  }
  say('Nothing was removed: this is the plan alone (G4-5a).');
  return EXIT.PLANNED;
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
