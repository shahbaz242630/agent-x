import { describe, expect, it } from 'vitest';

import {
  EXIT,
  imagesToKeep,
  KEEP,
  kindOf,
  main,
  MANIFESTS,
  MAX_PAGES,
  MAX_REMOVALS,
  type Package,
  OWNER,
  PACKAGE,
  PAGE_SIZE,
  PAUSE_MS,
  planPrune,
  prune,
  realPackage,
  removalOrder,
  REGISTRY_TOKEN,
  Stopped,
  USAGE,
  type Version,
  VERSIONS_API,
  versionsIn,
} from './prune.ts';
import { IMAGE_REPOSITORY } from './verify.ts';

const T0 = Date.parse('2026-09-10T00:00:00Z');
const MINUTE = 60_000;

const digest = (n: number): string => `sha256:${n.toString(16).padStart(64, '0')}`;
const commit = (n: number): string => n.toString(16).padStart(40, 'c');
const indexTag = (image: string): string => `sha256-${image.slice('sha256:'.length)}`;

/**
 * Image n as cosign 3.1.3 leaves it on the registry (read from it, S25): the
 * image, its signature bundle, the index cosign wrote then, the SBOM bundle,
 * and the index that replaced the first, tagged. Image n is pushed n hours
 * after T0; its versions have ids and digests 10n to 10n + 4.
 */
function published(n: number): { readonly image: Version; readonly all: Version[]; readonly bundles: string[] } {
  const at = T0 + n * 60 * MINUTE;
  const version = (k: number, minutes: number, tags: string[]): Version => ({
    id: n * 10 + k,
    digest: digest(n * 10 + k),
    created: at + minutes * MINUTE,
    tags,
  });
  const image = version(0, 0, [commit(n)]);
  const signature = version(1, 1, []);
  const replaced = version(2, 1, []);
  const sbom = version(3, 5, []);
  const index = version(4, 5, [indexTag(image.digest)]);
  return {
    image,
    all: [image, signature, replaced, sbom, index],
    bundles: [signature.digest, sbom.digest],
  };
}

const PUBLISHED = [1, 2, 3, 4, 5, 6, 7, 8].map(published);
const at = (n: number) => {
  const found = PUBLISHED[n - 1];
  if (found === undefined) throw new Error(`no image ${String(n)} in the fixture`);
  return found;
};
const VERSIONS = PUBLISHED.flatMap(({ all }) => all);
const BUNDLES = new Map(PUBLISHED.map(({ image, bundles }) => [image.digest, bundles]));
const indexOf = (n: number): Version => {
  const found = at(n).all[4];
  if (found === undefined) throw new Error(`no index for image ${String(n)} in the fixture`);
  return found;
};
const ids = (versions: readonly { id: number }[]): number[] => versions.map(({ id }) => id).sort((a, b) => a - b);
const idsOf = (...ns: number[]): number[] => ids(ns.flatMap((n) => at(n).all));

/** Main's history in the fixture: commit n comes after every commit below it; any other isn't known. */
const ORDER = new Map(Array.from({ length: 60 }, (_, k) => [commit(k + 1), k + 1]));
const HISTORY = {
  isAncestor: (ancestor: string, of: string): boolean => {
    const before = ORDER.get(ancestor);
    const after = ORDER.get(of);
    return before !== undefined && after !== undefined && before <= after;
  },
};
/** Run n's commit and the digest its image job published. */
const own = (n: number) => ({ commit: commit(n), digest: at(n).image.digest });
const commits = (images: readonly { commit: string }[]): string[] => images.map((image) => image.commit);

describe('the package it prunes', () => {
  it('is the repository CI publishes to and verify.ts reads', () => {
    expect(`ghcr.io/${OWNER}/${PACKAGE}`).toBe(IMAGE_REPOSITORY);
    expect(KEEP).toBe(5);
  });
});

describe('kindOf', () => {
  const version = (tags: string[]): Version => ({ id: 1, digest: digest(1), created: T0, tags });

  it('tells an image by its commit, an index by the image it lists for, and the rest by having no tag', () => {
    expect(kindOf(version([commit(1)]))).toEqual({ kind: 'image', commit: commit(1) });
    expect(kindOf(version([indexTag(digest(7))]))).toEqual({ kind: 'index', of: digest(7) });
    expect(kindOf(version([]))).toEqual({ kind: 'untagged' });
  });

  it('refuses a tag of any other shape, or a second tag', () => {
    for (const tags of [
      ['latest'],
      [commit(1).toUpperCase()],
      [commit(1).slice(1)],
      [`sha256-${'a'.repeat(63)}`],
      [`sha256-${'A'.repeat(64)}`],
      [`${indexTag(digest(7))}.sig`],
      [commit(1), 'latest'],
      [commit(1), commit(2)],
    ]) {
      expect(() => kindOf(version(tags))).toThrow(`has tags the prune doesn't know: ${tags.join(', ')}`);
    }
  });
});

describe('versionsIn', () => {
  /** One version as GitHub's package API lists it. */
  const listed = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    id: 612_345_678,
    name: digest(9),
    url: 'https://api.github.com/users/o/packages/container/p/versions/612345678',
    package_html_url: 'https://github.com/users/o/packages/container/package/p',
    created_at: '2026-09-18T11:31:02Z',
    updated_at: '2026-09-18T11:31:02Z',
    html_url: 'https://github.com/users/o/packages/container/p/612345678',
    metadata: { package_type: 'container', container: { tags: [commit(9)] } },
    ...overrides,
  });

  it('reads the id, digest, time and tags of each', () => {
    expect(versionsIn([listed(), listed({ id: 5, metadata: { container: { tags: [] } } })])).toEqual([
      { id: 612_345_678, digest: digest(9), created: Date.parse('2026-09-18T11:31:02Z'), tags: [commit(9)] },
      { id: 5, digest: digest(9), created: Date.parse('2026-09-18T11:31:02Z'), tags: [] },
    ]);
    expect(versionsIn([])).toEqual([]);
  });

  it('refuses anything but a list', () => {
    expect(() => versionsIn({ message: 'Not Found' })).toThrow('something other than a list of versions');
  });

  it('refuses a version without a whole id, a digest, a time or its list of tags', () => {
    for (const entry of [
      null,
      'version',
      listed({ id: '612345678' }),
      listed({ id: 0 }),
      listed({ id: 1.5 }),
      listed({ id: 2 ** 53 }),
      listed({ name: 'sha256:abc' }),
      listed({ name: commit(9) }),
      listed({ created_at: 'yesterday' }),
      listed({ created_at: 1_758_195_062 }),
      listed({ metadata: undefined }),
      listed({ metadata: { container: {} } }),
      listed({ metadata: { container: { tags: commit(9) } } }),
      listed({ metadata: { container: { tags: [9] } } }),
    ]) {
      expect(() => versionsIn([entry])).toThrow('a version without an id, a digest, a time and its tags');
    }
  });
});

describe('imagesToKeep', () => {
  it('keeps the newest five, and nothing older than the fifth is safe from removal', () => {
    const kept = imagesToKeep(VERSIONS, own(8), HISTORY);
    expect(commits(kept.images)).toEqual([8, 7, 6, 5, 4].map(commit));
    expect(kept.since).toBe(at(4).image.created);
  });

  it('keeps this run’s image and every later one when it runs again after a newer one, without moving the line', () => {
    // Staging runs a later commit's image then ("past" in release.ts), whichever it is.
    const kept = imagesToKeep(VERSIONS, own(2), HISTORY);
    expect(commits(kept.images)).toEqual([8, 7, 6, 5, 4, 3, 2].map(commit));
    expect(kept.since).toBe(at(4).image.created);
  });

  it('keeps every later image when a run again pushed this commit’s image anew', () => {
    const again: Version = { id: 200, digest: digest(200), created: T0 + 10 * 60 * MINUTE, tags: [commit(2)] };
    const untagged = { ...at(2).image, tags: [] };
    const versions = [...VERSIONS.filter(({ id }) => id !== untagged.id), untagged, again];
    const kept = imagesToKeep(versions, { commit: commit(2), digest: again.digest }, HISTORY);
    expect(commits(kept.images)).toEqual([2, 8, 7, 6, 5, 4, 3].map(commit));
    expect(kept.since).toBe(at(5).image.created);
  });

  it('keeps an image whose commit this clone does not know', () => {
    const stranger: Version = { id: 300, digest: digest(300), created: T0, tags: ['d'.repeat(40)] };
    const kept = imagesToKeep([...VERSIONS, stranger], own(8), HISTORY);
    expect(commits(kept.images)).toEqual([...[8, 7, 6, 5, 4].map(commit), 'd'.repeat(40)]);
  });

  it('keeps every image when there are five or fewer', () => {
    const few = [1, 2, 3].flatMap((n) => at(n).all);
    const kept = imagesToKeep(few, own(3), HISTORY);
    expect(commits(kept.images)).toEqual([3, 2, 1].map(commit));
    expect(kept.since).toBe(at(1).image.created);
  });

  it('takes the later id first for images pushed in the same millisecond', () => {
    const same = { ...at(3).image, created: at(4).image.created };
    const others = VERSIONS.filter(({ id }) => id !== same.id);
    expect(imagesToKeep([...others, same], own(8), HISTORY).images.map(({ id }) => id)).toEqual([80, 70, 60, 50, 40]);
    expect(imagesToKeep([same, ...others], own(8), HISTORY).images.map(({ id }) => id)).toEqual([80, 70, 60, 50, 40]);
  });

  it('refuses when this run’s image is not in the package, is not an image, or is another commit’s', () => {
    expect(() => imagesToKeep(VERSIONS, { commit: commit(8), digest: digest(999) }, HISTORY)).toThrow(
      `this run's image (${digest(999)}) isn't in the package`,
    );
    expect(() => imagesToKeep(VERSIONS, { commit: commit(8), digest: indexOf(8).digest }, HISTORY)).toThrow(
      "isn't in the package",
    );
    expect(() => imagesToKeep(VERSIONS, { commit: commit(7), digest: at(8).image.digest }, HISTORY)).toThrow(
      `this run's image (${at(8).image.digest}) is tagged ${commit(8)}, not ${commit(7)}`,
    );
  });

  it('refuses a package holding a version it does not know', () => {
    const odd: Version = { id: 1_000, digest: digest(1_000), created: T0, tags: ['latest'] };
    expect(() => imagesToKeep([...VERSIONS, odd], own(8), HISTORY)).toThrow("tags the prune doesn't know: latest");
  });

  it('refuses when git cannot say how the commits stand', () => {
    const broken = {
      isAncestor: (): boolean => {
        throw new Error('git couldn’t compare them');
      },
    };
    expect(() => imagesToKeep(VERSIONS, own(8), broken)).toThrow('git couldn’t compare them');
  });
});

describe('planPrune', () => {
  const planFor = (
    n: number,
    versions = VERSIONS,
    bundles: ReadonlyMap<string, readonly string[] | undefined> = BUNDLES,
  ) => planPrune(versions, imagesToKeep(versions, own(n), HISTORY), bundles, own(n).digest);
  const replaced = (n: number): Version => {
    const found = at(n).all[2];
    if (found === undefined) throw new Error(`no replaced index for image ${String(n)} in the fixture`);
    return found;
  };

  it('removes the older images with their signatures, SBOMs and indexes, and keeps the newest five whole', () => {
    const plan = planFor(8);
    expect(ids(plan.remove)).toEqual(idsOf(1, 2, 3));
    expect(commits(plan.removedImages)).toEqual([3, 2, 1].map(commit));
  });

  it('keeps an older run’s image and every later one, each with its tagged index and the bundles that lists, and nothing else of them', () => {
    const plan = planFor(2);
    expect(ids(plan.remove)).toEqual(ids([...at(1).all, replaced(2), replaced(3)]));
    expect(commits(plan.removedImages)).toEqual([commit(1)]);
  });

  it('keeps a bundle a kept index lists, however old', () => {
    const old: Version = { id: 3, digest: digest(3), created: T0, tags: [] };
    const listing = [...at(2).bundles, old.digest];
    const plan = planFor(2, [...VERSIONS, old], new Map([...BUNDLES, [at(2).image.digest, listing]]));
    expect(ids(plan.remove)).toEqual(ids([...at(1).all, replaced(2), replaced(3)]));
  });

  it('removes nothing pushed from the moment the oldest kept image was, even what no index lists yet', () => {
    // A merge running alongside: its image pushed and signed, its index not yet written.
    const untagged = (id: number, created: number): Version => ({ id, digest: digest(id), created, tags: [] });
    const pushing: Version = { id: 90, digest: digest(90), created: T0 + 9 * 60 * MINUTE, tags: [commit(9)] };
    const bundle = untagged(91, pushing.created + MINUTE);
    // With it, the newest five are 9 to 5.
    const since = at(5).image.created;
    const onTheLine = untagged(1_001, since);
    const justBefore = untagged(1_002, since - 1);
    const versions = [...VERSIONS, onTheLine, justBefore, pushing, bundle];
    const bundles = new Map([...BUNDLES, [pushing.digest, undefined]]);
    const kept = imagesToKeep(versions, own(8), HISTORY);
    expect(kept.since).toBe(since);
    const plan = planPrune(versions, kept, bundles, own(8).digest);
    expect(ids(plan.remove)).toEqual(ids([...[1, 2, 3, 4].flatMap((n) => at(n).all), justBefore]));
  });

  it('refuses when this run’s image has no index of its signature and SBOM', () => {
    const bundles = new Map([...BUNDLES, [at(8).image.digest, undefined]]);
    expect(() => planFor(8, VERSIONS, bundles)).toThrow(
      `this run's image (${at(8).image.digest}) has no index of its signature and SBOM`,
    );
    expect(() => planFor(8, VERSIONS, new Map())).toThrow('has no index');
  });

  it('removes nothing from a package of five images or fewer', () => {
    const few = [1, 2, 3, 4, 5].flatMap((n) => at(n).all);
    const plan = planFor(5, few);
    expect(plan.remove).toEqual([]);
    expect(plan.removedImages).toEqual([]);
  });
});

/** What GitHub's package API sends for one version. */
const apiEntry = (version: Version): Record<string, unknown> => ({
  id: version.id,
  name: version.digest,
  created_at: new Date(version.created).toISOString(),
  metadata: { package_type: 'container', container: { tags: [...version.tags] } },
});

const indexBody = (bundles: readonly string[]): string =>
  JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: bundles.map((bundle) => ({
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: bundle,
      size: 900,
      artifactType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    })),
  });

const json = (body: unknown, status = 200, contentType = 'application/json'): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': contentType } });

const indexResponse = (body: string): Response =>
  new Response(body, { status: 200, headers: { 'content-type': 'application/vnd.oci.image.index.v1+json' } });

interface Call {
  readonly url: string;
  readonly method: string;
  readonly authorization: string | null;
}

/** A fetch that answers from a handler and records every request. */
function recording(handler: (url: string, method: string) => Response | Promise<Response>): {
  http: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const http: typeof fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const method = init?.method ?? 'GET';
    calls.push({ url, method, authorization: new Headers(init?.headers).get('authorization') });
    return handler(url, method);
  };
  return { http, calls };
}

// Stand-ins for the job's own credential and the registry's pull credential: plain words.
const JOB_WORD = 'plainword';
const PULL_WORD = 'otherword';
const ACTOR = 'someone';
const BASIC = `Basic ${Buffer.from(`${ACTOR}:${JOB_WORD}`).toString('base64')}`;

/**
 * The package served as GitHub would: versions in pages, the registry's
 * sign-in, each image's index, and removals, refused after `allowed` of them.
 */
function serving(
  versions: readonly Version[],
  indexes: ReadonlyMap<string, readonly string[] | undefined>,
  allowed = Number.POSITIVE_INFINITY,
) {
  let listed = [...versions];
  let removed = 0;
  return recording((url, method) => {
    if (method === 'DELETE') {
      const id = Number(url.slice(`${VERSIONS_API}/`.length));
      if (!url.startsWith(`${VERSIONS_API}/`) || removed >= allowed) {
        return new Response(null, { status: 403, statusText: 'Forbidden' });
      }
      if (!listed.some((version) => version.id === id))
        return new Response(null, { status: 404, statusText: 'Not Found' });
      listed = listed.filter((version) => version.id !== id);
      removed += 1;
      return new Response(null, { status: 204 });
    }
    if (url.startsWith(`${VERSIONS_API}?`)) {
      const page = Number(new URL(url).searchParams.get('page'));
      return json(listed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map(apiEntry));
    }
    if (url === REGISTRY_TOKEN) return json({ token: PULL_WORD });
    const found = [...indexes].find(([image]) => url === `${MANIFESTS}/${indexTag(image)}`);
    if (found?.[1] !== undefined) return indexResponse(indexBody(found[1]));
    return new Response(null, { status: 404, statusText: 'Not Found' });
  });
}

describe('realPackage', () => {
  it('lists every version a page at a time, as the job, until a page comes back short', async () => {
    const many = Array.from({ length: PAGE_SIZE + 3 }, (_, k): Version => ({
      id: k + 1,
      digest: digest(k + 1),
      created: T0 + k,
      tags: [],
    }));
    const { http, calls } = serving(many, new Map());
    const versions = await realPackage(JOB_WORD, ACTOR, http).versions();
    expect(ids(versions)).toEqual(ids(many));
    expect(calls).toEqual([
      { url: `${VERSIONS_API}?per_page=100&page=1`, method: 'GET', authorization: `Bearer ${JOB_WORD}` },
      { url: `${VERSIONS_API}?per_page=100&page=2`, method: 'GET', authorization: `Bearer ${JOB_WORD}` },
    ]);
  });

  it('counts a version once when a push moves it onto the next page too', async () => {
    const first = Array.from({ length: PAGE_SIZE }, (_, k): Version => ({
      id: k + 1,
      digest: digest(k + 1),
      created: T0,
      tags: [],
    }));
    const { http } = recording((url) => json((url.endsWith('page=1') ? first : first.slice(-2)).map(apiEntry)));
    expect(await realPackage(JOB_WORD, ACTOR, http).versions()).toHaveLength(PAGE_SIZE);
  });

  it('stops after its last page, whatever the API keeps sending', async () => {
    const full = Array.from({ length: PAGE_SIZE }, (_, k): Version => ({
      id: k + 1,
      digest: digest(k + 1),
      created: T0,
      tags: [],
    }));
    const { http, calls } = recording(() => json(full.map(apiEntry)));
    await expect(realPackage(JOB_WORD, ACTOR, http).versions()).rejects.toThrow(
      'the package has more than 5000 versions; the prune stops there',
    );
    expect(calls).toHaveLength(MAX_PAGES);
  });

  it('says a refusal by its status alone, never with the credential it sent', async () => {
    const { http } = recording(() => json({ message: `Bad credentials ${JOB_WORD}` }, 403));
    const refusal = realPackage(JOB_WORD, ACTOR, http).versions();
    await expect(refusal).rejects.toThrow(/^the package API answered 403$/);
  });

  it('reads an index with a pull credential from the registry, signed in to once, as `docker login` does', async () => {
    const indexes = new Map([
      [at(8).image.digest, at(8).bundles],
      [at(7).image.digest, at(7).bundles],
    ]);
    const { http, calls } = serving([], indexes);
    const source = realPackage(JOB_WORD, ACTOR, http);
    expect(await source.bundles(at(8).image.digest)).toEqual(at(8).bundles);
    expect(await source.bundles(at(7).image.digest)).toEqual(at(7).bundles);
    expect(calls).toEqual([
      { url: REGISTRY_TOKEN, method: 'GET', authorization: BASIC },
      { url: `${MANIFESTS}/${indexTag(at(8).image.digest)}`, method: 'GET', authorization: `Bearer ${PULL_WORD}` },
      { url: `${MANIFESTS}/${indexTag(at(7).image.digest)}`, method: 'GET', authorization: `Bearer ${PULL_WORD}` },
    ]);
  });

  it('finds no index for an image not yet signed', async () => {
    const { http } = serving([], new Map());
    expect(await realPackage(JOB_WORD, ACTOR, http).bundles(at(8).image.digest)).toBeUndefined();
  });

  it('refuses an index it cannot trust, and a registry that fails', async () => {
    const reading = (response: () => Response) =>
      realPackage(
        JOB_WORD,
        ACTOR,
        recording((url) => (url === REGISTRY_TOKEN ? json({ token: PULL_WORD }) : response())).http,
      ).bundles(at(8).image.digest);
    await expect(reading(() => new Response('', { status: 500, statusText: 'Internal Server Error' }))).rejects.toThrow(
      /^the registry answered 500 Internal Server Error$/,
    );
    await expect(
      reading(() => json({ manifests: [] }, 200, 'application/vnd.oci.image.manifest.v1+json')),
    ).rejects.toThrow('tag for sha256:');
    await expect(reading(() => indexResponse('{"schemaVersion":2}'))).rejects.toThrow('lists no manifests');
    await expect(reading(() => indexResponse('{"manifests":[{"digest":"sha256:abc"}]}'))).rejects.toThrow(
      'lists something other than a manifest by digest',
    );
    await expect(reading(() => indexResponse('{"manifests":[null]}'))).rejects.toThrow('other than a manifest');
    await expect(realPackage(JOB_WORD, ACTOR, serving([], new Map()).http).bundles('sha256:abc')).rejects.toThrow(
      'not an image digest: sha256:abc',
    );
  });

  it('removes a version by its id, as the job, and counts nothing but success', async () => {
    const { http, calls } = recording(() => new Response(null, { status: 204 }));
    await realPackage(JOB_WORD, ACTOR, http).remove(indexOf(8));
    expect(calls).toEqual([
      { url: `${VERSIONS_API}/${String(indexOf(8).id)}`, method: 'DELETE', authorization: `Bearer ${JOB_WORD}` },
    ]);
    for (const [status, statusText] of [
      [404, 'Not Found'],
      [403, 'Forbidden'],
      [429, 'Too Many Requests'],
    ] as const) {
      const refusing = recording(() => new Response(null, { status, statusText }));
      await expect(realPackage(JOB_WORD, ACTOR, refusing.http).remove(indexOf(8))).rejects.toThrow(
        `removing ${indexOf(8).digest}, the package API answered ${String(status)} ${statusText}`,
      );
    }
  });

  it('removes nothing by an id that is not one', async () => {
    const { http, calls } = recording(() => new Response(null, { status: 204 }));
    for (const id of [0, -84, 1.5, Number.NaN]) {
      await expect(realPackage(JOB_WORD, ACTOR, http).remove({ ...indexOf(8), id })).rejects.toThrow(
        `not a version's id: ${String(id)}`,
      );
    }
    expect(calls).toEqual([]);
  });

  it("refuses when the registry's sign-in fails or sends no pull credential", async () => {
    const signingIn = (answer: Response) =>
      realPackage(JOB_WORD, ACTOR, recording(() => answer).http).bundles(at(8).image.digest);
    await expect(signingIn(json({}, 401))).rejects.toThrow(/^the registry's sign-in answered 401$/);
    await expect(signingIn(json({ token: '' }))).rejects.toThrow("the registry's sign-in sent no token");
    await expect(signingIn(json(['token']))).rejects.toThrow('sent no token');
  });
});

describe('removalOrder', () => {
  it('takes the oldest first, the lower id first at the same moment, and no more than a run may', () => {
    const many = Array.from({ length: MAX_REMOVALS + 5 }, (_, k): Version => ({
      id: 1_000 - k,
      digest: digest(1_000 - k),
      created: T0 + (k % 7) * MINUTE,
      tags: [],
    }));
    const order = removalOrder(many);
    expect(order).toHaveLength(MAX_REMOVALS);
    for (const [index, version] of order.entries()) {
      const next = order[index + 1];
      if (next === undefined) continue;
      expect(version.created < next.created || (version.created === next.created && version.id < next.id)).toBe(true);
    }
    const all = removalOrder([...many].reverse());
    expect(all.map(({ id }) => id)).toEqual(order.map(({ id }) => id));
  });
});

/** A package held in memory; `listing` can change what a read after the first sends. */
function held(
  initial: readonly Version[],
  options: {
    readonly refuseAt?: number;
    readonly keepsRemoved?: boolean;
    readonly listing?: (versions: Version[], read: number) => Promise<Version[]>;
  } = {},
) {
  let versions = [...initial];
  let reads = 0;
  const events: string[] = [];
  const source: Package = {
    versions: () => {
      reads += 1;
      const now = [...versions];
      return options.listing === undefined ? Promise.resolve(now) : options.listing(now, reads);
    },
    bundles: (image) => Promise.resolve(BUNDLES.get(image)),
    remove: (version) => {
      if (events.filter((event) => event.startsWith('remove')).length === options.refuseAt) {
        return Promise.reject(new Error('the package API answered 403 Forbidden'));
      }
      events.push(`remove ${String(version.id)}`);
      if (options.keepsRemoved !== true) versions = versions.filter(({ id }) => id !== version.id);
      return Promise.resolve();
    },
  };
  const pause = (ms: number): Promise<void> => {
    events.push(`pause ${String(ms)}`);
    return Promise.resolve();
  };
  return { source, events, pause, remaining: () => versions };
}

describe('prune', () => {
  const pruning = async (store: ReturnType<typeof held>, n = 8) => {
    const lines: string[] = [];
    await prune(own(n), store.source, HISTORY, (line) => lines.push(line), store.pause);
    return lines;
  };
  const removedIds = (events: readonly string[]): number[] =>
    ids(events.filter((event) => event.startsWith('remove ')).map((event) => ({ id: Number(event.slice(7)) })));

  it('removes what the plan names, oldest first with a pause between each, then finds every kept image there', async () => {
    const store = held(VERSIONS);
    const lines = await pruning(store);
    const order = removalOrder(
      planPrune(VERSIONS, imagesToKeep(VERSIONS, own(8), HISTORY), BUNDLES, own(8).digest).remove,
    );
    expect(store.events).toEqual(
      order.flatMap((version, index) => [
        ...(index > 0 ? [`pause ${String(PAUSE_MS)}`] : []),
        `remove ${String(version.id)}`,
      ]),
    );
    expect(removedIds(store.events)).toEqual(idsOf(1, 2, 3));
    expect(ids(store.remaining())).toEqual(idsOf(4, 5, 6, 7, 8));
    expect(lines).toContain(
      'Removing 3 images and 12 other versions (their signatures and SBOMs, and indexes nothing reads):',
    );
    expect(lines.slice(-2)).toEqual([
      'Removed 15 versions.',
      'The package now holds 25 versions, every kept image among them.',
    ]);
  });

  it('leaves what is past a run’s limit to the next run', async () => {
    const fifty = Array.from({ length: 50 }, (_, k) => published(k + 1));
    const versions = fifty.flatMap(({ all }) => all);
    const bundles = new Map(fifty.map(({ image, bundles: listed }) => [image.digest, listed]));
    const store = held(versions);
    const source: Package = { ...store.source, bundles: (image) => Promise.resolve(bundles.get(image)) };
    const lines: string[] = [];
    const last = { commit: commit(50), digest: fifty[49]?.image.digest ?? '' };
    await prune(last, source, HISTORY, (line) => lines.push(line), store.pause);
    expect(lines).toContain(`Removed ${String(MAX_REMOVALS)} versions.`);
    expect(lines).toContain(`25 more are left for the next run (at most ${String(MAX_REMOVALS)} a run).`);
    await prune(last, source, HISTORY, (line) => lines.push(line), store.pause);
    expect(lines).toContain('Removed 25 versions.');
    expect(store.remaining()).toHaveLength(25);
  });

  it('stops at a removal GitHub refuses, saying how many it had removed', async () => {
    const store = held(VERSIONS, { refuseAt: 4 });
    const stopped = pruning(store);
    await expect(stopped).rejects.toBeInstanceOf(Stopped);
    await expect(stopped).rejects.toMatchObject({ removed: 4, message: 'the package API answered 403 Forbidden' });
    expect(store.remaining()).toHaveLength(VERSIONS.length - 4);
  });

  it('stops when a kept image is missing afterwards', async () => {
    const store = held(VERSIONS, {
      listing: (versions, read) =>
        Promise.resolve(read === 1 ? versions : versions.filter(({ id }) => id !== at(6).image.id)),
    });
    await expect(pruning(store)).rejects.toMatchObject({
      name: 'Stopped',
      removed: 15,
      message: `kept images are missing afterwards: ${commit(6)}`,
    });
  });

  it('stops when a version it removed is still listed afterwards', async () => {
    const store = held(VERSIONS, { keepsRemoved: true });
    await expect(pruning(store)).rejects.toMatchObject({
      removed: 15,
      message: '15 of the versions removed are still listed',
    });
  });

  it('stops, saying so, when the package can’t be read again afterwards', async () => {
    const store = held(VERSIONS, {
      listing: (versions, read) =>
        read === 1 ? Promise.resolve(versions) : Promise.reject(new Error('the package API answered 502 Bad Gateway')),
    });
    await expect(pruning(store)).rejects.toMatchObject({
      removed: 15,
      message: 'the package API answered 502 Bad Gateway',
    });
  });

  it('removes nothing when the plan can’t be made', async () => {
    const store = held(VERSIONS);
    const refused = prune(
      { commit: commit(8), digest: digest(999) },
      store.source,
      HISTORY,
      () => undefined,
      store.pause,
    );
    await expect(refused).rejects.not.toBeInstanceOf(Stopped);
    await expect(refused).rejects.toThrow("isn't in the package");
    expect(store.events).toEqual([]);
  });
});

describe('main', () => {
  const ENV = { GITHUB_TOKEN: JOB_WORD, GITHUB_ACTOR: ACTOR };

  const run = async (
    argv: string[],
    env: Record<string, string | undefined> = ENV,
    http = serving(VERSIONS, BUNDLES),
  ) => {
    const lines: string[] = [];
    const pauses: number[] = [];
    const code = await main(
      argv,
      env,
      http.http,
      HISTORY,
      (line) => lines.push(line),
      (ms) => {
        pauses.push(ms);
        return Promise.resolve();
      },
    );
    return { code, lines, calls: http.calls, pauses };
  };

  it('says what a prune would remove, and only reads', async () => {
    const { code, lines, calls } = await run(['plan', commit(8), at(8).image.digest]);
    expect(code).toBe(EXIT.DONE);
    expect(lines).toEqual([
      `${IMAGE_REPOSITORY}: 40 versions (8 images, 8 signature indexes, 24 untagged).`,
      'Keeping 5 images:',
      `  ${commit(8)}  2026-09-10 08:00  (this run)`,
      `  ${commit(7)}  2026-09-10 07:00`,
      `  ${commit(6)}  2026-09-10 06:00`,
      `  ${commit(5)}  2026-09-10 05:00`,
      `  ${commit(4)}  2026-09-10 04:00`,
      'Would remove 3 images and 12 other versions (their signatures and SBOMs, and indexes nothing reads):',
      `  ${commit(3)}  2026-09-10 03:00`,
      `  ${commit(2)}  2026-09-10 02:00`,
      `  ${commit(1)}  2026-09-10 01:00`,
      'Nothing was removed: this is the plan alone.',
    ]);
    expect(calls.every(({ method }) => method === 'GET')).toBe(true);
    // The job's own credential goes to GitHub's API and the registry's sign-in alone.
    for (const call of calls) {
      const sent = call.authorization ?? '';
      if (call.url.startsWith(`${MANIFESTS}/`)) expect(sent).toBe(`Bearer ${PULL_WORD}`);
      else expect([`Bearer ${JOB_WORD}`, BASIC]).toContain(sent);
    }
    expect(calls.filter(({ url }) => url.startsWith(`${MANIFESTS}/`))).toHaveLength(5);
  });

  it('prunes as the job: every write a removal of a version the plan names, and it reads the package again', async () => {
    const { code, lines, calls, pauses } = await run(['prune', commit(8), at(8).image.digest]);
    expect(code).toBe(EXIT.DONE);
    const writes = calls.filter(({ method }) => method !== 'GET');
    expect(writes.map(({ method }) => method)).toEqual(Array.from({ length: 15 }, () => 'DELETE'));
    expect(ids(writes.map(({ url }) => ({ id: Number(url.slice(`${VERSIONS_API}/`.length)) })))).toEqual(
      idsOf(1, 2, 3),
    );
    for (const write of writes) expect(write.authorization).toBe(`Bearer ${JOB_WORD}`);
    expect(pauses).toEqual(Array.from({ length: 14 }, () => PAUSE_MS));
    expect(lines.at(-1)).toBe('The package now holds 25 versions, every kept image among them.');
    expect(calls.at(-1)?.url).toBe(`${VERSIONS_API}?per_page=100&page=1`);
  });

  it('says how far it got when GitHub refuses a removal', async () => {
    const { code, lines } = await run(['prune', commit(8), at(8).image.digest], ENV, serving(VERSIONS, BUNDLES, 2));
    expect(code).toBe(EXIT.REFUSED);
    const third = removalOrder(
      idsOf(1, 2, 3).map((id) => VERSIONS.find((version) => version.id === id) ?? at(1).image),
    )[2];
    expect(lines.at(-1)).toBe(
      `Stopped after removing 2 versions: removing ${third?.digest ?? ''}, the package API answered 403 Forbidden.`,
    );
  });

  it('refuses, removing nothing, when the plan cannot be made', async () => {
    const { code, lines } = await run(['plan', commit(8), digest(999)]);
    expect(code).toBe(EXIT.REFUSED);
    expect(lines).toEqual([`Refused: this run's image (${digest(999)}) isn't in the package. Nothing was removed.`]);

    const offline = recording(() => Promise.reject(new Error('fetch failed')));
    expect((await run(['plan', commit(8), at(8).image.digest], ENV, offline)).lines).toEqual([
      'Refused: fetch failed. Nothing was removed.',
    ]);
  });

  it('needs the job token and actor Actions sets', async () => {
    for (const env of [
      {},
      { GITHUB_TOKEN: JOB_WORD },
      { GITHUB_ACTOR: ACTOR },
      { GITHUB_TOKEN: '', GITHUB_ACTOR: ACTOR },
      { GITHUB_TOKEN: JOB_WORD, GITHUB_ACTOR: '' },
    ]) {
      const { code, lines, calls } = await run(['plan', commit(8), at(8).image.digest], env);
      expect(code).toBe(EXIT.REFUSED);
      expect(lines).toEqual([
        'Refused: GITHUB_TOKEN and GITHUB_ACTOR must be set (Actions sets both). Nothing was removed.',
      ]);
      expect(calls).toEqual([]);
    }
  });

  it('knows two commands, each with a commit and its digest', async () => {
    for (const argv of [
      [],
      ['plan'],
      ['remove', commit(8), at(8).image.digest],
      ['plan', at(8).image.digest],
      ['plan', commit(8)],
      ['plan', at(8).image.digest, commit(8)],
      ['plan', commit(8).toUpperCase(), at(8).image.digest],
      ['plan', commit(8), 'sha256:abc'],
      ['plan', commit(8), at(8).image.digest, 'more'],
    ]) {
      const { code, lines, calls } = await run(argv);
      expect(code).toBe(EXIT.USAGE);
      expect(lines).toEqual([USAGE]);
      expect(calls).toEqual([]);
    }
  });
});
