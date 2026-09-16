// SEC-SC-02: every container image the repository names is pinned by digest,
// so a changed image can't slip in under the same tag, and carries a version
// tag, so a human can see what it is. The compose stack's Postgres is the same
// image the database tests run on, and its Node is the image the app is built
// on, so one weekly bump moves them together.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { POSTGRES_IMAGES } from '../test-db/postgres-images.ts';

const COMPOSE_FILE = 'deploy/compose/compose.yaml';
const DOCKERFILE = 'Dockerfile';

/** `name:tag@sha256:<64 hex>`, with a registry and path allowed in the name. */
const PINNED = /^(?<name>[a-z0-9][a-z0-9._/-]*):(?<tag>[A-Za-z0-9][A-Za-z0-9._-]*)@sha256:(?<digest>[0-9a-f]{64})$/g;

/** Why an image reference is not acceptable, or nothing. */
export function imageProblems(images: readonly string[]): string[] {
  return images.flatMap((image) => {
    const tag = [...image.matchAll(PINNED)][0]?.groups?.tag;
    if (tag === undefined) return [`${image}: not written as name:tag@sha256:<64 hex digits>`];
    if (tag === 'latest' || !/[0-9]/.test(tag)) return [`${image}: the tag must name a version (not latest)`];
    return [];
  });
}

interface ComposeFile {
  services: Record<string, { image?: string }>;
}

/** Every `image:` in a compose file, by service. */
export function composeImages(text: string): Record<string, string> {
  const { services } = parse(text, { merge: true }) as ComposeFile;
  return Object.fromEntries(
    Object.entries(services).flatMap(([name, service]) => (service.image === undefined ? [] : [[name, service.image]])),
  );
}

/** Every `FROM` in a Dockerfile, in order, without the stage name. */
export function dockerfileImages(text: string): string[] {
  return text
    .split('\n')
    .map((line) => [...line.matchAll(/^FROM\s+(\S+)/g)][0]?.[1])
    .filter((image): image is string => image !== undefined);
}

const compose = composeImages(readFileSync(COMPOSE_FILE, 'utf8'));
const dockerfile = dockerfileImages(readFileSync(DOCKERFILE, 'utf8'));

/** The image built from the Dockerfile is named, not pulled; it has no digest to pin. */
const OUR_IMAGE = 'agentx-app:local';

describe('SEC-SC-02 container images are pinned by digest', () => {
  it('finds the images (so the checks below are not vacuous)', () => {
    expect(Object.keys(compose).length).toBeGreaterThanOrEqual(5);
    expect(dockerfile.length).toBe(2);
  });

  it('pins every third-party image in the compose stack', () => {
    const pulled = Object.values(compose).filter((image) => image !== OUR_IMAGE);
    expect(pulled.length).toBeGreaterThanOrEqual(4);
    expect(imageProblems(pulled)).toEqual([]);
  });

  it('pins the base image of both Dockerfile stages, and uses the same one twice', () => {
    expect(imageProblems(dockerfile)).toEqual([]);
    expect(new Set(dockerfile).size).toBe(1);
  });

  it('builds on the Node major the repository runs (.nvmrc)', () => {
    const major = readFileSync('.nvmrc', 'utf8').trim();
    expect(dockerfile[0]).toMatch(new RegExp(`^node:${major}\\.[0-9]+\\.[0-9]+-`));
  });

  it('runs the compose stack on the newest Postgres the database tests run on', () => {
    const newest = Object.keys(POSTGRES_IMAGES).sort().at(-1) ?? '';
    expect(newest).not.toBe('');
    expect(compose.db).toBe(POSTGRES_IMAGES[newest]);
  });

  it('uses the app image itself for the jobs that share it, and the base image for the volume step', () => {
    expect(compose.api).toBe(OUR_IMAGE);
    expect(compose.migrate).toBe(OUR_IMAGE);
    expect(compose['zitadel-volume']).toBe(dockerfile[0]);
  });

  it('keeps Zitadel and its login on the same version', () => {
    const version = (image: string | undefined): string | undefined => image?.match(/:(v[0-9.]+)@/)?.[1];
    expect(version(compose.zitadel)).toMatch(/^v4\./);
    expect(version(compose['zitadel-init'])).toBe(version(compose.zitadel));
    expect(version(compose.login)).toBe(version(compose.zitadel));
  });

  it('runs the same Zitadel image on Azure as the compose stack, so one bump moves both', () => {
    const named = (text: string, parameter: string): string | undefined =>
      [...text.matchAll(new RegExp(`^param ${parameter} = '([^']+)'$`, 'gm'))][0]?.[1];
    const azure = readFileSync('deploy/azure/staging.apps.bicepparam', 'utf8');
    expect(imageProblems([named(azure, 'zitadelImage') ?? ''])).toEqual([]);
    expect(named(azure, 'zitadelImage')).toBe(compose.zitadel);
    // Ours is named by digest alone there, which CI gives the deployment.
    expect(azure).toContain("param appImageRepository = 'ghcr.io/shahbaz242630/agent-x'");
  });

  it('lets Dependabot propose digests, minors and patches, never a major, which moves by hand', () => {
    const { updates } = parse(readFileSync('.github/dependabot.yml', 'utf8')) as {
      updates: { 'package-ecosystem': string; ignore?: { 'dependency-name': string; 'update-types'?: string[] }[] }[];
    };
    const docker = updates.filter((update) => update['package-ecosystem'] === 'docker');
    expect(docker).toHaveLength(1);
    expect(docker[0]?.ignore).toEqual([{ 'dependency-name': '*', 'update-types': ['version-update:semver-major'] }]);
  });

  it('the check catches every way an image can be left unpinned', () => {
    const digest = 'a'.repeat(64);
    expect(
      imageProblems([
        'postgres',
        'postgres:18.6-trixie',
        `postgres@sha256:${digest}`,
        `postgres:latest@sha256:${digest}`,
        `postgres:trixie@sha256:${digest}`,
        `postgres:18.6-trixie@sha256:${'a'.repeat(63)}`,
        `postgres:18.6-trixie@sha1:${digest}`,
        `ghcr.io/zitadel/zitadel:v4.17.3@sha256:${digest}`,
        `node:24.21.0-trixie-slim@sha256:${digest}`,
      ]),
    ).toEqual([
      'postgres: not written as name:tag@sha256:<64 hex digits>',
      'postgres:18.6-trixie: not written as name:tag@sha256:<64 hex digits>',
      `postgres@sha256:${digest}: not written as name:tag@sha256:<64 hex digits>`,
      `postgres:latest@sha256:${digest}: the tag must name a version (not latest)`,
      `postgres:trixie@sha256:${digest}: the tag must name a version (not latest)`,
      `postgres:18.6-trixie@sha256:${'a'.repeat(63)}: not written as name:tag@sha256:<64 hex digits>`,
      `postgres:18.6-trixie@sha1:${digest}: not written as name:tag@sha256:<64 hex digits>`,
    ]);
  });

  it('reads FROM lines and compose images as written', () => {
    expect(dockerfileImages('FROM a:1@sha256:x AS build\nRUN x\nFROM a:1@sha256:x\n')).toEqual([
      'a:1@sha256:x',
      'a:1@sha256:x',
    ]);
    expect(composeImages('services:\n  a:\n    image: img:1\n  b:\n    build: .\n')).toEqual({ a: 'img:1' });
  });
});
