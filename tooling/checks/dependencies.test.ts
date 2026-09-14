// Rule Book §5, SEC-DATA-03: every production dependency of a package or app
// is on the reviewed list in tooling/allowed-dependencies.ts, with its reason,
// and every entry there is still used. The banned-module lists catch known
// telemetry SDKs by name; this catches everything else.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ALLOWED_DEPENDENCIES } from '../allowed-dependencies.ts';

interface Manifest {
  dependencies?: Record<string, string>;
}

/** Every package.json under packages/ and apps/, with its production dependencies. */
function productManifests(): { file: string; dependencies: Record<string, string> }[] {
  return ['packages', 'apps']
    .filter((parent) => existsSync(parent))
    .flatMap((parent) =>
      readdirSync(parent, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => path.join(parent, entry.name, 'package.json')),
    )
    .filter((file) => existsSync(file))
    .map((file) => ({ file, dependencies: (JSON.parse(readFileSync(file, 'utf8')) as Manifest).dependencies ?? {} }));
}

/** Production dependencies that aren't workspace packages. */
function externalDependencies(dependencies: Record<string, string>): string[] {
  return Object.entries(dependencies)
    .filter(([, spec]) => !spec.startsWith('workspace:'))
    .map(([name]) => name);
}

describe('Rule Book §5: production dependencies are reviewed', () => {
  const manifests = productManifests();

  it('finds the product packages (so the checks below are not vacuous)', () => {
    expect(manifests.length).toBeGreaterThanOrEqual(3);
  });

  it('allows only listed packages as production dependencies', () => {
    const unlisted = manifests.flatMap(({ file, dependencies }) =>
      externalDependencies(dependencies)
        .filter((name) => !Object.hasOwn(ALLOWED_DEPENDENCIES, name))
        .map((name) => `${file}: ${name}`),
    );
    expect(unlisted).toEqual([]);
  });

  it('lists nothing no package uses any more', () => {
    const used = new Set(manifests.flatMap(({ dependencies }) => externalDependencies(dependencies)));
    expect(Object.keys(ALLOWED_DEPENDENCIES).filter((name) => !used.has(name))).toEqual([]);
  });

  it('gives every entry a reason', () => {
    expect(Object.entries(ALLOWED_DEPENDENCIES).filter(([, reason]) => reason.trim().length < 10)).toEqual([]);
  });
});
