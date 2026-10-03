// Rule Book §5: every package the product runs with, its dependencies'
// dependencies included, carries a licence on the reviewed list below, so no
// copyleft or unlicensed code reaches the image unnoticed. Development tools
// never ship, and are left out.
import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

/** Permissive licences, each letting us ship the code in a closed product. */
const ALLOWED_LICENCES = new Set([
  '0BSD',
  'Apache-2.0',
  'BlueOak-1.0.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'CC0-1.0',
  'ISC',
  'MIT',
]);

/** A reviewed licence, or an SPDX choice such as `(MIT OR Apache-2.0)` with one reviewed option: the choice is ours. */
const allowed = (license: unknown): boolean =>
  typeof license === 'string' &&
  license
    .replace(/^\((.*)\)$/, '$1')
    .split(' OR ')
    .some((option) => ALLOWED_LICENCES.has(option.trim()));

interface Manifest {
  name?: string;
  version?: string;
  license?: unknown;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const read = (file: string) => JSON.parse(readFileSync(file, 'utf8')) as Manifest;

/** A dependency's folder as Node finds it from `from`: the nearest node_modules up the tree. */
function installed(name: string, from: string): string | undefined {
  for (let dir = from; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, 'node_modules', name);
    if (existsSync(path.join(candidate, 'package.json'))) return realpathSync(candidate);
    if (path.dirname(dir) === dir) return undefined;
  }
}

/** The workspace's product packages: apps/* and packages/*. */
function workspacePackages(): string[] {
  return ['apps', 'packages'].flatMap((parent) =>
    readdirSync(parent, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && existsSync(path.join(parent, entry.name, 'package.json')))
      .map((entry) => path.resolve(parent, entry.name)),
  );
}

/** Every external package the product runs with, by its folder, walked from the workspace's production dependencies. */
function productionPackages(): Map<string, Manifest> {
  const found = new Map<string, Manifest>();
  const missing: string[] = [];
  const queue = workspacePackages();
  const workspace = new Set(queue);
  for (let dir = queue.shift(); dir !== undefined; dir = queue.shift()) {
    const manifest = read(path.join(dir, 'package.json'));
    // An optional dependency for another platform is never installed, so its absence is no gap.
    const optional = new Set(Object.keys(manifest.optionalDependencies ?? {}));
    for (const name of [...Object.keys(manifest.dependencies ?? {}), ...optional]) {
      const at = installed(name, dir);
      if (at === undefined) {
        if (!optional.has(name)) missing.push(`${name} (from ${dir})`);
        continue;
      }
      if (workspace.has(at) || found.has(at)) continue;
      found.set(at, read(path.join(at, 'package.json')));
      queue.push(at);
    }
  }
  expect(missing).toEqual([]);
  return found;
}

describe('Rule Book §5: the product ships only permissively licensed code', () => {
  const packages = productionPackages();

  it('finds the product’s dependencies (so the check below is not vacuous)', () => {
    expect(packages.size).toBeGreaterThan(60);
  });

  it('allows only reviewed licences', () => {
    const refused = [...packages.values()]
      .filter(({ license }) => !allowed(license))
      .map(({ name, version, license }) => `${String(name)}@${String(version)}: ${JSON.stringify(license)}`);
    expect(refused).toEqual([]);
  });
});
