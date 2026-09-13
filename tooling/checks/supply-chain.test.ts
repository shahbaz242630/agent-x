// SEC-SC-01: the pnpm supply-chain settings are in force. Release age, trust
// policy, blocked build scripts, a hash-pinned pnpm, exact versions and a
// frozen-lockfile install in CI. Settings are read from pnpm itself, so an
// override from anywhere (a global config, an environment variable) shows up.
// Any relaxation must be in the exceptions list with a reason, an owner and an
// unexpired date (Rule Book §7).
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';

import { SUPPLY_CHAIN_EXCEPTIONS, type SupplyChainException } from '../supply-chain-exceptions.ts';

type Json = Record<string, unknown>;

const readJson = (file: string): Json => JSON.parse(readFileSync(file, 'utf8')) as Json;
const readYaml = (file: string): Json => parse(readFileSync(file, 'utf8')) as Json;

const rootManifest = readJson('package.json');
const workspaceFile = readYaml('pnpm-workspace.yaml');
const workflowFiles = readdirSync('.github/workflows').map((file) => path.join('.github/workflows', file));

/**
 * Every key pnpm-workspace.yaml may hold. Anything else (overrides,
 * packageExtensions, a loosening option new in some pnpm release) fails the
 * check until it is reviewed and added here.
 */
const REVIEWED_WORKSPACE_KEYS = [
  'packages',
  'minimumReleaseAge',
  'minimumReleaseAgeStrict',
  'minimumReleaseAgeIgnoreMissingTime',
  'trustPolicy',
  'blockExoticSubdeps',
  'strictDepBuilds',
  'engineStrict',
  'enablePrePostScripts',
  'savePrefix',
  'pmOnFail',
];
/** Keys allowed only to carry exceptions registered in supply-chain-exceptions.ts. */
const EXCEPTION_KEYS: SupplyChainException['setting'][] = [
  'allowBuilds',
  'minimumReleaseAgeExclude',
  'trustPolicyExclude',
];

/** The settings pnpm actually applies, from the pinned pnpm via Corepack. */
let effective: Json;

beforeAll(() => {
  const command = ['corepack', 'pnpm', 'config', 'list', '--json'];
  const result =
    process.platform === 'win32'
      ? // Corepack is a .cmd shim on Windows, which only a shell runs. The command is fixed text.
        spawnSync(command.join(' '), { encoding: 'utf8', shell: true, timeout: 60_000 })
      : spawnSync(command[0] ?? '', command.slice(1), { encoding: 'utf8', timeout: 60_000 });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`pnpm config list failed (${String(result.status)}): ${result.stderr}`);
  }
  effective = JSON.parse(result.stdout) as Json;
});

/** The workspace's package.json files: the root plus every apps/* and packages/* folder that has one. */
function workspaceManifests(): string[] {
  const members = ['apps', 'packages']
    .filter((parent) => existsSync(parent))
    .flatMap((parent) =>
      readdirSync(parent, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => path.join(parent, entry.name, 'package.json')),
    );
  return ['package.json', ...members.filter((file) => existsSync(file))];
}

/** A YYYY-MM-DD date that exists on the calendar. */
function isRealDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().startsWith(value);
}

/** Exceptions missing a reason or owner, or whose expiry is malformed or before `today` (YYYY-MM-DD). */
function invalidExceptions(entries: readonly SupplyChainException[], today: string): SupplyChainException[] {
  return entries.filter(
    (entry) =>
      entry.reason.trim() === '' || entry.owner.trim() === '' || !isRealDate(entry.expires) || entry.expires < today,
  );
}

function selectorsIn(setting: SupplyChainException['setting']): string[] {
  const value = effective[setting];
  if (value === undefined) return [];
  if (setting === 'allowBuilds') {
    return Object.entries(value as Record<string, boolean>)
      .filter(([, allowed]) => allowed)
      .map(([selector]) => selector);
  }
  return value as string[];
}

describe('SEC-SC-01 pnpm supply-chain settings are enforced', () => {
  it('sets only reviewed keys in pnpm-workspace.yaml', () => {
    const unreviewed = Object.keys(workspaceFile).filter(
      (key) => !REVIEWED_WORKSPACE_KEYS.includes(key) && !(EXCEPTION_KEYS as string[]).includes(key),
    );
    expect(unreviewed).toEqual([]);
  });

  it('waits at least 3 days before installing a new release, and fails rather than guess', () => {
    expect(effective.minimumReleaseAge).toBeGreaterThanOrEqual(4320);
    expect(effective.minimumReleaseAgeStrict).toBe(true);
    expect(effective.minimumReleaseAgeIgnoreMissingTime).toBe(false);
  });

  it('refuses a package whose publishing trust has dropped', () => {
    expect(effective.trustPolicy).toBe('no-downgrade');
  });

  it('re-verifies the lockfile instead of trusting it', () => {
    expect(effective.trustLockfile).not.toBe(true);
  });

  it('keeps transitive dependencies on the registry', () => {
    expect(effective.blockExoticSubdeps).toBe(true);
  });

  it('blocks dependency build scripts unless reviewed', () => {
    expect(effective.strictDepBuilds).toBe(true);
    expect(effective.dangerouslyAllowAllBuilds).not.toBe(true);
  });

  it('runs no hidden pre- or post- script around a check', () => {
    expect(effective.enablePrePostScripts).toBe(false);
  });

  it('has no hook or config file that could rewrite packages or settings', () => {
    const present = ['.pnpmfile.cjs', '.pnpmfile.mjs', '.pnpmfile.js', '.corepack.env', '.npmrc'].filter((file) =>
      existsSync(file),
    );
    expect(present).toEqual([]);
    expect(workspaceFile.configDependencies ?? {}).toEqual({});
  });

  it('pins pnpm itself to an exact version and its sha512', () => {
    expect(rootManifest.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}$/);
  });

  it("keeps the lockfile one YAML document, so GitHub's dependency graph sees every package", () => {
    const documents = parseAllDocuments(readFileSync('pnpm-lock.yaml', 'utf8'));
    expect(documents).toHaveLength(1);
    const importers = (documents[0]?.toJS() as Json | undefined)?.importers as Json | undefined;
    expect(Object.keys(importers ?? {}).sort()).toEqual(
      [
        '.',
        ...workspaceManifests()
          .slice(1)
          .map((file) => path.dirname(file).replaceAll('\\', '/')),
      ].sort(),
    );
  });

  it('declares every dependency at an exact version (or a workspace link)', () => {
    const loose = workspaceManifests().flatMap((file) => {
      const manifest = readJson(file);
      return ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap((field) =>
        Object.entries((manifest[field] ?? {}) as Record<string, string>)
          .filter(([, spec]) => !/^(\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?|workspace:\*)$/.test(spec))
          .map(([name, spec]) => `${file} ${field}: ${name}@${spec}`),
      );
    });
    expect(loose).toEqual([]);
  });

  it('installs in CI from the frozen lockfile, with no pnpm setting overridden', () => {
    const ci = readYaml('.github/workflows/ci.yml');
    const verifySteps = ((ci.jobs as Record<string, Json>).verify?.steps ?? []) as Json[];

    expect(verifySteps.map((step) => step.run)).toContain('pnpm install --frozen-lockfile');
    // Environment overrides, flags that relax a check, and any Corepack variable
    // other than the one that switches off its repository env file.
    const loosening = /pnpm_config_|npm_config_|--no-frozen-lockfile|--trust-|--config\.|COREPACK_(?!ENV_FILE: '0')/i;
    const overriding = workflowFiles.filter((file) => loosening.test(readFileSync(file, 'utf8')));
    expect(overriding).toEqual([]);
  });

  describe('every CI job that runs pnpm', () => {
    const runsCorepack = (step: { run?: unknown }): boolean =>
      typeof step.run === 'string' && step.run.includes('corepack');
    const pnpmJobs = workflowFiles.flatMap((file) =>
      Object.entries((readYaml(file).jobs ?? {}) as Record<string, Json>)
        .filter(([, job]) => ((job.steps ?? []) as Json[]).some(runsCorepack))
        .map(([name, job]) => ({ label: `${file}: ${name}`, job })),
    );

    it('exists (so the checks below are not vacuous)', () => {
      expect(pnpmJobs.length).toBeGreaterThanOrEqual(2);
    });

    it('stops Corepack reading a repository env file', () => {
      const unguarded = pnpmJobs.filter(({ job }) => (job.env as Json | undefined)?.COREPACK_ENV_FILE !== '0');
      expect(unguarded.map(({ label }) => label)).toEqual([]);
    });

    it('installs the newest Node 24, so package.json engines always holds', () => {
      const stale = pnpmJobs.filter(({ job }) => {
        const setupNode = ((job.steps ?? []) as Json[]).find((step) =>
          String(step.uses).startsWith('actions/setup-node@'),
        );
        return (setupNode?.with as Json | undefined)?.['check-latest'] !== true;
      });
      expect(stale.map(({ label }) => label)).toEqual([]);
    });
  });

  it('lets Dependabot propose only versions old enough to install', () => {
    const dependabot = readYaml('.github/dependabot.yml');
    const npm = (dependabot.updates as Json[]).find((update) => update['package-ecosystem'] === 'npm');
    const cooldown = (npm?.cooldown ?? {}) as Record<string, unknown>;
    const minimumDays = Number(effective.minimumReleaseAge) / 1440;

    expect(cooldown['default-days']).toBeGreaterThanOrEqual(minimumDays);
    for (const [key, days] of Object.entries(cooldown).filter(([key]) => key.endsWith('-days'))) {
      expect({ [key]: days }).toEqual({ [key]: Math.max(Number(days), minimumDays) });
    }
    // A package excluded from the cooldown would be proposed too fresh to install.
    expect(cooldown.exclude ?? []).toEqual([]);
  });

  describe('every relaxation is registered, justified and unexpired', () => {
    it.each(EXCEPTION_KEYS)('%s matches the exceptions list', (setting) => {
      const registered = SUPPLY_CHAIN_EXCEPTIONS.filter((entry) => entry.setting === setting).map(
        (entry) => entry.selector,
      );
      expect(selectorsIn(setting).sort()).toEqual(registered.sort());
    });

    it('has a reason, an owner and a real, future expiry date for every exception', () => {
      expect(invalidExceptions(SUPPLY_CHAIN_EXCEPTIONS, new Date().toISOString().slice(0, 10))).toEqual([]);
    });

    it('rejects an exception with no reason or owner, a malformed or impossible date, or a past date', () => {
      const valid: SupplyChainException = {
        setting: 'minimumReleaseAgeExclude',
        selector: 'example@1.0.0',
        reason: 'urgent security fix',
        owner: 'partner',
        expires: '2026-10-01',
      };
      const entries = [
        valid,
        { ...valid, reason: ' ' },
        { ...valid, owner: '' },
        { ...valid, expires: '2026-9-30' },
        { ...valid, expires: '2026-02-30' },
        { ...valid, expires: '2026-09-12' },
      ];
      expect(invalidExceptions(entries, '2026-09-13')).toEqual(entries.slice(1));
    });
  });
});
